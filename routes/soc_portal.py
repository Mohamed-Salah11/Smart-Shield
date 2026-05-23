"""
routes/soc_portal.py
--------------------
SOC Team Portal — a dedicated web interface for Security Operations Center
analysts, served under /soc-portal and gated by tier-based access control.

Tier hierarchy (ascending privilege):
  L1 — Triage Analyst:    view alerts, open/view cases
  L2 — Investigator:      L1 + add notes, assign cases, threat intel
  L3 — Incident Responder: L2 + quick actions (block IP, reload firewall, close cases)

Authentication is separate from the admin UI session (soc_* session keys).
"""

import ipaddress as _ip
import json
import json as _json
import time
from datetime import datetime, timezone

from flask import (
    Blueprint, jsonify, redirect, render_template,
    request, session, url_for, flash,
)
from werkzeug.security import check_password_hash

from app.database import get_db
from app.audit_log import log_soc_event
from app.soc_portal_auth import (
    active_soc_analysts,
    clear_mfa_pending,
    drop_soc_session,
    get_mfa_pending,
    get_soc_session_user,
    get_user_soc_tier,
    set_mfa_pending,
    soc_login_required,
    soc_portal_enabled,
    soc_tier_required,
    touch_soc_session,
    user_has_mfa,
)

soc_portal_bp = Blueprint("soc_portal", __name__, url_prefix="/soc-portal")


@soc_portal_bp.before_request
def _enforce_soc_bind_ip():
    """Defense-in-depth: refuse SOC portal requests that arrive on a host
    other than the configured SOC bind_ip.

    The admin nginx vhost is configured to 404 /soc-portal/* on the admin IP
    (see ``nginx_writer._soc_isolation_block``), but if nginx is bypassed,
    misconfigured, or not in front (dev runs), gunicorn would still serve the
    blueprint from any host. This check makes the boundary an app-side
    invariant.

    Behavior:
      * bind_ip unset / "" / "0.0.0.0"     → allow (legacy single-IP mode)
      * request host IP matches bind_ip    → allow
      * request host IP differs            → 404 (look like the route doesn't exist)
    """
    try:
        conn = get_db()
        row = conn.execute(
            "SELECT enabled, bind_ip FROM soc_portal_config WHERE id=1"
        ).fetchone()
    except Exception:
        return None
    if not row or not bool(row["enabled"]):
        return None
    bind_ip = (row["bind_ip"] or "").strip()
    if not bind_ip or bind_ip == "0.0.0.0":
        return None
    # request.host is "ip[:port]"; split off the port if present. The full URL
    # never carries a username/credential so a simple rsplit is safe.
    host_value = (request.host or "").rsplit(":", 1)[0].strip("[]")
    if host_value == bind_ip:
        return None
    from flask import abort
    abort(404)


# SOC alert feed allowlist. Anything not listed here is treated as routine
# non-SOC noise and excluded from /soc-portal/api/alerts. Default-deny — a
# new SIEM action joins the SOC view only after deliberate review.
# Session entries are restricted to multi-fail aggregates (lockouts); single
# auth failures are not, in themselves, a security risk.
SOC_ALERT_ACTIONS: "dict[str, object]" = {
    "ids":           "*",
    "security":      {"su_attempt_failed",
                      "brute_force_detected", "ids_flood_detected",
                      "insecure_protocol_detected", "pf_table_overload",
                      "multi_failed_login", "login_blocked_user_lockout"},
    "session":       {"soc_login_blocked_user_lockout"},
    "vpn":           {"vpn_auth_fail"},
    "file_download": "*",
    "system":        {"kernel_panic", "out_of_memory",
                      "service_down", "cert_expired"},
}


def _is_soc_relevant(evt: dict) -> bool:
    cat    = (evt.get("category") or "").lower()
    action = (evt.get("action")   or "").lower()
    allowed = SOC_ALERT_ACTIONS.get(cat)
    if allowed is None:
        return False
    if allowed != "*" and action not in allowed:
        return False
    return True


def _resolve_event_uuid(conn, data: dict) -> str:
    """Return the canonical event_uuid for an action/assignment request.

    The SOC frontend was migrated in Wave A to send ``event_uuid``. For
    backward compatibility with cached browser tabs still posting the
    legacy ``event_key`` (the event's ISO-8601 timestamp), resolve the
    timestamp to a uuid by looking it up in the events table.

    Returns an empty string when neither identifier resolves — callers
    treat that as a 400 from the client.
    """
    uuid_in = (data.get("event_uuid") or "").strip()
    if uuid_in:
        return uuid_in
    legacy = (data.get("event_key") or "").strip()
    if not legacy:
        return ""
    try:
        row = conn.execute(
            "SELECT event_uuid FROM events WHERE ts = ? "
            "ORDER BY id DESC LIMIT 1",
            (legacy,),
        ).fetchone()
        if row and row["event_uuid"]:
            return row["event_uuid"]
    except Exception:
        pass
    return ""


# ---------------------------------------------------------------------------
# Brute-force / lockout helpers — reuse the admin login_failures table
# ---------------------------------------------------------------------------

def _bf_config(conn):
    """Return (threshold, blocktime, detection_time, pass_list) from advanced_admin_access."""
    try:
        row = conn.execute(
            "SELECT threshold, blocktime, detection_time, pass_list "
            "FROM advanced_admin_access WHERE id=1"
        ).fetchone()
    except Exception:
        row = None
    if row:
        try:
            pass_list = _json.loads(row["pass_list"] or "[]")
        except Exception:
            pass_list = []
        return (
            int(row["threshold"]      or 30),
            int(row["blocktime"]      or 120),
            int(row["detection_time"] or 1800),
            pass_list,
        )
    return 30, 120, 1800, []


def _ip_whitelisted(remote: str, pass_list) -> bool:
    try:
        remote_ip = _ip.ip_address(remote or "")
    except ValueError:
        return False
    for cidr in pass_list:
        try:
            if remote_ip in _ip.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def _check_ip_lockout(conn, remote: str, threshold: int, blocktime: int,
                     detection_time: int):
    """Return (blocked, wait_seconds). Mirrors routes/auth.py:69-86."""
    if threshold <= 0:
        return False, 0
    now          = time.time()
    window_start = now - detection_time
    recent_count = conn.execute(
        "SELECT COUNT(*) FROM login_failures WHERE remote_addr=? AND failed_at>?",
        (remote, window_start),
    ).fetchone()[0]
    if recent_count < threshold:
        return False, 0
    last_fail = conn.execute(
        "SELECT MAX(failed_at) FROM login_failures WHERE remote_addr=?",
        (remote,),
    ).fetchone()[0]
    if last_fail and (now - last_fail) < blocktime:
        return True, int(blocktime - (now - last_fail))
    return False, 0


def _check_username_lockout(conn, username: str):
    """Return True if username has 5+ failures in the last 15 minutes."""
    if not username:
        return False
    count = conn.execute(
        "SELECT COUNT(*) FROM login_failures WHERE username=? AND failed_at>?",
        (username, time.time() - 900),
    ).fetchone()[0]
    return count >= 5


def _record_failure(conn, remote: str, username: str) -> None:
    conn.execute(
        "INSERT INTO login_failures (remote_addr, failed_at, username) VALUES (?,?,?)",
        (remote, time.time(), username or None),
    )
    conn.commit()
    # Forward a failure-burst alert to the SOC portal (single fails pass).
    try:
        from app.services.login_alerts import note_login_failure
        note_login_failure(conn, username, remote, target="soc_portal")
    except Exception:
        pass


def _clear_failures(conn, remote: str, username: str) -> None:
    conn.execute("DELETE FROM login_failures WHERE remote_addr=?", (remote,))
    if username:
        conn.execute("DELETE FROM login_failures WHERE username=?", (username,))
    conn.commit()


@soc_portal_bp.context_processor
def _inject_soc_context():
    """Inject SOC session values into every SOC portal template."""
    user_id, username, tier = get_soc_session_user()
    return {
        "soc_user_id":   user_id,
        "soc_username":  username or "",
        "soc_tier":      tier or "",
    }


@soc_portal_bp.before_request
def _soc_presence_heartbeat():
    """Record analyst presence on every request from an authenticated session."""
    user_id, username, tier = get_soc_session_user()
    if user_id:
        touch_soc_session(user_id, username, tier)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _portal_disabled_response():
    return render_template("soc_portal/disabled.html"), 503


def _get_config():
    conn = get_db()
    return conn.execute("SELECT * FROM soc_portal_config WHERE id=1").fetchone()


def _soc_log_event(**kwargs):
    """
    Emit an audit event tagged as SOC-portal-originated.

    Thin wrapper over :func:`app.audit_log.log_soc_event`, which stamps the
    ``details.soc_origin`` marker so the admin firewall-log view excludes SOC
    team activity (see ``hide_soc`` in routes/status.py:api_logs).
    """
    log_soc_event(**kwargs)


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@soc_portal_bp.route("/login", methods=["GET", "POST"])
def login():
    cfg = _get_config()
    if not (cfg and cfg["enabled"]):
        return _portal_disabled_response()

    # Already logged in — redirect to dashboard
    user_id, _, _ = get_soc_session_user()
    if user_id:
        return redirect(url_for("soc_portal.dashboard"))

    error  = None
    conn   = get_db()
    remote = request.remote_addr or ""
    threshold, blocktime, detection_time, pass_list = _bf_config(conn)
    whitelisted = _ip_whitelisted(remote, pass_list)

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # IP-based brute-force gate (mirrors admin login behaviour).
        if not whitelisted:
            blocked, wait = _check_ip_lockout(conn, remote, threshold, blocktime, detection_time)
            if blocked:
                return render_template(
                    "soc_portal/login.html",
                    error=f"Too many failed attempts from this address. Try again in {wait}s.",
                ), 429

            if username and _check_username_lockout(conn, username):
                _soc_log_event(
                    category="security",
                    action="soc_login_blocked_user_lockout",
                    username=username,
                    remote_addr=remote,
                    details={"window_minutes": 15, "threshold": 5},
                )
                return render_template(
                    "soc_portal/login.html",
                    error="Too many failed attempts for this account. Please wait 15 minutes before trying again.",
                ), 429

        user = conn.execute(
            "SELECT id, username, password, status FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        if not user or user["status"] != "active" or not check_password_hash(user["password"], password):
            error = "Invalid username or password."
            if not whitelisted:
                _record_failure(conn, remote, username)
            _soc_log_event(
                category="security",
                action="soc_login_failed",
                username=username,
                remote_addr=remote,
                details={"reason": "bad_credentials"},
            )
        else:
            tier = get_user_soc_tier(user["id"])
            if not tier:
                error = "Your account does not have SOC portal access."
                if not whitelisted:
                    _record_failure(conn, remote, username)
                _soc_log_event(
                    category="security",
                    action="soc_login_denied",
                    username=username,
                    remote_addr=remote,
                    details={"reason": "no_soc_tier"},
                )
            elif user_has_mfa(user["id"]):
                # Password OK — defer session establishment until TOTP succeeds.
                set_mfa_pending(user["id"], user["username"], tier)
                _soc_log_event(
                    category="session",
                    action="soc_login_mfa_required",
                    username=user["username"],
                    remote_addr=remote,
                    details={"tier": tier},
                )
                return redirect(url_for("soc_portal.login_mfa"))
            else:
                session["soc_user_id"]  = user["id"]
                session["soc_username"] = user["username"]
                session["soc_tier"]     = tier
                _clear_failures(conn, remote, user["username"])
                _soc_log_event(
                    category="session",
                    action="soc_login_success",
                    username=user["username"],
                    remote_addr=remote,
                    details={"tier": tier, "mfa": False},
                )
                return redirect(url_for("soc_portal.dashboard"))

    return render_template("soc_portal/login.html", error=error)


@soc_portal_bp.route("/login/mfa", methods=["GET", "POST"])
def login_mfa():
    """Second-factor (TOTP) step. Reached only after a valid password."""
    cfg = _get_config()
    if not (cfg and cfg["enabled"]):
        return _portal_disabled_response()

    pending_id, pending_user, pending_tier = get_mfa_pending()
    if not pending_id:
        flash("Your sign-in has expired. Please start over.", "warning")
        return redirect(url_for("soc_portal.login"))

    error  = None
    conn   = get_db()
    remote = request.remote_addr or ""

    if request.method == "POST":
        code = (request.form.get("code") or "").strip()
        row  = conn.execute(
            "SELECT totp_secret FROM users WHERE id = ?", (pending_id,)
        ).fetchone()
        secret = ""
        if row and row["totp_secret"]:
            from app.secret_store import decrypt_secret
            secret = decrypt_secret(row["totp_secret"])

        from app.totp import verify as _verify_totp
        if not _verify_totp(secret, code):
            error = "That code is incorrect or has expired."
            _record_failure(conn, remote, pending_user)
            _soc_log_event(
                category="security",
                action="soc_mfa_failed",
                username=pending_user,
                remote_addr=remote,
                details={"tier": pending_tier},
            )
            # Lock the account on repeated MFA failures (same threshold as
            # password failures — 5 in 15 min).
            if _check_username_lockout(conn, pending_user):
                clear_mfa_pending()
                _soc_log_event(
                    category="security",
                    action="soc_login_blocked_user_lockout",
                    username=pending_user,
                    remote_addr=remote,
                    details={"stage": "mfa", "threshold": 5},
                )
                return render_template(
                    "soc_portal/login.html",
                    error="Too many failed attempts for this account. Please wait 15 minutes before trying again.",
                ), 429
        else:
            session["soc_user_id"]  = pending_id
            session["soc_username"] = pending_user
            session["soc_tier"]     = pending_tier
            clear_mfa_pending()
            _clear_failures(conn, remote, pending_user)
            _soc_log_event(
                category="session",
                action="soc_login_success",
                username=pending_user,
                remote_addr=remote,
                details={"tier": pending_tier, "mfa": True},
            )
            return redirect(url_for("soc_portal.dashboard"))

    return render_template("soc_portal/login_mfa.html", error=error,
                           username=pending_user)


@soc_portal_bp.route("/logout", methods=["POST"])
def logout():
    username = session.get("soc_username", "unknown")
    drop_soc_session(session.get("soc_user_id"))
    session.pop("soc_user_id", None)
    session.pop("soc_username", None)
    session.pop("soc_tier", None)
    clear_mfa_pending()
    session.pop("soc_totp_enroll_secret", None)
    _soc_log_event(
        category="session",
        action="soc_logout",
        username=username,
        remote_addr=request.remote_addr,
        details={},
    )
    return redirect(url_for("soc_portal.login"))


# ---------------------------------------------------------------------------
# Security settings — analyst self-service MFA enrollment
# ---------------------------------------------------------------------------

@soc_portal_bp.route("/security", methods=["GET"])
@soc_login_required
def security():
    """MFA status + enroll/disable entry point."""
    user_id, username, tier = get_soc_session_user()
    return render_template("soc_portal/security.html",
                           mfa_enabled=user_has_mfa(user_id),
                           username=username, tier=tier)


@soc_portal_bp.route("/security/enroll", methods=["GET", "POST"])
@soc_login_required
def security_enroll():
    """Two-stage TOTP enrollment: generate secret, then verify a code to activate."""
    user_id, username, tier = get_soc_session_user()
    if user_has_mfa(user_id):
        flash("MFA is already enabled on your account.", "info")
        return redirect(url_for("soc_portal.security"))

    from app.totp import generate_secret, provisioning_uri, verify as _verify_totp

    error = None
    if request.method == "POST":
        code   = (request.form.get("code") or "").strip()
        secret = session.get("soc_totp_enroll_secret") or ""
        if not secret:
            flash("Enrollment session expired — please start again.", "warning")
            return redirect(url_for("soc_portal.security_enroll"))

        if _verify_totp(secret, code):
            from app.secret_store import encrypt_secret
            conn = get_db()
            conn.execute(
                "UPDATE users SET totp_secret=?, totp_enabled=1 WHERE id=?",
                (encrypt_secret(secret), user_id),
            )
            conn.commit()
            session.pop("soc_totp_enroll_secret", None)
            _soc_log_event(
                category="security",
                action="soc_mfa_enabled",
                username=username, remote_addr=request.remote_addr,
                details={"tier": tier},
            )
            flash("MFA enabled. You'll be prompted for a 6-digit code at next sign-in.", "success")
            return redirect(url_for("soc_portal.security"))
        error = "That code didn't verify. Make sure your device clock is accurate and try again."

    # GET (or POST with wrong code) — show or refresh the QR/secret.
    secret = session.get("soc_totp_enroll_secret")
    if not secret:
        secret = generate_secret()
        session["soc_totp_enroll_secret"] = secret
    uri = provisioning_uri(secret, account=username or "soc-analyst")
    return render_template("soc_portal/security_enroll.html",
                           secret=secret, uri=uri, error=error,
                           username=username, tier=tier)


@soc_portal_bp.route("/security/disable", methods=["POST"])
@soc_login_required
def security_disable():
    """Disable MFA — requires current password AND a valid TOTP code."""
    user_id, username, tier = get_soc_session_user()
    password = request.form.get("password") or ""
    code     = (request.form.get("code") or "").strip()

    conn = get_db()
    row  = conn.execute(
        "SELECT password, totp_secret FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if not row or not check_password_hash(row["password"], password):
        flash("Wrong password — MFA not changed.", "danger")
        return redirect(url_for("soc_portal.security"))

    from app.secret_store import decrypt_secret
    from app.totp import verify as _verify_totp
    secret = decrypt_secret(row["totp_secret"] or "")
    if not _verify_totp(secret, code):
        flash("Wrong authenticator code — MFA not changed.", "danger")
        return redirect(url_for("soc_portal.security"))

    conn.execute(
        "UPDATE users SET totp_secret='', totp_enabled=0 WHERE id=?",
        (user_id,),
    )
    conn.commit()
    _soc_log_event(
        category="security",
        action="soc_mfa_disabled",
        username=username, remote_addr=request.remote_addr,
        details={"tier": tier},
    )
    flash("MFA has been disabled on your account.", "success")
    return redirect(url_for("soc_portal.security"))


# ---------------------------------------------------------------------------
# Saved searches — analyst-defined queries, optionally scheduled
# ---------------------------------------------------------------------------

@soc_portal_bp.route("/saved-searches", methods=["GET", "POST"])
@soc_login_required
def saved_searches():
    from app.services import saved_searches as ss
    conn = get_db()
    _, username, _ = get_soc_session_user()

    if request.method == "POST":
        op = request.form.get("op", "")
        if op == "save":
            payload = {
                "id":               request.form.get("id"),
                "name":             request.form.get("name"),
                "owner":            username or "soc",
                "schedule_minutes": request.form.get("schedule_minutes", 0),
                "enabled":          request.form.get("enabled") == "on",
                "query": {
                    "search":     (request.form.get("search") or "").strip(),
                    "categories": [c.strip() for c in (request.form.get("categories") or "").split(",") if c.strip()],
                    "severities": [s.strip() for s in (request.form.get("severities") or "").split(",") if s.strip()],
                    "actions":    [a.strip() for a in (request.form.get("actions") or "").split(",") if a.strip()],
                    "limit":      request.form.get("limit") or 200,
                },
            }
            result = ss.upsert_search(conn, payload)
            if not result["ok"]:
                flash(result.get("message", "Save failed."), "danger")
            else:
                _soc_log_event(category="system", action="saved_search_saved",
                          username=username, remote_addr=request.remote_addr,
                          details={"name": payload["name"]})
                flash("Saved search updated.", "success")
        elif op == "delete":
            try:
                ss.delete_search(conn, int(request.form.get("id") or 0))
                flash("Saved search deleted.", "success")
            except Exception:
                flash("Failed to delete search.", "danger")
        return redirect(url_for("soc_portal.saved_searches"))

    return render_template(
        "soc_portal/saved_searches.html",
        searches=ss.list_searches(conn),
    )


@soc_portal_bp.route("/api/saved-searches/<int:sid>/run", methods=["POST"])
@soc_login_required
def api_saved_search_run(sid):
    """Execute a saved search on demand."""
    from app.services import saved_searches as ss
    conn = get_db()
    row  = conn.execute("SELECT query_json FROM saved_searches WHERE id=?", (sid,)).fetchone()
    if not row:
        return jsonify({"ok": False, "message": "not found"}), 404
    import json as _j
    try:
        query = _j.loads(row["query_json"] or "{}")
    except Exception:
        query = {}
    events = ss.run_search(query)
    return jsonify({"ok": True, "count": len(events), "events": events[:25]})


# ---------------------------------------------------------------------------
# Risk-based alerting feed
# ---------------------------------------------------------------------------

@soc_portal_bp.route("/api/risk-top", methods=["GET"])
@soc_login_required
def api_risk_top():
    """Return the top-N entities ranked by current (decayed) risk score."""
    try:
        limit = min(int(request.args.get("limit") or 20), 100)
    except (TypeError, ValueError):
        limit = 20
    from app.services.risk_scoring import top_risky
    return jsonify({"ok": True, "entities": top_risky(limit=limit)})


# ---------------------------------------------------------------------------
# IOC lookup — search the local TI cache + event store for an indicator
# ---------------------------------------------------------------------------

@soc_portal_bp.route("/api/ioc-lookup", methods=["GET"])
@soc_login_required
def api_ioc_lookup():
    """Return TI-hit status + recent events touching the given IOC."""
    ioc = (request.args.get("ioc") or "").strip()
    if not ioc:
        return jsonify({"ok": False, "message": "ioc is required"}), 400
    if len(ioc) > 256:
        return jsonify({"ok": False, "message": "ioc too long"}), 400

    from app.services.ti_enrichment import lookup
    result = lookup(ioc)
    _, username, _ = get_soc_session_user()
    _soc_log_event(
        category="security", action="soc_ioc_lookup",
        username=username, remote_addr=request.remote_addr,
        details={"ioc": ioc, "ti_hit": result["ti_hit"],
                 "event_count": result["event_count"]},
    )
    return jsonify({"ok": True, **result})


# ---------------------------------------------------------------------------
# SmartShield AI chatbot (SOC portal surface)
# ---------------------------------------------------------------------------

@soc_portal_bp.route("/api/chat", methods=["POST"])
@soc_login_required
def api_chat():
    """Agentic chat for SOC analysts — investigation + tier-gated SOC actions."""
    data     = request.get_json(force=True) or {}
    messages = data.get("messages", [])
    if not messages:
        return jsonify({"ok": False, "message": "No messages provided."}), 400

    user_id, username, _ = get_soc_session_user()
    from app.services.chatbot_service import process_chat
    conn   = get_db()
    result = process_chat(conn, messages, username or "", user_id, surface="soc")

    _soc_log_event(
        category="system",
        action="soc_chatbot_query",
        username=username,
        remote_addr=request.remote_addr,
        details={"turns": len(messages), "ok": result.get("ok", False)},
    )
    return jsonify(result)


@soc_portal_bp.route("/api/approve_action", methods=["POST"])
@soc_login_required
def api_approve_action():
    """Approve / reject a pending SOC chatbot write action (tier-gated)."""
    data     = request.get_json(force=True) or {}
    action   = data.get("action")
    approved = bool(data.get("approved", False))

    if not action or not isinstance(action, dict):
        return jsonify({"ok": False, "message": "Invalid action payload."}), 400
    if not approved:
        return jsonify({"ok": True, "reply": "Action cancelled."})

    from app.services.chatbot_service import execute_approved_action, _SOC_WRITE_TOOLS
    tool = action.get("tool", "")
    if tool not in _SOC_WRITE_TOOLS:
        return jsonify({
            "ok": False,
            "message": "Only SOC actions can be run from the SOC portal.",
        }), 403

    user_id, username, _ = get_soc_session_user()
    conn   = get_db()
    result = execute_approved_action(conn, action, username or "", user_id)

    _soc_log_event(
        category="security",
        action="soc_chatbot_action_executed",
        username=username,
        remote_addr=request.remote_addr,
        details={"tool": tool, "ok": result.get("ok")},
    )
    return jsonify(result)


# ---------------------------------------------------------------------------
# Dashboard (L1+)
# ---------------------------------------------------------------------------

@soc_portal_bp.route("/")
@soc_login_required
def dashboard():
    conn = get_db()
    _, username, tier = get_soc_session_user()

    open_cases = conn.execute(
        "SELECT COUNT(*) AS c FROM siem_cases WHERE status='open'"
    ).fetchone()["c"]

    my_cases = conn.execute(
        "SELECT COUNT(*) AS c FROM siem_cases WHERE status='open' AND assigned_to=?",
        (session.get("soc_user_id"),),
    ).fetchone()["c"]

    # Alerts are served via /api/alerts (NDJSON file); no SQL query needed here.

    threat_feed_row = conn.execute(
        "SELECT updated_at FROM ids_threat_feeds WHERE id=1"
    ).fetchone()

    return render_template(
        "soc_portal/dashboard.html",
        username=username,
        tier=tier,
        open_cases=open_cases,
        my_cases=my_cases,
        threat_feed_updated=threat_feed_row["updated_at"] if threat_feed_row else "—",
    )


# ---------------------------------------------------------------------------
# Live Alerts (L1+)
# ---------------------------------------------------------------------------

@soc_portal_bp.route("/alerts")
@soc_login_required
def alerts():
    _, username, tier = get_soc_session_user()
    return render_template("soc_portal/alerts.html", username=username, tier=tier)


@soc_portal_bp.route("/api/alerts")
@soc_login_required
def api_alerts():
    """JSON: recent security + IDS events from the audit log."""
    from app.audit_log import tail_events_since
    from app.database import get_db as _get_db

    after_ts = request.args.get("after", "")
    try:
        limit = min(int(request.args.get("limit", 200) or 200), 500)
    except (ValueError, TypeError):
        limit = 200

    events = tail_events_since(
        after_ts=after_ts,
        limit=limit,
        categories=list(SOC_ALERT_ACTIONS.keys()),
    )
    events = [e for e in events if _is_soc_relevant(e)]

    conn = _get_db()
    actions_map = {}      # by event_uuid
    actions_legacy = {}   # by timestamp — fallback for pre-v35 rows
    assign_map = {}       # by event_uuid
    assign_legacy = {}    # by timestamp — fallback
    if events:
        # Modern lookup: by event_uuid. Pre-v34 events have no uuid, so the
        # query is harmless on those rows (the IN clause never matches).
        uuids = [e.get("event_uuid", "") for e in events if e.get("event_uuid")]
        if uuids:
            u_ph = ",".join("?" * len(uuids))
            rows = conn.execute(
                f"SELECT event_uuid, action, taken_by, case_id "
                f"FROM siem_alert_actions WHERE event_uuid IN ({u_ph})",
                uuids,
            ).fetchall()
            for row in rows:
                if row["event_uuid"]:
                    actions_map[row["event_uuid"]] = dict(row)
            arows = conn.execute(
                f"SELECT event_uuid, assignee_id, assignee_name "
                f"FROM siem_alert_assignments WHERE event_uuid IN ({u_ph})",
                uuids,
            ).fetchall()
            for row in arows:
                if row["event_uuid"]:
                    assign_map[row["event_uuid"]] = dict(row)

        # Legacy lookup by timestamp — covers any action/assignment row that
        # the v35 backfill couldn't resolve (event row evicted by retention
        # before the migration ran). Also covers events with no uuid yet.
        keys = [e.get("timestamp", "") for e in events if e.get("timestamp")]
        if keys:
            k_ph = ",".join("?" * len(keys))
            rows = conn.execute(
                f"SELECT event_key, action, taken_by, case_id "
                f"FROM siem_alert_actions WHERE event_key IN ({k_ph})",
                keys,
            ).fetchall()
            for row in rows:
                actions_legacy[row["event_key"]] = dict(row)
            arows = conn.execute(
                f"SELECT event_key, assignee_id, assignee_name "
                f"FROM siem_alert_assignments WHERE event_key IN ({k_ph})",
                keys,
            ).fetchall()
            for row in arows:
                assign_legacy[row["event_key"]] = dict(row)

    enriched = []
    for evt in events:
        ts = evt.get("timestamp", "")
        uuid_v = evt.get("event_uuid", "")
        entry = dict(evt)
        entry["analyst_action"] = (
            actions_map.get(uuid_v) if uuid_v else None
        ) or actions_legacy.get(ts)
        entry["assignment"] = (
            assign_map.get(uuid_v) if uuid_v else None
        ) or assign_legacy.get(ts)
        entry["effective_severity"] = _derive_severity(evt)
        enriched.append(entry)

    return jsonify(enriched)


def _derive_severity(event: dict) -> str:
    """Derive a meaningful severity for SOC display when the logged value is generic 'info'."""
    cat    = (event.get("category") or "").lower()
    action = (event.get("action")   or "").lower()
    logged = (event.get("severity") or "info").lower()
    if logged not in ("info", ""):
        return logged
    if cat == "ids":
        return "critical"
    if cat == "security":
        if any(k in action for k in ("fail", "block", "deny", "brute", "attack")):
            return "high"
        return "medium"
    if cat == "session":
        if any(k in action for k in ("fail", "deny", "block")):
            return "high"
        return "low"
    if cat == "system":
        return "medium"
    if cat == "network":
        return "low"
    return "info"


# ---------------------------------------------------------------------------
# Alert assignment — every alert can be assigned to a logged-in analyst
# ---------------------------------------------------------------------------

@soc_portal_bp.route("/api/active-analysts")
@soc_login_required
def api_active_analysts():
    """List SOC analysts currently logged in — the valid 'assign to' targets."""
    return jsonify({"ok": True, "analysts": active_soc_analysts()})


# ---------------------------------------------------------------------------
# Wave C: persistent SOC alerts (deduplicated)
#
# Detectors (correlation engine, IDS handler, …) populate the ``alerts``
# table via app.services.alert_service so the SOC queue is no longer a raw
# event list. The endpoints below expose that table to the portal frontend
# in parallel to the legacy /api/alerts feed (which stays for backward
# compatibility until the UI fully migrates).
# ---------------------------------------------------------------------------

@soc_portal_bp.route("/api/alerts2")
@soc_login_required
def api_alerts_v2():
    """Persistent deduplicated SOC alerts from the ``alerts`` table."""
    from app.services.alert_service import list_alerts

    status_in = (request.args.get("status") or "").strip().lower()
    if status_in == "open":
        status = ["new", "acknowledged", "in_progress", "escalated", "case_opened"]
    elif status_in == "closed":
        status = ["closed", "false_positive", "suppressed"]
    elif status_in:
        status = [s.strip() for s in status_in.split(",") if s.strip()]
    else:
        status = None

    severity = None
    sev_raw = (request.args.get("severity") or "").strip().lower()
    if sev_raw:
        severity = [s.strip() for s in sev_raw.split(",") if s.strip()]

    assigned = request.args.get("assigned_to")
    try:
        assigned_to = int(assigned) if assigned not in (None, "") else None
    except (TypeError, ValueError):
        assigned_to = None

    try:
        limit  = min(int(request.args.get("limit", 200) or 200), 500)
    except (ValueError, TypeError):
        limit = 200
    try:
        offset = max(int(request.args.get("offset", 0) or 0), 0)
    except (ValueError, TypeError):
        offset = 0

    conn = get_db()
    alerts_out = list_alerts(
        conn, status=status, severity=severity,
        assigned_to=assigned_to, limit=limit, offset=offset,
    )
    total = conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()["c"]
    return jsonify({"ok": True, "alerts": alerts_out,
                    "count": len(alerts_out), "total": total})


@soc_portal_bp.route("/api/alerts2/<int:alert_id>/ack", methods=["POST"])
@soc_login_required
def api_alerts_v2_ack(alert_id):
    from app.services.alert_service import acknowledge_alert
    _, username, _ = get_soc_session_user()
    data = request.get_json(silent=True) or {}
    conn = get_db()
    ok = acknowledge_alert(conn, alert_id, actor=username or "analyst",
                           note=(data.get("note") or "").strip())
    conn.commit()
    if not ok:
        return jsonify({"ok": False, "message": "Alert not found"}), 404
    return jsonify({"ok": True})


@soc_portal_bp.route("/api/alerts2/<int:alert_id>/assign", methods=["POST"])
@soc_login_required
def api_alerts_v2_assign(alert_id):
    from app.services.alert_service import assign_alert
    _, username, _ = get_soc_session_user()
    data = request.get_json(silent=True) or {}
    assignee_id   = data.get("assignee_id")
    assignee_name = (data.get("assignee_name") or "").strip()

    if assignee_id not in (None, "", 0, "0"):
        try:
            assignee_id = int(assignee_id)
        except (TypeError, ValueError):
            return jsonify({"ok": False, "message": "Invalid assignee."}), 400
        active = {a["user_id"]: a for a in active_soc_analysts()}
        if assignee_id not in active:
            return jsonify({
                "ok": False,
                "message": "That analyst is not currently logged in.",
            }), 400
        assignee_name = active[assignee_id]["username"]

    conn = get_db()
    ok = assign_alert(conn, alert_id, actor=username or "analyst",
                      assignee_id=assignee_id, assignee_name=assignee_name)
    conn.commit()
    if not ok:
        return jsonify({"ok": False, "message": "Alert not found"}), 404
    return jsonify({"ok": True, "assigned_to": assignee_name or None})


@soc_portal_bp.route("/api/alerts2/<int:alert_id>/close", methods=["POST"])
@soc_login_required
def api_alerts_v2_close(alert_id):
    from app.services.alert_service import close_alert
    _, username, _ = get_soc_session_user()
    data = request.get_json(silent=True) or {}
    conn = get_db()
    ok = close_alert(
        conn, alert_id, actor=username or "analyst",
        closure_type=(data.get("closure_type") or "resolved").strip().lower(),
        note=(data.get("note") or "").strip(),
    )
    conn.commit()
    if not ok:
        return jsonify({"ok": False, "message": "Alert not found"}), 404
    return jsonify({"ok": True})


@soc_portal_bp.route("/api/alerts2/<int:alert_id>/false_positive", methods=["POST"])
@soc_login_required
def api_alerts_v2_false_positive(alert_id):
    from app.services.alert_service import mark_false_positive
    _, username, _ = get_soc_session_user()
    data = request.get_json(silent=True) or {}
    suppress = data.get("suppress")
    suppress_match = None
    if suppress and isinstance(suppress, dict) and suppress.get("match_value"):
        suppress_match = suppress
    conn = get_db()
    ok = mark_false_positive(
        conn, alert_id, actor=username or "analyst",
        note=(data.get("note") or "").strip(),
        suppress_match=suppress_match,
    )
    conn.commit()
    if not ok:
        return jsonify({"ok": False, "message": "Alert not found"}), 404
    return jsonify({"ok": True})


@soc_portal_bp.route("/alerts/assign", methods=["POST"])
@soc_login_required
def alerts_assign():
    """Assign (or clear) a live alert. Only currently-active analysts are valid."""
    data      = request.get_json(force=True) or {}
    event_key = (data.get("event_key") or "").strip()
    conn = get_db()
    event_uuid = _resolve_event_uuid(conn, data)
    if not (event_uuid or event_key):
        return jsonify({"ok": False, "message": "event_uuid is required."}), 400

    assignee_id = data.get("assignee_id")
    _, username, _ = get_soc_session_user()

    # Empty/zero assignee — clear the assignment.
    if assignee_id in (None, "", 0, "0"):
        if event_uuid:
            conn.execute(
                "DELETE FROM siem_alert_assignments WHERE event_uuid=?",
                (event_uuid,),
            )
        if event_key:
            # Drop legacy timestamp-keyed row too — the migration may have
            # left it behind if the event row was evicted by retention.
            conn.execute(
                "DELETE FROM siem_alert_assignments WHERE event_key=?",
                (event_key,),
            )
        conn.commit()
        _soc_log_event(
            category="security", action="soc_alert_unassigned",
            username=username, remote_addr=request.remote_addr,
            details={"event_uuid": event_uuid, "event_key": event_key},
        )
        return jsonify({"ok": True, "assigned_to": None})

    try:
        assignee_id = int(assignee_id)
    except (TypeError, ValueError):
        return jsonify({"ok": False, "message": "Invalid assignee."}), 400

    # Only analysts with an active SOC session may be assigned.
    active = {a["user_id"]: a for a in active_soc_analysts()}
    if assignee_id not in active:
        return jsonify({
            "ok": False,
            "message": "That analyst is not currently logged in.",
        }), 400
    assignee_name = active[assignee_id]["username"]

    # event_key column is PRIMARY KEY (migration v31). We keep writing it
    # so legacy reads continue to work; the new event_uuid column is the
    # collision-safe join key going forward.
    write_key = event_key or event_uuid
    conn.execute(
        "INSERT INTO siem_alert_assignments "
        "(event_key, event_uuid, assignee_id, assignee_name, assigned_by, assigned_at) "
        "VALUES (?,?,?,?,?,CURRENT_TIMESTAMP) "
        "ON CONFLICT(event_key) DO UPDATE SET "
        "event_uuid=excluded.event_uuid, "
        "assignee_id=excluded.assignee_id, assignee_name=excluded.assignee_name, "
        "assigned_by=excluded.assigned_by, assigned_at=CURRENT_TIMESTAMP",
        (write_key, event_uuid, assignee_id, assignee_name, username or ""),
    )
    conn.commit()
    _soc_log_event(
        category="security", action="soc_alert_assigned",
        username=username, remote_addr=request.remote_addr,
        details={"event_uuid": event_uuid, "event_key": event_key,
                 "assignee": assignee_name},
    )
    return jsonify({"ok": True, "assigned_to": assignee_name})


# ---------------------------------------------------------------------------
# Case Management (L1+ read/open, L2+ notes/assign, L3 close)
# ---------------------------------------------------------------------------

@soc_portal_bp.route("/cases")
@soc_login_required
def cases():
    _, username, tier = get_soc_session_user()
    conn = get_db()
    open_cases = conn.execute(
        """
        SELECT sc.*, u.username AS assignee_name
        FROM siem_cases sc
        LEFT JOIN users u ON u.id = sc.assigned_to
        WHERE sc.status = 'open'
        ORDER BY sc.created_at DESC
        """
    ).fetchall()
    closed_cases = conn.execute(
        """
        SELECT sc.*, u.username AS assignee_name
        FROM siem_cases sc
        LEFT JOIN users u ON u.id = sc.assigned_to
        WHERE sc.status = 'closed'
        ORDER BY sc.updated_at DESC LIMIT 50
        """
    ).fetchall()
    analysts = conn.execute(
        """
        SELECT DISTINCT u.id, u.username
        FROM users u
        INNER JOIN user_groups ug ON ug.user_id = u.id
        INNER JOIN groups g ON g.id = ug.group_id
        WHERE g.soc_tier IS NOT NULL
        ORDER BY u.username
        """
    ).fetchall()
    return render_template(
        "soc_portal/cases.html",
        username=username,
        tier=tier,
        open_cases=open_cases,
        closed_cases=closed_cases,
        analysts=analysts,
    )


@soc_portal_bp.route("/cases/open", methods=["POST"])
@soc_login_required
def cases_open():
    """L1+: Open a new security case."""
    data = request.get_json(force=True) or {}
    title       = (data.get("title") or "").strip()
    description = (data.get("description") or "").strip()
    severity    = data.get("severity", "medium")
    source_event = data.get("source_event", "")

    if not title:
        return jsonify({"ok": False, "message": "Title is required."}), 400
    if severity not in ("low", "medium", "high", "critical"):
        severity = "medium"

    _, username, _ = get_soc_session_user()
    conn = get_db()
    cur = conn.execute(
        """
        INSERT INTO siem_cases (title, description, severity, status, created_by, source_event)
        VALUES (?, ?, ?, 'open', ?, ?)
        """,
        (title, description, severity, username, source_event),
    )
    conn.commit()
    case_id = cur.lastrowid
    _soc_log_event(
        category="security",
        action="soc_case_opened",
        username=username,
        remote_addr=request.remote_addr,
        details={"case_id": case_id, "title": title, "severity": severity},
    )
    return jsonify({"ok": True, "case_id": case_id})


@soc_portal_bp.route("/cases/<int:case_id>")
@soc_login_required
def case_detail(case_id):
    conn = get_db()
    case = conn.execute("SELECT * FROM siem_cases WHERE id=?", (case_id,)).fetchone()
    if not case:
        return render_template("soc_portal/404.html"), 404

    notes = conn.execute(
        "SELECT * FROM siem_case_notes WHERE case_id=? ORDER BY created_at ASC",
        (case_id,),
    ).fetchall()
    events = conn.execute(
        "SELECT * FROM siem_case_events WHERE case_id=? ORDER BY event_timestamp ASC",
        (case_id,),
    ).fetchall()
    analysts = conn.execute(
        """
        SELECT DISTINCT u.id, u.username
        FROM users u
        INNER JOIN user_groups ug ON ug.user_id = u.id
        INNER JOIN groups g ON g.id = ug.group_id
        WHERE g.soc_tier IS NOT NULL
        ORDER BY u.username
        """
    ).fetchall()

    _, username, tier = get_soc_session_user()
    return render_template(
        "soc_portal/case_detail.html",
        case=case,
        notes=notes,
        events=events,
        analysts=analysts,
        username=username,
        tier=tier,
    )


@soc_portal_bp.route("/cases/<int:case_id>/note", methods=["POST"])
@soc_login_required
@soc_tier_required("L2")
def case_add_note(case_id):
    """L2+: Add an investigation note to a case."""
    data = request.get_json(force=True) or {}
    note = (data.get("note") or "").strip()
    if not note:
        return jsonify({"ok": False, "message": "Note cannot be empty."}), 400

    _, username, _ = get_soc_session_user()
    conn = get_db()
    conn.execute(
        "INSERT INTO siem_case_notes (case_id, note, created_by) VALUES (?,?,?)",
        (case_id, note, username),
    )
    conn.execute(
        "UPDATE siem_cases SET updated_at=CURRENT_TIMESTAMP WHERE id=?", (case_id,)
    )
    conn.commit()
    return jsonify({"ok": True})


@soc_portal_bp.route("/cases/<int:case_id>/assign", methods=["POST"])
@soc_login_required
def case_assign(case_id):
    """L1+ (self-assign only for L1) / L2+ (any analyst): Assign a case."""
    data = request.get_json(force=True) or {}
    assignee_id = data.get("assignee_id")
    user_id, username, tier = get_soc_session_user()

    if tier == "L1":
        # L1 may only assign to themselves
        if assignee_id is not None and int(assignee_id) != int(user_id):
            return jsonify({"ok": False, "message": "L1 analysts can only assign cases to themselves."}), 403

    conn = get_db()
    conn.execute(
        "UPDATE siem_cases SET assigned_to=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
        (assignee_id, case_id),
    )
    conn.commit()
    _soc_log_event(
        category="security",
        action="soc_case_assigned",
        username=username,
        remote_addr=request.remote_addr,
        details={"case_id": case_id, "assignee_id": assignee_id},
    )
    return jsonify({"ok": True})


_FIVE_W_KEYS = ("who", "what", "when", "where", "why")


def _extract_five_w(data: dict) -> "tuple[dict, list[str]]":
    """Pull the 5W fields out of a JSON payload. Returns (values, missing_keys).
    Treats whitespace-only as missing."""
    values  = {k: (data.get(k) or "").strip() for k in _FIVE_W_KEYS}
    missing = [k.upper() for k in _FIVE_W_KEYS if not values[k]]
    return values, missing


def _format_five_w_note(prefix: str, five_w: dict, extra: str = "") -> str:
    body = (
        f"{prefix}\n"
        f"WHO:   {five_w['who']}\n"
        f"WHAT:  {five_w['what']}\n"
        f"WHEN:  {five_w['when']}\n"
        f"WHERE: {five_w['where']}\n"
        f"WHY:   {five_w['why']}"
    )
    extra = (extra or "").strip()
    if extra:
        body += f"\n\nAdditional: {extra}"
    return body


@soc_portal_bp.route("/cases/<int:case_id>/escalate", methods=["POST"])
@soc_login_required
def case_escalate(case_id):
    """
    L1 → escalate to L2 (true positive needs investigation).
    L2 → escalate to L3 (needs incident response).
    L3 → cannot escalate (already top tier; close the case instead).
    """
    data = request.get_json(force=True) or {}
    _, username, tier = get_soc_session_user()

    tier_map = {"L1": "L2", "L2": "L3"}
    target_tier = tier_map.get(tier)
    if not target_tier:
        return jsonify({"ok": False, "message": "L3 is the top response tier. Close the case instead."}), 400

    five_w, missing = _extract_five_w(data)
    if missing:
        return jsonify({
            "ok": False,
            "message": "All 5 W's are required: " + ", ".join(missing),
        }), 400
    extra = (data.get("note") or data.get("resolution") or "").strip()

    note_text = _format_five_w_note(f"[ESCALATED TO {target_tier}]", five_w, extra)

    conn = get_db()
    # Escalation is a hand-off: clear the assignee so the case leaves the
    # escalating analyst's queue and lands unassigned in the next tier's.
    conn.execute(
        "UPDATE siem_cases SET escalation_tier=?, assigned_to=NULL, "
        "updated_at=CURRENT_TIMESTAMP WHERE id=?",
        (target_tier, case_id),
    )
    conn.execute(
        "INSERT INTO siem_case_notes (case_id, note, created_by) VALUES (?,?,?)",
        (case_id, note_text, username),
    )
    conn.commit()
    _soc_log_event(
        category="security",
        action="soc_case_escalated",
        username=username,
        remote_addr=request.remote_addr,
        details={"case_id": case_id, "escalated_to": target_tier, "five_w": five_w},
    )

    # Notify the SOC tier the case moved to, with a PDF incident report.
    try:
        from app.services.mail_alerts import send_incident_followup
        send_incident_followup(kind="escalated", case_id=case_id,
                               target_tier=target_tier, actor=username,
                               note=note_text)
    except Exception:
        pass
    return jsonify({"ok": True, "escalated_to": target_tier})


@soc_portal_bp.route("/cases/<int:case_id>/close", methods=["POST"])
@soc_login_required
def case_close(case_id):
    """
    L1/L2: may only close as 'false_positive'.
    L3:    may close as 'false_positive' or 'resolved'.
    """
    data = request.get_json(force=True) or {}
    resolution    = (data.get("resolution") or "").strip()
    closure_type  = (data.get("closure_type") or "resolved").strip()
    _, username, tier = get_soc_session_user()

    if closure_type not in ("false_positive", "resolved"):
        closure_type = "resolved"

    if tier in ("L1", "L2") and closure_type != "false_positive":
        return jsonify({
            "ok": False,
            "message": f"{tier} analysts can only close cases as false positives. Escalate true positives instead.",
        }), 403

    five_w, missing = _extract_five_w(data)
    if missing:
        return jsonify({
            "ok": False,
            "message": "All 5 W's are required: " + ", ".join(missing),
        }), 400

    label = "FALSE POSITIVE" if closure_type == "false_positive" else "TRUE POSITIVE"
    note_text = _format_five_w_note(f"[CLOSED — {label}]", five_w, resolution)

    conn = get_db()
    conn.execute(
        "UPDATE siem_cases SET status='closed', closure_type=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
        (closure_type, case_id),
    )
    conn.execute(
        "INSERT INTO siem_case_notes (case_id, note, created_by) VALUES (?,?,?)",
        (case_id, note_text, username),
    )
    conn.commit()
    _soc_log_event(
        category="security",
        action="soc_case_closed",
        username=username,
        remote_addr=request.remote_addr,
        details={"case_id": case_id, "closure_type": closure_type, "five_w": five_w},
    )

    # Email the alert recipients an "incident handled" follow-up with a PDF.
    try:
        from app.services.mail_alerts import send_incident_followup
        send_incident_followup(kind="closed", case_id=case_id,
                               actor=username, note=note_text)
    except Exception:
        pass
    return jsonify({"ok": True})


@soc_portal_bp.route("/api/cases")
@soc_login_required
def api_cases():
    conn = get_db()
    status = request.args.get("status", "open")
    rows = conn.execute(
        """
        SELECT sc.id, sc.title, sc.severity, sc.status, sc.created_by,
               sc.created_at, sc.updated_at, u.username AS assignee_name
        FROM siem_cases sc
        LEFT JOIN users u ON u.id = sc.assigned_to
        WHERE sc.status = ?
        ORDER BY sc.created_at DESC LIMIT 200
        """,
        (status,),
    ).fetchall()
    return jsonify([dict(r) for r in rows])


# ---------------------------------------------------------------------------
# Threat Intelligence (L2+)
# ---------------------------------------------------------------------------

@soc_portal_bp.route("/threat-intel")
@soc_login_required
@soc_tier_required("L2")
def threat_intel():
    _, username, tier = get_soc_session_user()
    return render_template("soc_portal/threat_intel.html", username=username, tier=tier)


@soc_portal_bp.route("/api/threat-feeds")
@soc_login_required
@soc_tier_required("L2")
def api_threat_feeds():
    """JSON: threat feed summary (abuse.ch counts + last update)."""
    conn = get_db()
    feed = conn.execute("SELECT * FROM ids_threat_feeds WHERE id=1").fetchone()
    ids_cfg = conn.execute("SELECT * FROM ids_config WHERE id=1").fetchone()
    ids_rules = conn.execute(
        "SELECT name, enabled, url FROM ids_rulesets ORDER BY name"
    ).fetchall()

    return jsonify({
        "threat_feeds_enabled": bool(ids_cfg and ids_cfg["block_list_enabled"]) if ids_cfg else False,
        "last_updated": feed["updated_at"] if feed else None,
        "rulesets": [dict(r) for r in ids_rules],
    })


# ---------------------------------------------------------------------------
# Quick Actions (L3 only)
# ---------------------------------------------------------------------------

@soc_portal_bp.route("/actions")
@soc_login_required
@soc_tier_required("L3")
def actions():
    _, username, tier = get_soc_session_user()
    return render_template("soc_portal/actions.html", username=username, tier=tier)


@soc_portal_bp.route("/actions/block-ip", methods=["POST"])
@soc_login_required
@soc_tier_required("L3")
def action_block_ip():
    """
    L3: Block an IP. The block is persisted to ``soc_blocked_ips`` and enforced
    via the ``<soc_blocklist>`` PF table, so it survives firewall reloads.
    """
    data = request.get_json(force=True) or {}
    ip   = (data.get("ip") or "").strip()
    note = (data.get("note") or "").strip()

    if not ip:
        return jsonify({"ok": False, "message": "IP address is required."}), 400

    import ipaddress
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({"ok": False, "message": "Invalid IP address."}), 400

    _, username, _ = get_soc_session_user()
    conn = get_db()

    # Persist the block — soc_blocked_ips is the source of truth for the table.
    conn.execute(
        "INSERT INTO soc_blocked_ips (ip, note, blocked_by) VALUES (?,?,?) "
        "ON CONFLICT(ip) DO UPDATE SET note=excluded.note, "
        "blocked_by=excluded.blocked_by, created_at=CURRENT_TIMESTAMP",
        (ip, note, username or ""),
    )
    conn.commit()

    # Reload PF first so the regenerated ruleset carries the <soc_blocklist>
    # table + block rule (the persistent table starts empty), then push the
    # blocked IPs into it.
    ok = True
    messages = []
    try:
        from app.services.pf_generator import reload_pf_rules
        pf = reload_pf_rules(conn)
        if not pf.get("ok"):
            ok = False
            messages.append(f"PF reload failed: {pf.get('message', '')}")
    except Exception as exc:
        ok = False
        messages.append(f"PF reload error: {exc}")

    try:
        from app.services.soc_blocklist import push_soc_blocklist_to_pf
        push = push_soc_blocklist_to_pf(conn)
        if push.get("message"):
            messages.append(push["message"])
        if not push.get("ok"):
            ok = False
    except Exception as exc:
        ok = False
        messages.append(f"Blocklist push error: {exc}")

    output = " | ".join(m for m in messages if m)
    _soc_log_event(
        category="security",
        action="soc_block_ip",
        username=username,
        remote_addr=request.remote_addr,
        details={"ip": ip, "note": note, "applied": ok, "output": output},
    )
    return jsonify({
        "ok": ok,
        "message": (f"IP {ip} blocked and enforced on the firewall."
                    if ok else
                    f"IP {ip} recorded, but enforcement reported errors: {output}"),
    })


@soc_portal_bp.route("/actions/reload-firewall", methods=["POST"])
@soc_login_required
@soc_tier_required("L3")
def action_reload_firewall():
    """L3: File a "reload firewall" recommendation for Core/Admin to approve.

    SOC analysts cannot directly mutate firewall state — separation Rule 1.
    The PF reload is performed by the admin side once the recommendation is
    approved (see app/services/soc_recommendations.py).
    """
    _, username, _ = get_soc_session_user()
    data   = request.get_json(silent=True) or {}
    reason = (data.get("reason") or "").strip() or "SOC L3 requested PF reload"

    conn = get_db()
    from app.services.soc_recommendations import create_recommendation
    result = create_recommendation(
        conn,
        action_type="reload_firewall",
        target_value="pf",
        reason=reason,
        severity=(data.get("severity") or "medium"),
        created_by=username or "",
        source_alert_id=(data.get("source_alert_id") or ""),
    )

    _soc_log_event(
        category="system",
        action="soc_reload_firewall_requested",
        username=username,
        remote_addr=request.remote_addr,
        details={"recommendation_id": result.get("id"), "reason": reason},
    )
    return jsonify({
        "ok": bool(result.get("ok")),
        "message": (f"Firewall reload requested — recommendation "
                    f"#{result.get('id')} awaiting admin approval."
                    if result.get("ok")
                    else result.get("message", "Failed to file recommendation.")),
        "recommendation_id": result.get("id"),
    })


# ---------------------------------------------------------------------------
# Response Recommendations — SOC analysts file recommendations; they are
# reviewed inside the portal and then sent to SmartShield Core for approval.
# The SOC Portal never changes firewall state directly (separation Rule 1).
# ---------------------------------------------------------------------------

@soc_portal_bp.route("/recommendations")
@soc_login_required
def recommendations():
    _, username, tier = get_soc_session_user()
    conn = get_db()
    from app.services.soc_recommendations import list_recommendations
    recs = list_recommendations(conn, limit=200)
    return render_template("soc_portal/recommendations.html",
                           username=username, tier=tier, recs=recs)


@soc_portal_bp.route("/recommendations/create", methods=["POST"])
@soc_login_required
def recommendation_create():
    """Any analyst may file a response recommendation (starts as pending)."""
    _, username, _ = get_soc_session_user()
    conn = get_db()
    from app.services.soc_recommendations import create_recommendation
    res = create_recommendation(
        conn,
        action_type=request.form.get("action_type", ""),
        target_value=request.form.get("target_value", ""),
        reason=request.form.get("reason", "").strip(),
        severity=request.form.get("severity", "medium"),
        created_by=username,
        source_alert_id=request.form.get("source_alert_id", "").strip(),
    )
    if res["ok"]:
        _soc_log_event(category="security", action="soc_recommendation_filed",
                       username=username, remote_addr=request.remote_addr,
                       details={"recommendation_id": res["id"],
                                "action_type": request.form.get("action_type", ""),
                                "target": request.form.get("target_value", "")})
    flash(res["message"], "success" if res["ok"] else "danger")
    return redirect(url_for("soc_portal.recommendations"))


@soc_portal_bp.route("/recommendations/<int:rec_id>/review", methods=["POST"])
@soc_login_required
@soc_tier_required("L2")
def recommendation_review(rec_id):
    """L2/L3: endorse a pending recommendation to Core, or reject it."""
    _, username, _ = get_soc_session_user()
    conn = get_db()
    from app.services.soc_recommendations import soc_approve, soc_reject
    decision = request.form.get("decision", "")
    if decision == "approve":
        res = soc_approve(conn, rec_id, username)
        action = "soc_recommendation_approved"
    elif decision == "reject":
        res = soc_reject(conn, rec_id, username)
        action = "soc_recommendation_rejected"
    else:
        flash("Unknown decision.", "danger")
        return redirect(url_for("soc_portal.recommendations"))
    if res["ok"]:
        _soc_log_event(category="security", action=action,
                       username=username, remote_addr=request.remote_addr,
                       details={"recommendation_id": rec_id})
    flash(res["message"], "success" if res["ok"] else "danger")
    return redirect(url_for("soc_portal.recommendations"))
