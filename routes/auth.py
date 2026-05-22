import time
import json as _json
import ipaddress as _ip
from datetime import datetime, timezone

from flask import Blueprint, render_template, request, redirect, url_for, session, jsonify
from werkzeug.security import check_password_hash
from app.database import get_db
from app.audit_log import log_event
from app.uploads import profile_picture_url


auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/")
def index():
    return redirect(url_for("auth.login"))


def _no_users_exist() -> bool:
    try:
        conn = get_db()
        row = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()
        return row["c"] == 0
    except Exception:
        return False


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if _no_users_exist():
        return redirect(url_for("setup.wizard_index"))

    conn   = get_db()
    error  = None
    remote = request.remote_addr or ""

    # Load brute-force settings from advanced_admin_access
    cfg_row = conn.execute(
        "SELECT threshold, blocktime, detection_time, pass_list FROM advanced_admin_access WHERE id=1"
    ).fetchone()
    if cfg_row:
        threshold      = int(cfg_row["threshold"]      or 30)
        blocktime      = int(cfg_row["blocktime"]       or 120)
        detection_time = int(cfg_row["detection_time"]  or 1800)
        try:
            pass_list = _json.loads(cfg_row["pass_list"] or "[]")
        except Exception:
            pass_list = []
    else:
        threshold, blocktime, detection_time, pass_list = 30, 120, 1800, []

    # Check if remote IP is whitelisted (skip brute-force for pass_list IPs)
    whitelisted = False
    try:
        remote_ip = _ip.ip_address(remote)
        for cidr in pass_list:
            try:
                if remote_ip in _ip.ip_network(cidr, strict=False):
                    whitelisted = True
                    break
            except ValueError:
                continue
    except ValueError:
        pass

    # Enforce block before processing credentials
    if request.method == "POST" and not whitelisted and threshold > 0:
        now          = time.time()
        window_start = now - detection_time
        recent_count = conn.execute(
            "SELECT COUNT(*) FROM login_failures WHERE remote_addr=? AND failed_at>?",
            (remote, window_start)
        ).fetchone()[0]
        if recent_count >= threshold:
            last_fail = conn.execute(
                "SELECT MAX(failed_at) FROM login_failures WHERE remote_addr=?",
                (remote,)
            ).fetchone()[0]
            if last_fail and (now - last_fail) < blocktime:
                wait = int(blocktime - (now - last_fail))
                return render_template(
                    "login.html",
                    error=f"Too many failed login attempts. Try again in {wait} second(s)."
                )

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        # Per-username lockout: 5 failures within 15 minutes triggers lockout.
        if username and not whitelisted:
            per_user_count = conn.execute(
                "SELECT COUNT(*) FROM login_failures WHERE username=? AND failed_at>?",
                (username, time.time() - 900)
            ).fetchone()[0]
            if per_user_count >= 5:
                log_event(
                    category="security",
                    action="login_blocked_user_lockout",
                    username=username,
                    remote_addr=remote,
                    details={"failures": per_user_count},
                )
                error = "Too many failed attempts. Please wait 15 minutes before trying again."
                return render_template("login.html", error=error), 429

        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cur.fetchone()

        # Reject disabled/inactive accounts. Don't differentiate the error
        # message — keep "invalid username or password" so the existence of
        # the account isn't disclosed.
        user_status = None
        if user and "status" in user.keys():
            user_status = (user["status"] or "active").strip().lower()
        is_active = user is not None and (user_status is None or user_status == "active")

        if user and is_active and check_password_hash(user["password"], password):
            # Clear failure history on successful login (both IP and username based)
            conn.execute("DELETE FROM login_failures WHERE remote_addr=?", (remote,))
            conn.execute("DELETE FROM login_failures WHERE username=?", (username,))
            conn.commit()
            session["username"]     = user["username"]
            session["user_id"]      = user["id"]
            session["is_superuser"] = bool(user["is_superuser"]) if "is_superuser" in user.keys() else (user["username"] == "admin")
            if user["profile_picture"]:
                session["user_avatar"] = profile_picture_url(user["profile_picture"])
            else:
                session.pop("user_avatar", None)
            log_event(
                category="session",
                action="login_success",
                username=user["username"],
                remote_addr=remote,
                details={"user_id": user["id"]},
            )
            return redirect(url_for("system.dashboard"))

        # Record failure for non-whitelisted IPs (store both IP and username)
        if not whitelisted:
            conn.execute(
                "INSERT INTO login_failures (remote_addr, failed_at, username) VALUES (?,?,?)",
                (remote, time.time(), username or None)
            )
            conn.commit()
            # Forward a failure-burst alert to the SOC portal (single fails pass).
            try:
                from app.services.login_alerts import note_login_failure
                note_login_failure(conn, username, remote, target="admin_ui")
            except Exception:
                pass
        reason = "invalid_credentials"
        if user and not is_active:
            # Distinguish inactive-account rejection in the audit log even
            # though the UI message stays generic.
            reason = "inactive_account"
        log_event(
            category="session",
            action="login_failed",
            username=username or "anonymous",
            remote_addr=remote,
            details={"reason": reason},
        )
        error = "Invalid username or password"

    return render_template("login.html", error=error)


@auth_bp.route("/logout", methods=["POST"])
def logout():
    # CSRF for browser sessions is enforced by app/__init__.py's
    # _csrf_guard before_request hook for all unsafe methods.
    log_event(
        category="session",
        action="logout",
        username=session.get("username", "anonymous"),
        remote_addr=request.remote_addr,
        details={"user_id": session.get("user_id")},
    )
    session.clear()
    return redirect(url_for("auth.login"))


# Failed reauth attempts within this window trigger a lockout.
_REAUTH_WINDOW_SECONDS = 600    # 10 min
_REAUTH_MAX_FAILURES   = 5
_REAUTH_LOCKOUT_SECS   = 300    # 5 min


@auth_bp.route("/reauth", methods=["POST"])
def reauth():
    """
    Reauthentication endpoint for destructive-action gates.
    POST JSON: {"password": "..."}
    On success sets session["reauth_time"] and returns {"ok": True}.
    On failure increments login_failures and returns {"ok": False}.

    Throttling: after _REAUTH_MAX_FAILURES failed reauth attempts within
    _REAUTH_WINDOW_SECONDS, the user is locked out for _REAUTH_LOCKOUT_SECS.
    Lockout is keyed by user_id (not IP) because reauth is always for an
    authenticated session.
    """
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"ok": False, "message": "Not logged in."}), 401

    data     = request.get_json(silent=True) or {}
    password = (data.get("password") or "").strip()
    if not password:
        return jsonify({"ok": False, "message": "Password is required."}), 400

    conn    = get_db()
    remote  = request.remote_addr or ""
    row     = conn.execute("SELECT username, password FROM users WHERE id=?", (user_id,)).fetchone()
    if not row:
        return jsonify({"ok": False, "message": "User not found."}), 404

    # Throttle check — count recent failures for this username.
    now = time.time()
    fail_count = conn.execute(
        "SELECT COUNT(*) FROM login_failures WHERE username=? AND failed_at>?",
        (row["username"], now - _REAUTH_WINDOW_SECONDS),
    ).fetchone()[0]
    if fail_count >= _REAUTH_MAX_FAILURES:
        last_fail = conn.execute(
            "SELECT MAX(failed_at) FROM login_failures WHERE username=?",
            (row["username"],),
        ).fetchone()[0] or 0
        if (now - last_fail) < _REAUTH_LOCKOUT_SECS:
            wait = int(_REAUTH_LOCKOUT_SECS - (now - last_fail))
            log_event(
                category="security",
                action="reauth_locked",
                username=row["username"],
                remote_addr=remote,
                details={"wait_seconds": wait, "failures": fail_count},
            )
            # Invalidate any cached reauth on lockout so the in-flight
            # sensitive flow has to be re-initiated.
            session.pop("reauth_time", None)
            return jsonify({
                "ok": False,
                "message": f"Too many failed attempts. Try again in {wait} second(s).",
                "locked_seconds": wait,
            }), 429

    if check_password_hash(row["password"], password):
        session["reauth_time"] = datetime.now(timezone.utc).isoformat()
        log_event(
            category="security",
            action="reauth_success",
            username=row["username"],
            remote_addr=remote,
        )
        return jsonify({"ok": True})

    # Failed reauth — record in login_failures
    conn.execute(
        "INSERT INTO login_failures (remote_addr, failed_at, username) VALUES (?,?,?)",
        (remote, time.time(), row["username"])
    )
    conn.commit()
    log_event(
        category="security",
        action="reauth_failed",
        username=row["username"],
        remote_addr=remote,
    )
    return jsonify({"ok": False, "message": "Incorrect password."}), 403
