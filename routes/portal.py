"""
portal.py
---------
Public-facing captive portal served on the redirect port (default 8081).
Clients are unauthenticated; NO @login_required here.

Routes
------
GET  /portal/              → login page (username/password or voucher)
POST /portal/auth          → process login; sets session cookie
GET  /portal/success       → shown after successful auth
GET  /portal/logout        → end session and remove from PF table
"""

import json
import sys
from urllib.parse import urlparse
from flask import (
    Blueprint, render_template, request, redirect,
    url_for, session, jsonify,
)
from app.database import get_db

portal_bp = Blueprint("portal", __name__, url_prefix="/portal")


def _client_mac(ip: str) -> str:
    """Look up MAC address for *ip* via ARP table on FreeBSD."""
    if not sys.platform.startswith("freebsd"):
        return ""
    try:
        from app.services.network_service import run_command
        r = run_command(["arp", "-n", ip], check=False)
        for line in (r.stdout or "").splitlines():
            parts = line.split()
            # arp -n output: <ip> (<ip>) at <mac> on <iface>
            if len(parts) >= 4 and parts[3] not in ("(incomplete)", "permanent"):
                return parts[3].lower()
    except Exception:
        pass
    return ""

def _sanitize_orig_url(url: str) -> str:
    """Return *url* if it is safe to render in href/JS, else ''.

    Safe = relative URL (no netloc) OR absolute http(s) URL. Drops
    javascript:, data:, vbscript:, file:, and any other unknown scheme so
    block.html / login.html cannot be tricked into executing a payload via
    an attacker-controlled `url=` query parameter.
    """
    url = (url or "").strip()
    if not url:
        return ""
    parsed = urlparse(url)
    if not parsed.netloc:
        # Relative — must still start with a single "/" (rejects "//evil.com").
        return url if url.startswith("/") and not url.startswith("//") else ""
    if parsed.scheme in ("http", "https"):
        return url
    return ""


def _safe_redirect_target(url: str) -> str:
    """Redirect target after captive portal login. Falls back to
    /portal/success when the URL is not safe (see _sanitize_orig_url)."""
    safe = _sanitize_orig_url(url)
    return safe or url_for("portal.success")


def _policy_context(source) -> dict:
    policy = (source.get("policy") or "").strip().lower()
    if policy != "content":
        policy = ""
    raw_url = (source.get("url") or source.get("orig_url") or "").strip()
    return {
        "policy":        policy,
        "domain":        (source.get("domain")        or "").strip().lower(),
        "orig_url":      _sanitize_orig_url(raw_url),
        "back_template": (source.get("back_template") or "login"),
        "popup":         "1" if source.get("popup") else "",
    }


def _portal_enabled(conn) -> bool:
    import json
    row = conn.execute(
        "SELECT value_json FROM service_state WHERE key_name='captive_portal_settings'"
    ).fetchone()
    if not row:
        return True  # no settings yet → treat as enabled so the page is reachable
    try:
        settings = json.loads(row["value_json"])
        # Only disabled when the admin explicitly set enabled=False
        return bool(settings.get("enabled", True))
    except Exception:
        return True


@portal_bp.route("/", methods=["GET"])
def login():
    conn = get_db()
    context = _policy_context(request.args)
    # Content-filter block redirects (policy=content) must always reach the block page
    # even when the standalone captive portal feature is explicitly disabled.
    if not _portal_enabled(conn) and context.get("policy") != "content":
        return render_template("portal/disabled.html"), 503
    return render_template("portal/login.html", **context)


@portal_bp.route("/auth", methods=["POST"])
def auth():
    conn     = get_db()
    ip       = request.remote_addr or ""
    mac      = _client_mac(ip)
    context  = _policy_context(request.form)
    orig_url = context["orig_url"]

    auth_type = request.form.get("auth_type", "credentials")

    from app.services.captive_portal import (
        authenticate_session, redeem_voucher, try_password_auth,
        too_many_recent_attempts, record_captive_auth_attempt,
    )

    # Rate-limit brute-force attempts before doing any credential work.
    # Voucher attempts have their own tighter cap.
    if auth_type == "voucher":
        if too_many_recent_attempts(conn, ip, window_seconds=300,
                                    max_attempts=5, auth_type="voucher"):
            from app.audit_log import log_event as _log_event
            _log_event(
                category="security", action="captive_portal_rate_limited",
                remote_addr=ip, severity="medium",
                details={"auth_type": "voucher"},
            )
            return render_template(
                "portal/login.html",
                error="Too many voucher attempts. Try again in a few minutes.",
                **context,
            ), 429
    elif too_many_recent_attempts(conn, ip, window_seconds=300, max_attempts=10):
        from app.audit_log import log_event as _log_event
        _log_event(
            category="security", action="captive_portal_rate_limited",
            remote_addr=ip, severity="medium",
            details={"auth_type": auth_type},
        )
        return render_template(
            "portal/login.html",
            error="Too many login attempts. Try again in a few minutes.",
            **context,
        ), 429

    if auth_type == "voucher":
        code   = (request.form.get("voucher_code") or "").strip().upper()
        result = redeem_voucher(conn, code, mac, ip)
    else:
        username = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "").strip()

        if not username or not password:
            return render_template(
                "portal/login.html",
                error="Username and password are required.",
                **context,
            )

        # Load portal settings once for whitelist, session duration, etc.
        _cp_row = conn.execute(
            "SELECT value_json FROM service_state WHERE key_name='captive_portal_settings'"
        ).fetchone()
        _cp_settings = json.loads(_cp_row["value_json"]) if _cp_row else {}
        _whitelist = {u.strip().lower() for u in (_cp_settings.get("whitelist_users") or [])}
        is_whitelisted = username.strip().lower() in _whitelist
        try:
            _duration = int(_cp_settings.get("session_duration_minutes") or 60)
        except (TypeError, ValueError):
            _duration = 60

        # Shared RADIUS-then-local credential check (used by /auth and the public
        # /api/captive-portal/authenticate endpoint). Keeps both surfaces in lockstep.
        auth_result = try_password_auth(conn, username, password)
        if not auth_result.get("ok"):
            # Log the detailed reason (which may include RADIUS internals) but
            # return only a generic string to the unauthenticated client.
            from app.audit_log import log_event as _log_event
            _log_event(
                category="security", action="captive_portal_login_failed",
                remote_addr=ip, severity="medium",
                details={
                    "auth_type": auth_type, "mac": mac,
                    "reason": auth_result.get("message", "auth failed"),
                },
            )
            return render_template(
                "portal/login.html",
                error="Invalid username or password.",
                **context,
            )
        is_superuser = is_whitelisted or (
            auth_result.get("auth_type") == "local" and auth_result.get("is_superuser", False)
        )
        result = authenticate_session(
            conn, mac, ip, username=username,
            is_superuser=is_superuser,
            duration_minutes=_duration,
        )

    if not result.get("ok"):
        record_captive_auth_attempt(
            conn, ip,
            username=(request.form.get("username") or ""),
            auth_type=auth_type, success=False,
        )
        # Phase 6.2 — log the internal reason (PF table failure, DB write error,
        # voucher state, etc.) but surface only a generic message to the
        # unauthenticated client. Operational details belong in the audit log.
        from app.audit_log import log_event as _log_event
        _log_event(
            category="security", action="captive_portal_login_failed",
            remote_addr=ip, severity="medium",
            details={"auth_type": auth_type, "mac": mac,
                     "reason": result.get("message", "Authentication failed")},
        )
        _popup_err = request.form.get("popup", "")
        back_template = request.form.get("back_template", "login")
        # For voucher redemption keep the result message — that branch returns
        # short, user-actionable strings ("voucher already used", "expired")
        # which are safe to show. Credential-path failures funnel through the
        # try_password_auth path above (which already returns a generic error),
        # so reaching this block from credentials means a session-layer failure
        # (PF/DB) — always show the generic string for those.
        if auth_type == "voucher":
            _client_msg = result.get("message", "Authentication failed.")
        else:
            _client_msg = "We couldn't complete sign-in. Please try again."
        if back_template == "block":
            return render_template(
                "portal/block.html",
                error=_client_msg,
                popup=_popup_err,
                **context,
            )
        return render_template(
            "portal/login.html",
            error=_client_msg,
            popup=_popup_err,
            **context,
        )

    record_captive_auth_attempt(
        conn, ip,
        username=(request.form.get("username") or ""),
        auth_type=auth_type, success=True,
    )
    from app.audit_log import log_event as _log_event
    _log_event(
        category="session", action="captive_portal_login_success",
        remote_addr=ip, severity="info",
        details={"auth_type": auth_type, "mac": mac,
                 "username": (request.form.get("username") or f"voucher:{request.form.get('voucher_code','?')}")},
    )
    session["portal_authenticated"] = True
    session["content_filter_authenticated"] = True
    session["portal_ip"] = ip

    back_template = request.form.get("back_template", "login")
    popup         = request.form.get("popup", "")

    if back_template == "block":
        if popup:
            # Popup flow: redirect to success.html which closes the popup
            # and navigates the opener (block page) to the original URL.
            return redirect(url_for(
                "portal.success",
                popup="1",
                policy=context["policy"] or "content",
                orig_url=context["orig_url"],
                domain=context["domain"],
            ))
        # Non-popup: render authenticated block view (existing behaviour).
        return render_template("portal/block.html", authenticated=True, **context)

    return redirect(_safe_redirect_target(orig_url))


@portal_bp.route("/status")
def portal_status():
    """Lightweight auth-check polled by the block page JS to detect when popup auth completes.

    Source of truth is the DB session, not the browser cookie. The Flask
    session flag only exists for UI helpers (e.g. showing the user's name);
    it must never be the basis for network-level authorization.
    """
    conn = get_db()
    ip = request.remote_addr or ""
    try:
        from app.services.content_policy import has_active_captive_session
        authenticated = has_active_captive_session(conn, ip)
    except Exception:
        authenticated = False
    return jsonify({"authenticated": authenticated})


@portal_bp.route("/success", methods=["GET"])
def success():
    return render_template("portal/success.html", **_policy_context(request.args))


@portal_bp.route("/block", methods=["GET"])
def block():
    """
    Content Policy block page.
    Shown when a client's browser hits Smart Shield's LAN IP after DNS redirects a
    blocked domain here.  No portal-enabled check — this page must always be
    reachable so blocked clients can authenticate.
    """
    domain   = request.args.get("domain", "").strip()
    orig_url = request.args.get("url",    "").strip()

    # Fallback: derive domain from the Host header (browser DNS-redirect path)
    if not domain:
        import ipaddress as _ip
        raw = (request.headers.get("Host") or "").split(":")[0].strip().lower()
        try:
            _ip.ip_address(raw)  # it's an IP — don't treat as a blocked domain
        except ValueError:
            if raw and "." in raw:
                domain = raw
                if not orig_url:
                    orig_url = request.url

    # When DNS redirects without passing the original URL, reconstruct from domain
    if not orig_url and domain:
        orig_url = f"http://{domain}"

    # Drop javascript:/data:/etc. URLs before passing to the template — those
    # would otherwise execute when the user clicks "Continue" or the page
    # auto-redirects after auth.
    orig_url = _sanitize_orig_url(orig_url)

    context = {"policy": "content", "domain": domain, "orig_url": orig_url}
    # Authoritative gate: DB-backed captive session keyed on client IP, not the
    # Flask cookie. The cookie can outlive the PF/DB session (expiry, admin
    # revocation, server restart), so trusting it here would show "Access
    # Granted" to a client whose network access has actually been pulled.
    conn = get_db()
    try:
        from app.services.content_policy import has_active_captive_session
        authenticated = has_active_captive_session(conn, request.remote_addr or "")
    except Exception:
        authenticated = False

    if authenticated:
        return render_template("portal/success.html", **context)

    # Unauthenticated — render the branded block page. policy_mode tells the
    # template whether a normal login can actually unblock the site (only in
    # captive_auth_required mode); in the other modes the block is intentional
    # and the page must not over-promise a login bypass.
    try:
        from app.services.content_policy import get_content_policy_mode
        context["policy_mode"] = get_content_policy_mode(conn)
    except Exception:
        context["policy_mode"] = "dns_redirect_block_page"
    context["authenticated"] = False
    return render_template("portal/block.html", **context)


@portal_bp.route("/logout", methods=["GET", "POST"])
def logout():
    conn = get_db()
    ip   = session.get("portal_ip") or request.remote_addr or ""
    if ip:
        row = conn.execute(
            "SELECT id FROM captive_sessions WHERE ip_address=? AND logged_out=0",
            (ip,),
        ).fetchone()
        if row:
            from app.services.captive_portal import logout_session
            logout_session(conn, row["id"])
    from app.audit_log import log_event as _log_event
    _log_event(
        category="session", action="captive_portal_logout",
        username=session.get("username", "portal-user"),
        remote_addr=ip or request.remote_addr,
        details={"ip": ip},
    )
    session.pop("portal_authenticated", None)
    session.pop("portal_ip", None)
    session.pop("content_filter_authenticated", None)
    return render_template(
        "portal/login.html",
        message="You have been logged out.",
        **_policy_context(request.args),
    )
