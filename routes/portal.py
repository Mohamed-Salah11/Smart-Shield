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

def _safe_redirect_target(url: str) -> str:
    """Redirect to the original URL after captive portal login.
    Allows relative URLs, same-host URLs, and any external http/https URL
    (external redirects are the normal captive portal post-auth behaviour).
    Rejects non-http schemes (javascript:, data:, etc.) as a safety measure.
    """
    url = (url or "").strip()
    if not url:
        return url_for("portal.success")

    parsed = urlparse(url)

    # Allow relative URLs.
    if not parsed.netloc:
        return url

    # Allow any absolute http or https URL (covers external sites after captive portal auth).
    if parsed.scheme in ("http", "https"):
        return url

    return url_for("portal.success")


def _policy_context(source) -> dict:
    policy = (source.get("policy") or "").strip().lower()
    if policy != "content":
        policy = ""
    return {
        "policy": policy,
        "domain": (source.get("domain") or "").strip().lower(),
        "orig_url": (source.get("url") or source.get("orig_url") or "").strip(),
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
    if not _portal_enabled(conn):
        return render_template("portal/disabled.html"), 503
    return render_template("portal/login.html", **_policy_context(request.args))


@portal_bp.route("/auth", methods=["POST"])
def auth():
    conn     = get_db()
    ip       = request.remote_addr or ""
    mac      = _client_mac(ip)
    context  = _policy_context(request.form)
    orig_url = context["orig_url"]

    auth_type = request.form.get("auth_type", "credentials")

    from app.services.captive_portal import (
        authenticate_session, redeem_voucher, authenticate_radius,
    )

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

        # Load portal whitelist once for both auth paths
        _cp_row = conn.execute(
            "SELECT value_json FROM service_state WHERE key_name='captive_portal_settings'"
        ).fetchone()
        _cp_settings = json.loads(_cp_row["value_json"]) if _cp_row else {}
        _whitelist = {u.strip().lower() for u in (_cp_settings.get("whitelist_users") or [])}
        is_whitelisted = username.strip().lower() in _whitelist

        # Try RADIUS first; fall back to local user table
        radius_result = authenticate_radius(conn, username, password)
        if radius_result.get("ok"):
            result = authenticate_session(
                conn, mac, ip, username=username,
                is_superuser=is_whitelisted,
            )
        else:
            # Local user check — use correct column names from the users table
            from werkzeug.security import check_password_hash as _chk
            row = conn.execute(
                "SELECT password, is_superuser FROM users WHERE username=? AND (status IS NULL OR status='active')",
                (username,),
            ).fetchone()
            if not row or not _chk(row["password"], password):
                return render_template(
                    "portal/login.html",
                    error="Invalid username or password.",
                    **context,
                )
            is_superuser = bool(row["is_superuser"]) or is_whitelisted
            result = authenticate_session(conn, mac, ip, username=username, is_superuser=is_superuser)

    if not result.get("ok"):
        # Decide which template to return to (block page or generic login page)
        back_template = request.form.get("back_template", "login")
        if back_template == "block":
            return render_template(
                "portal/block.html",
                error=result.get("message", "Authentication failed."),
                **context,
            )
        return render_template(
            "portal/login.html",
            error=result.get("message", "Authentication failed."),
            **context,
        )

    session["portal_authenticated"] = True
    session["content_filter_authenticated"] = True
    session["portal_ip"] = ip

    back_template = request.form.get("back_template", "login")

    if back_template == "block":
        # User came via the DNS-redirect block page (direct navigation, not a popup).
        # Render block.html authenticated view — it has auto-redirect JS + Continue button.
        return render_template("portal/block.html", authenticated=True, **context)

    if context["policy"] == "content":
        # Popup/interstitial flow — success.html uses window.opener to navigate the parent tab.
        return render_template("portal/success.html", **context)

    return redirect(_safe_redirect_target(orig_url))


@portal_bp.route("/success", methods=["GET"])
def success():
    return render_template("portal/success.html", **_policy_context(request.args))


@portal_bp.route("/block", methods=["GET"])
def block():
    """
    Content Police block page.
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

    # Already authenticated — let the user through
    context = {"policy": "content", "domain": domain, "orig_url": orig_url}
    if session.get("content_filter_authenticated") or session.get("portal_authenticated"):
        return render_template("portal/success.html", **context)

    return redirect(url_for("portal.login", policy="content", domain=domain, url=orig_url))


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
    session.pop("portal_authenticated", None)
    session.pop("portal_ip", None)
    session.pop("content_filter_authenticated", None)
    return render_template(
        "portal/login.html",
        message="You have been logged out.",
        **_policy_context(request.args),
    )
