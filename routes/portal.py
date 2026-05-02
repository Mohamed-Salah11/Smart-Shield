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

import sys
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


def _portal_enabled(conn) -> bool:
    import json
    row = conn.execute(
        "SELECT value_json FROM service_state WHERE key_name='captive_portal_settings'"
    ).fetchone()
    if not row:
        return False
    try:
        return bool(json.loads(row["value_json"]).get("enabled", False))
    except Exception:
        return False


@portal_bp.route("/", methods=["GET"])
def login():
    conn = get_db()
    if not _portal_enabled(conn):
        return render_template("portal/disabled.html"), 503
    orig_url = request.args.get("url", "")
    return render_template("portal/login.html", orig_url=orig_url)


@portal_bp.route("/auth", methods=["POST"])
def auth():
    conn     = get_db()
    ip       = request.remote_addr or ""
    mac      = _client_mac(ip)
    orig_url = request.form.get("orig_url", "")

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
                orig_url=orig_url,
            )

        # Try RADIUS first; fall back to local user table
        radius_result = authenticate_radius(conn, username, password)
        if radius_result.get("ok"):
            result = authenticate_session(conn, mac, ip, username=username)
        else:
            # Local user check — use correct column names from the users table
            from werkzeug.security import check_password_hash as _chk
            row = conn.execute(
                "SELECT password FROM users WHERE username=? AND (status IS NULL OR status='active')",
                (username,),
            ).fetchone()
            if not row or not _chk(row["password"], password):
                return render_template(
                    "portal/login.html",
                    error="Invalid username or password.",
                    orig_url=orig_url,
                )
            result = authenticate_session(conn, mac, ip, username=username)

    if not result.get("ok"):
        # Decide which template to return to (block page or generic login page)
        back_template = request.form.get("back_template", "login")
        domain = request.form.get("domain", "")
        if back_template == "block":
            return render_template(
                "portal/block.html",
                error=result.get("message", "Authentication failed."),
                domain=domain,
                orig_url=orig_url,
            )
        return render_template(
            "portal/login.html",
            error=result.get("message", "Authentication failed."),
            orig_url=orig_url,
        )

    session["portal_authenticated"] = True
    session["content_filter_authenticated"] = True
    session["portal_ip"] = ip

    # If came from block page, go back to block success view
    back_template = request.form.get("back_template", "login")
    domain = request.form.get("domain", "")
    if back_template == "block":
        return render_template("portal/block.html", authenticated=True, domain=domain, orig_url=orig_url)

    return redirect(orig_url if orig_url else url_for("portal.success"))


@portal_bp.route("/success", methods=["GET"])
def success():
    return render_template("portal/success.html")


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

    # If the user already authenticated in this session, let them through
    if session.get("content_filter_authenticated") or session.get("portal_authenticated"):
        if orig_url:
            return redirect(orig_url)
        return render_template("portal/block.html", authenticated=True, domain=domain, orig_url=orig_url)

    return render_template("portal/block.html", domain=domain, orig_url=orig_url)


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
    return render_template("portal/login.html", message="You have been logged out.")
