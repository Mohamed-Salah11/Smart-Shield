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
            # Local user check
            import hashlib, hmac as _hmac
            row = conn.execute(
                "SELECT password_hash FROM users WHERE username=? AND disabled=0",
                (username,),
            ).fetchone()
            if not row:
                return render_template(
                    "portal/login.html",
                    error="Invalid username or password.",
                    orig_url=orig_url,
                )
            import bcrypt
            try:
                valid = bcrypt.checkpw(password.encode(), row["password_hash"].encode())
            except Exception:
                valid = False
            if not valid:
                return render_template(
                    "portal/login.html",
                    error="Invalid username or password.",
                    orig_url=orig_url,
                )
            result = authenticate_session(conn, mac, ip, username=username)

    if not result.get("ok"):
        return render_template(
            "portal/login.html",
            error=result.get("message", "Authentication failed."),
            orig_url=orig_url,
        )

    session["portal_authenticated"] = True
    session["portal_ip"] = ip
    return redirect(url_for("portal.success", url=orig_url) if not orig_url else orig_url)


@portal_bp.route("/success", methods=["GET"])
def success():
    return render_template("portal/success.html")


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
