"""
app/vpn_portal_auth.py
----------------------
Authentication helpers for the **remote-user** VPN portal at /vpn-portal.

This portal is a separate identity surface from the admin UI and the SOC
portal — it backs the ``vpn_portal_users`` table introduced in migration
v29, lives under its own session namespace (``vpn_*`` keys), and emits
events under ``category="vpn_portal"`` so admin-level audit reviews
clearly distinguish "remote VPN user logged in" from "admin logged in".

Auth model:
* Password — argon2/werkzeug ``check_password_hash`` against
  ``vpn_portal_users.password_hash``.
* Optional TOTP — when ``totp_enrolled = 1`` the user is sent to
  ``/vpn-portal/mfa`` after a correct password; the AES-GCM-encrypted
  ``totp_secret_enc`` is decrypted on demand via ``secret_store``.
* Lockout — 5 failures / 15 min per username **and** 5 failures / 15 min
  per IP — both tracked in ``vpn_portal_login_attempts``.
"""

from __future__ import annotations

import time
from functools import wraps

from flask import jsonify, redirect, render_template, request, session, url_for


_MFA_PENDING_TTL = 300   # 5 minutes
_LOCKOUT_WINDOW  = 900   # 15 minutes
_LOCKOUT_LIMIT   = 5     # failures inside the window → locked


# ---------------------------------------------------------------------------
# Session helpers — keep VPN-portal session keys distinct from admin/SOC.
# ---------------------------------------------------------------------------

def get_vpn_session_user():
    """Return (user_id, username) from the VPN-portal session or (None, None)."""
    return (session.get("vpn_user_id"), session.get("vpn_username"))


def set_session_user(user_id: int, username: str) -> None:
    session["vpn_user_id"]  = int(user_id)
    session["vpn_username"] = username
    session["vpn_login_at"] = int(time.time())


def clear_session_user() -> None:
    for k in ("vpn_user_id", "vpn_username", "vpn_login_at",
              "vpn_pending_user_id", "vpn_pending_username",
              "vpn_pending_at"):
        session.pop(k, None)


# ---------------------------------------------------------------------------
# MFA pending state
# ---------------------------------------------------------------------------

def set_mfa_pending(user_id: int, username: str) -> None:
    session["vpn_pending_user_id"]  = int(user_id)
    session["vpn_pending_username"] = username
    session["vpn_pending_at"]       = int(time.time())


def get_mfa_pending():
    started = session.get("vpn_pending_at")
    if not started or (time.time() - int(started)) > _MFA_PENDING_TTL:
        clear_mfa_pending()
        return (None, None)
    return (session.get("vpn_pending_user_id"),
            session.get("vpn_pending_username"))


def clear_mfa_pending() -> None:
    for k in ("vpn_pending_user_id", "vpn_pending_username", "vpn_pending_at"):
        session.pop(k, None)


# ---------------------------------------------------------------------------
# Lockout
# ---------------------------------------------------------------------------

def record_attempt(conn, username: str, remote_addr: str,
                   success: bool, reason: str = "") -> None:
    try:
        conn.execute(
            "INSERT INTO vpn_portal_login_attempts "
            "(username, remote_addr, success, reason) VALUES (?,?,?,?)",
            (username or "", remote_addr or "", 1 if success else 0, reason or ""),
        )
        conn.commit()
    except Exception:
        pass


def is_locked_out(conn, username: str, remote_addr: str) -> bool:
    """Return True if either the username or the IP has exceeded the limit."""
    cutoff = time.time() - _LOCKOUT_WINDOW
    try:
        if username:
            row = conn.execute(
                "SELECT COUNT(*) AS c FROM vpn_portal_login_attempts "
                "WHERE username=? AND success=0 "
                "AND strftime('%s', ts) > ?",
                (username, str(int(cutoff))),
            ).fetchone()
            if row and (row["c"] or 0) >= _LOCKOUT_LIMIT:
                return True
        if remote_addr:
            row = conn.execute(
                "SELECT COUNT(*) AS c FROM vpn_portal_login_attempts "
                "WHERE remote_addr=? AND success=0 "
                "AND strftime('%s', ts) > ?",
                (remote_addr, str(int(cutoff))),
            ).fetchone()
            if row and (row["c"] or 0) >= _LOCKOUT_LIMIT:
                return True
    except Exception:
        pass
    return False


# ---------------------------------------------------------------------------
# Decorator — gate every authenticated portal route
# ---------------------------------------------------------------------------

def vpn_portal_login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        uid, _ = get_vpn_session_user()
        if not uid:
            if request.is_json or request.path.startswith("/vpn-portal/api/"):
                return jsonify({"ok": False,
                                "error": "session expired"}), 401
            return redirect(url_for("vpn_portal.login"))
        return view(*args, **kwargs)
    return wrapped


# ---------------------------------------------------------------------------
# Portal-level enable check
# ---------------------------------------------------------------------------

def vpn_portal_enabled(conn) -> bool:
    try:
        row = conn.execute(
            "SELECT enabled FROM vpn_portal_config WHERE id=1"
        ).fetchone()
        return bool(row and row["enabled"])
    except Exception:
        return False


# ---------------------------------------------------------------------------
# User helpers
# ---------------------------------------------------------------------------

def get_user_by_username(conn, username: str):
    try:
        return conn.execute(
            "SELECT * FROM vpn_portal_users WHERE username=?",
            (username or "",),
        ).fetchone()
    except Exception:
        return None


def get_user_by_id(conn, user_id):
    try:
        return conn.execute(
            "SELECT * FROM vpn_portal_users WHERE id=?",
            (int(user_id),),
        ).fetchone()
    except Exception:
        return None


def decrypt_totp_secret(user_row) -> str:
    """Return the plain TOTP secret for *user_row* or "" if not enrolled."""
    enc = (user_row["totp_secret_enc"] or "") if user_row else ""
    if not enc:
        return ""
    try:
        from app.secret_store import decrypt_secret
        return decrypt_secret(enc) or ""
    except Exception:
        return ""


def render_disabled():
    return render_template("vpn_portal/disabled.html"), 503
