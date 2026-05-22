"""
routes/vpn_portal.py
--------------------
Self-service portal for remote VPN users at /vpn-portal.

This is the public-facing surface remote users hit to log in, enroll
MFA, and download their own `.ovpn` profile — separate from the admin
UI (where only operators belong) and the SOC portal (analysts).

The blueprint is *registered* unconditionally in app/__init__.py, but
each route gates on ``vpn_portal_config.enabled`` so an admin can hide
the surface entirely without unregistering the blueprint.
"""

from __future__ import annotations

import time
from flask import (
    Blueprint, Response, jsonify, redirect, render_template,
    request, session, url_for,
)
from werkzeug.security import check_password_hash

from app.audit_log import log_event
from app.database import get_db
from app.vpn_portal_auth import (
    clear_mfa_pending, clear_session_user, decrypt_totp_secret,
    get_mfa_pending, get_user_by_id, get_user_by_username,
    get_vpn_session_user, is_locked_out, record_attempt,
    render_disabled, set_mfa_pending, set_session_user,
    vpn_portal_enabled, vpn_portal_login_required,
)

vpn_portal_bp = Blueprint(
    "vpn_portal",
    __name__,
    url_prefix="/vpn-portal",
    template_folder="../templates",
)


# ---------------------------------------------------------------------------
# Context — make username available to templates without per-route plumbing.
# ---------------------------------------------------------------------------

@vpn_portal_bp.context_processor
def _inject_user():
    uid, username = get_vpn_session_user()
    return {"vpn_user_id": uid, "vpn_username": username or ""}


# ---------------------------------------------------------------------------
# Login (password)
# ---------------------------------------------------------------------------

@vpn_portal_bp.route("/", methods=["GET"])
@vpn_portal_login_required
def home():
    conn = get_db()
    if not vpn_portal_enabled(conn):
        return render_disabled()
    uid, _ = get_vpn_session_user()
    user = get_user_by_id(conn, uid)
    if not user or user["disabled"]:
        clear_session_user()
        return redirect(url_for("vpn_portal.login"))
    server = None
    if user["ovpn_server_id"]:
        server = conn.execute(
            "SELECT id, description, server_mode, protocol, local_port "
            "FROM openvpn_servers WHERE id=?",
            (user["ovpn_server_id"],),
        ).fetchone()
    return render_template(
        "vpn_portal/home.html",
        user=dict(user),
        server=dict(server) if server else None,
    )


@vpn_portal_bp.route("/login", methods=["GET", "POST"])
def login():
    conn = get_db()
    if not vpn_portal_enabled(conn):
        return render_disabled()

    if get_vpn_session_user()[0]:
        return redirect(url_for("vpn_portal.home"))

    error  = None
    remote = request.remote_addr or ""

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        if is_locked_out(conn, username, remote):
            log_event(category="vpn_portal", action="vpn_portal_lockout",
                      severity="medium", username=username,
                      remote_addr=remote,
                      details={"limit": 5, "window_seconds": 900})
            return render_template(
                "vpn_portal/login.html",
                error="Too many failed attempts. Try again in 15 minutes.",
            ), 429

        user = get_user_by_username(conn, username)
        if (not user or user["disabled"]
                or not check_password_hash(user["password_hash"] or "", password)):
            record_attempt(conn, username, remote, success=False,
                           reason="bad_credentials")
            log_event(category="vpn_portal", action="vpn_portal_login_failed",
                      severity="medium", username=username, remote_addr=remote,
                      details={"reason": "bad_credentials"})
            error = "Invalid username or password."
            return render_template("vpn_portal/login.html", error=error), 401

        # Password OK. If TOTP is enrolled, route through /mfa; otherwise
        # complete the login now.
        if user["totp_enrolled"]:
            set_mfa_pending(user["id"], user["username"])
            return redirect(url_for("vpn_portal.mfa"))

        set_session_user(user["id"], user["username"])
        record_attempt(conn, username, remote, success=True, reason="password")
        conn.execute(
            "UPDATE vpn_portal_users SET last_login_at=CURRENT_TIMESTAMP "
            "WHERE id=?",
            (user["id"],),
        )
        conn.commit()
        log_event(category="vpn_portal", action="vpn_portal_login_ok",
                  username=username, remote_addr=remote,
                  details={"mfa": False})
        return redirect(url_for("vpn_portal.home"))

    return render_template("vpn_portal/login.html", error=error)


@vpn_portal_bp.route("/mfa", methods=["GET", "POST"])
def mfa():
    conn = get_db()
    if not vpn_portal_enabled(conn):
        return render_disabled()

    pending_id, pending_username = get_mfa_pending()
    if not pending_id:
        return redirect(url_for("vpn_portal.login"))

    error = None
    if request.method == "POST":
        from app.totp import verify as _totp_verify
        code = (request.form.get("code") or "").strip()
        user = get_user_by_id(conn, pending_id)
        secret = decrypt_totp_secret(user)
        if not secret or not _totp_verify(secret, code):
            record_attempt(conn, pending_username, request.remote_addr or "",
                           success=False, reason="bad_mfa")
            log_event(category="vpn_portal", action="vpn_portal_mfa_failed",
                      severity="medium", username=pending_username,
                      remote_addr=request.remote_addr or "",
                      details={"reason": "bad_code"})
            error = "Invalid code. Please try again."
        else:
            set_session_user(pending_id, pending_username)
            clear_mfa_pending()
            record_attempt(conn, pending_username, request.remote_addr or "",
                           success=True, reason="mfa")
            conn.execute(
                "UPDATE vpn_portal_users SET last_login_at=CURRENT_TIMESTAMP "
                "WHERE id=?",
                (pending_id,),
            )
            conn.commit()
            log_event(category="vpn_portal", action="vpn_portal_login_ok",
                      username=pending_username,
                      remote_addr=request.remote_addr or "",
                      details={"mfa": True})
            return redirect(url_for("vpn_portal.home"))

    return render_template("vpn_portal/login_mfa.html", error=error,
                           username=pending_username)


@vpn_portal_bp.route("/logout", methods=["POST"])
def logout():
    uid, username = get_vpn_session_user()
    if uid:
        log_event(category="vpn_portal", action="vpn_portal_logout",
                  username=username or "",
                  remote_addr=request.remote_addr or "")
    clear_session_user()
    return redirect(url_for("vpn_portal.login"))


# ---------------------------------------------------------------------------
# TOTP enrollment
# ---------------------------------------------------------------------------

@vpn_portal_bp.route("/security/enroll", methods=["GET", "POST"])
@vpn_portal_login_required
def enroll_mfa():
    from app.secret_store import encrypt_secret
    from app.totp import generate_secret, provisioning_uri, verify as totp_verify

    conn = get_db()
    uid, username = get_vpn_session_user()
    user = get_user_by_id(conn, uid)
    if not user:
        return redirect(url_for("vpn_portal.login"))

    if request.method == "POST":
        # Two phases: enrol (commit), or unenrol.
        if request.form.get("action") == "unenrol":
            conn.execute(
                "UPDATE vpn_portal_users SET totp_enrolled=0, totp_secret_enc='' "
                "WHERE id=?",
                (uid,),
            )
            conn.commit()
            log_event(category="vpn_portal", action="vpn_portal_mfa_unenrolled",
                      username=username or "",
                      remote_addr=request.remote_addr or "")
            return redirect(url_for("vpn_portal.home"))

        secret = (session.get("vpn_pending_totp_secret") or "").strip()
        code   = (request.form.get("code") or "").strip()
        if secret and totp_verify(secret, code):
            conn.execute(
                "UPDATE vpn_portal_users SET totp_secret_enc=?, totp_enrolled=1 "
                "WHERE id=?",
                (encrypt_secret(secret), uid),
            )
            conn.commit()
            session.pop("vpn_pending_totp_secret", None)
            log_event(category="vpn_portal", action="vpn_portal_mfa_enrolled",
                      username=username or "",
                      remote_addr=request.remote_addr or "")
            return redirect(url_for("vpn_portal.home"))
        error = "Code did not match. Try again."
    else:
        error = None

    # GET (or POST validation failure) — mint a fresh secret if none staged.
    secret = session.get("vpn_pending_totp_secret")
    if not secret:
        secret = generate_secret()
        session["vpn_pending_totp_secret"] = secret
    uri = provisioning_uri(secret, account=username or "vpn-user",
                           issuer="Smart Shield VPN")
    return render_template("vpn_portal/security_enroll.html",
                           secret=secret, uri=uri, error=error,
                           already_enrolled=bool(user["totp_enrolled"]))


# ---------------------------------------------------------------------------
# Profile download — the whole point of this portal
# ---------------------------------------------------------------------------

@vpn_portal_bp.route("/download/ovpn", methods=["GET"])
@vpn_portal_login_required
def download_ovpn():
    from app.services.openvpn_writer import generate_client_ovpn

    conn = get_db()
    uid, username = get_vpn_session_user()
    user = get_user_by_id(conn, uid)
    if not user or user["disabled"]:
        return Response("Account is disabled.", status=403,
                        mimetype="text/plain")
    if not user["ovpn_server_id"] or not user["client_cert_id"]:
        return Response(
            "No OpenVPN profile is assigned to your account yet. "
            "Please contact your administrator.",
            status=404, mimetype="text/plain",
        )

    try:
        ovpn_text = generate_client_ovpn(
            conn, user["ovpn_server_id"], user["client_cert_id"]
        )
    except Exception as exc:
        return Response(f"Profile generation failed: {exc}", status=500,
                        mimetype="text/plain")

    log_event(category="vpn_portal",
              action="vpn_portal_config_downloaded",
              username=username or "",
              remote_addr=request.remote_addr or "",
              details={"server_id": user["ovpn_server_id"],
                       "client_cert_id": user["client_cert_id"]})

    filename = f"{(username or 'vpn-user')}.ovpn"
    return Response(
        ovpn_text,
        mimetype="application/x-openvpn-profile",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )


@vpn_portal_bp.route("/password", methods=["POST"])
@vpn_portal_login_required
def change_password():
    from werkzeug.security import generate_password_hash

    conn = get_db()
    uid, username = get_vpn_session_user()
    user = get_user_by_id(conn, uid)
    if not user:
        return redirect(url_for("vpn_portal.login"))

    current  = request.form.get("current") or ""
    new_pw   = request.form.get("new") or ""
    confirm  = request.form.get("confirm") or ""

    if not check_password_hash(user["password_hash"] or "", current):
        return jsonify({"ok": False, "error": "Current password is wrong."}), 400
    if len(new_pw) < 10:
        return jsonify({"ok": False,
                        "error": "New password must be at least 10 characters."}), 400
    if new_pw != confirm:
        return jsonify({"ok": False,
                        "error": "Confirmation does not match new password."}), 400

    conn.execute(
        "UPDATE vpn_portal_users SET password_hash=? WHERE id=?",
        (generate_password_hash(new_pw), uid),
    )
    conn.commit()
    log_event(category="vpn_portal", action="vpn_portal_password_changed",
              username=username or "",
              remote_addr=request.remote_addr or "")
    return jsonify({"ok": True})
