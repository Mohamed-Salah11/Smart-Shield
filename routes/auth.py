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

        if user and check_password_hash(user["password"], password):
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
        log_event(
            category="session",
            action="login_failed",
            username=username or "anonymous",
            remote_addr=remote,
            details={"reason": "invalid_credentials"},
        )
        error = "Invalid username or password"

    return render_template("login.html", error=error)


@auth_bp.route("/logout")
def logout():
    log_event(
        category="session",
        action="logout",
        username=session.get("username", "anonymous"),
        remote_addr=request.remote_addr,
        details={"user_id": session.get("user_id")},
    )
    session.clear()
    return redirect(url_for("auth.login"))


@auth_bp.route("/reauth", methods=["POST"])
def reauth():
    """
    Reauthentication endpoint for destructive-action gates.
    POST JSON: {"password": "..."}
    On success sets session["reauth_time"] and returns {"ok": True}.
    On failure increments login_failures and returns {"ok": False}.
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
