from flask import Blueprint, render_template, request, redirect, url_for, session
from werkzeug.security import check_password_hash
from app.database import get_db
from app.audit_log import log_event
from app.uploads import profile_picture_url


auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/")
def index():
    return redirect(url_for("auth.login"))


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cur.fetchone()

        if user and check_password_hash(user["password"], password):
            session["username"] = user["username"]
            session["user_id"] = user["id"]
            session["is_superuser"] = bool(user["is_superuser"]) if "is_superuser" in user.keys() else (user["username"] == "admin")
            if user["profile_picture"]:
                session["user_avatar"] = profile_picture_url(user["profile_picture"])
            else:
                session.pop("user_avatar", None)
            log_event(
                category="session",
                action="login_success",
                username=user["username"],
                remote_addr=request.remote_addr,
                details={"user_id": user["id"]},
            )
            return redirect(url_for("system.dashboard"))

        log_event(
            category="session",
            action="login_failed",
            username=username or "anonymous",
            remote_addr=request.remote_addr,
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
