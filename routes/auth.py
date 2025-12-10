from flask import Blueprint, render_template, request, redirect, url_for, session
from app.database import get_db

auth_bp = Blueprint("auth", __name__)

@auth_bp.route("/")
def index():
    return redirect(url_for("auth.login"))

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        conn = get_db()
        cur = conn.cursor()

        cur.execute("""
            SELECT * FROM users WHERE username=? AND password=?
        """, (username, password))

        user = cur.fetchone()

        if user:
            session["username"] = username
            session["user_id"] = user["id"]
            # Store profile picture in session
            if user["profile_picture"]:
                session["user_avatar"] = url_for('static', filename=user["profile_picture"])
            else:
                session.pop("user_avatar", None)
            return redirect(url_for("system.dashboard"))
        else:
            error = "Invalid username or password"

    return render_template("login.html", error=error)


@auth_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))
