from flask import Blueprint, render_template, request, redirect, url_for
from app.database import get_db

users_bp = Blueprint("users", __name__, url_prefix="/system/user-manager")


@users_bp.route("/", methods=["GET"])
def user_manager():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT users.*, group_concat(groups.name, ', ') AS groups
        FROM users
        LEFT JOIN user_groups ON users.id = user_groups.user_id
        LEFT JOIN groups ON user_groups.group_id = groups.id
        GROUP BY users.id
    """)

    users = cur.fetchall()

    cur.execute("SELECT * FROM groups")
    groups = cur.fetchall()

    return render_template("user_manager.html", users=users, groups=groups)


@users_bp.route("/add", methods=["POST"])
def add_user():
    username = request.form.get("username")
    password = request.form.get("password")
    full_name = request.form.get("full_name")
    group = request.form.get("groups")

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO users (username, password, full_name)
        VALUES (?, ?, ?)
    """, (username, password, full_name))

    user_id = cur.lastrowid

    if group:
        cur.execute("SELECT id FROM groups WHERE name=?", (group,))
        group_row = cur.fetchone()
        if group_row:
            cur.execute("""
                INSERT INTO user_groups (user_id, group_id)
                VALUES (?, ?)
            """, (user_id, group_row["id"]))

    conn.commit()
    return redirect(url_for("users.user_manager"))


@users_bp.route("/delete/<int:user_id>", methods=["POST"])
def delete_user(user_id):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("DELETE FROM user_groups WHERE user_id=?", (user_id,))
    cur.execute("DELETE FROM users WHERE id=?", (user_id,))

    conn.commit()
    return redirect(url_for("users.user_manager"))


@users_bp.route("/change-password/<int:user_id>", methods=["POST"])
def change_password(user_id):
    new_password = request.form.get("new_password")

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        UPDATE users SET password=? WHERE id=?
    """, (new_password, user_id))

    conn.commit()
    return redirect(url_for("users.user_manager"))


@users_bp.route("/add-group", methods=["POST"])
def add_group():
    name = request.form.get("group_name")
    description = request.form.get("description")

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO groups (name, description)
        VALUES (?, ?)
    """, (name, description))

    conn.commit()
    return redirect(url_for("users.user_manager"))
