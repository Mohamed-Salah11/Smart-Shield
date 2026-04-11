from flask import Blueprint, render_template, request, redirect, url_for, jsonify, session
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename
from app.database import get_db
from app.auth_utils import login_required
import os
import sys
from app.db_utils import db_cursor

users_bp = Blueprint("users", __name__, url_prefix="/system/user-manager")

DEFAULT_UPLOAD_DIR = (
    "/var/db/smart-shield/uploads/profile_pictures"
    if sys.platform.startswith("freebsd")
    else "static/uploads/profile_pictures"
)

UPLOAD_FOLDER = os.getenv(
    "SMARTSHIELD_UPLOAD_DIR",
    DEFAULT_UPLOAD_DIR
)
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def _redirect_back(default_endpoint="users.user_manager"):
    return redirect(request.referrer or url_for(default_endpoint))


@users_bp.route("/", methods=["GET"])
@login_required
def user_manager():
    with db_cursor() as (_, cur):
        cur.execute(
            """
            SELECT users.*, group_concat(groups.name, ', ') AS groups
            FROM users
            LEFT JOIN user_groups ON users.id = user_groups.user_id
            LEFT JOIN groups ON user_groups.group_id = groups.id
            GROUP BY users.id
            """
        )
        users = cur.fetchall()

        cur.execute("SELECT * FROM groups")
        groups = cur.fetchall()

    return render_template("user_manager.html", users=users, groups=groups)


@users_bp.route("/groups", methods=["GET"])
@login_required
def group_manager():
    with db_cursor() as (_, cur):
        cur.execute(
            """
            SELECT g.id, g.name, g.description, COUNT(ug.user_id) AS member_count
            FROM groups g
            LEFT JOIN user_groups ug ON ug.group_id = g.id
            GROUP BY g.id, g.name, g.description
            ORDER BY g.name COLLATE NOCASE
            """
        )
        groups = cur.fetchall()

        cur.execute("SELECT id, username, full_name FROM users ORDER BY username COLLATE NOCASE")
        users = cur.fetchall()

    return render_template("user_group.html", groups=groups, users=users)


@users_bp.route("/add", methods=["POST"])
@login_required
def add_user():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    full_name = request.form.get("full_name")
    email = request.form.get("email")
    group = request.form.get("groups")

    profile_picture = None
    if "profile_picture" in request.files:
        file = request.files["profile_picture"]
        if file and file.filename and allowed_file(file.filename):
            filename = secure_filename(f"{username}_{file.filename}")
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            file.save(filepath)
            profile_picture = f"uploads/profile_pictures/{filename}"

    with db_cursor(commit=True) as (_, cur):
        cur.execute(
            """
            INSERT INTO users (username, password, full_name, email, profile_picture)
            VALUES (?, ?, ?, ?, ?)
            """,
            (username, generate_password_hash(password), full_name, email, profile_picture),
        )
        user_id = cur.lastrowid

        if group:
            cur.execute("SELECT id FROM groups WHERE name=?", (group,))
            group_row = cur.fetchone()
            if group_row:
                cur.execute(
                    "INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)",
                    (user_id, group_row["id"]),
                )

    return redirect(url_for("users.user_manager"))


@users_bp.route("/add-group", methods=["POST"])
@login_required
def add_group():
    group_name = (request.form.get("group_name") or request.form.get("name") or "").strip()
    description = (request.form.get("description") or "").strip()
    if not group_name:
        return _redirect_back()

    with db_cursor(commit=True) as (_, cur):
        cur.execute(
            "INSERT OR IGNORE INTO groups (name, description) VALUES (?, ?)",
            (group_name, description),
        )

    return _redirect_back()


@users_bp.route("/edit-group/<int:group_id>", methods=["POST"])
@login_required
def edit_group(group_id):
    group_name = (request.form.get("group_name") or request.form.get("name") or "").strip()
    description = (request.form.get("description") or "").strip()
    if not group_name:
        return _redirect_back("users.group_manager")

    with db_cursor(commit=True) as (_, cur):
        cur.execute(
            "UPDATE groups SET name = ?, description = ? WHERE id = ?",
            (group_name, description, group_id),
        )

    return _redirect_back("users.group_manager")


@users_bp.route("/delete-group/<int:group_id>", methods=["POST"])
@login_required
def delete_group(group_id):
    with db_cursor(commit=True) as (_, cur):
        cur.execute("DELETE FROM user_groups WHERE group_id = ?", (group_id,))
        cur.execute("DELETE FROM groups WHERE id = ?", (group_id,))

    return _redirect_back("users.group_manager")


@users_bp.route("/group/<int:group_id>/add-member", methods=["POST"])
@login_required
def add_group_member(group_id):
    user_id = request.form.get("user_id", type=int)
    if user_id is None:
        return _redirect_back("users.group_manager")

    with db_cursor(commit=True) as (_, cur):
        cur.execute(
            "INSERT OR IGNORE INTO user_groups (user_id, group_id) VALUES (?, ?)",
            (user_id, group_id),
        )

    return _redirect_back("users.group_manager")


@users_bp.route("/group/<int:group_id>/remove-member/<int:user_id>", methods=["POST"])
@login_required
def remove_group_member(group_id, user_id):
    with db_cursor(commit=True) as (_, cur):
        cur.execute(
            "DELETE FROM user_groups WHERE user_id = ? AND group_id = ?",
            (user_id, group_id),
        )

    return _redirect_back("users.group_manager")


@users_bp.route("/group/<int:group_id>/members", methods=["GET"])
@login_required
def list_group_members(group_id):
    with db_cursor() as (_, cur):
        cur.execute(
            """
            SELECT u.id, u.username, u.full_name
            FROM users u
            INNER JOIN user_groups ug ON ug.user_id = u.id
            WHERE ug.group_id = ?
            ORDER BY u.username COLLATE NOCASE
            """,
            (group_id,),
        )
        members = [dict(row) for row in cur.fetchall()]

    return jsonify({"members": members})


@users_bp.route("/delete/<int:user_id>", methods=["POST"])
@login_required
def delete_user(user_id):
    with db_cursor(commit=True) as (_, cur):
        cur.execute("DELETE FROM user_groups WHERE user_id=?", (user_id,))
        cur.execute("DELETE FROM users WHERE id=?", (user_id,))
    return redirect(url_for("users.user_manager"))


@users_bp.route("/change-password/<int:user_id>", methods=["POST"])
@login_required
def change_password(user_id):
    new_password = request.form.get("new_password") or ""

    with db_cursor(commit=True) as (_, cur):
        cur.execute(
            "UPDATE users SET password=? WHERE id=?",
            (generate_password_hash(new_password), user_id),
        )

    return redirect(url_for("users.user_manager"))

@users_bp.route("/edit/<int:user_id>", methods=["POST"])
@login_required
def edit_user(user_id):
    username = request.form.get("username")
    full_name = request.form.get("full_name")
    email = request.form.get("email")
    status = request.form.get("status")
    group = request.form.get("groups")

    profile_picture = None

    with db_cursor(commit=True) as (_, cur):
        cur.execute("SELECT profile_picture FROM users WHERE id=?", (user_id,))
        current_user = cur.fetchone()
        profile_picture = current_user["profile_picture"] if current_user else None

        if "profile_picture" in request.files:
            file = request.files["profile_picture"]
            if file and file.filename and allowed_file(file.filename):
                if profile_picture:
                    old_path = os.path.join("static", profile_picture.lstrip("/").replace("static/", ""))
                    if os.path.exists(old_path):
                        try:
                            os.remove(old_path)
                        except OSError:
                            pass

                filename = secure_filename(f"{username}_{file.filename}")
                filepath = os.path.join(UPLOAD_FOLDER, filename)
                file.save(filepath)
                profile_picture = f"uploads/profile_pictures/{filename}"

        cur.execute(
            """
            UPDATE users
            SET username=?, full_name=?, email=?, status=?, profile_picture=?
            WHERE id=?
            """,
            (username, full_name, email, status, profile_picture, user_id),
        )

        cur.execute("DELETE FROM user_groups WHERE user_id=?", (user_id,))
        if group:
            cur.execute("SELECT id FROM groups WHERE name=?", (group,))
            group_row = cur.fetchone()
            if group_row:
                cur.execute(
                    "INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)",
                    (user_id, group_row["id"]),
                )

    if session.get("user_id") == user_id:
        session["username"] = username
        if profile_picture:
            session["user_avatar"] = url_for("static", filename=profile_picture)
        else:
            session.pop("user_avatar", None)

    return redirect(url_for("users.user_manager"))
