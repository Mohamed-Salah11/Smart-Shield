from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from app.database import get_db
from werkzeug.utils import secure_filename
import os

users_bp = Blueprint("users", __name__, url_prefix="/system/user-manager")

UPLOAD_FOLDER = 'static/uploads/profile_pictures'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


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
    email = request.form.get("email")
    group = request.form.get("groups")
    
    # Handle profile picture upload
    profile_picture = None
    if 'profile_picture' in request.files:
        file = request.files['profile_picture']
        if file and file.filename and allowed_file(file.filename):
            filename = secure_filename(f"{username}_{file.filename}")
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            file.save(filepath)
            profile_picture = f"uploads/profile_pictures/{filename}"

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO users (username, password, full_name, email, profile_picture)
        VALUES (?, ?, ?, ?, ?)
    """, (username, password, full_name, email, profile_picture))

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


@users_bp.route("/edit/<int:user_id>", methods=["POST"])
def edit_user(user_id):
    username = request.form.get("username")
    full_name = request.form.get("full_name")
    email = request.form.get("email")
    status = request.form.get("status")
    group = request.form.get("groups")
    
    conn = get_db()
    cur = conn.cursor()
    
    # Get current profile picture
    cur.execute("SELECT profile_picture FROM users WHERE id=?", (user_id,))
    current_user = cur.fetchone()
    profile_picture = current_user["profile_picture"] if current_user else None
    
    # Handle profile picture upload
    if 'profile_picture' in request.files:
        file = request.files['profile_picture']
        if file and file.filename and allowed_file(file.filename):
            # Delete old profile picture if exists
            if profile_picture:
                old_path = os.path.join('static', profile_picture.lstrip('/').replace('static/', ''))
                if os.path.exists(old_path):
                    try:
                        os.remove(old_path)
                    except:
                        pass
            
            filename = secure_filename(f"{username}_{file.filename}")
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            file.save(filepath)
            profile_picture = f"uploads/profile_pictures/{filename}"
    
    cur.execute("""
        UPDATE users 
        SET username=?, full_name=?, email=?, status=?, profile_picture=?
        WHERE id=?
    """, (username, full_name, email, status, profile_picture, user_id))
    
    # Update group membership
    cur.execute("DELETE FROM user_groups WHERE user_id=?", (user_id,))
    if group:
        cur.execute("SELECT id FROM groups WHERE name=?", (group,))
        group_row = cur.fetchone()
        if group_row:
            cur.execute("""
                INSERT INTO user_groups (user_id, group_id)
                VALUES (?, ?)
            """, (user_id, group_row["id"]))
    
    conn.commit()
    
    # Update session if the edited user is the current logged-in user
    if session.get("user_id") == user_id:
        session["username"] = username
        if profile_picture:
            session["user_avatar"] = url_for('static', filename=profile_picture)
        else:
            session.pop("user_avatar", None)
    
    return redirect(url_for("users.user_manager"))


@users_bp.route("/groups", methods=["GET"])
def groups_manager():
    conn = get_db()
    cur = conn.cursor()
    
    # Get all groups with member count
    cur.execute("""
        SELECT groups.*, COUNT(user_groups.user_id) as member_count
        FROM groups
        LEFT JOIN user_groups ON groups.id = user_groups.group_id
        GROUP BY groups.id
    """)
    groups = cur.fetchall()
    
    # Get all users for assigning to groups
    cur.execute("SELECT id, username, full_name FROM users")
    users = cur.fetchall()
    
    conn.close()
    return render_template("user_group.html", groups=groups, users=users)


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
    conn.close()
    
    # Check if we came from the groups page
    if request.referrer and '/groups' in request.referrer:
        return redirect(url_for("users.groups_manager"))
    return redirect(url_for("users.user_manager"))


@users_bp.route("/edit-group/<int:group_id>", methods=["POST"])
def edit_group(group_id):
    name = request.form.get("group_name")
    description = request.form.get("description")
    
    conn = get_db()
    cur = conn.cursor()
    
    cur.execute("""
        UPDATE groups SET name=?, description=? WHERE id=?
    """, (name, description, group_id))
    
    conn.commit()
    conn.close()
    return redirect(url_for("users.groups_manager"))


@users_bp.route("/delete-group/<int:group_id>", methods=["POST"])
def delete_group(group_id):
    conn = get_db()
    cur = conn.cursor()
    
    # Remove all user associations first
    cur.execute("DELETE FROM user_groups WHERE group_id=?", (group_id,))
    # Delete the group
    cur.execute("DELETE FROM groups WHERE id=?", (group_id,))
    
    conn.commit()
    conn.close()
    return redirect(url_for("users.groups_manager"))


@users_bp.route("/group/<int:group_id>/members", methods=["GET"])
def get_group_members(group_id):
    conn = get_db()
    cur = conn.cursor()
    
    cur.execute("""
        SELECT users.id, users.username, users.full_name
        FROM users
        JOIN user_groups ON users.id = user_groups.user_id
        WHERE user_groups.group_id=?
    """, (group_id,))
    members = cur.fetchall()
    
    conn.close()
    return {"members": [dict(m) for m in members]}


@users_bp.route("/group/<int:group_id>/add-member", methods=["POST"])
def add_group_member(group_id):
    user_id = request.form.get("user_id")
    
    conn = get_db()
    cur = conn.cursor()
    
    # Check if already a member
    cur.execute("SELECT 1 FROM user_groups WHERE user_id=? AND group_id=?", (user_id, group_id))
    if not cur.fetchone():
        cur.execute("INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)", (user_id, group_id))
        conn.commit()
    
    conn.close()
    return redirect(url_for("users.groups_manager"))


@users_bp.route("/group/<int:group_id>/remove-member/<int:user_id>", methods=["POST"])
def remove_group_member(group_id, user_id):
    conn = get_db()
    cur = conn.cursor()
    
    cur.execute("DELETE FROM user_groups WHERE user_id=? AND group_id=?", (user_id, group_id))
    conn.commit()
    
    conn.close()
    return redirect(url_for("users.groups_manager"))
