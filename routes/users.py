from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from app.auth_utils import login_required, superuser_required, reauth_required
import os
from app.db_utils import db_cursor
from app.uploads import (
    ensure_upload_dir,
    get_upload_dir,
    profile_picture_url,
    resolve_profile_picture_path,
)

users_bp = Blueprint("users", __name__, url_prefix="/system/user-manager")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

ensure_upload_dir()


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def _redirect_back(default_endpoint="users.user_manager"):
    return redirect(request.referrer or url_for(default_endpoint))


def _humanize_endpoint(endpoint):
    return endpoint.replace(".", " / ").replace("_", " ").title()


def _category_for_endpoint(endpoint):
    category_key = (endpoint.split(".", 1)[0] if "." in endpoint else "other").lower()
    category_labels = {
        "system": "System",
        "interfaces": "Interfaces",
        "firewall": "Firewall",
        "services": "Services",
        "vpn": "VPN",
        "status": "Status",
        "diagnostics": "Diagnostics",
        "routing": "Routing",
        "network_api": "Network API",
    }
    return category_key, category_labels.get(category_key, category_key.replace("_", " ").title())


def _permission_catalog():
    from app.api_auth import API_PERMISSION_CATALOG

    excluded_prefixes = ("auth.", "static.", "users.")
    excluded_endpoints = {"system.logout"}
    entries = []
    for rule in current_app.url_map.iter_rules():
        endpoint = rule.endpoint
        if endpoint.startswith(excluded_prefixes):
            continue
        if endpoint in excluded_endpoints:
            continue
        if "GET" not in rule.methods:
            continue
        if "<" in rule.rule:
            continue
        if "/api/" in rule.rule or rule.rule.startswith("/api/"):
            continue
        category_key, category = _category_for_endpoint(endpoint)
        entries.append(
            {
                "endpoint": endpoint,
                "path": rule.rule,
                "label": _humanize_endpoint(endpoint),
                "category": category,
                "category_key": category_key,
            }
        )

    # Keep unique endpoint entries and stable ordering by URL path then label.
    seen = set()
    unique_entries = []
    for entry in sorted(entries, key=lambda x: (x["path"], x["label"])):
        if entry["endpoint"] in seen:
            continue
        seen.add(entry["endpoint"])
        unique_entries.append(entry)

    # Append API-level permission strings so they can be granted to groups.
    for perm, area, path_hint, description in API_PERMISSION_CATALOG:
        unique_entries.append({
            "endpoint": perm,
            "path": path_hint,
            "label": f"[API] {description}",
            "category": area,
            "category_key": area.lower().replace("/", "_").replace(" ", "_"),
        })

    return unique_entries


def _valid_permission_endpoints(selected_endpoints):
    catalog_endpoints = {entry["endpoint"] for entry in _permission_catalog()}
    return sorted(set(ep for ep in selected_endpoints if ep in catalog_endpoints))


@users_bp.route("/profile-picture/<path:filename>", methods=["GET"])
@login_required
def profile_picture_file(filename):
    safe_name = secure_filename(os.path.basename(filename))
    if not safe_name:
        abort(404)

    upload_dir = get_upload_dir()
    file_path = os.path.join(upload_dir, safe_name)
    if not os.path.isfile(file_path):
        abort(404)

    return send_from_directory(upload_dir, safe_name, conditional=True, max_age=300)


@users_bp.route("/", methods=["GET"])
@superuser_required
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
@superuser_required
def group_manager():
    with db_cursor() as (_, cur):
        cur.execute(
            """
            SELECT g.id, g.name, g.description, COUNT(DISTINCT ug.user_id) AS member_count
            FROM groups g
            LEFT JOIN user_groups ug ON ug.group_id = g.id
            GROUP BY g.id, g.name, g.description
            ORDER BY g.name COLLATE NOCASE
            """
        )
        groups = cur.fetchall()

        cur.execute("SELECT id, username, full_name FROM users ORDER BY username COLLATE NOCASE")
        users = cur.fetchall()

        cur.execute("SELECT group_id, endpoint FROM group_page_permissions ORDER BY endpoint COLLATE NOCASE")
        permission_rows = cur.fetchall()

    group_permissions = {}
    for row in permission_rows:
        group_permissions.setdefault(row["group_id"], []).append(row["endpoint"])

    available_permissions = _permission_catalog()
    category_rank = {
        "system": 1,
        "interfaces": 2,
        "firewall": 3,
        "services": 4,
        "vpn": 5,
        "status": 6,
        "diagnostics": 7,
        "routing": 8,
        "other": 99,
    }
    grouped = {}
    for item in available_permissions:
        grouped.setdefault(item["category_key"], {"name": item["category"], "items": []})
        grouped[item["category_key"]]["items"].append(item)

    permission_categories = []
    for key, data in grouped.items():
        permission_categories.append(
            {
                "key": key,
                "name": data["name"],
                "items": sorted(data["items"], key=lambda x: (x["path"], x["label"])),
                "rank": category_rank.get(key, 50),
            }
        )
    permission_categories.sort(key=lambda x: (x["rank"], x["name"]))

    return render_template(
        "user_group.html",
        groups=groups,
        users=users,
        group_permissions=group_permissions,
        available_permissions=available_permissions,
        permission_categories=permission_categories,
    )


@users_bp.route("/add", methods=["POST"])
@superuser_required
def add_user():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    full_name = request.form.get("full_name")
    email = request.form.get("email")
    group = request.form.get("groups")

    if not password or len(password) < 8:
        flash("Password must be at least 8 characters.", "danger")
        return redirect(url_for("users.user_manager"))

    profile_picture = None
    if "profile_picture" in request.files:
        file = request.files["profile_picture"]
        if file and file.filename and allowed_file(file.filename):
            filename = secure_filename(f"{username}_{file.filename}")
            filepath = os.path.join(get_upload_dir(), filename)
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
@superuser_required
def add_group():
    group_name = (request.form.get("group_name") or request.form.get("name") or "").strip()
    description = (request.form.get("description") or "").strip()
    allowed_endpoints = _valid_permission_endpoints(request.form.getlist("allowed_endpoints"))
    if not group_name:
        return _redirect_back()

    with db_cursor(commit=True) as (_, cur):
        cur.execute(
            "INSERT OR IGNORE INTO groups (name, description) VALUES (?, ?)",
            (group_name, description),
        )
        inserted = cur.rowcount > 0
        if inserted:
            group_id = cur.lastrowid
            for endpoint in allowed_endpoints:
                cur.execute(
                    "INSERT INTO group_page_permissions (group_id, endpoint) VALUES (?, ?)",
                    (group_id, endpoint),
                )

    return _redirect_back()


@users_bp.route("/edit-group/<int:group_id>", methods=["POST"])
@superuser_required
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
@superuser_required
def delete_group(group_id):
    with db_cursor(commit=True) as (_, cur):
        cur.execute("DELETE FROM user_groups WHERE group_id = ?", (group_id,))
        cur.execute("DELETE FROM groups WHERE id = ?", (group_id,))

    return _redirect_back("users.group_manager")


@users_bp.route("/group/<int:group_id>/add-member", methods=["POST"])
@superuser_required
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
@superuser_required
def remove_group_member(group_id, user_id):
    with db_cursor(commit=True) as (_, cur):
        cur.execute(
            "DELETE FROM user_groups WHERE user_id = ? AND group_id = ?",
            (user_id, group_id),
        )

    return _redirect_back("users.group_manager")


@users_bp.route("/group/<int:group_id>/members", methods=["GET"])
@superuser_required
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


@users_bp.route("/group/<int:group_id>/permissions", methods=["POST"])
@superuser_required
def set_group_permissions(group_id):
    allowed_endpoints = request.form.getlist("allowed_endpoints")
    valid_endpoints = _valid_permission_endpoints(allowed_endpoints)

    with db_cursor(commit=True) as (_, cur):
        cur.execute("SELECT id FROM groups WHERE id = ?", (group_id,))
        if cur.fetchone() is None:
            return _redirect_back("users.group_manager")

        cur.execute("DELETE FROM group_page_permissions WHERE group_id = ?", (group_id,))
        for endpoint in valid_endpoints:
            cur.execute(
                "INSERT INTO group_page_permissions (group_id, endpoint) VALUES (?, ?)",
                (group_id, endpoint),
            )

    return _redirect_back("users.group_manager")


@users_bp.route("/delete/<int:user_id>", methods=["POST"])
@superuser_required
def delete_user(user_id):
    if user_id == session.get("user_id"):
        flash("You cannot delete your own account.", "danger")
        return redirect(url_for("users.user_manager"))
    with db_cursor(commit=True) as (_, cur):
        cur.execute("SELECT COALESCE(is_superuser, 0) AS is_superuser FROM users WHERE id = ?", (user_id,))
        row = cur.fetchone()
        if row and row["is_superuser"]:
            return _redirect_back("users.user_manager")

        cur.execute("DELETE FROM user_groups WHERE user_id=?", (user_id,))
        cur.execute("DELETE FROM users WHERE id=?", (user_id,))
    return redirect(url_for("users.user_manager"))


@users_bp.route("/change-password/<int:user_id>", methods=["POST"])
@superuser_required
@reauth_required(reason="change password")
def change_password(user_id):
    old_password = request.form.get("old_password") or ""
    new_password = request.form.get("new_password") or ""
    confirm_password = request.form.get("confirm_password") or ""

    if not new_password:
        flash("New password is required.", "danger")
        return redirect(url_for("users.user_manager"))

    if new_password != confirm_password:
        flash("Password confirmation does not match. Password was not changed.", "danger")
        return redirect(url_for("users.user_manager"))

    with db_cursor(commit=True) as (_, cur):
        cur.execute("SELECT password FROM users WHERE id=?", (user_id,))
        current_user = cur.fetchone()
        if not current_user:
            flash("User was not found. Password was not changed.", "danger")
            return redirect(url_for("users.user_manager"))

        if not old_password:
            flash("Current password is required to change password.", "danger")
            return redirect(url_for("users.user_manager"))

        if not check_password_hash(current_user["password"], old_password):
            flash("Current password is incorrect. Password was not changed.", "danger")
            return redirect(url_for("users.user_manager"))

        cur.execute(
            "UPDATE users SET password=? WHERE id=?",
            (generate_password_hash(new_password), user_id),
        )

    flash("Password updated successfully.", "success")
    return redirect(url_for("users.user_manager"))

@users_bp.route("/edit/<int:user_id>", methods=["POST"])
@superuser_required
def edit_user(user_id):
    username = request.form.get("username")
    full_name = request.form.get("full_name")
    email = request.form.get("email")
    status = request.form.get("status")
    group = request.form.get("groups")
    old_password = request.form.get("old_password") or ""
    new_password = request.form.get("new_password") or ""
    confirm_password = request.form.get("confirm_password") or ""

    if new_password and new_password != confirm_password:
        flash("Password confirmation does not match. User profile was not updated.", "danger")
        return redirect(url_for("users.user_manager"))

    profile_picture = None

    with db_cursor(commit=True) as (_, cur):
        cur.execute("SELECT profile_picture, password FROM users WHERE id=?", (user_id,))
        current_user = cur.fetchone()
        profile_picture = current_user["profile_picture"] if current_user else None

        if new_password:
            if len(new_password) < 8:
                flash("Password must be at least 8 characters.", "danger")
                return redirect(url_for("users.user_manager"))
            if not old_password:
                flash("Current password is required to set a new password.", "danger")
                return redirect(url_for("users.user_manager"))
            if not current_user or not check_password_hash(current_user["password"], old_password):
                flash("Current password is incorrect. Password was not changed.", "danger")
                return redirect(url_for("users.user_manager"))

        if "profile_picture" in request.files:
            file = request.files["profile_picture"]
            if file and file.filename and allowed_file(file.filename):
                if profile_picture:
                    old_path = resolve_profile_picture_path(profile_picture)
                    if os.path.exists(old_path):
                        try:
                            os.remove(old_path)
                        except OSError:
                            pass

                filename = secure_filename(f"{username}_{file.filename}")
                filepath = os.path.join(get_upload_dir(), filename)
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

        if new_password:
            cur.execute(
                "UPDATE users SET password=? WHERE id=?",
                (generate_password_hash(new_password), user_id),
            )

    if session.get("user_id") == user_id:
        session["username"] = username
        if profile_picture:
            session["user_avatar"] = profile_picture_url(profile_picture)
        else:
            session.pop("user_avatar", None)

    if new_password:
        flash("User profile and password updated successfully.", "success")
    else:
        flash("User profile updated successfully.", "success")

    return redirect(url_for("users.user_manager"))
