from datetime import datetime, timezone
from functools import wraps
from flask import session, redirect, url_for, request, render_template, jsonify, flash
from app.db_utils import db_cursor


ALWAYS_ALLOWED_ENDPOINTS = {"system.dashboard", "system.logout"}


def _is_api_path(path):
    p = (path or "").lower()
    return p.startswith("/api/") or "/api/" in p


def _load_user_profile(user_id):
    with db_cursor() as (_, cur):
        cur.execute(
            "SELECT id, username, COALESCE(is_superuser, 0) AS is_superuser FROM users WHERE id = ?",
            (user_id,),
        )
        user = cur.fetchone()
        if not user:
            return None

        cur.execute(
            """
            SELECT DISTINCT gp.endpoint
            FROM group_page_permissions gp
            INNER JOIN user_groups ug ON ug.group_id = gp.group_id
            WHERE ug.user_id = ?
            """,
            (user_id,),
        )
        permissions = {row["endpoint"] for row in cur.fetchall()}

    return {
        "id": user["id"],
        "username": user["username"],
        "is_superuser": bool(user["is_superuser"]),
        "permissions": permissions,
    }


def _has_page_access(profile, endpoint):
    if not endpoint:
        return True
    if profile["is_superuser"]:
        return True
    if endpoint in ALWAYS_ALLOWED_ENDPOINTS:
        return True
    if endpoint in profile["permissions"]:
        return True

    # Optional wildcard support (e.g. "firewall.*")
    for rule in profile["permissions"]:
        if rule.endswith(".*"):
            prefix = rule[:-2]
            if endpoint.startswith(prefix + "."):
                return True

    return False


def login_required(view_func):
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        user_id = session.get("user_id")
        if not user_id:
            if _is_api_path(request.path):
                from flask import jsonify
                return jsonify({"ok": False, "message": "Session expired. Please refresh and log in."}), 401
            return redirect(url_for("auth.login"))

        profile = _load_user_profile(user_id)
        if not profile:
            session.clear()
            return redirect(url_for("auth.login"))

        session["username"] = profile["username"]
        session["is_superuser"] = profile["is_superuser"]

        # Enforce whitelist on non-API pages.
        if not _is_api_path(request.path):
            if not _has_page_access(profile, request.endpoint):
                return render_template("not_authorized.html"), 403

        return view_func(*args, **kwargs)

    return wrapped_view


def superuser_required(view_func):
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("auth.login"))

        profile = _load_user_profile(user_id)
        if not profile:
            session.clear()
            return redirect(url_for("auth.login"))

        session["username"] = profile["username"]
        session["is_superuser"] = profile["is_superuser"]

        if not profile["is_superuser"]:
            return render_template("not_authorized.html"), 403

        return view_func(*args, **kwargs)

    return wrapped_view


def reauth_is_fresh(max_age_seconds: int = 300) -> bool:
    """True when ``session["reauth_time"]`` is set and within ``max_age_seconds``."""
    reauth_time_str = session.get("reauth_time")
    if not reauth_time_str:
        return False
    try:
        reauth_dt = datetime.fromisoformat(reauth_time_str)
        if reauth_dt.tzinfo is None:
            reauth_dt = reauth_dt.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - reauth_dt).total_seconds()
        return age <= max_age_seconds
    except (ValueError, TypeError):
        return False


def reauth_required(reason=""):
    """
    Decorator that requires a recent reauthentication (within 5 minutes).

    Checks ``session["reauth_time"]``; if missing or stale, returns:
      JSON {"ok": False, "reauth_required": True, "message": "..."} with 403.

    Usage::

        @reauth_required(reason="factory reset")
        def my_view():
            ...
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapped_view(*args, **kwargs):
            if not reauth_is_fresh():
                return jsonify({
                    "ok": False,
                    "reauth_required": True,
                    "message": "Please re-authenticate to perform this action.",
                }), 403
            return view_func(*args, **kwargs)
        return wrapped_view
    return decorator


def reauth_required_form(redirect_endpoint, **redirect_kwargs):
    """Form-friendly variant of :func:`reauth_required`.

    For browser form POSTs that redirect (rather than consuming JSON). On a
    missing/stale reauth it flashes a message and redirects to
    ``redirect_endpoint`` instead of returning a raw JSON 403.

    Usage::

        @reauth_required_form("diagnostics.backup_restore", tab="backup")
        def my_view():
            ...
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapped_view(*args, **kwargs):
            if not reauth_is_fresh():
                flash("Please re-authenticate (re-enter your password) to perform this action.", "warning")
                return redirect(url_for(redirect_endpoint, **redirect_kwargs))
            return view_func(*args, **kwargs)
        return wrapped_view
    return decorator
