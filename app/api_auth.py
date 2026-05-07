"""
app/api_auth.py
---------------
API-level permission decorator.

All mutating JSON API endpoints (POST/PUT/DELETE under /api/ paths) should
be decorated with ``@api_permission_required("api.<area>.<action>")``.

The permission string is stored in ``group_page_permissions.endpoint`` just
like page-level permissions, so existing group management UI covers both.

Superusers bypass all permission checks.
Non-superusers need the exact permission string (or a wildcard like
``api.firewall.*``) granted to at least one of their groups.
"""

from functools import wraps

from flask import jsonify, session

from app.auth_utils import _load_user_profile


def api_permission_required(permission: str):
    """
    Return a decorator that enforces *permission* on an API endpoint.

    * Unauthenticated requests → JSON 401.
    * Superusers → always allowed.
    * Others → JSON 403 if *permission* is not in their group grants.

    This decorator performs its own session + DB check and does **not** need
    to be stacked with ``@login_required`` (doing so is harmless but wastes a
    DB round-trip).

    Usage::

        @bp.route("/api/things", methods=["POST"])
        @api_permission_required("api.firewall.edit")
        def create_thing():
            ...
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            user_id = session.get("user_id")
            if not user_id:
                return jsonify({"error": "Authentication required"}), 401

            profile = _load_user_profile(user_id)
            if not profile:
                session.clear()
                return jsonify({"error": "Authentication required"}), 401

            # Superusers bypass all permission checks.
            if profile["is_superuser"]:
                # Keep session fresh so UI helpers work.
                session["username"] = profile["username"]
                session["is_superuser"] = True
                return view_func(*args, **kwargs)

            granted = profile["permissions"]

            # Direct match.
            if permission in granted:
                return view_func(*args, **kwargs)

            # Wildcard: group has "api.firewall.*" → grants "api.firewall.edit".
            if "." in permission:
                prefix = permission.rsplit(".", 1)[0]
                if f"{prefix}.*" in granted:
                    return view_func(*args, **kwargs)

            return jsonify({
                "error": "Forbidden",
                "detail": f"Permission required: {permission}",
                "permission": permission,
            }), 403

        return wrapped
    return decorator


# ---------------------------------------------------------------------------
# Catalog of API permission strings (used by the group manager UI)
# ---------------------------------------------------------------------------

API_PERMISSION_CATALOG = [
    # Firewall
    ("api.firewall.edit",   "Firewall",  "/firewall/api/*", "Create/edit/delete firewall rules, NAT, aliases, schedules, shaper"),
    # VPN
    ("api.vpn.edit",        "VPN",       "/vpn/api/*",      "Create/edit/delete VPN tunnels, clients, users, PSKs"),
    ("api.vpn.apply",       "VPN",       "/vpn/api/*/apply","Apply/reload VPN services (OpenVPN, IPsec, L2TP)"),
    # Network / Interfaces
    ("api.network.edit",    "Network",   "/api/network/*",  "Update interfaces, DHCP pools, static leases, PPPoE"),
    ("api.network.apply",   "Network",   "/api/network/apply", "Apply live interface / routing changes on FreeBSD"),
    # IDS / IPS
    ("api.system.edit", "System", "/services/api/*", "Run config backup, restore, and system service actions"),
    ("api.ids.edit",        "IDS/IPS",   "/ids/api/*",      "Toggle IDS, manage rulesets, trigger rule updates"),
]
