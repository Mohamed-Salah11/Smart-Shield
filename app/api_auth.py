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

from flask import g, jsonify, session

from app.auth_utils import _load_user_profile, login_required


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
# Browser vs machine API decorators (Phase 11 boundary tightening)
#
# Existing mutating routes can keep stacking ``@login_required`` +
# ``@api_permission_required(...)``. New routes should pick one of these two
# wrappers so the auth model — browser session or machine token/HMAC — is
# legible at the call site and so the route security lint
# (``tools/security_lint_routes.py``) can verify it.
# ---------------------------------------------------------------------------

def browser_api_required(permission: str):
    """
    Browser-session JSON API: ``@login_required`` + ``@api_permission_required``.

    Stamps ``g.requires_csrf = True`` so any downstream introspection can
    confirm browser-CSRF expectation. The CSRF guard runs in ``before_request``
    and already enforces tokens for browser sessions — this flag is for
    auditing/lint, not runtime gating.
    """
    def decorator(view_func):
        @wraps(view_func)
        @login_required
        @api_permission_required(permission)
        def wrapper(*args, **kwargs):
            g.requires_csrf = True
            return view_func(*args, **kwargs)
        return wrapper
    return decorator


def machine_api_required(scope: str):
    """
    Machine-to-machine JSON API: requires a valid API token carrying ``scope``.

    Delegates to ``require_api_scope`` in :mod:`app.api_tokens` so token
    validation stays single-sourced. On success the wrapped handler runs with
    ``g.api_token_authenticated = True`` and ``g.requires_csrf = False`` — the
    CSRF guard treats this as a machine call and skips the session check.
    """
    def decorator(view_func):
        from app.api_tokens import require_api_scope

        @wraps(view_func)
        def inner(*args, **kwargs):
            g.api_token_authenticated = True
            g.requires_csrf = False
            return view_func(*args, **kwargs)

        guarded = require_api_scope(scope)(inner)
        # Mark the registered view function so the CSRF before_request guard can
        # recognise this as a machine-token endpoint *statically* — before the
        # route body (which sets g.api_token_authenticated) ever runs. Without
        # this, the CSRF guard would run first, see no token flag, and reject
        # the tokenized machine call for lacking a browser CSRF token.
        guarded._is_machine_api = True
        return guarded
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
    # SOC Portal — two distinct boundaries (Phase 6.2):
    #   api.soc.control = SmartShield Core admin manages the SOC Portal SERVICE
    #                     (enable/disable, port, TLS, restart, tier assignment).
    #   api.soc.manage  = SOC analyst WORK inside the SOC Portal
    #                     (cases, alerts, investigations, recommendations).
    ("api.soc.control", "SOC Portal", "/system/soc-portal-*", "Manage the SOC Portal service, access and runtime settings"),
    ("api.soc.manage",  "SOC Portal", "/soc-portal/api/*",    "SOC analyst case / alert / recommendation work inside the portal"),
    # Logging — read/export for the dedicated firewall log + future DNS/IDS views
    ("api.logs.read",   "Logging",    "/firewall/logs/api/*", "Read firewall/DNS/IDS logs and stats"),
    ("api.logs.export", "Logging",    "/firewall/logs/api/export", "Export firewall log rows as CSV"),
]
