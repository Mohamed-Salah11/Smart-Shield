"""CSRF before_request guard registration.

Extracted from the app factory. The exempt-endpoint constants and
``is_machine_authenticated_request`` remain defined in ``app/__init__.py``
(``tools/security_lint_routes.py`` parses them from that file by name), so we
import them here at call time to avoid an import cycle.
"""

from flask import request


def register_csrf(app):
    from app import (
        CSRF_EXEMPT_ENDPOINT_PREFIXES,
        CSRF_EXEMPT_ENDPOINTS,
        is_machine_authenticated_request,
    )
    from app.security import validate_csrf_or_abort

    @app.before_request
    def _csrf_guard():
        endpoint = request.endpoint or ""
        if endpoint.startswith(CSRF_EXEMPT_ENDPOINT_PREFIXES):
            return
        if endpoint in CSRF_EXEMPT_ENDPOINTS:
            return
        # Machine-token endpoints (decorated with @machine_api_required) carry
        # no browser CSRF token; their own require_api_scope wrapper enforces
        # token auth. Detect them statically from the registered view function
        # so the decision doesn't depend on a g-flag the route only sets later.
        view_func = app.view_functions.get(endpoint)
        if view_func is not None and getattr(view_func, "_is_machine_api", False):
            return
        if is_machine_authenticated_request():
            return
        validate_csrf_or_abort()
