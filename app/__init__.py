import json
import os

# Load environment variables before config.py class bodies evaluate their
# os.getenv() calls. Two sources, first wins (override=False on the second):
#   1. SMARTSHIELD_ENV_FILE (defaults to the FreeBSD appliance env file).
#      This is the production source of truth installed by bsd/install.sh.
#   2. The repo-root .env, for development checkouts and tests.
from dotenv import load_dotenv

_DEFAULT_APPLIANCE_ENV_FILE = "/usr/local/etc/smartshield/smartshield.env"
_appliance_env_file = os.getenv("SMARTSHIELD_ENV_FILE", _DEFAULT_APPLIANCE_ENV_FILE)
if _appliance_env_file and os.path.exists(_appliance_env_file):
    load_dotenv(_appliance_env_file, override=False)
load_dotenv(override=False)

from flask import Flask, g
from .database import init_db
from .config import get_config


def _load_version_info() -> dict:
    """Load version.json from repo root if present. Falls back to a minimal
    stub so callers can rely on the keys being defined."""
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(here, "version.json")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {"name": "Smart Shield", "version": "unknown", "build": "unknown"}


VERSION_INFO = _load_version_info()
__version__ = VERSION_INFO.get("version", "unknown")


# Blueprint prefixes whose endpoints are wholly machine-auth (API tokens or
# pre-auth captive-portal HTTP) and therefore cannot carry a session-bound
# CSRF token. `network_api.` used to live here but it serves browser-session
# admin endpoints (host whitelist, policy-exempt, etc.) — those now require
# CSRF like any other admin mutation.
#
# NOTE: tools/security_lint_routes.py parses these two constants out of THIS
# file by name. Keep them defined here as plain literals.
CSRF_EXEMPT_ENDPOINT_PREFIXES = (
    "hec.",
    "portal.",
)

# Named machine-auth endpoints that don't sit under a wholly-machine blueprint.
# These authenticate via HMAC / Bearer token at the handler level and can't
# present a browser CSRF token. Each entry MUST validate its own auth.
CSRF_EXEMPT_ENDPOINTS = frozenset({
    "vpn.openvpn_hook",
})


def is_machine_authenticated_request() -> bool:
    """True when the current request has authenticated via a non-browser
    mechanism (API token or HMAC). The CSRF guard uses this to skip the
    session-bound CSRF check for machine callers; route handlers remain
    responsible for the actual auth check.

    Note: Flask's CSRF before_request runs before per-route auth decorators,
    so this only returns True when an earlier hook has explicitly stamped
    ``g.api_token_authenticated`` or ``g.hmac_authenticated``. Endpoints
    relying on this should set the flag in a request hook registered ahead
    of ``_csrf_guard`` (or be marked ``_is_machine_api`` so the guard can
    recognise them statically).
    """
    if getattr(g, "api_token_authenticated", False):
        return True
    if getattr(g, "hmac_authenticated", False):
        return True
    return False


def create_app():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    app = Flask(
        __name__,
        template_folder=os.path.join(base_dir, "templates"),
        static_folder=os.path.join(base_dir, "static"),
    )

    app.config.from_object(get_config())

    # Trust one proxy hop (nginx) so request.remote_addr reflects the real
    # client IP instead of 127.0.0.1, keeping captive-portal checks and
    # audit logs correct.
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    if not app.config.get("SECRET_KEY"):
        raise RuntimeError(
            "SECRET_KEY is not set. Create a .env file (see .env.example) and set SECRET_KEY."
        )

    # ── Request/response middleware ──────────────────────────────────────────
    # Registration order below defines before_request execution order, and is
    # kept identical to the original monolithic factory:
    #   1. CSP nonce            (security_headers)
    #   2. CSRF guard           (csrf)
    #   3. content/captive      (captive_middleware)
    #   4. session timeout      (audit_middleware)
    #   5. request timing       (audit_middleware)
    #   6. periodic expiry      (audit_middleware)
    # after_request: audit runs before the security-header writer (reverse
    # registration order), matching the original.
    from .security_headers import register_security_headers
    from .csrf import register_csrf
    from .captive_middleware import register_captive_middleware
    from .audit_middleware import register_audit_middleware

    register_security_headers(app)
    register_csrf(app)
    register_captive_middleware(app)
    register_audit_middleware(app)

    # ── Database + filesystem ────────────────────────────────────────────────
    from .database import close_db
    app.teardown_appcontext(close_db)

    from .services.freebsd_setup import ensure_dirs
    ensure_dirs()

    init_db()

    # ── Live-mode safety gate ────────────────────────────────────────────────
    # Refuse to boot when /usr/local/etc/smartshield/smartshield.env is world-
    # readable in 'live' mode — the file holds SECRET_KEY and
    # SMARTSHIELD_MASTER_KEY. Dev / dry-run / degraded keep booting (the
    # warning still surfaces via startup_warnings()).
    from .services.runtime_mode import assert_env_file_safe
    assert_env_file_safe()

    # ── Background workers (leader-elected) ──────────────────────────────────
    from .background import start_background_workers
    start_background_workers(app)

    # ── Routes + WebSocket ───────────────────────────────────────────────────
    from .blueprints import register_blueprints
    register_blueprints(app)

    from .websocket import register_websocket
    register_websocket(app)

    return app
