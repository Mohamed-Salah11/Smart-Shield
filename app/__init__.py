import os
import time

from flask import Flask, g, request, session
from .database import init_db
from dotenv import load_dotenv
from .security import get_csrf_token, validate_csrf_or_abort
from .audit_log import log_event
from .uploads import profile_picture_url

_SENSITIVE_KEY_MARKERS = {
    "password",
    "secret",
    "token",
    "key",
    "psk",
    "auth",
    "cookie",
}


def _humanize_endpoint(endpoint: str):
    if not endpoint:
        return ""
    return endpoint.replace(".", " / ").replace("_", " ").title()


def _is_sensitive_key(key: str):
    lowered = (key or "").strip().lower()
    return any(marker in lowered for marker in _SENSITIVE_KEY_MARKERS)


def _safe_payload_keys():
    data = request.get_json(silent=True)
    if isinstance(data, dict):
        keys = []
        for key in sorted(data.keys()):
            if _is_sensitive_key(str(key)):
                continue
            keys.append(str(key))
            if len(keys) >= 12:
                break
        return keys
    if isinstance(data, list):
        return [f"<list:{len(data)}>"]
    return []


def _activity_summary(is_api_request: bool, method: str, path: str, endpoint: str):
    endpoint_label = _humanize_endpoint(endpoint)
    if is_api_request:
        if endpoint_label:
            return f"{method} API call: {endpoint_label}"
        return f"{method} API call: {path}"

    if endpoint_label:
        return f"Viewed page: {endpoint_label}"
    return f"Viewed page: {path}"


def create_app():
    load_dotenv()
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    app = Flask(
        __name__,
        template_folder=os.path.join(base_dir, "templates"),
        static_folder=os.path.join(base_dir, "static"),
    )

    app.secret_key = os.getenv("SECRET_KEY")
    if not app.secret_key:
        raise RuntimeError(
            "SECRET_KEY is not set. Create a .env file (for example: copy .env.example .env) and set SECRET_KEY."
        )

    @app.before_request
    def _csrf_guard():
        validate_csrf_or_abort()

    @app.before_request
    def _request_timing_start():
        g.request_start_time = time.perf_counter()

    @app.context_processor
    def _csrf_context():
        return {
            "csrf_token": get_csrf_token,
            "profile_picture_url": profile_picture_url,
        }

    @app.after_request
    def _audit_browsing_events(response):
        try:
            if request.path.startswith("/static/") or request.endpoint == "static":
                return response

            user_id = session.get("user_id")
            if not user_id:
                return response

            # Avoid duplicate noise for endpoints that already emit explicit session events.
            if request.endpoint in {"auth.login", "auth.logout", "system.logout"}:
                return response

            elapsed_ms = 0
            started = getattr(g, "request_start_time", None)
            if started is not None:
                elapsed_ms = int((time.perf_counter() - started) * 1000)

            details = {
                "method": request.method,
                "path": request.path,
                "endpoint": request.endpoint or "",
                "status_code": response.status_code,
                "latency_ms": elapsed_ms,
                "user_agent": request.user_agent.string[:200] if request.user_agent else "",
                "query_string": request.query_string.decode("utf-8", "ignore")[:200],
                "referrer": (request.referrer or "")[:200],
                "view_args": request.view_args or {},
            }

            is_api_request = request.path.startswith("/api/") or "/api/" in request.path
            details["activity"] = _activity_summary(
                is_api_request=is_api_request,
                method=request.method,
                path=request.path,
                endpoint=request.endpoint or "",
            )

            if request.method == "GET" and not is_api_request:
                log_event(
                    category="browsing",
                    action="page_view",
                    username=session.get("username", "anonymous"),
                    remote_addr=request.remote_addr,
                    details=details,
                )
            elif is_api_request and request.method in {"POST", "PUT", "PATCH", "DELETE"}:
                details["payload_keys"] = _safe_payload_keys()
                log_event(
                    category="system",
                    action="api_change",
                    username=session.get("username", "anonymous"),
                    remote_addr=request.remote_addr,
                    details=details,
                )
        except Exception:
            # Audit logging must never break request flow.
            pass

        return response

    # Ensure all required directories exist before the DB is opened.
    from .services.freebsd_setup import ensure_dirs
    ensure_dirs()

    init_db()

    from routes.auth import auth_bp
    from routes.users import users_bp
    from routes.system import system_bp
    from routes.interfaces import interfaces_bp
    from routes.routing import routing_bp
    from routes.services import services_bp
    from routes.firewall import firewall_bp
    from routes.vpn import vpn_bp
    from routes.status import status_bp
    from routes.diagnostics import diagnostics_bp
    from routes.network_api import network_api_bp
    from routes.ids import ids_bp
    from routes.filters import filters_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(system_bp)
    app.register_blueprint(interfaces_bp)
    app.register_blueprint(routing_bp)
    app.register_blueprint(services_bp)
    app.register_blueprint(firewall_bp)
    app.register_blueprint(vpn_bp)
    app.register_blueprint(status_bp)
    app.register_blueprint(diagnostics_bp)
    app.register_blueprint(network_api_bp)
    app.register_blueprint(ids_bp)
    app.register_blueprint(filters_bp)

    return app
