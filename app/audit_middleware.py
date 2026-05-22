"""Session lifecycle, request timing, captive-session maintenance, template
context, and per-request audit logging.

Extracted from the app factory. ``register_audit_middleware`` registers the
before/after request hooks and the template context processor that the admin
UI relies on.
"""

import logging
import time

from flask import g, redirect, request, session, url_for

from app.audit_log import log_event
from app.uploads import profile_picture_url
from app.security import get_csrf_token


logger = logging.getLogger(__name__)


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


def register_audit_middleware(app):
    @app.before_request
    def _enforce_session_timeout():
        """Expire idle sessions after PERMANENT_SESSION_LIFETIME seconds."""
        if not session.get("user_id"):
            return
        idle_limit = app.config.get("PERMANENT_SESSION_LIFETIME", 3600)
        if isinstance(idle_limit, int):
            pass
        else:
            try:
                idle_limit = int(idle_limit.total_seconds())
            except Exception:
                idle_limit = 3600
        last_active = session.get("_last_active", 0)
        now = time.time()
        if last_active and (now - last_active) > idle_limit:
            session.clear()
            if request.path.startswith("/api/") or "/api/" in request.path:
                from flask import jsonify as _jsonify
                return _jsonify({"ok": False, "message": "Session expired due to inactivity."}), 401
            return redirect(url_for("auth.login"))
        session["_last_active"] = now
        session.permanent = True

    @app.before_request
    def _request_timing_start():
        g.request_start_time = time.perf_counter()

    @app.before_request
    def _periodic_expire_sessions():
        _periodic_expire_sessions._last_ts = getattr(_periodic_expire_sessions, "_last_ts", 0.0)
        _periodic_expire_sessions._reconcile_ts = getattr(_periodic_expire_sessions, "_reconcile_ts", 0.0)
        now = time.time()
        if now - _periodic_expire_sessions._last_ts < 60:
            return
        _periodic_expire_sessions._last_ts = now
        try:
            from app.services.captive_portal import expire_sessions
            from app.database import get_db
            expire_sessions(get_db())
        except Exception:
            # Best-effort housekeeping. A captive-portal expiry failure must
            # not break a regular request — but a silent pass hides genuine
            # DB / PF drift, so log the traceback (Fv11 review §P1-07).
            logger.warning("captive expire_sessions failed", exc_info=True)
        # Reconcile PF tables every 5 minutes so they cannot silently drift
        # from the DB after a crash, reload, or manual pfctl edit.
        if now - _periodic_expire_sessions._reconcile_ts >= 300:
            _periodic_expire_sessions._reconcile_ts = now
            try:
                from app.services.captive_portal import reconcile_captive_pf_tables
                from app.database import get_db
                reconcile_captive_pf_tables(get_db())
            except Exception:
                logger.warning(
                    "captive PF reconcile failed — table state may drift from DB",
                    exc_info=True,
                )

    @app.context_processor
    def _csrf_context():
        from app.services.runtime_mode import mode_badge
        from app.soc_portal_auth import soc_portal_enabled
        from routes.terminal import terminal_is_enabled

        return {
            "csrf_token": get_csrf_token,
            "profile_picture_url": profile_picture_url,
            "runtime_mode_badge": mode_badge(),
            "soc_portal_enabled": soc_portal_enabled,
            "terminal_enabled": terminal_is_enabled,
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

            # Admin page navigation is intentionally NOT logged — it is high
            # volume with no security value. Config changes are captured by the
            # api_change event below, which is the real audit trail.
            if is_api_request and request.method in {"POST", "PUT", "PATCH", "DELETE"}:
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
