from routes.system import system_bp
from routes.system._common import *  # noqa: F401,F403
from routes.system._common import _general_config_path, _config_bool, _load_general_config, _safe_count, _build_dashboard_payload  # noqa: F401


@system_bp.route("/")
@login_required
def system_home():
    return redirect(url_for("system.general_setup"))


@system_bp.route("/theme-editor")
@login_required
def theme_editor():
    return render_template("theme_editor.html", title="Theme Editor")

@system_bp.route("/dashboard")
@login_required
def dashboard():
    payload = _build_dashboard_payload()
    return render_template(
        "dashboard.html",
        dashboard_columns=payload["dashboard_columns"],
        dashboard_payload=payload,
    )


@system_bp.route("/dashboard/data", methods=["GET"])
@login_required
def dashboard_data():
    return jsonify({"status": "success", "data": _build_dashboard_payload()})


@system_bp.route("/dashboard/stream")
@login_required
def dashboard_stream():
    """Server-Sent Events endpoint — pushes a health snapshot every 10 s."""
    import time as _time

    def _event_stream():
        while True:
            try:
                payload = _build_dashboard_payload(include_health=True)
                data = json.dumps({"status": "success", "data": payload})
                yield f"data: {data}\n\n"
            except Exception as exc:
                yield f"data: {json.dumps({'status': 'error', 'message': str(exc)})}\n\n"
            _time.sleep(10)

    from flask import Response
    return Response(
        _event_stream(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )

@system_bp.route("/logout", methods=["POST"])
def logout():
    # CSRF on this POST is enforced by the global _csrf_guard before_request
    # hook in app/__init__.py.
    log_event(
        category="session",
        action="logout",
        username=session.get("username", "anonymous"),
        remote_addr=request.remote_addr,
        details={"user_id": session.get("user_id")},
    )
    session.clear()
    return redirect(url_for("auth.login"))


# ----------------------------
# GENERAL SETUP
# ----------------------------
