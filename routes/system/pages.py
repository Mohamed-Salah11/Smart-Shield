from routes.system import system_bp
from routes.system._common import *  # noqa: F401,F403
from routes.system._common import _general_config_path, _config_bool, _load_general_config, _safe_count, _build_dashboard_payload, render_placeholder  # noqa: F401


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
# HELP PAGES
# ----------------------------
# Fv11 review §P1-01: every /system/* route must require an authenticated
# admin session. These are appliance help/about/upgrade pages that previously
# rendered without `@login_required`, which leaked the product version and UI
# structure to anonymous LAN clients. Public-facing landing pages live under
# /portal/* and /static/, not /system/*.

@system_bp.route("/docs")
@login_required
def docs():
    return render_placeholder("docs.html")

@system_bp.route("/about")
@login_required
def about():
    return render_placeholder("about.html")

@system_bp.route("/bug")
@login_required
def bug():
    return render_placeholder("bug.html")

@system_bp.route("/forum")
@login_required
def forum():
    return render_placeholder("forum.html")

@system_bp.route("/freebsd")
@login_required
def freebsd():
    return render_placeholder("freebsd.html")

@system_bp.route("/smart-shield-book")
@login_required
def smart_shield_book():
    return render_template("smart_shield_book.html")

@system_bp.route("/paid-support")
@login_required
def paid_support():
    return render_template("paid_support.html")

@system_bp.route("/survey")
@login_required
def survey():
    return render_placeholder("survey.html")

@system_bp.route("/upgrade")
@login_required
def upgrade():
    return render_placeholder("upgrade.html")

@system_bp.route("/help")
@login_required
def help_page():
    return render_placeholder("help.html")


# ----------------------------
# GENERAL SETUP
# ----------------------------
