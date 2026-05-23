"""Background worker startup.

Extracted from the app factory. A single leader worker (elected via an
exclusive flock) starts the daemon threads; the rest skip startup so multiple
Gunicorn workers don't each spawn collectors.

Fv11 review §P1-07: every worker is started inside `_try_start`, which logs
the traceback at WARNING and tags the worker name on failure. The previous
implementation silently `pass`-swallowed the exception, which made debugging
"why isn't the IDS collector running?" impossible. Imports remain lazy
inside each thunk so a missing optional dep (e.g. idstools on a dev box)
keeps the rest of the workers booting.
"""

import logging

logger = logging.getLogger(__name__)


def _try_start(worker_name: str, thunk) -> None:
    """Run a background-worker starter thunk and convert any failure into a
    logged warning. The appliance keeps booting either way. The thunk is
    responsible for its own lazy import so we don't fail-fast on optional
    deps."""
    try:
        thunk()
    except Exception as exc:
        logger.warning(
            "background worker failed to start: worker=%s (%s: %s)",
            worker_name, type(exc).__name__, exc,
            exc_info=True,
        )


def start_background_workers(app):
    # Emit startup warnings for missing optional keys (chatbot, threat intel,
    # master key) regardless of leadership.
    def _startup_warnings():
        from app.services.runtime_mode import startup_warnings
        startup_warnings()
    _try_start("startup_warnings", _startup_warnings)

    # Elect a single leader worker before starting background daemon threads.
    from app.services.worker_lock import acquire_worker_lock
    if not acquire_worker_lock():
        return

    # SIEM background collectors (FreeBSD only; silent no-op on dev)
    def _siem():
        from app.services.siem_collector import start_siem_collectors
        start_siem_collectors()
    _try_start("siem_collector", _siem)

    # Threat-intel feed collector (requires ABUSECH_AUTH_KEY; else silent no-op)
    def _threat_intel():
        from app.services.abusech_client import start_threat_intel_collector
        start_threat_intel_collector()
    _try_start("threat_intel", _threat_intel)

    # Mail-alert sender thread (drains the queue fed by log_event; silent
    # no-op until an admin enables it on the Mail Alerts page).
    def _mail():
        from app.services.mail_alerts import start_mail_alert_worker
        start_mail_alert_worker()
    _try_start("mail_alerts", _mail)

    # Gateway health monitor (pings gateways every 30s; FreeBSD only)
    def _gateway():
        from app.services.gateway_monitor import start_gateway_monitor
        start_gateway_monitor()
    _try_start("gateway_monitor", _gateway)

    # Schedule enforcer (reloads PF when schedule windows open/close; FreeBSD only)
    def _schedule():
        from app.services.schedule_enforcer import start_schedule_enforcer
        start_schedule_enforcer(app)
    _try_start("schedule_enforcer", _schedule)

    # SIEM log forwarder (sends events to an upstream syslog/CEF collector;
    # silent no-op until enabled in Log Forwarding settings)
    def _log_forwarder():
        from app.services.log_forwarder import start_log_forwarder
        start_log_forwarder()
    _try_start("log_forwarder", _log_forwarder)
