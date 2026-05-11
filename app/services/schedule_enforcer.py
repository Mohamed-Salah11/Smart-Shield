"""
schedule_enforcer.py
--------------------
Background daemon that re-applies PF rules when firewall schedule windows
open or close. Checks schedule state every 60 seconds; only reloads PF
when active/inactive status changes from the previous check.

Public API:
  start_schedule_enforcer(app)  -- start background daemon thread (idempotent)
"""

import logging
import sys
import threading
import time

_log = logging.getLogger(__name__)

_ENFORCER_STARTED = False
_ENFORCER_LOCK = threading.Lock()

_POLL_INTERVAL = 60  # seconds


def _enforcer_loop(app):
    """Main daemon loop — runs every 60s."""
    prev_states: dict = {}

    while True:
        try:
            _run_check(app, prev_states)
        except Exception as exc:
            _log.warning("schedule_enforcer: unhandled error in loop: %s", exc)
        time.sleep(_POLL_INTERVAL)


def _run_check(app, prev_states: dict):
    """Compare schedule states; reload PF if any changed."""
    try:
        with app.app_context():
            from app.database import get_db
            from app.services.schedule_service import get_all_schedule_states
            from app.services.pf_generator import reload_pf_rules
            from app.audit_log import log_event

            conn = get_db()
            current_states = get_all_schedule_states(conn)

            # Detect any change
            changed = False
            for name, active in current_states.items():
                if name not in prev_states or prev_states[name] != active:
                    changed = True
                    break
            # Also detect schedules that were removed
            if not changed:
                for name in prev_states:
                    if name not in current_states:
                        changed = True
                        break

            if changed and prev_states:
                # prev_states is empty on first iteration — don't reload on startup
                _log.info(
                    "schedule_enforcer: schedule state changed, reloading PF rules"
                )
                try:
                    result = reload_pf_rules(conn)
                    log_event(
                        category="firewall",
                        action="schedule_enforcement_reload",
                        details={
                            "ok": result.get("ok"),
                            "message": result.get("message", ""),
                            "changed_schedules": [
                                name
                                for name, active in current_states.items()
                                if prev_states.get(name) != active
                            ],
                        },
                    )
                except Exception as exc:
                    _log.warning(
                        "schedule_enforcer: PF reload failed: %s", exc
                    )

            # Update prev_states in-place so the dict reference in the loop persists
            prev_states.clear()
            prev_states.update(current_states)

    except Exception as exc:
        _log.warning("schedule_enforcer: _run_check error: %s", exc)


def start_schedule_enforcer(app):
    """Start the background schedule enforcer daemon thread (idempotent).

    Parameters
    ----------
    app : Flask application instance — needed to push an app context inside the thread.
    """
    global _ENFORCER_STARTED

    if not sys.platform.startswith("freebsd"):
        _log.debug("schedule_enforcer: non-FreeBSD — skipping daemon startup")
        return

    with _ENFORCER_LOCK:
        if _ENFORCER_STARTED:
            return
        _ENFORCER_STARTED = True

    t = threading.Thread(
        target=_enforcer_loop,
        args=(app,),
        name="schedule-enforcer",
        daemon=True,
    )
    t.start()
    _log.info(
        "schedule_enforcer: daemon started (poll interval=%ds)", _POLL_INTERVAL
    )
