"""
gateway_monitor.py
------------------
Background daemon that pings all configured gateways every 30s and records
reachability in the DB. Updates the gateway's 'status' column and logs
state changes to the audit log.

Public API:
  start_gateway_monitor()  -- start background daemon thread (idempotent)
  get_gateway_health()     -- return current reachability dict {gw_id: bool}
"""

import logging
import sys
import threading
import time

_log = logging.getLogger(__name__)

# Module-level health dict: {gateway_id: bool}
_GATEWAY_HEALTH: dict = {}
_MONITOR_STARTED = False
_MONITOR_LOCK = threading.Lock()

_POLL_INTERVAL = 30  # seconds


def get_gateway_health() -> dict:
    """Return the current reachability dict {gw_id: bool}."""
    return dict(_GATEWAY_HEALTH)


import shutil as _shutil
_PING_BIN = _shutil.which("ping") or "/sbin/ping"


def _ping_gateway(ip: str) -> bool:
    """Ping a gateway IP. Returns True if reachable."""
    try:
        from app.services.network_service import run_command
        result = run_command(
            [_PING_BIN, "-c", "2", "-W", "1", "-q", ip],
            check=False,
            timeout_seconds=5,
        )
        return result.returncode == 0
    except Exception as exc:
        _log.debug("gateway_monitor: ping %s failed: %s", ip, exc)
        return False


def _monitor_loop():
    """Main daemon loop — runs every 30s."""
    global _GATEWAY_HEALTH

    while True:
        try:
            _run_check()
        except Exception as exc:
            _log.warning("gateway_monitor: unhandled error in loop: %s", exc)
        time.sleep(_POLL_INTERVAL)


def _run_check():
    """Query gateways, ping each, update DB, log state changes."""
    global _GATEWAY_HEALTH

    try:
        from app.database import get_db
        from app.audit_log import log_event
    except Exception as exc:
        _log.warning("gateway_monitor: import error: %s", exc)
        return

    try:
        conn = get_db()
    except Exception as exc:
        _log.warning("gateway_monitor: cannot get DB connection: %s", exc)
        return

    try:
        rows = conn.execute(
            "SELECT id, name, gateway AS ip_address FROM gateways "
            "WHERE disabled IS NULL OR disabled=0"
        ).fetchall()
    except Exception as exc:
        _log.warning("gateway_monitor: cannot query gateways: %s", exc)
        return

    new_health: dict = {}

    for row in rows:
        gw_id = row["id"]
        gw_name = row["name"]
        ip = (row["ip_address"] or "").strip()

        if not ip:
            continue

        reachable = _ping_gateway(ip)
        new_health[gw_id] = reachable

        # Detect state change
        prev = _GATEWAY_HEALTH.get(gw_id)
        state_changed = (prev is not None) and (prev != reachable)

        # Update DB
        try:
            conn.execute(
                "UPDATE gateways SET last_seen=CURRENT_TIMESTAMP, reachable=? WHERE id=?",
                (1 if reachable else 0, gw_id),
            )
            conn.commit()
        except Exception:
            # 'reachable' or 'last_seen' column may not exist yet — skip gracefully
            try:
                conn.rollback()
            except Exception:
                pass

        # Log state changes
        if state_changed:
            try:
                log_event(
                    category="network",
                    action="gateway_state_change",
                    details={
                        "gateway_id": gw_id,
                        "gateway_name": gw_name,
                        "ip": ip,
                        "was_reachable": prev,
                        "now_reachable": reachable,
                    },
                )
            except Exception as exc:
                _log.warning(
                    "gateway_monitor: log_event failed for %s: %s", gw_name, exc
                )

    _GATEWAY_HEALTH = new_health


def start_gateway_monitor():
    """Start the background gateway monitor daemon thread (idempotent)."""
    global _MONITOR_STARTED

    if not sys.platform.startswith("freebsd"):
        _log.debug("gateway_monitor: non-FreeBSD — skipping daemon startup")
        return

    with _MONITOR_LOCK:
        if _MONITOR_STARTED:
            return
        _MONITOR_STARTED = True

    t = threading.Thread(target=_monitor_loop, name="gateway-monitor", daemon=True)
    t.start()
    _log.info("gateway_monitor: daemon started (poll interval=%ds)", _POLL_INTERVAL)
