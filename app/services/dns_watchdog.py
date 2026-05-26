"""
app/services/dns_watchdog.py
----------------------------
Self-healing background loop for Unbound (LAN DNS).

LAN clients are pointed at the appliance's LAN IP for DNS (DHCP), and when
content filtering is active PF funnels all LAN :53 through Unbound. If Unbound
isn't actually serving the LAN — e.g. it only bound 127.0.0.1 (the install-time
bootstrap config), or the FreeBSD base ``local_unbound`` shadowed it — the whole
LAN loses name resolution even though ``service unbound status`` says "running"
(clients can ping IPs but can't browse). Nothing recovered this automatically.

This module polls once a minute and, when Unbound is not serving the LAN, runs
the shared recovery path in ``dns_writer`` (disable base local_unbound,
regenerate the LAN-binding config, start + verify, re-apply PF), then audits the
result. It keeps only the cool-down/cap policy + audit mapping; all the real
work lives in ``dns_writer.recover_dns_service`` so the watchdog can't drift from
the GUI apply behaviour.

Disable auto-recovery by setting the ``dns_resolver`` service_state JSON
``watchdog_enabled`` to ``false``.
"""

from __future__ import annotations

import json
import threading
import time


_STARTED        = threading.Event()
_TICK_SECS      = 60       # poll cadence
_LAST_TRY_KEY   = "dns_last_recovery_attempt"
_TRY_COUNT_KEY  = "dns_recovery_attempts_hour"
_MIN_BACKOFF    = 300      # at least 5 min between attempts
_MAX_PER_HOUR   = 6        # hard cap so a broken loop doesn't burn the host


def _now_epoch() -> int:
    return int(time.time())


def _read_state(conn, key: str, default: str = "") -> str:
    try:
        row = conn.execute("SELECT value FROM siem_state WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default
    except Exception:
        return default


def _write_state(conn, key: str, value: str) -> None:
    try:
        conn.execute(
            "INSERT INTO siem_state (key, value, updated_at) "
            "VALUES (?, ?, CURRENT_TIMESTAMP) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value, "
            "updated_at = CURRENT_TIMESTAMP",
            (key, value),
        )
        conn.commit()
    except Exception:
        pass


def _hour_counter(conn) -> dict:
    raw = _read_state(conn, _TRY_COUNT_KEY, "")
    try:
        data = json.loads(raw) if raw else {}
    except Exception:
        data = {}
    current_bucket = _now_epoch() // 3600
    if data.get("hour_bucket") != current_bucket:
        data = {"hour_bucket": current_bucket, "count": 0}
    return data


def _bump_hour_counter(conn) -> int:
    data = _hour_counter(conn)
    data["count"] = int(data.get("count") or 0) + 1
    _write_state(conn, _TRY_COUNT_KEY, json.dumps(data))
    return data["count"]


def _should_attempt(conn) -> "tuple[bool, str]":
    last_try = _read_state(conn, _LAST_TRY_KEY, "0")
    try:
        last_ts = int(last_try)
    except (TypeError, ValueError):
        last_ts = 0
    elapsed = _now_epoch() - last_ts
    if elapsed < _MIN_BACKOFF:
        return False, f"cooldown ({_MIN_BACKOFF - elapsed}s remaining)"
    hc = _hour_counter(conn)
    if int(hc.get("count") or 0) >= _MAX_PER_HOUR:
        return False, f"hourly cap reached ({_MAX_PER_HOUR})"
    return True, ""


def _watchdog_enabled(conn) -> bool:
    """Auto-recovery is on unless explicitly disabled in the dns_resolver state."""
    try:
        row = conn.execute(
            "SELECT value_json FROM service_state WHERE key_name='dns_resolver'"
        ).fetchone()
        if not row or not row["value_json"]:
            return True
        return bool(json.loads(row["value_json"]).get("watchdog_enabled", True))
    except Exception:
        return True


def attempt_recovery() -> dict:
    """
    One-shot recovery: skip when Unbound is already serving the LAN; otherwise
    delegate to ``dns_writer.recover_dns_service`` (the shared safe path the GUI
    also uses), honouring the cool-down/cap policy and auditing the outcome.

    Returns ``{"ok", "skipped"?, "reason"?, "message"}``. Safe to call from any
    thread — it opens its own short-lived connection.
    """
    from app.audit_log import _events_db, log_event
    from app.services.dns_writer import recover_dns_service, unbound_serving_lan

    conn = _events_db()
    if conn is None:
        return {"ok": False, "skipped": True, "reason": "events_db_unavailable",
                "message": "events DB unavailable"}
    try:
        if not _watchdog_enabled(conn):
            return {"ok": True, "skipped": True, "reason": "watchdog_disabled",
                    "message": "dns_resolver.watchdog_enabled = false"}
        if unbound_serving_lan(conn):
            return {"ok": True, "skipped": True, "reason": "already_serving",
                    "message": "Unbound is serving the LAN"}

        ok, reason = _should_attempt(conn)
        if not ok:
            return {"ok": True, "skipped": True, "reason": "rate_limited",
                    "message": reason}

        # Bump counters BEFORE the attempt so a crash doesn't leak an extra try.
        _write_state(conn, _LAST_TRY_KEY, str(_now_epoch()))
        attempts = _bump_hour_counter(conn)

        try:
            result = recover_dns_service(conn, actor="watchdog")
        except Exception as exc:
            log_event(
                category="network", action="dns_auto_recovery_failed",
                severity="high", username="watchdog", remote_addr="",
                details={"stage": "recover", "error": str(exc)[:512],
                         "attempts_this_hour": attempts},
            )
            return {"ok": False, "reason": "exception", "message": str(exc),
                    "attempts_this_hour": attempts}

        if result.get("ok"):
            log_event(
                category="network", action="dns_auto_recovered",
                severity="medium", username="watchdog", remote_addr="",
                details={
                    "attempts_this_hour": attempts,
                    "service_message": (result.get("service_message")
                                        or result.get("message") or "")[:512],
                },
            )
            return {"ok": True, "message": "Unbound recovered by watchdog",
                    "attempts_this_hour": attempts}

        log_event(
            category="network", action="dns_auto_recovery_failed",
            severity="high", username="watchdog", remote_addr="",
            details={
                "stage":           "recover",
                "reason":          result.get("reason", "did_not_serve"),
                "attempts_this_hour": attempts,
                "service_message": (result.get("service_message") or "")[:512],
            },
        )
        return {"ok": False,
                "reason": result.get("reason", "did_not_serve"),
                "message": result.get("message",
                                      "recovery returned but Unbound is not serving the LAN"),
                "attempts_this_hour": attempts}
    finally:
        try: conn.close()
        except Exception: pass


def _watchdog_loop():
    # Stagger initial run so it doesn't pile onto boot-time work (and lands just
    # after the IDS watchdog's 45s first tick).
    time.sleep(50)
    while True:
        try:
            attempt_recovery()
        except Exception as exc:
            from app.app_log import log_warning
            log_warning("dns_watchdog", "watchdog tick failed", {"error": str(exc)})
        time.sleep(_TICK_SECS)


def start_dns_watchdog():
    """Start the watchdog daemon thread (idempotent per process)."""
    if _STARTED.is_set():
        return
    _STARTED.set()
    threading.Thread(target=_watchdog_loop, name="dns-watchdog", daemon=True).start()
