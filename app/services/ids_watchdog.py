"""
app/services/ids_watchdog.py
----------------------------
Self-healing background loop for Suricata.

When the appliance shows
    "marked as enabled in config but is not currently running"
nothing in the codebase currently does anything about it — the operator
has to ssh in or click Enable again. This module fixes that: it polls
once a minute and, if Suricata is gone while the admin still wants it on,
re-validates the config and starts the daemon, then audits the recovery.

Disable per-appliance with ``UPDATE ids_config SET watchdog_enabled = 0``
(or unset the flag from the GUI when that lands), e.g. while debugging a
genuinely-broken config and you don't want auto-recovery masking the
errors.
"""

from __future__ import annotations

import json
import sys
import threading
import time


_STARTED        = threading.Event()
_TICK_SECS      = 60      # poll cadence
_VERIFY_SECS    = 10      # wait for daemon to come up before judging it
_LAST_TRY_KEY   = "ids_last_recovery_attempt"
_TRY_COUNT_KEY  = "ids_recovery_attempts_hour"
_MIN_BACKOFF    = 300     # at least 5 min between attempts
_MAX_PER_HOUR   = 6       # hard cap so a broken loop doesn't burn the host


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
    """Return ``{"hour_bucket": int, "count": int}`` for rate-limiting."""
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
    """Return ``(allowed, reason)`` for the cool-down + cap policy."""
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


def _suricata_alive() -> bool:
    """Lightweight pgrep check — avoids importing run_command here to keep
    the watchdog usable even when service_manager hits an error path."""
    if not sys.platform.startswith("freebsd"):
        return True   # never auto-recover off-box
    from app.services.network_service import run_command
    try:
        r = run_command(["pgrep", "-x", "suricata"], check=False)
        return r.returncode == 0
    except Exception:
        return False


def _ids_settings(conn) -> "tuple[bool, bool]":
    """Return (cfg_enabled, watchdog_enabled). Watchdog defaults to on
    if the column doesn't exist (older DBs pre-migration v28)."""
    try:
        row = conn.execute(
            "SELECT enabled, "
            "COALESCE(watchdog_enabled, 1) AS watchdog_enabled "
            "FROM ids_config WHERE id = 1"
        ).fetchone()
        if not row:
            return False, True
        return bool(row["enabled"]), bool(row["watchdog_enabled"])
    except Exception:
        return False, True


def attempt_recovery() -> dict:
    """
    One-shot recovery: delegate to the shared, safety-gated recovery path in
    ``ids_writer`` so the watchdog can never drift from the UI's enable/apply
    behavior (IPS safety gate, rule bootstrap + readiness, YAML validate, rc.conf
    enable, verified restart, stale-state cleanup). This module keeps only the
    cool-down/cap policy and the audit-event mapping.

    Returns ``{"ok", "skipped"?, "reason"?, "message"}``. Safe to call from
    any thread — it opens its own short-lived connection.
    """
    from app.audit_log import _events_db, log_event
    from app.services.ids_writer import recover_ids_service

    conn = _events_db()
    if conn is None:
        return {"ok": False, "skipped": True, "reason": "events_db_unavailable",
                "message": "events DB unavailable"}
    try:
        cfg_enabled, watchdog_enabled = _ids_settings(conn)
        if not cfg_enabled:
            return {"ok": True, "skipped": True, "reason": "disabled_in_config",
                    "message": "ids_config.enabled = 0"}
        if not watchdog_enabled:
            return {"ok": True, "skipped": True, "reason": "watchdog_disabled",
                    "message": "ids_config.watchdog_enabled = 0"}
        if _suricata_alive():
            return {"ok": True, "skipped": True, "reason": "already_running",
                    "message": "Suricata is alive"}

        ok, reason = _should_attempt(conn)
        if not ok:
            return {"ok": True, "skipped": True, "reason": "rate_limited",
                    "message": reason}

        # Bump counters BEFORE the attempt so a crash doesn't leak an extra
        # attempt past the rate limit.
        _write_state(conn, _LAST_TRY_KEY, str(_now_epoch()))
        attempts = _bump_hour_counter(conn)

        # Single safe path — same gating/validation/verified-restart/state-cleanup
        # the UI uses. recover_ids_service clears stale enabled state on the
        # failure reasons (ips_safety_failed / invalid_yaml / rules_not_ready / …)
        # so we don't have to here.
        try:
            result = recover_ids_service(conn, actor="watchdog")
        except Exception as exc:
            log_event(
                category="security", action="ids_auto_recovery_failed",
                severity="high", username="watchdog", remote_addr="",
                details={"stage": "recover", "error": str(exc)[:512],
                         "attempts_this_hour": attempts},
            )
            return {"ok": False, "reason": "exception", "message": str(exc),
                    "attempts_this_hour": attempts}

        if result.get("ok"):
            log_event(
                category="security", action="ids_auto_recovered",
                severity="medium", username="watchdog", remote_addr="",
                details={
                    "attempts_this_hour": attempts,
                    "service_message": (result.get("service_message")
                                        or result.get("message") or "")[:512],
                },
            )
            return {"ok": True, "message": "Suricata restarted by watchdog",
                    "attempts_this_hour": attempts}

        log_event(
            category="security", action="ids_auto_recovery_failed",
            severity="high", username="watchdog", remote_addr="",
            details={
                "stage":             "recover",
                "reason":            result.get("reason", "did_not_start"),
                "attempts_this_hour": attempts,
                "service_message":   (result.get("service_message") or "")[:512],
                "log_tail":          result.get("log_tail", []),
                "oom_killed":        bool(result.get("oom_killed")),
                "dmesg":             result.get("dmesg", ""),
            },
        )
        return {"ok": False,
                "reason": result.get("reason", "did_not_start"),
                "message": result.get("message",
                                      "recovery returned but daemon is not alive"),
                "service_message": result.get("service_message", ""),
                "log_tail": result.get("log_tail", []),
                "oom_killed": bool(result.get("oom_killed")),
                "attempts_this_hour": attempts}
    finally:
        try: conn.close()
        except Exception: pass


def _watchdog_loop():
    # Stagger initial run so it doesn't pile onto boot-time work.
    time.sleep(45)
    while True:
        try:
            attempt_recovery()
        except Exception as exc:
            from app.app_log import log_warning
            log_warning("ids_watchdog", "watchdog tick failed", {"error": str(exc)})
        time.sleep(_TICK_SECS)


def start_ids_watchdog():
    """Start the watchdog daemon thread (idempotent per process)."""
    if _STARTED.is_set():
        return
    _STARTED.set()
    threading.Thread(target=_watchdog_loop, name="siem-ids-watchdog",
                     daemon=True).start()
