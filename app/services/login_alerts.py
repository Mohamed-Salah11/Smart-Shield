"""
app/services/login_alerts.py
----------------------------
Failure-burst detection for login attempts.

A single failed login is routine noise; a *burst* of failures against one
account is a security signal the SOC should see. This module is called right
after a failed login is recorded in ``login_failures`` (by both the admin UI
and the SOC portal). When the recent-failure count for an account crosses a
small threshold it emits one consolidated ``multi_failed_login`` security
event — which the SOC alert feed surfaces — and then suppresses duplicates for
a cooldown window so a sustained attack does not flood the feed.

The eventual account lockout is reported separately by the existing
``*_blocked_user_lockout`` events; this module only covers the early burst.
"""

from __future__ import annotations

import threading
import time

# A burst is this many failures for one account inside the detection window.
_BURST_THRESHOLD = 3
# Failures older than this (seconds) no longer count toward the burst — matches
# the 15-minute per-account lockout window used by the login routes.
_DETECTION_WINDOW = 900
# Do not re-fire the alert for the same account within this many seconds.
_COOLDOWN = 600

# username -> last-fired epoch
_FIRED: dict = {}
_FIRED_LOCK = threading.Lock()


def note_login_failure(conn, username: str, remote_addr: str,
                       target: str = "admin_ui") -> bool:
    """
    Record-time hook: inspect ``login_failures`` for *username* and, when the
    recent failures form a burst, emit a ``multi_failed_login`` SOC alert.

    *target* identifies which surface was attacked (``admin_ui`` /
    ``soc_portal``). Returns True when an alert was emitted. Never raises.
    """
    username = (username or "").strip()
    if not username:
        return False  # cannot aggregate anonymous attempts by account

    try:
        window_start = time.time() - _DETECTION_WINDOW
        rows = conn.execute(
            "SELECT remote_addr, failed_at FROM login_failures "
            "WHERE username=? AND failed_at>? ORDER BY failed_at ASC",
            (username, window_start),
        ).fetchall()
    except Exception:
        return False

    count = len(rows)
    if count < _BURST_THRESHOLD:
        return False  # "pass it if one fail only" — and below the burst line

    now = time.time()
    with _FIRED_LOCK:
        if now - _FIRED.get(username, 0) < _COOLDOWN:
            return False
        _FIRED[username] = now
        # Bound the map so a wide username spray cannot grow it forever.
        if len(_FIRED) > 5000:
            for k, t in list(_FIRED.items()):
                if now - t > _COOLDOWN:
                    _FIRED.pop(k, None)

    source_ips = sorted({(r["remote_addr"] or "").strip()
                         for r in rows if (r["remote_addr"] or "").strip()})
    attempts = [
        {"remote_addr": (r["remote_addr"] or "").strip(),
         "failed_at": float(r["failed_at"] or 0)}
        for r in rows
    ]

    try:
        from app.audit_log import log_event
        log_event(
            category="security",
            action="multi_failed_login",
            username=username,
            remote_addr=(remote_addr or "").strip(),
            severity="high",
            details={
                "target":         target,
                "failure_count":  count,
                "window_seconds": _DETECTION_WINDOW,
                "source_ips":     source_ips,
                "attempts":       attempts,
                "threshold":      _BURST_THRESHOLD,
            },
        )
    except Exception:
        return False
    return True
