"""
app_log.py
----------
Structured operational application log for Smart Shield.

Separation of concerns
-----------------------
audit_log.py   Records SECURITY events: logins, config changes, privileged actions.
app_log.py     Records OPERATIONAL events: service start/stop, apply results, errors.

Both write NDJSON (newline-delimited JSON) to separate log files.

Log rotation
------------
On FreeBSD, newsyslog handles rotation via /usr/local/etc/newsyslog.d/.
See bsd/etc/newsyslog.d/smartshield.conf for the recommended config.
The log file is reopened on each write so rotation (rename+recreate) is
handled transparently without the app needing a SIGHUP.

Secret redaction
----------------
Values whose keys contain 'password', 'secret', 'key', 'token', 'psk' are
replaced with ``***`` before writing to prevent accidental log disclosure.

Public API
----------
log_info(component, message, details)    -> None
log_warning(component, message, details) -> None
log_error(component, message, details)   -> None
tail_app_events(limit, level, component) -> list
"""

import json
import os
import sys
from datetime import datetime, timezone

_REDACT_KEYS = {"password", "secret", "key", "token", "psk", "auth", "credential"}


def _default_app_log_path() -> str:
    if sys.platform.startswith("freebsd"):
        from app.config import _ss_dir
        return os.path.join(_ss_dir("/var/log"), "app.log")
    return "logs/app.log"


def _app_log_path() -> str:
    return os.getenv("SMARTSHIELD_APP_LOG_PATH", _default_app_log_path())


def _ensure_parent(path: str):
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)


def _redact(obj, depth: int = 0):
    """Recursively redact sensitive key values in dicts."""
    if depth > 5:
        return obj
    if isinstance(obj, dict):
        return {
            k: ("***" if any(s in k.lower() for s in _REDACT_KEYS) else _redact(v, depth + 1))
            for k, v in obj.items()
        }
    if isinstance(obj, (list, tuple)):
        return [_redact(i, depth + 1) for i in obj]
    return obj


def _write(level: str, component: str, message: str, details: dict):
    path = _app_log_path()
    try:
        _ensure_parent(path)
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level":     level,
            "component": (component or "app")[:64],
            "message":   str(message)[:512],
            "details":   _redact(details or {}),
        }
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=True) + "\n")
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Public write API
# ---------------------------------------------------------------------------

def log_info(component: str, message: str, details: dict = None):
    _write("INFO", component, message, details or {})


def log_warning(component: str, message: str, details: dict = None):
    _write("WARNING", component, message, details or {})


def log_error(component: str, message: str, details: dict = None):
    _write("ERROR", component, message, details or {})


# ---------------------------------------------------------------------------
# Read API
# ---------------------------------------------------------------------------

def tail_app_events(
    limit: int = 200,
    level: str = "",
    component: str = "",
    search: str = "",
) -> list:
    """
    Return the most-recent ``limit`` app-log entries (newest first).

    Parameters
    ----------
    limit     : Maximum entries to return (capped at 1000).
    level     : If set, filter by exact level (INFO / WARNING / ERROR).
    component : If set, filter by component name prefix.
    search    : Free-text search across message and details JSON.
    """
    path  = _app_log_path()
    limit = max(1, min(int(limit), 1000))
    if not os.path.exists(path):
        return []

    level_filter     = (level     or "").upper().strip()
    component_filter = (component or "").lower().strip()
    search_term      = (search    or "").lower().strip()

    events = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if level_filter and entry.get("level", "").upper() != level_filter:
                    continue
                if component_filter and not entry.get("component", "").lower().startswith(component_filter):
                    continue
                if search_term:
                    haystack = (
                        entry.get("message", "") + " " +
                        json.dumps(entry.get("details", {}))
                    ).lower()
                    if search_term not in haystack:
                        continue
                events.append(entry)
    except OSError:
        return []

    events.reverse()
    return events[:limit]


def app_log_stats() -> dict:
    """Return per-level event counts for the entire app log."""
    path  = _app_log_path()
    stats: dict = {}
    if not os.path.exists(path):
        return stats
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                lvl = entry.get("level", "UNKNOWN")
                stats[lvl] = stats.get(lvl, 0) + 1
    except OSError:
        pass
    return stats
