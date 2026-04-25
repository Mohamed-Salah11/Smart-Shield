import json
import os
import sys
from datetime import datetime, timezone


def _default_audit_path():
    if sys.platform.startswith("freebsd"):
        return "/var/log/smart-shield/audit.log"
    return "logs/audit.log"


def _audit_log_path():
    return os.getenv("SMARTSHIELD_AUDIT_LOG_PATH", _default_audit_path())


def _ensure_parent_dir(path: str):
    parent_dir = os.path.dirname(os.path.abspath(path))
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)


def log_event(category: str, action: str, username=None, remote_addr=None, details=None):
    try:
        path = _audit_log_path()
        _ensure_parent_dir(path)

        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "category": category,
            "action": action,
            "username": username or "anonymous",
            "remote_addr": remote_addr or "",
            "details": details or {},
        }

        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=True) + "\n")
    except OSError:
        # Never block the app flow if logging path permissions are missing.
        return False
    return True


def tail_events(limit=200, category=None):
    """Return the most-recent `limit` events, newest first."""
    path = _audit_log_path()
    if not os.path.exists(path):
        return []

    events = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if category and entry.get("category") != category:
                    continue
                events.append(entry)
    except OSError:
        return []

    if limit <= 0:
        return list(reversed(events))
    return list(reversed(events[-limit:]))


def tail_events_since(after_ts: str = "", limit: int = 200, categories=None) -> list:
    """
    Return events whose timestamp is strictly greater than `after_ts`.
    Results are ordered newest-first.  Pass after_ts="" to get the most
    recent `limit` events across all time.
    """
    path = _audit_log_path()
    if not os.path.exists(path):
        return []

    cat_set = set(categories) if categories else None
    events = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if after_ts and entry.get("timestamp", "") <= after_ts:
                    continue
                if cat_set and entry.get("category") not in cat_set:
                    continue
                events.append(entry)
    except OSError:
        return []

    events.reverse()                   # newest first
    if limit > 0:
        events = events[:limit]
    return events


def log_stats() -> dict:
    """
    Return per-category event counts for the entire log file.
    Also includes a special 'login_failed' key for security dashboards.
    """
    path = _audit_log_path()
    stats: dict = {}
    failed_logins = 0
    total = 0
    if not os.path.exists(path):
        return stats
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                cat = entry.get("category", "unknown")
                stats[cat] = stats.get(cat, 0) + 1
                total += 1
                if entry.get("action") == "login_failed":
                    failed_logins += 1
    except OSError:
        pass
    stats["_total"] = total
    stats["_login_failed"] = failed_logins
    return stats
