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


def log_event(category: str, action: str, username=None, remote_addr=None,
              details=None, severity: str = "info"):
    """Append one audit event to the log file. Never raises."""
    try:
        path = _audit_log_path()
        _ensure_parent_dir(path)

        entry = {
            "timestamp":   datetime.now(timezone.utc).isoformat(),
            "severity":    severity,
            "category":    category,
            "action":      action,
            "username":    username or "anonymous",
            "remote_addr": remote_addr or "",
            "details":     details or {},
        }

        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=True) + "\n")
    except OSError:
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


def tail_events_since(after_ts: str = "", limit: int = 200,
                      categories=None, severities=None,
                      start_ts: str = "", end_ts: str = "") -> list:
    """
    Return events whose timestamp is strictly greater than `after_ts`.
    Results are ordered newest-first.  Pass after_ts="" to get the most
    recent `limit` events across all time.

    Optional filters:
      categories  — list of category strings to include
      severities  — list of severity strings to include ("critical","high",...)
      start_ts    — ISO-8601 lower bound (inclusive)
      end_ts      — ISO-8601 upper bound (inclusive)
    """
    path = _audit_log_path()
    if not os.path.exists(path):
        return []

    cat_set = set(categories) if categories else None
    sev_set = set(severities) if severities else None
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
                ts = entry.get("timestamp", "")
                if after_ts and ts <= after_ts:
                    continue
                if start_ts and ts < start_ts:
                    continue
                if end_ts and ts > end_ts:
                    continue
                if cat_set and entry.get("category") not in cat_set:
                    continue
                if sev_set and entry.get("severity", "info") not in sev_set:
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
    Also includes special keys: _total, _login_failed, _critical, _high.
    """
    path = _audit_log_path()
    stats: dict = {}
    failed_logins = 0
    critical = 0
    high = 0
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
                sev = entry.get("severity", "info")
                if sev == "critical":
                    critical += 1
                elif sev == "high":
                    high += 1
    except OSError:
        pass
    stats["_total"]        = total
    stats["_login_failed"] = failed_logins
    stats["_critical"]     = critical
    stats["_high"]         = high
    return stats
