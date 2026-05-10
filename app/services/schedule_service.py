"""
schedule_service.py
--------------------
Timezone-aware firewall schedule evaluator for Smart Shield.

A firewall schedule is active when the current date/time falls within
any of its configured date+time ranges.  Multiple ranges use OR semantics:
if ANY range matches, the schedule is considered active.

The schedule data model uses firewall_schedules + firewall_schedule_ranges.
Range fields:
    year        — 0 means "any year"
    month       — 0 means "any month"
    days_csv    — comma-separated day numbers 1-31 ("" = any day)
    start_time  — HH:MM
    end_time    — HH:MM (if < start_time the range is overnight e.g. 22:00→06:00)

Integration
-----------
pf_generator calls filter_rules_by_schedule() to exclude rules whose
schedule window is not currently active before writing pf.conf.
"""

import logging
from datetime import datetime, timezone, time as dt_time
from typing import Optional

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_time(t: str) -> dt_time:
    """Parse "HH:MM" → datetime.time. Returns midnight on parse error."""
    try:
        parts = t.strip().split(":")
        return dt_time(int(parts[0]), int(parts[1]))
    except Exception:
        return dt_time(0, 0)


def _range_active(range_row: dict, now: datetime) -> bool:
    """
    Return True if *now* falls within a single firewall_schedule_ranges row.

    Overnight ranges (start > end, e.g. 22:00→06:00) are handled correctly.
    """
    year     = range_row.get("year") or 0
    month    = range_row.get("month") or 0
    days_csv = (range_row.get("days_csv") or "").strip()
    start_t  = _parse_time(range_row.get("start_time") or "00:00")
    end_t    = _parse_time(range_row.get("end_time") or "23:59")

    # Year check — 0 means any year
    if year and year != now.year:
        return False

    # Month check — 0 means any month
    if month and month != now.month:
        return False

    # Day-of-month check — empty string means any day
    if days_csv:
        try:
            allowed = {int(d.strip()) for d in days_csv.split(",") if d.strip()}
            if now.day not in allowed:
                return False
        except ValueError:
            pass

    # Time-of-day check
    now_t = now.time().replace(second=0, microsecond=0)
    if start_t <= end_t:
        # Normal same-day range
        return start_t <= now_t <= end_t
    else:
        # Overnight range — active when AFTER start OR BEFORE end
        return now_t >= start_t or now_t <= end_t


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def is_schedule_active(conn, schedule_name: str,
                       now: Optional[datetime] = None) -> bool:
    """
    Return True if the named schedule is currently active.

    *now* defaults to UTC. Pass a timezone-aware datetime for local-time checks.
    Returns False when the schedule does not exist or has no ranges configured.
    """
    if now is None:
        now = datetime.now(timezone.utc)

    try:
        sched = conn.execute(
            "SELECT id FROM firewall_schedules WHERE name=?", (schedule_name,)
        ).fetchone()
        if not sched:
            return False

        ranges = conn.execute(
            "SELECT year, month, days_csv, start_time, end_time "
            "FROM firewall_schedule_ranges WHERE schedule_id=?",
            (sched["id"],),
        ).fetchall()

        return any(_range_active(dict(r), now) for r in ranges)
    except Exception as exc:
        _log.warning("schedule_service: error evaluating '%s': %s", schedule_name, exc)
        return False


def get_all_schedule_states(conn) -> dict:
    """
    Return {schedule_name: bool} for every defined schedule.
    Used by the UI to show active/inactive badges without individual DB calls.
    """
    now = datetime.now(timezone.utc)
    result: dict = {}
    try:
        schedules = conn.execute(
            "SELECT id, name FROM firewall_schedules"
        ).fetchall()
        for sched in schedules:
            ranges = conn.execute(
                "SELECT year, month, days_csv, start_time, end_time "
                "FROM firewall_schedule_ranges WHERE schedule_id=?",
                (sched["id"],),
            ).fetchall()
            result[sched["name"]] = any(_range_active(dict(r), now) for r in ranges)
    except Exception as exc:
        _log.warning("schedule_service: get_all_schedule_states error: %s", exc)
    return result


def filter_rules_by_schedule(conn, rules: list,
                              now: Optional[datetime] = None) -> list:
    """
    Filter a list of rule dicts to only those whose schedule is currently active.

    Rules with an empty or NULL schedule field are always included.
    The schedule evaluation result is cached per schedule name to avoid
    redundant DB lookups when many rules share the same schedule.

    Parameters
    ----------
    conn   open SQLite connection
    rules  list of rule dicts with a 'schedule' key
    now    optional override for "current time" (useful for testing)
    """
    if now is None:
        now = datetime.now(timezone.utc)

    cache: dict = {}
    active_rules = []

    for rule in rules:
        sched_name = (rule.get("schedule") or "").strip()
        if not sched_name:
            # No schedule → always active
            active_rules.append(rule)
            continue

        if sched_name not in cache:
            cache[sched_name] = is_schedule_active(conn, sched_name, now)

        if cache[sched_name]:
            active_rules.append(rule)
        else:
            _log.debug("schedule_service: rule id=%s excluded by schedule '%s'",
                       rule.get("id"), sched_name)

    return active_rules
