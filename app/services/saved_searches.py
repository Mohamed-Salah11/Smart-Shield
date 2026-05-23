"""
app/services/saved_searches.py
------------------------------
Analyst-defined queries against the events store, optionally scheduled to
re-run on a fixed interval. When a scheduled search has at least one match
it emits a ``saved_search_match`` security event so the SOC dashboard and
correlation rules can react.

The query payload is a JSON object with the same filter shape used by the
L2 hunt API:

    {"search": "...", "categories": [...], "severities": [...],
     "actions": [...], "start_ts": "...", "end_ts": "...",
     "limit": 200}

The scheduler also drives ``risk_scoring.decay_all()`` once an hour so risk
scores stay current without spinning up yet another background thread.
"""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timedelta, timezone


_STARTED   = threading.Event()
_TICK_SECS = 60   # wake up every minute; per-search cadence is checked here


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

def list_searches(conn) -> list:
    rows = conn.execute(
        "SELECT * FROM saved_searches ORDER BY name"
    ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["query"] = json.loads(d.get("query_json") or "{}")
        except Exception:
            d["query"] = {}
        out.append(d)
    return out


def upsert_search(conn, payload: dict) -> dict:
    name = (payload.get("name") or "").strip()
    if not name:
        return {"ok": False, "message": "name is required"}
    query = payload.get("query") or {}
    if not isinstance(query, dict):
        return {"ok": False, "message": "query must be an object"}
    try:
        schedule = max(0, min(int(payload.get("schedule_minutes") or 0), 1440))
    except (TypeError, ValueError):
        schedule = 0
    enabled = 1 if payload.get("enabled", True) else 0
    sid = payload.get("id")
    if sid:
        conn.execute(
            "UPDATE saved_searches SET name=?, owner=?, query_json=?, "
            "schedule_minutes=?, enabled=? WHERE id=?",
            (name, (payload.get("owner") or "system").strip(),
             json.dumps(query),
             schedule, enabled, int(sid)),
        )
    else:
        conn.execute(
            "INSERT INTO saved_searches (name, owner, query_json, "
            "schedule_minutes, enabled) VALUES (?,?,?,?,?)",
            (name, (payload.get("owner") or "system").strip(),
             json.dumps(query),
             schedule, enabled),
        )
    conn.commit()
    return {"ok": True}


def delete_search(conn, search_id: int) -> None:
    conn.execute("DELETE FROM saved_searches WHERE id=?", (int(search_id),))
    conn.commit()


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

def run_search(query: dict) -> list:
    """Execute *query* and return matching events (limit applied)."""
    from app.audit_log import tail_events_since, search_events_fts
    try:
        limit = min(int(query.get("limit") or 200), 1000)
    except (TypeError, ValueError):
        limit = 200
    categories = query.get("categories") or None
    severities = query.get("severities") or None
    actions    = query.get("actions") or None
    if isinstance(actions, list):
        actions = {a for a in actions if a}
    start_ts = (query.get("start_ts") or "").strip()
    end_ts   = (query.get("end_ts") or "").strip()
    search   = (query.get("search") or "").strip()

    if search:
        events = search_events_fts(query=search, limit=limit,
                                   categories=categories, severities=severities,
                                   start_ts=start_ts, end_ts=end_ts)
    else:
        events = tail_events_since(after_ts="", limit=limit,
                                   categories=categories, severities=severities,
                                   start_ts=start_ts, end_ts=end_ts)
    if actions:
        events = [e for e in events if e.get("action") in actions]
    return events[:limit]


def _execute_due(conn, now: float) -> int:
    """Run every saved search whose cadence has elapsed. Returns runs done."""
    from app.audit_log import log_event
    rows = conn.execute(
        "SELECT id, name, query_json, schedule_minutes, last_run_at "
        "FROM saved_searches WHERE enabled=1 AND schedule_minutes > 0"
    ).fetchall()
    runs = 0
    for r in rows:
        try:
            cadence = int(r["schedule_minutes"] or 0)
            if cadence <= 0:
                continue
            last = r["last_run_at"]
            if last:
                try:
                    last_epoch = datetime.fromisoformat(
                        last.replace("Z", "+00:00") if "T" in last
                        else last.replace(" ", "T") + "+00:00"
                    ).timestamp()
                except Exception:
                    last_epoch = 0
                if (now - last_epoch) < cadence * 60:
                    continue
            try:
                query = json.loads(r["query_json"] or "{}")
            except Exception:
                query = {}
            events = run_search(query)
            count  = len(events)
            conn.execute(
                "UPDATE saved_searches SET last_run_at=CURRENT_TIMESTAMP, "
                "last_match_count=? WHERE id=?",
                (count, r["id"]),
            )
            conn.commit()
            if count > 0:
                first_ts = events[0].get("timestamp", "")
                log_event(
                    category="security",
                    action="saved_search_match",
                    severity="medium",
                    username="siem",
                    remote_addr="",
                    details={
                        "saved_search_id":   r["id"],
                        "saved_search_name": r["name"],
                        "match_count":       count,
                        "first_match_ts":    first_ts,
                    },
                )
            runs += 1
        except Exception:
            continue
    return runs


def _scheduler_loop():
    # Stagger initial run.
    time.sleep(30)
    last_decay = 0.0
    while True:
        from app.audit_log import _events_db
        conn = _events_db()
        if conn is not None:
            try:
                _execute_due(conn, time.time())
            except Exception as exc:
                from app.app_log import log_warning
                log_warning("saved_searches", "scheduler tick failed", {"error": str(exc)})
            finally:
                try: conn.close()
                except Exception: pass

        # Run risk-score decay sweep at most once per hour.
        now = time.time()
        if now - last_decay > 3600:
            try:
                from app.services.risk_scoring import decay_all
                decay_all()
            except Exception:
                pass
            last_decay = now

        time.sleep(_TICK_SECS)


def start_scheduler():
    if _STARTED.is_set():
        return
    _STARTED.set()
    threading.Thread(target=_scheduler_loop, name="saved-search-scheduler",
                     daemon=True).start()
