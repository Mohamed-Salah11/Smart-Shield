"""
app/services/collector_health.py
--------------------------------
Per-collector status + dead-letter capture (Wave D).

The SIEM collector threads share three reliability concerns:

  * how many events they have written
  * how many they had to drop (parse failure, queue full, DB outage)
  * the last error message, so an operator can see *why* they're dropping

This module wraps the ``collector_state`` table behind small typed
helpers and exposes :func:`record_dead_letter` so a parse failure can be
preserved instead of silently discarded.

All helpers swallow DB errors — collector reliability tooling MUST NOT
itself crash the collector.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _conn():
    try:
        from app.audit_log import _events_db
        return _events_db()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Collector state
# ---------------------------------------------------------------------------

def heartbeat(source_name: str, *,
              source_type: str = "",
              path: str = "",
              offset: Optional[int] = None,
              file_size: Optional[int] = None,
              last_event_ts: str = "",
              events_added: int = 0,
              dropped_added: int = 0,
              last_error: Optional[str] = None,
              restart: bool = False) -> None:
    """Upsert a collector_state row.

    Pass only the fields you actually know — every argument is optional so
    the file-tail collectors can call this once per tick with their new
    offset, while a one-shot polling collector can just bump
    ``events_added``.
    """
    conn = _conn()
    if conn is None:
        return
    try:
        now = _utcnow()
        # Ensure the row exists.
        conn.execute(
            "INSERT INTO collector_state (source_name, source_type) "
            "VALUES (?, ?) "
            "ON CONFLICT(source_name) DO NOTHING",
            (source_name, source_type),
        )
        updates = ["last_seen = ?", "updated_at = ?"]
        params: list = [now, now]
        if source_type:
            updates.append("source_type = ?"); params.append(source_type)
        if path:
            updates.append("path = ?"); params.append(path)
        if offset is not None:
            updates.append("offset = ?"); params.append(int(offset))
        if file_size is not None:
            updates.append("file_size = ?"); params.append(int(file_size))
        if last_event_ts:
            updates.append("last_event_ts = ?"); params.append(last_event_ts)
        if events_added:
            updates.append("events_collected = events_collected + ?")
            params.append(int(events_added))
        if dropped_added:
            updates.append("events_dropped = events_dropped + ?")
            params.append(int(dropped_added))
        if last_error is not None:
            # Empty string clears the error; None leaves the previous one.
            updates.append("last_error = ?")
            params.append(last_error or None)
        if restart:
            updates.append("restart_count = restart_count + 1")
        params.append(source_name)
        conn.execute(
            f"UPDATE collector_state SET {', '.join(updates)} WHERE source_name = ?",
            params,
        )
        conn.commit()
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def list_state() -> list:
    """Return every collector_state row as a dict (for the health UI)."""
    conn = _conn()
    if conn is None:
        return []
    try:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM collector_state ORDER BY source_name"
        )]
    finally:
        try:
            conn.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Dead-letter queue
# ---------------------------------------------------------------------------

# Hard cap on how many DLQ rows we keep; the writer prunes oldest first
# whenever it would push the table past this. 5k rows × ~4 KB = ~20 MB
# absolute worst case, well within retention.
_DLQ_MAX_ROWS = 5000


def record_dead_letter(source_name: str, *,
                       source_type: str = "",
                       reason: str = "",
                       raw_payload: str = "",
                       details: Optional[dict] = None,
                       bump_dropped: bool = True) -> None:
    """Persist a parse failure / queue overflow / DB outage.

    Best-effort: never raises. The collector calling this should still
    ``continue`` on its parse-failure path — record_dead_letter is purely
    observability, not delivery.
    """
    conn = _conn()
    if conn is None:
        return
    try:
        # Truncate raw payload — a 1 MB syslog message should not bloat the
        # diagnostic table beyond what an operator can usefully see.
        if raw_payload and len(raw_payload) > 8192:
            raw_payload = raw_payload[:8192] + "\n... [truncated]"
        conn.execute(
            "INSERT INTO event_dead_letter "
            "(ts, source_type, source_name, reason, raw_payload, details) "
            "VALUES (?,?,?,?,?,?)",
            (_utcnow(), source_type, source_name, reason or "parse_failure",
             raw_payload or "",
             json.dumps(details or {}, ensure_ascii=True)),
        )

        # Cap table size — oldest rows go first.
        total = conn.execute("SELECT COUNT(*) FROM event_dead_letter").fetchone()[0]
        if total > _DLQ_MAX_ROWS:
            conn.execute(
                "DELETE FROM event_dead_letter WHERE id IN "
                "(SELECT id FROM event_dead_letter ORDER BY id ASC LIMIT ?)",
                (total - _DLQ_MAX_ROWS,),
            )
        conn.commit()
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass

    if bump_dropped:
        heartbeat(source_name, source_type=source_type, dropped_added=1)


def list_dead_letter(limit: int = 100, source_name: str = "",
                     since_id: int = 0) -> list:
    """Return recent dead-letter rows for the operator health UI."""
    conn = _conn()
    if conn is None:
        return []
    try:
        where = "1=1"
        params: list = []
        if source_name:
            where += " AND source_name = ?"; params.append(source_name)
        if since_id:
            where += " AND id > ?"; params.append(int(since_id))
        params.append(int(limit))
        return [dict(r) for r in conn.execute(
            f"SELECT * FROM event_dead_letter WHERE {where} "
            f"ORDER BY id DESC LIMIT ?",
            params,
        )]
    finally:
        try:
            conn.close()
        except Exception:
            pass


def purge_dead_letter(*, older_than_days: int = 0,
                      source_name: str = "") -> int:
    """Purge DLQ rows older than *older_than_days* (or all rows when 0).

    Returns the number of deleted rows. Used by the collector-health UI's
    "Purge" button to clear noise after a parser fix.
    """
    conn = _conn()
    if conn is None:
        return 0
    try:
        params: list = []
        where = "1=1"
        if older_than_days > 0:
            cutoff = (datetime.now(timezone.utc).timestamp()
                      - older_than_days * 86400)
            iso = datetime.fromtimestamp(cutoff, tz=timezone.utc).isoformat()
            where += " AND ts < ?"; params.append(iso)
        if source_name:
            where += " AND source_name = ?"; params.append(source_name)
        before = conn.execute(
            f"SELECT COUNT(*) FROM event_dead_letter WHERE {where}", params
        ).fetchone()[0]
        conn.execute(
            f"DELETE FROM event_dead_letter WHERE {where}", params
        )
        conn.commit()
        return int(before)
    except Exception:
        return 0
    finally:
        try:
            conn.close()
        except Exception:
            pass


def replay_dead_letter(dlq_id: int) -> dict:
    """Re-run the parser on a DLQ row. Deletes the row on success.

    Only ``source_name='pflog0'`` rows are supported today — that is the
    one parser whose fix-cycle is fast (operators iterate on
    ``parse_pflog_line`` and want to retry without waiting for new traffic).
    Returns ``{"ok": bool, "message": str, "parsed": dict | None}``.
    """
    conn = _conn()
    if conn is None:
        return {"ok": False, "message": "DB unavailable", "parsed": None}
    try:
        row = conn.execute(
            "SELECT id, source_name, source_type, raw_payload "
            "FROM event_dead_letter WHERE id = ?",
            (int(dlq_id),),
        ).fetchone()
        if not row:
            return {"ok": False, "message": "not found", "parsed": None}
        src = row["source_name"] or ""
        raw = row["raw_payload"] or ""
        if src == "pflog0":
            from app.services.parsers.pf_parser import parse_pflog_line
            parsed = parse_pflog_line(raw)
            if not parsed:
                return {"ok": False, "message": "parser still rejects line",
                        "parsed": None}
            # Re-ingest path lives in siem_collector — call the same handler
            # the live tail uses so behaviour is identical.
            try:
                from app.services.siem_collector import _handle_pflog_line
                _handle_pflog_line({}, raw)
            except Exception as exc:
                return {"ok": False,
                        "message": f"re-ingest failed: {exc}",
                        "parsed": parsed}
            conn.execute("DELETE FROM event_dead_letter WHERE id = ?",
                         (int(dlq_id),))
            conn.commit()
            return {"ok": True, "message": "replayed + cleared",
                    "parsed": parsed}
        return {"ok": False,
                "message": f"replay not supported for source {src!r}",
                "parsed": None}
    except Exception as exc:
        return {"ok": False, "message": str(exc), "parsed": None}
    finally:
        try:
            conn.close()
        except Exception:
            pass


__all__ = [
    "heartbeat",
    "list_state",
    "record_dead_letter",
    "list_dead_letter",
    "purge_dead_letter",
    "replay_dead_letter",
]
