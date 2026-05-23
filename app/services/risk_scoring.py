"""
app/services/risk_scoring.py
----------------------------
Per-entity risk score. Whenever a correlation rule fires (or any
"interesting" event is logged), we bump the score for the involved
entities — typically the source IP and/or username — by a severity-based
delta. The score decays exponentially with time so a quiet entity drifts
back toward zero, mirroring how Splunk ES handles risk-based alerting.

Persistence lives in the ``risk_scores`` table introduced in migration v27:
    (entity_type, entity_value, score, last_updated)

Public API:
    bump(entity_type, entity_value, severity, reason)
    top_risky(limit=20)               — UI / report data source
    decay_all()                       — call from a slow background tick
    current_score(entity_type, val)   — read-through with on-the-fly decay
"""

from __future__ import annotations

import math
import threading
import time
from datetime import datetime, timezone


_LOCK = threading.Lock()

_SEV_DELTA = {
    "critical": 25.0,
    "high":     10.0,
    "medium":    4.0,
    "low":       1.5,
    "info":      0.0,
}

# Half-life of the score in seconds. A risk bump of 10 from a "high" event
# decays to 5 in 24 h and to 1.25 in 48 h.
_HALF_LIFE_SECS = 86_400.0


def _now_ts() -> float:
    return time.time()


def _parse_ts(ts_str: str) -> float:
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError, AttributeError):
        return _now_ts()


def _decayed(score: float, last_ts: float, now: float = None) -> float:
    """Exponential decay with the configured half-life."""
    if score <= 0:
        return 0.0
    now = now or _now_ts()
    age = max(0.0, now - last_ts)
    return score * math.pow(0.5, age / _HALF_LIFE_SECS)


def bump(entity_type: str, entity_value: str, severity: str,
         reason: str = "") -> float:
    """
    Add the severity's delta to *entity*'s current (decayed) score.
    Returns the new score. Silent no-op on empty entity_value or unknown
    severity. Never raises.
    """
    entity_type  = (entity_type or "").strip().lower()
    entity_value = (entity_value or "").strip()
    if not entity_type or not entity_value:
        return 0.0
    delta = _SEV_DELTA.get((severity or "info").lower(), 0.0)
    if delta <= 0:
        return 0.0

    from app.audit_log import _events_db
    conn = _events_db()
    if conn is None:
        return 0.0
    try:
        with _LOCK:
            row = conn.execute(
                "SELECT score, last_updated FROM risk_scores "
                "WHERE entity_type=? AND entity_value=?",
                (entity_type, entity_value),
            ).fetchone()
            now = _now_ts()
            if row:
                base = _decayed(float(row["score"] or 0), _parse_ts(row["last_updated"]), now)
                new_score = base + delta
                conn.execute(
                    "UPDATE risk_scores SET score=?, last_updated=CURRENT_TIMESTAMP "
                    "WHERE entity_type=? AND entity_value=?",
                    (new_score, entity_type, entity_value),
                )
            else:
                new_score = delta
                conn.execute(
                    "INSERT INTO risk_scores (entity_type, entity_value, score) "
                    "VALUES (?, ?, ?)",
                    (entity_type, entity_value, new_score),
                )
            conn.commit()
            return new_score
    except Exception:
        return 0.0
    finally:
        try: conn.close()
        except Exception: pass


def current_score(entity_type: str, entity_value: str) -> float:
    """Return the live (decayed) score for *entity*, 0 if unknown."""
    from app.audit_log import _events_db
    conn = _events_db()
    if conn is None:
        return 0.0
    try:
        row = conn.execute(
            "SELECT score, last_updated FROM risk_scores "
            "WHERE entity_type=? AND entity_value=?",
            (entity_type, entity_value),
        ).fetchone()
        if not row:
            return 0.0
        return _decayed(float(row["score"] or 0), _parse_ts(row["last_updated"]))
    except Exception:
        return 0.0
    finally:
        try: conn.close()
        except Exception: pass


def top_risky(limit: int = 20, min_score: float = 1.0) -> list:
    """
    Return the highest-scoring entities (after decay), newest-first on ties.
    Used by the SOC dashboard and the executive report.
    """
    from app.audit_log import _events_db
    conn = _events_db()
    if conn is None:
        return []
    try:
        rows = conn.execute(
            "SELECT entity_type, entity_value, score, last_updated FROM risk_scores"
        ).fetchall()
    except Exception:
        return []
    finally:
        try: conn.close()
        except Exception: pass
    now = _now_ts()
    decorated = []
    for r in rows:
        score = _decayed(float(r["score"] or 0),
                         _parse_ts(r["last_updated"]), now)
        if score < min_score:
            continue
        decorated.append({
            "entity_type":  r["entity_type"],
            "entity_value": r["entity_value"],
            "score":        round(score, 2),
            "last_updated": r["last_updated"],
        })
    decorated.sort(key=lambda d: (-d["score"], d["last_updated"]))
    return decorated[:max(1, int(limit or 20))]


def decay_all() -> int:
    """
    Persist the decayed score back to disk for every row and delete rows
    that have decayed below 0.1. Returns the number of rows pruned.

    Intended to be called from a low-frequency background tick (the
    saved-search scheduler thread is a convenient host).
    """
    from app.audit_log import _events_db
    conn = _events_db()
    if conn is None:
        return 0
    pruned = 0
    try:
        with _LOCK:
            rows = conn.execute(
                "SELECT id, score, last_updated FROM risk_scores"
            ).fetchall()
            now = _now_ts()
            for r in rows:
                d = _decayed(float(r["score"] or 0), _parse_ts(r["last_updated"]), now)
                if d < 0.1:
                    conn.execute("DELETE FROM risk_scores WHERE id=?", (r["id"],))
                    pruned += 1
                else:
                    conn.execute(
                        "UPDATE risk_scores SET score=?, last_updated=CURRENT_TIMESTAMP "
                        "WHERE id=?",
                        (d, r["id"]),
                    )
            conn.commit()
    except Exception as exc:
        from app.app_log import log_warning
        log_warning("risk_scoring", "decay_all sweep failed", {"error": str(exc)})
    finally:
        try: conn.close()
        except Exception: pass
    return pruned
