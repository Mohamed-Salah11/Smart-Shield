"""
app/services/ti_enrichment.py
-----------------------------
Inline threat-intelligence enrichment for the audit-log pipeline.

The abuse.ch collector ([app/services/abusech_client.py](app/services/abusech_client.py))
already persists the latest ThreatFox IOC IP list as JSON in
``siem_state.threat_intel_last_update_ips`` (and pushes it to the PF
``ss_threat_intel`` table for inline blocking). This module reads that list
into an in-memory set, refreshes it periodically, and offers two helpers:

* ``enrich_details(details)`` — scans the well-known IP fields on an event's
  details payload (``src_ip``, ``dest_ip``, ``remote_addr``, etc.) and, if
  any match the TI set, appends a ``ti_hits`` list documenting the match.
  Called from ``audit_log.log_event`` before persistence so every alert
  inherits the enrichment without each collector having to opt in.

* ``lookup(ioc)`` — used by the SOC portal IOC lookup endpoint to answer
  "is this indicator known to our threat-intel set?" with sub-millisecond
  latency. Returns a dict the API can serialize directly.
"""

from __future__ import annotations

import json
import threading
import time

_CACHE_LOCK    = threading.Lock()
_CACHE_IPS:    set = set()
_CACHE_LOADED: float = 0.0
_CACHE_TTL     = 300            # seconds — re-read the DB at most every 5 min
_IP_FIELDS     = (
    "src_ip", "dest_ip", "dst_ip", "remote_addr",
    "source_ip", "destination_ip", "client_ip", "peer_ip",
)


def _load_ti_set(force: bool = False) -> set:
    """Return the cached TI IP set, refreshing from siem_state when stale."""
    global _CACHE_LOADED, _CACHE_IPS
    now = time.time()
    if not force and (now - _CACHE_LOADED) < _CACHE_TTL and _CACHE_IPS is not None:
        return _CACHE_IPS

    from app.audit_log import _events_db
    conn = _events_db()
    if conn is None:
        return _CACHE_IPS
    try:
        row = conn.execute(
            "SELECT value FROM siem_state WHERE key = 'threat_intel_last_update_ips'"
        ).fetchone()
        ips = set(json.loads(row["value"])) if row and row["value"] else set()
    except Exception:
        ips = _CACHE_IPS
    finally:
        try:
            conn.close()
        except Exception:
            pass
    with _CACHE_LOCK:
        _CACHE_IPS    = ips
        _CACHE_LOADED = now
    return _CACHE_IPS


def refresh_cache() -> int:
    """Force a refresh of the in-memory TI set. Returns the new size."""
    return len(_load_ti_set(force=True))


def enrich_details(details) -> dict:
    """
    Return *details* with a ``ti_hits`` list appended whenever any well-known
    IP field is found in the TI set. Pure function — never raises.
    """
    if not isinstance(details, dict) or not details:
        return details or {}
    ti = _load_ti_set()
    if not ti:
        return details
    hits = []
    seen = set()
    for field in _IP_FIELDS:
        v = details.get(field)
        if not v:
            continue
        v = str(v).strip().split(":")[0]          # strip :port
        if v and v not in seen and v in ti:
            seen.add(v)
            hits.append({
                "ioc":      v,
                "type":     "ip",
                "feed":     "abuse.ch/ThreatFox",
                "field":    field,
            })
    if hits:
        enriched = dict(details)
        existing = enriched.get("ti_hits") or []
        if isinstance(existing, list):
            enriched["ti_hits"] = existing + hits
        else:
            enriched["ti_hits"] = hits
        return enriched
    return details


def lookup(ioc: str) -> dict:
    """
    Look up a single indicator against the local TI set and the events store.

    Returns:
        {
          "ioc":        str,
          "ti_hit":     bool,         # in the local TI cache?
          "feed":       "abuse.ch/ThreatFox" | None,
          "event_count": int,         # events whose details contain this string
          "events":     [...]         # up to 25 most recent matching events
        }
    """
    needle = (ioc or "").strip()
    if not needle:
        return {"ioc": "", "ti_hit": False, "feed": None,
                "event_count": 0, "events": []}

    ti = _load_ti_set()
    hit = needle in ti

    from app.audit_log import _events_db
    conn = _events_db()
    events: list = []
    count = 0
    if conn is not None:
        try:
            like = f"%{needle}%"
            count = conn.execute(
                "SELECT COUNT(*) FROM events WHERE details LIKE ? OR remote_addr = ?",
                (like, needle),
            ).fetchone()[0]
            rows = conn.execute(
                "SELECT ts, severity, category, action, username, remote_addr, details "
                "FROM events WHERE details LIKE ? OR remote_addr = ? "
                "ORDER BY id DESC LIMIT 25",
                (like, needle),
            ).fetchall()
            for r in rows:
                try:
                    d = json.loads(r["details"]) if r["details"] else {}
                except Exception:
                    d = {}
                events.append({
                    "timestamp":   r["ts"],
                    "severity":    r["severity"] or "info",
                    "category":    r["category"] or "",
                    "action":      r["action"] or "",
                    "username":    r["username"] or "",
                    "remote_addr": r["remote_addr"] or "",
                    "details":     d,
                })
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    return {
        "ioc":         needle,
        "ti_hit":      hit,
        "feed":        "abuse.ch/ThreatFox" if hit else None,
        "event_count": count,
        "events":      events,
    }
