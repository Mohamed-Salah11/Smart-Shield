"""
app/services/alert_service.py
-----------------------------
SOC alert lifecycle (Wave C).

Detectors (correlation engine, IDS handler, DNS policy, captive portal,
auth failures, threat intel, …) call :func:`create_or_update_alert` instead
of writing analyst-action rows themselves.  The service deduplicates by
``dedup_key`` so a noisy signature firing 200 times in a row produces one
``alerts`` row with ``count = 200`` and a fresh ``last_seen`` — not 200
separate rows in the SOC queue.

All mutators write a row to ``alert_actions`` so the case history captures
exactly when each analyst touched each alert.

The functions in this module are intentionally small and stateless — they
just take a sqlite3 connection (the caller is responsible for the
transaction boundary).  None of them call ``conn.commit()``; callers do it
once per request.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Iterable, Optional


# ---------------------------------------------------------------------------
# Severity ladder — used to decide whether a repeated alert should escalate.
# ---------------------------------------------------------------------------
_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _severity_rank(sev: str) -> int:
    return _SEV_RANK.get((sev or "").strip().lower(), 1)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Suppression
# ---------------------------------------------------------------------------

def _is_suppressed(conn, *, dedup_key: str, signature_id: str = "",
                   src_ip: str = "", dst_ip: str = "",
                   domain: str = "", username: str = "",
                   rule_id: str = "", alert_type: str = "") -> Optional[int]:
    """Return the suppression id if any active rule matches, else None.

    Match types are evaluated in priority order — narrower keys (dedup_key,
    signature_id) win before broader ones (src_ip, domain).  Expired rules
    (``expires_at < now``) are skipped without being deleted; the operator
    can re-enable them by clearing ``expires_at``.
    """
    candidates = (
        ("dedup_key",    dedup_key),
        ("signature_id", signature_id),
        ("rule_id",      rule_id),
        ("alert_type",   alert_type),
        ("src_ip",       src_ip),
        ("dst_ip",       dst_ip),
        ("domain",       domain),
        ("username",     username),
    )
    now = _utcnow()
    for match_type, value in candidates:
        if not value:
            continue
        row = conn.execute(
            "SELECT id FROM alert_suppressions "
            "WHERE enabled = 1 AND match_type = ? AND match_value = ? "
            "  AND (expires_at IS NULL OR expires_at = '' OR expires_at > ?) "
            "LIMIT 1",
            (match_type, value, now),
        ).fetchone()
        if row:
            return row["id"] if hasattr(row, "keys") else row[0]
    return None


# ---------------------------------------------------------------------------
# Core: create / update an alert
# ---------------------------------------------------------------------------

def create_or_update_alert(
    conn,
    *,
    dedup_key: str,
    title: str,
    severity: str = "medium",
    category: str = "",
    alert_type: str = "",
    description: str = "",
    source_event_id: Optional[int] = None,
    source_event_uuid: str = "",
    src_ip: str = "",
    dst_ip: str = "",
    username: str = "",
    hostname: str = "",
    mac: str = "",
    domain: str = "",
    rule_id: str = "",
    rule_name: str = "",
    signature_id: str = "",
    mitre_tactic: str = "",
    mitre_technique: str = "",
    risk_score: float = 0.0,
    details: Optional[dict] = None,
) -> Optional[int]:
    """Insert a new alert or bump the count on an existing open one.

    Returns the ``alerts.id`` of the row, or ``None`` if the alert was
    suppressed (a suppression row matched and no record was created).
    """
    if not dedup_key:
        # Defensive: every alert needs a dedup key so the deduplicating
        # unique index can do its job. Callers should always supply one.
        dedup_key = f"adhoc:{uuid.uuid4().hex}"

    if _is_suppressed(
        conn,
        dedup_key=dedup_key,
        signature_id=signature_id,
        src_ip=src_ip,
        dst_ip=dst_ip,
        domain=domain,
        username=username,
        rule_id=rule_id,
        alert_type=alert_type,
    ):
        return None

    now = _utcnow()
    existing = conn.execute(
        "SELECT id, severity, count, status "
        "FROM alerts "
        "WHERE dedup_key = ? "
        "  AND status NOT IN ('closed', 'false_positive', 'suppressed') "
        "ORDER BY id DESC LIMIT 1",
        (dedup_key,),
    ).fetchone()

    if existing:
        # Bump the open alert; escalate severity if the new event is more
        # severe than what we recorded so the SOC queue surfaces the worst
        # case.
        new_severity = existing["severity"]
        if _severity_rank(severity) > _severity_rank(existing["severity"]):
            new_severity = severity
        new_count = (existing["count"] or 0) + 1
        conn.execute(
            "UPDATE alerts SET last_seen = ?, count = ?, severity = ?, "
            "                  risk_score = MAX(risk_score, ?), "
            "                  updated_at = ? "
            "WHERE id = ?",
            (now, new_count, new_severity, risk_score, now, existing["id"]),
        )
        _record_observation(
            conn, existing["id"],
            event_uuid=source_event_uuid, src_ip=src_ip, dst_ip=dst_ip,
            domain=domain, username=username, hostname=hostname,
            summary=title, details=details,
        )
        return existing["id"]

    alert_uuid = uuid.uuid4().hex
    cur = conn.execute(
        "INSERT INTO alerts ("
        "  alert_uuid, first_seen, last_seen, status, severity, category, "
        "  alert_type, title, description, source_event_id, source_event_uuid, "
        "  dedup_key, count, src_ip, dst_ip, username, hostname, mac, domain, "
        "  rule_id, rule_name, signature_id, mitre_tactic, mitre_technique, "
        "  risk_score, details, created_at, updated_at"
        ") VALUES (?,?,?, 'new', ?,?, ?,?,?, ?,?, ?, 1, ?,?,?,?,?,?, ?,?,?, ?,?, ?, ?, ?,?)",
        (
            alert_uuid, now, now,
            severity, category,
            alert_type, title, description,
            source_event_id, source_event_uuid,
            dedup_key,
            src_ip, dst_ip, username, hostname, mac, domain,
            rule_id, rule_name, signature_id,
            mitre_tactic, mitre_technique,
            risk_score,
            json.dumps(details or {}, ensure_ascii=True),
            now, now,
        ),
    )
    alert_id = cur.lastrowid
    # Wave K: record the first occurrence as an observation too, so the
    # detail page can show every event from the start — not just from the
    # second hit onwards.
    _record_observation(
        conn, alert_id,
        event_uuid=source_event_uuid, src_ip=src_ip, dst_ip=dst_ip,
        domain=domain, username=username, hostname=hostname,
        summary=title, details=details,
    )
    return alert_id


def _record_observation(conn, alert_id: int, *, event_uuid: str = "",
                        src_ip: str = "", dst_ip: str = "",
                        domain: str = "", url: str = "",
                        username: str = "", hostname: str = "",
                        summary: str = "",
                        details: Optional[dict] = None) -> Optional[int]:
    """Append one observation row to the alert's timeline.

    Best-effort: the alert update is the durability guarantee, so a missing
    ``alert_observations`` table (older DB that hasn't migrated yet) is
    swallowed silently rather than failing the dedup write.
    """
    try:
        cur = conn.execute(
            "INSERT INTO alert_observations ("
            "  alert_id, event_uuid, src_ip, dst_ip, domain, url, "
            "  username, hostname, summary, raw_json"
            ") VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                alert_id,
                event_uuid or None,
                src_ip or None,
                dst_ip or None,
                domain or None,
                url or None,
                username or None,
                hostname or None,
                summary or "",
                json.dumps(details or {}, ensure_ascii=True),
            ),
        )
        return cur.lastrowid
    except Exception:
        return None


def list_alert_observations(conn, alert_id: int, *,
                            limit: int = 100, offset: int = 0) -> list:
    """Return recent observations for an alert, newest first."""
    try:
        rows = conn.execute(
            "SELECT id, alert_id, event_uuid, observed_at, src_ip, dst_ip, "
            "       domain, url, username, hostname, summary, raw_json "
            "FROM alert_observations "
            "WHERE alert_id = ? "
            "ORDER BY observed_at DESC, id DESC "
            "LIMIT ? OFFSET ?",
            (int(alert_id), int(limit), int(offset)),
        ).fetchall()
    except Exception:
        return []
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["raw_json"] = json.loads(d.get("raw_json") or "{}") or {}
        except Exception:
            d["raw_json"] = {}
        out.append(d)
    return out


# ---------------------------------------------------------------------------
# Analyst actions
# ---------------------------------------------------------------------------

def _log_action(conn, alert_id: int, action: str, actor: str,
                note: str = "", old_status: str = "",
                new_status: str = "", details: Optional[dict] = None):
    conn.execute(
        "INSERT INTO alert_actions "
        "(alert_id, action, actor, note, old_status, new_status, details) "
        "VALUES (?,?,?,?,?,?,?)",
        (alert_id, action, actor or "system", note or "",
         old_status or "", new_status or "",
         json.dumps(details or {}, ensure_ascii=True)),
    )


def _get_alert(conn, alert_id: int):
    return conn.execute(
        "SELECT id, status, severity FROM alerts WHERE id = ?",
        (alert_id,),
    ).fetchone()


def acknowledge_alert(conn, alert_id: int, actor: str, note: str = "") -> bool:
    a = _get_alert(conn, alert_id)
    if not a:
        return False
    old = a["status"]
    now = _utcnow()
    conn.execute(
        "UPDATE alerts SET status = 'acknowledged', "
        "                  acknowledged_by = ?, acknowledged_at = ?, "
        "                  updated_at = ? "
        "WHERE id = ?",
        (actor, now, now, alert_id),
    )
    _log_action(conn, alert_id, "ack", actor, note, old, "acknowledged")
    return True


def assign_alert(conn, alert_id: int, *, actor: str,
                 assignee_id: Optional[int], assignee_name: str = "") -> bool:
    a = _get_alert(conn, alert_id)
    if not a:
        return False
    now = _utcnow()
    if assignee_id in (None, 0, "", "0"):
        conn.execute(
            "UPDATE alerts SET assigned_to = NULL, assigned_name = NULL, "
            "                  assigned_by = NULL, assigned_at = NULL, "
            "                  updated_at = ? "
            "WHERE id = ?",
            (now, alert_id),
        )
        _log_action(conn, alert_id, "unassign", actor,
                    details={"prev_assignee": assignee_name})
        return True
    conn.execute(
        "UPDATE alerts SET assigned_to = ?, assigned_name = ?, "
        "                  assigned_by = ?, assigned_at = ?, "
        "                  updated_at = ? "
        "WHERE id = ?",
        (int(assignee_id), assignee_name, actor, now, now, alert_id),
    )
    _log_action(conn, alert_id, "assign", actor,
                details={"assignee_id": assignee_id,
                         "assignee_name": assignee_name})
    return True


def close_alert(conn, alert_id: int, *, actor: str,
                closure_type: str = "resolved",
                note: str = "") -> bool:
    a = _get_alert(conn, alert_id)
    if not a:
        return False
    old = a["status"]
    now = _utcnow()
    conn.execute(
        "UPDATE alerts SET status = 'closed', closed_by = ?, closed_at = ?, "
        "                  closure_type = ?, updated_at = ? "
        "WHERE id = ?",
        (actor, now, closure_type, now, alert_id),
    )
    _log_action(conn, alert_id, "close", actor, note, old, "closed",
                details={"closure_type": closure_type})
    return True


def mark_false_positive(conn, alert_id: int, *, actor: str,
                        note: str = "",
                        suppress_match: Optional[dict] = None) -> bool:
    """Mark alert as false positive. Optionally create a suppression rule
    so the same noise does not re-create the alert next time it fires.

    ``suppress_match`` is a dict like ``{"match_type": "signature_id",
    "match_value": "2014847", "expires_at": "2026-06-01T00:00:00Z"}``.
    """
    a = _get_alert(conn, alert_id)
    if not a:
        return False
    old = a["status"]
    now = _utcnow()
    sup_id = None
    if suppress_match and suppress_match.get("match_value"):
        cur = conn.execute(
            "INSERT INTO alert_suppressions "
            "(name, enabled, match_type, match_value, reason, created_by, expires_at) "
            "VALUES (?, 1, ?, ?, ?, ?, ?)",
            (
                suppress_match.get("name") or f"FP-{alert_id}",
                suppress_match.get("match_type") or "dedup_key",
                suppress_match["match_value"],
                note or suppress_match.get("reason", ""),
                actor,
                suppress_match.get("expires_at") or None,
            ),
        )
        sup_id = cur.lastrowid

    conn.execute(
        "UPDATE alerts SET status = 'false_positive', closure_type = 'false_positive', "
        "                  closed_by = ?, closed_at = ?, "
        "                  suppression_id = COALESCE(?, suppression_id), "
        "                  updated_at = ? "
        "WHERE id = ?",
        (actor, now, sup_id, now, alert_id),
    )
    _log_action(conn, alert_id, "false_positive", actor, note, old,
                "false_positive",
                details={"suppression_id": sup_id})
    return True


def reopen_alert(conn, alert_id: int, *, actor: str, note: str = "") -> bool:
    a = _get_alert(conn, alert_id)
    if not a:
        return False
    old = a["status"]
    now = _utcnow()
    conn.execute(
        "UPDATE alerts SET status = 'new', closed_at = NULL, closed_by = NULL, "
        "                  closure_type = NULL, updated_at = ? "
        "WHERE id = ?",
        (now, alert_id),
    )
    _log_action(conn, alert_id, "reopen", actor, note, old, "new")
    return True


def link_alert_to_case(conn, alert_id: int, case_id: int,
                       actor: str) -> bool:
    a = _get_alert(conn, alert_id)
    if not a:
        return False
    old = a["status"]
    now = _utcnow()
    try:
        conn.execute(
            "INSERT INTO case_alerts (case_id, alert_id, added_by) "
            "VALUES (?, ?, ?) "
            "ON CONFLICT(case_id, alert_id) DO NOTHING",
            (case_id, alert_id, actor),
        )
    except Exception:
        # On SQLite versions without ON CONFLICT support — fall back to a
        # best-effort SELECT-then-INSERT. Race condition is benign because
        # the unique index will reject the second writer.
        already = conn.execute(
            "SELECT 1 FROM case_alerts WHERE case_id = ? AND alert_id = ?",
            (case_id, alert_id),
        ).fetchone()
        if not already:
            conn.execute(
                "INSERT INTO case_alerts (case_id, alert_id, added_by) "
                "VALUES (?, ?, ?)",
                (case_id, alert_id, actor),
            )
    conn.execute(
        "UPDATE alerts SET case_id = ?, status = 'case_opened', updated_at = ? "
        "WHERE id = ?",
        (case_id, now, alert_id),
    )
    _log_action(conn, alert_id, "case_linked", actor,
                old_status=old, new_status="case_opened",
                details={"case_id": case_id})
    return True


def list_alerts(conn, *, status: Optional[Iterable[str]] = None,
                severity: Optional[Iterable[str]] = None,
                assigned_to: Optional[int] = None,
                limit: int = 200, offset: int = 0) -> list:
    """Query the alerts table for the SOC alerts feed."""
    where = ["1=1"]
    params: list = []
    if status:
        statuses = list(status)
        where.append("status IN (%s)" % ",".join("?" * len(statuses)))
        params += statuses
    if severity:
        sevs = list(severity)
        where.append("severity IN (%s)" % ",".join("?" * len(sevs)))
        params += sevs
    if assigned_to is not None:
        where.append("assigned_to = ?")
        params.append(int(assigned_to))
    rows = conn.execute(
        f"SELECT * FROM alerts WHERE {' AND '.join(where)} "
        f"ORDER BY last_seen DESC LIMIT ? OFFSET ?",
        params + [int(limit), int(offset)],
    ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["details"] = json.loads(d.get("details") or "{}") or {}
        except Exception:
            d["details"] = {}
        out.append(d)
    return out


__all__ = [
    "create_or_update_alert",
    "acknowledge_alert",
    "assign_alert",
    "close_alert",
    "mark_false_positive",
    "reopen_alert",
    "link_alert_to_case",
    "list_alerts",
    "list_alert_observations",
]
