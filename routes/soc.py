"""
routes/soc.py
-------------
SOC (Security Operations Center) APIs.

The legacy HTML consoles at /soc/l1 and /soc/l2 have been replaced by the
unified SOC portal at /soc-portal. Those endpoints now return a 301 redirect
to the portal's alerts page so old bookmarks keep working.

The /soc/api/l1/* and /soc/api/l2/* JSON endpoints are kept (admin-session
authenticated) for any external tooling that already consumes them; new
clients should prefer the /soc-portal/api/* surface, which is authenticated
with the dedicated SOC session.
"""

import json as _json

from flask import Blueprint, jsonify, redirect, render_template, request, session, url_for

from app.api_auth import api_permission_required
from app.auth_utils import login_required

soc_bp = Blueprint("soc", __name__, url_prefix="/soc")


def _resolve_event_uuid(conn, data: dict) -> str:
    """Return the canonical event_uuid for an action request.

    Prefer ``event_uuid`` (sent by the post-Wave-A frontend). For legacy
    browser tabs still posting ``event_key`` (the ISO-8601 timestamp),
    resolve the timestamp to a uuid via the events table.  Returns "" when
    nothing resolves — caller treats that as a 400.
    """
    uuid_in = (data.get("event_uuid") or "").strip()
    if uuid_in:
        return uuid_in
    legacy = (data.get("event_key") or "").strip()
    if not legacy:
        return ""
    try:
        row = conn.execute(
            "SELECT event_uuid FROM events WHERE ts = ? "
            "ORDER BY id DESC LIMIT 1",
            (legacy,),
        ).fetchone()
        if row and row["event_uuid"]:
            return row["event_uuid"]
    except Exception:
        pass
    return ""


# ---------------------------------------------------------------------------
# Legacy HTML console routes — redirect to the unified SOC portal.
# ---------------------------------------------------------------------------

@soc_bp.route("/l1")
@login_required
def soc_l1():
    """Legacy L1 triage console — redirected to the SOC portal alerts page."""
    return redirect(url_for("soc_portal.alerts"), code=301)


@soc_bp.route("/l2")
@login_required
def soc_l2():
    """Legacy L2 investigation workbench — redirected to the SOC portal cases page."""
    return redirect(url_for("soc_portal.cases"), code=301)


# ---------------------------------------------------------------------------
# L1 APIs
# ---------------------------------------------------------------------------

@soc_bp.route("/api/l1/queue")
@login_required
def l1_queue():
    """
    Return the SOC L1 alert queue — security + IDS + session events enriched
    with any analyst action taken (acknowledge / false_positive / escalated).

    Query params:
      status  — 'new' | 'acknowledged' | 'false_positive' | 'escalated' | 'all' (default all)
      limit   — max events (default 200, max 500)
    """
    from app.audit_log import tail_events_since
    from app.database import get_db

    status_filter = request.args.get("status", "all").strip().lower()
    try:
        limit = min(int(request.args.get("limit", 200) or 200), 500)
    except (ValueError, TypeError):
        limit = 200

    # L1 triage queue spans security/IDS/session events plus privileged
    # command executions and system config changes so analysts can see what
    # operators actually ran in the live CLI and what changed on the box.
    events = tail_events_since(
        limit=500,
        categories=["security", "ids", "session", "privileged", "system"],
    )

    # Build lookups of latest action per event — keyed by uuid (preferred,
    # collision-safe) AND legacy timestamp (covers pre-v35 rows whose
    # event_uuid backfill missed because the events row had aged out).
    conn = get_db()
    action_map: dict = {}        # by event_uuid
    action_legacy: dict = {}     # by timestamp
    if events:
        uuids = [e.get("event_uuid", "") for e in events if e.get("event_uuid")]
        keys  = [e.get("timestamp", "")  for e in events if e.get("timestamp")]
        if uuids:
            u_ph = ",".join("?" * len(uuids))
            for r in conn.execute(
                f"SELECT event_uuid, action, taken_by, taken_at, note, case_id "
                f"FROM siem_alert_actions WHERE event_uuid IN ({u_ph}) "
                f"ORDER BY taken_at ASC",
                uuids,
            ):
                if r["event_uuid"]:
                    action_map[r["event_uuid"]] = {
                        "action_status":   r["action"],
                        "action_taken_by": r["taken_by"],
                        "action_taken_at": r["taken_at"],
                        "action_note":     r["note"],
                        "case_id":         r["case_id"],
                    }
        if keys:
            k_ph = ",".join("?" * len(keys))
            for r in conn.execute(
                f"SELECT event_key, action, taken_by, taken_at, note, case_id "
                f"FROM siem_alert_actions WHERE event_key IN ({k_ph}) "
                f"ORDER BY taken_at ASC",
                keys,
            ):
                action_legacy[r["event_key"]] = {
                    "action_status":   r["action"],
                    "action_taken_by": r["taken_by"],
                    "action_taken_at": r["taken_at"],
                    "action_note":     r["note"],
                    "case_id":         r["case_id"],
                }

    # Merge action info into events: uuid hit wins; timestamp is fallback.
    enriched = []
    for e in events:
        ts = e.get("timestamp", "")
        uu = e.get("event_uuid", "")
        act = (action_map.get(uu) if uu else None) or action_legacy.get(ts, {})
        merged = {**e, **act}
        if not act:
            merged["action_status"] = None

        # Apply status filter
        if status_filter == "new" and merged.get("action_status"):
            continue
        if status_filter in ("acknowledged", "false_positive", "escalated"):
            if merged.get("action_status") != status_filter:
                continue

        enriched.append(merged)
        if len(enriched) >= limit:
            break

    return jsonify({"ok": True, "events": enriched, "count": len(enriched)})


@soc_bp.route("/api/l1/acknowledge", methods=["POST"])
@login_required
@api_permission_required("api.soc.manage")
def l1_acknowledge():
    """Mark an alert as acknowledged by the L1 analyst."""
    from app.audit_log import log_soc_event
    from app.database import get_db

    data      = request.get_json(silent=True) or {}
    event_key = (data.get("event_key") or "").strip()
    note      = (data.get("note") or "").strip()
    conn = get_db()
    event_uuid = _resolve_event_uuid(conn, data)
    if not (event_uuid or event_key):
        return jsonify({"ok": False, "message": "event_uuid required"}), 400

    taken_by = session.get("username") or "analyst"
    conn.execute(
        "INSERT INTO siem_alert_actions "
        "(event_key, event_uuid, event_action, action, taken_by, note) "
        "VALUES (?,?,?,?,?,?)",
        (event_key, event_uuid, data.get("event_action", ""),
         "acknowledged", taken_by, note),
    )
    conn.commit()
    log_soc_event(category="system", action="siem_alert_acknowledged",
                  username=taken_by, remote_addr=request.remote_addr,
                  details={"event_uuid": event_uuid,
                           "event_key": event_key, "note": note})
    return jsonify({"ok": True})


@soc_bp.route("/api/l1/escalate", methods=["POST"])
@login_required
@api_permission_required("api.soc.manage")
def l1_escalate():
    """
    Escalate an alert to L2: create a SIEM case and record the escalation.

    Body: {event_key, event_action, title, note, severity, source_event (full event obj)}
    """
    from app.audit_log import log_soc_event
    from app.database import get_db

    data      = request.get_json(silent=True) or {}
    event_key = (data.get("event_key") or "").strip()
    title     = (data.get("title") or "").strip()
    note      = (data.get("note") or "").strip()
    severity  = data.get("severity", "high")
    if severity not in ("critical", "high", "medium", "low"):
        severity = "high"
    conn = get_db()
    event_uuid = _resolve_event_uuid(conn, data)
    if not (event_uuid or event_key) or not title:
        return jsonify({
            "ok": False,
            "message": "event_uuid and title are required",
        }), 400

    taken_by = session.get("username") or "analyst"
    source_event = _json.dumps(data.get("source_event") or {})

    cur = conn.execute(
        """INSERT INTO siem_cases
           (title, description, severity, status, created_by, source_event, tags)
           VALUES (?,?,?,?,?,?,?)""",
        (title, note, severity, "open", taken_by, source_event, "escalated-from-l1"),
    )
    case_id = cur.lastrowid

    conn.execute(
        """INSERT INTO siem_alert_actions
           (event_key, event_uuid, event_action, action, taken_by, note, case_id)
           VALUES (?,?,?,?,?,?,?)""",
        (event_key, event_uuid, data.get("event_action", ""),
         "escalated", taken_by, note, case_id),
    )
    conn.commit()

    log_soc_event(category="system", action="siem_alert_escalated",
                  username=taken_by, remote_addr=request.remote_addr,
                  details={"event_uuid": event_uuid, "event_key": event_key,
                           "case_id": case_id, "title": title})

    # Notify the L2 SOC tier by email, with a PDF incident report.
    try:
        from app.services.mail_alerts import send_incident_followup
        send_incident_followup(kind="escalated", case_id=case_id,
                               event_key=event_key or event_uuid,
                               target_tier="L2",
                               actor=taken_by, note=note)
    except Exception:
        pass
    return jsonify({"ok": True, "case_id": case_id})


@soc_bp.route("/api/l1/false_positive", methods=["POST"])
@login_required
@api_permission_required("api.soc.manage")
def l1_false_positive():
    """Mark an alert as a false positive."""
    from app.audit_log import log_soc_event
    from app.database import get_db

    data      = request.get_json(silent=True) or {}
    event_key = (data.get("event_key") or "").strip()
    note      = (data.get("note") or "").strip()
    conn = get_db()
    event_uuid = _resolve_event_uuid(conn, data)
    if not (event_uuid or event_key):
        return jsonify({"ok": False, "message": "event_uuid required"}), 400

    taken_by = session.get("username") or "analyst"
    conn.execute(
        "INSERT INTO siem_alert_actions "
        "(event_key, event_uuid, event_action, action, taken_by, note) "
        "VALUES (?,?,?,?,?,?)",
        (event_key, event_uuid, data.get("event_action", ""),
         "false_positive", taken_by, note),
    )
    conn.commit()
    log_soc_event(category="system", action="siem_alert_fp",
                  username=taken_by, remote_addr=request.remote_addr,
                  details={"event_uuid": event_uuid,
                           "event_key": event_key, "note": note})
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# L2 APIs
# ---------------------------------------------------------------------------

@soc_bp.route("/api/l2/timeline")
@login_required
def l2_timeline():
    """
    Return all events involving a specific IP address (as src or dest),
    sorted oldest-first for timeline investigation.

    Query param: ip=x.x.x.x
    """
    from app.audit_log import tail_events_since

    ip = request.args.get("ip", "").strip()
    if not ip:
        return jsonify({"ok": False, "message": "ip param required"}), 400

    all_events = tail_events_since(limit=0)  # no limit — full history
    matched = []
    for e in all_events:
        d = e.get("details") or {}
        src_ips = {
            e.get("remote_addr", ""),
            d.get("src_ip", ""),
            d.get("src", ""),
        }
        dest_ips = {d.get("dest_ip", ""), d.get("dst_ip", ""), d.get("dst", "")}
        if ip in src_ips or ip in dest_ips:
            matched.append(e)

    # Timeline: oldest first
    matched.sort(key=lambda x: x.get("timestamp", ""))
    return jsonify({"ok": True, "ip": ip, "events": matched, "count": len(matched)})


@soc_bp.route("/api/l2/hunt")
@login_required
def l2_hunt():
    """
    Full-featured event search for L2 analysts.
    Proxies to the same audit log with all filter params supported.

    Query params (same as /status/api/logs):
      categories, severities, search, start_ts, end_ts, limit, actions
    """
    from app.audit_log import tail_events_since, search_events_fts

    since      = request.args.get("since",      "").strip()
    start_ts   = request.args.get("start_ts",   "").strip()
    end_ts     = request.args.get("end_ts",     "").strip()
    cats_raw   = request.args.get("categories", "").strip()
    sevs_raw   = request.args.get("severities", "").strip()
    actions_raw = request.args.get("actions",   "").strip()
    search     = request.args.get("search",     "").strip()
    try:
        limit = min(int(request.args.get("limit", 200) or 200), 500)
    except (ValueError, TypeError):
        limit = 200

    categories    = [c.strip() for c in cats_raw.split(",")   if c.strip()] if cats_raw   else None
    severities    = [s.strip() for s in sevs_raw.split(",")   if s.strip()] if sevs_raw   else None
    action_filter = {a.strip() for a in actions_raw.split(",") if a.strip()} if actions_raw else None

    if search:
        # Push the full-text predicate into SQLite so we don't read N×limit
        # rows into Python just to filter most of them out.
        events = search_events_fts(
            query=search, limit=limit,
            categories=categories, severities=severities,
            start_ts=start_ts, end_ts=end_ts,
        )
        if action_filter:
            events = [e for e in events if e.get("action") in action_filter]
    else:
        events = tail_events_since(
            after_ts=since, limit=limit,
            categories=categories, severities=severities,
            start_ts=start_ts, end_ts=end_ts,
        )
        if action_filter:
            events = [e for e in events if e.get("action") in action_filter]

    events = events[:limit]
    latest = events[0].get("timestamp", since) if events else since
    return jsonify({"ok": True, "events": events, "count": len(events), "latest_ts": latest})


@soc_bp.route("/api/l2/asset")
@login_required
def l2_asset():
    """
    Return tracked_hosts record + linked cases for an IP address.
    Query param: ip=x.x.x.x
    """
    from app.database import get_db

    ip = request.args.get("ip", "").strip()
    if not ip:
        return jsonify({"ok": False, "message": "ip param required"}), 400

    conn = get_db()
    host = conn.execute(
        "SELECT * FROM tracked_hosts WHERE ip_address=? LIMIT 1", (ip,)
    ).fetchone()

    cases = conn.execute(
        """SELECT sc.id, sc.title, sc.severity, sc.status, sc.created_at
           FROM siem_cases sc
           WHERE sc.source_event LIKE ?
              OR sc.description LIKE ?
           ORDER BY sc.created_at DESC LIMIT 20""",
        (f"%{ip}%", f"%{ip}%"),
    ).fetchall()

    return jsonify({
        "ok":    True,
        "ip":    ip,
        "asset": dict(host) if host else None,
        "cases": [dict(c) for c in cases],
    })
