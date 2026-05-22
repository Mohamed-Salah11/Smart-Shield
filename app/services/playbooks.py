"""
app/services/playbooks.py
-------------------------
A minimal automation engine: trigger → ordered steps → optional approval.

Playbooks are matched against every event going through ``log_event``. A
playbook fires when:

  * playbooks.enabled = 1
  * the event's action equals trigger_action (default ``correlation_match``)
  * the event's category equals trigger_category (default ``security``)
  * the event's severity is at least trigger_min_sev

When a playbook fires we create a ``playbook_runs`` row and execute its
steps in order. Steps that have ``approval_required: true`` halt the run
and leave it in ``awaiting_approval``; the SOC analyst can approve from
the Playbooks page, which resumes execution from the pending step.

Supported step types:

  ``log``        — record a custom event (e.g. for downstream rules)
  ``open_case``  — create a ``siem_cases`` row
  ``block_ip``   — add an IP to the ``soc_blocklist`` PF table
  ``notify``     — emit a high-severity ``playbook_notify`` event so
                   alerting (email, webhook, syslog) can pick it up
"""

from __future__ import annotations

import json
import threading


_SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_PLAYBOOK_RUNNING = threading.local()        # guard against recursion
_RUN_DETAILS_LIMIT = 1024


def _meets_severity(event_sev: str, min_sev: str) -> bool:
    return _SEV_ORDER.get((event_sev or "info").lower(), 0) >= \
           _SEV_ORDER.get((min_sev   or "medium").lower(), 2)


# ---------------------------------------------------------------------------
# Step implementations
# ---------------------------------------------------------------------------

def _step_log(args: dict, ctx: dict) -> dict:
    from app.audit_log import log_event
    log_event(
        category=args.get("category", "system"),
        action=args.get("action", "playbook_log"),
        username=ctx.get("playbook_name", "playbook"),
        remote_addr="",
        severity=args.get("severity", "info"),
        details={"message": args.get("message", ""),
                 "playbook_run_id": ctx.get("run_id")},
    )
    return {"ok": True, "message": "logged"}


def _step_open_case(args: dict, ctx: dict) -> dict:
    from app.audit_log import _events_db
    conn = _events_db()
    if conn is None:
        return {"ok": False, "message": "events DB unavailable"}
    try:
        title = (args.get("title")
                 or f"[Playbook] {ctx.get('playbook_name','run')}")
        cur = conn.execute(
            "INSERT INTO siem_cases (title, description, severity, status, "
            "created_by, source_event, tags) VALUES (?,?,?,?,?,?,?)",
            (title[:200],
             (args.get("description") or "Opened automatically by a playbook.")[:1000],
             args.get("severity", ctx.get("event_severity") or "high"),
             "open",
             "playbook",
             ctx.get("event_ts") or "",
             f"auto,playbook,run:{ctx.get('run_id')}"),
        )
        conn.commit()
        return {"ok": True, "message": f"case {cur.lastrowid} opened"}
    except Exception as exc:
        return {"ok": False, "message": f"open_case failed: {exc}"}
    finally:
        try: conn.close()
        except Exception: pass


def _step_block_ip(args: dict, ctx: dict) -> dict:
    # Resolve target IP from args or event context.
    ip = (args.get("ip") or "").strip()
    if not ip:
        ev = ctx.get("event") or {}
        ip = (ev.get("remote_addr") or
              (ev.get("details") or {}).get("src_ip") or
              (ev.get("details") or {}).get("source_ip") or "").strip()
    if not ip:
        return {"ok": False, "message": "no IP available to block"}

    import sys as _sys
    if not _sys.platform.startswith("freebsd"):
        return {"ok": True, "message": f"dry-run: would block {ip}"}

    try:
        from app.services.priv_helper import run_privileged
        r = run_privileged("pf.table_add", table="soc_blocklist", ip=ip)
        ok = r.returncode == 0
        msg = (r.stderr or r.stdout or "").strip() or ("blocked" if ok else "pfctl failed")
        return {"ok": ok, "message": f"{msg} ({ip})"}
    except Exception as exc:
        return {"ok": False, "message": f"block_ip failed: {exc}"}


def _step_notify(args: dict, ctx: dict) -> dict:
    from app.audit_log import log_event
    log_event(
        category="alert",
        action="playbook_notify",
        severity=args.get("severity", "high"),
        username=ctx.get("playbook_name", "playbook"),
        remote_addr="",
        details={
            "channel":         args.get("channel", "log"),  # log | future: email, webhook
            "message":         args.get("message", "")[:_RUN_DETAILS_LIMIT],
            "playbook_run_id": ctx.get("run_id"),
            "event":           ctx.get("event"),
        },
    )
    return {"ok": True, "message": f"notified via {args.get('channel','log')}"}


_STEP_HANDLERS = {
    "log":       _step_log,
    "open_case": _step_open_case,
    "block_ip":  _step_block_ip,
    "notify":    _step_notify,
}


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

def _match_playbooks(conn, event: dict) -> list:
    try:
        rows = conn.execute(
            "SELECT * FROM playbooks WHERE enabled = 1"
        ).fetchall()
    except Exception:
        return []
    matches = []
    action   = (event.get("action") or "").strip()
    category = (event.get("category") or "").strip()
    severity = (event.get("severity") or "info").strip().lower()
    for r in rows:
        if (r["trigger_action"] or "") and r["trigger_action"] != action:
            continue
        if (r["trigger_category"] or "") and r["trigger_category"] != category:
            continue
        if not _meets_severity(severity, r["trigger_min_sev"] or "medium"):
            continue
        matches.append(dict(r))
    return matches


def _execute_steps(conn, run_id: int, steps: list, ctx: dict, start_index: int = 0) -> str:
    """
    Execute *steps* starting at *start_index*. Returns the run status string.
    Persists progress into playbook_runs.steps_log_json.
    """
    log: list = []
    try:
        row = conn.execute(
            "SELECT steps_log_json FROM playbook_runs WHERE id=?", (run_id,)
        ).fetchone()
        if row and row["steps_log_json"]:
            log = json.loads(row["steps_log_json"]) or []
    except Exception:
        log = []

    for idx in range(start_index, len(steps)):
        step    = steps[idx] if isinstance(steps[idx], dict) else {}
        s_type  = (step.get("type") or "").lower()
        args    = step.get("args") or {}
        approval = bool(step.get("approval_required"))

        if approval:
            log.append({"index": idx, "type": s_type, "status": "awaiting_approval"})
            conn.execute(
                "UPDATE playbook_runs SET status='awaiting_approval', "
                "steps_log_json=? WHERE id=?",
                (json.dumps(log), run_id),
            )
            conn.commit()
            return "awaiting_approval"

        handler = _STEP_HANDLERS.get(s_type)
        if not handler:
            log.append({"index": idx, "type": s_type, "status": "skipped",
                        "message": "unknown step type"})
            continue
        try:
            result = handler(args, ctx) or {}
        except Exception as exc:
            result = {"ok": False, "message": f"step crashed: {exc}"}
        log.append({"index": idx, "type": s_type, "status": "ok" if result.get("ok") else "failed",
                    "message": (result.get("message") or "")[:_RUN_DETAILS_LIMIT]})

    conn.execute(
        "UPDATE playbook_runs SET status='done', finished_at=CURRENT_TIMESTAMP, "
        "steps_log_json=? WHERE id=?",
        (json.dumps(log), run_id),
    )
    conn.commit()
    return "done"


def on_event(event: dict) -> None:
    """
    Entry point called from ``log_event`` after persistence. Picks every
    matching playbook and either runs its steps or queues an approval.
    Guarded against recursion so a playbook's own emitted events don't
    re-trigger the same playbook.
    """
    if getattr(_PLAYBOOK_RUNNING, "active", False):
        return
    _PLAYBOOK_RUNNING.active = True
    try:
        from app.audit_log import _events_db
        conn = _events_db()
        if conn is None:
            return
        try:
            matches = _match_playbooks(conn, event)
            if not matches:
                return
            for pb in matches:
                try:
                    steps = json.loads(pb.get("steps_json") or "[]")
                except Exception:
                    steps = []
                if not isinstance(steps, list) or not steps:
                    continue
                cur = conn.execute(
                    "INSERT INTO playbook_runs (playbook_id, trigger_event_ts, "
                    "trigger_event_action, status) VALUES (?,?,?,?)",
                    (pb["id"], event.get("timestamp") or "",
                     event.get("action") or "", "running"),
                )
                run_id = cur.lastrowid
                conn.commit()
                ctx = {
                    "run_id":          run_id,
                    "playbook_name":   pb.get("name") or "",
                    "event":           event,
                    "event_ts":        event.get("timestamp") or "",
                    "event_severity":  event.get("severity") or "info",
                }
                _execute_steps(conn, run_id, steps, ctx, start_index=0)
        finally:
            try: conn.close()
            except Exception: pass
    finally:
        _PLAYBOOK_RUNNING.active = False


# ---------------------------------------------------------------------------
# Approval / resume — called from the Playbooks page
# ---------------------------------------------------------------------------

def approve_run(conn, run_id: int, approver: str) -> dict:
    row = conn.execute(
        "SELECT pr.id, pr.playbook_id, pr.status, pr.steps_log_json, "
        "       p.steps_json, p.name "
        "FROM playbook_runs pr JOIN playbooks p ON p.id = pr.playbook_id "
        "WHERE pr.id = ?",
        (run_id,),
    ).fetchone()
    if not row:
        return {"ok": False, "message": "run not found"}
    if row["status"] != "awaiting_approval":
        return {"ok": False, "message": f"run is {row['status']}, not awaiting approval"}
    try:
        steps = json.loads(row["steps_json"] or "[]")
        log   = json.loads(row["steps_log_json"] or "[]")
    except Exception:
        return {"ok": False, "message": "corrupt playbook payload"}
    pending = [i for i, l in enumerate(log) if l.get("status") == "awaiting_approval"]
    if not pending:
        return {"ok": False, "message": "no pending step found"}
    pending_idx = pending[0]
    # Mark the gate step as approved and continue from the next index.
    log[pending_idx]["status"]   = "approved"
    log[pending_idx]["approver"] = approver
    conn.execute(
        "UPDATE playbook_runs SET status='running', steps_log_json=? WHERE id=?",
        (json.dumps(log), run_id),
    )
    conn.commit()
    ctx = {"run_id": run_id, "playbook_name": row["name"], "event": {}}
    status = _execute_steps(conn, run_id, steps, ctx,
                            start_index=pending_idx + 1)
    return {"ok": True, "status": status}


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

def list_playbooks(conn) -> list:
    rows = conn.execute("SELECT * FROM playbooks ORDER BY name").fetchall()
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["steps"] = json.loads(d.get("steps_json") or "[]")
        except Exception:
            d["steps"] = []
        out.append(d)
    return out


def list_runs(conn, limit: int = 50) -> list:
    rows = conn.execute(
        "SELECT pr.*, p.name AS playbook_name FROM playbook_runs pr "
        "LEFT JOIN playbooks p ON p.id = pr.playbook_id "
        "ORDER BY pr.id DESC LIMIT ?",
        (int(limit or 50),),
    ).fetchall()
    return [dict(r) for r in rows]


def upsert_playbook(conn, payload: dict) -> dict:
    name = (payload.get("name") or "").strip()
    if not name:
        return {"ok": False, "message": "name is required"}
    steps = payload.get("steps") or []
    if isinstance(steps, str):
        try:
            steps = json.loads(steps or "[]")
        except Exception:
            return {"ok": False, "message": "steps must be valid JSON"}
    if not isinstance(steps, list):
        return {"ok": False, "message": "steps must be a list"}
    pid = payload.get("id")
    fields = (
        name,
        (payload.get("description") or "")[:1000],
        1 if payload.get("enabled", True) else 0,
        (payload.get("trigger_action") or "correlation_match").strip(),
        (payload.get("trigger_category") or "security").strip(),
        (payload.get("trigger_min_sev") or "medium").strip().lower(),
        json.dumps(steps),
    )
    if pid:
        conn.execute(
            "UPDATE playbooks SET name=?, description=?, enabled=?, trigger_action=?, "
            "trigger_category=?, trigger_min_sev=?, steps_json=?, "
            "updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (*fields, int(pid)),
        )
    else:
        conn.execute(
            "INSERT INTO playbooks (name, description, enabled, trigger_action, "
            "trigger_category, trigger_min_sev, steps_json, created_by) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (*fields, payload.get("created_by") or "admin"),
        )
    conn.commit()
    return {"ok": True}


def delete_playbook(conn, playbook_id: int) -> None:
    conn.execute("DELETE FROM playbooks WHERE id=?", (int(playbook_id),))
    conn.commit()
