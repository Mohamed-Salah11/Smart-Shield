"""
app/services/soc_recommendations.py
-----------------------------------
SOC response-recommendation workflow (Phase 9).

The SOC Portal does NOT change firewall state directly. Instead, an analyst
files a *recommendation* (e.g. "block 1.2.3.4"). SmartShield Core firewall
admin then reviews it and approves or rejects it before any firewall action
is applied. This keeps SOC team work and firewall control separated while
still letting the SOC drive a response.

Status lifecycle
----------------
    pending
      ├─ approved_by_soc ─ sent_to_core ─ approved_by_core ─ applied
      │                                  └ rejected_by_core
      │                                  └ (apply error) ──── failed
      └─ rejected_by_soc

All functions take an open sqlite3 connection (``conn``) so they work both
inside a Flask request and from background workers.
"""

from datetime import datetime, timezone


VALID_STATUSES = {
    "pending", "approved_by_soc", "rejected_by_soc", "sent_to_core",
    "approved_by_core", "rejected_by_core", "applied", "failed",
}

# action_type values the workflow understands. target_value is the operand
# (an IP for block/unblock).
VALID_ACTIONS = {"block_ip", "unblock_ip", "reload_firewall"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _validate_action_target(action_type: str, target_value: str) -> tuple:
    """Return ``(ok, error)`` for an action's operand.

    block/unblock require a real IP; reload_firewall takes no meaningful target
    (empty, or the literals ``pf``/``firewall``). Stops a recommendation with a
    bogus target from being filed, approved, and silently no-op'd by the PF push.
    """
    import ipaddress
    if action_type in ("block_ip", "unblock_ip"):
        try:
            ipaddress.ip_address((target_value or "").strip())
        except ValueError:
            return False, "target_value must be a valid IP address"
    if action_type == "reload_firewall" and target_value:
        if target_value not in ("pf", "firewall"):
            return False, "reload_firewall target must be empty, 'pf', or 'firewall'"
    return True, ""


def create_recommendation(conn, *, action_type: str, target_value: str,
                          reason: str = "", severity: str = "medium",
                          created_by: str = "", source_alert_id: str = "") -> dict:
    """
    File a new SOC recommendation in the ``pending`` state.

    Returns ``{"ok": bool, "id": int|None, "message": str}``.
    """
    action_type = (action_type or "").strip()
    target_value = (target_value or "").strip()
    if action_type not in VALID_ACTIONS:
        return {"ok": False, "id": None,
                "message": f"unknown action_type {action_type!r}"}
    if not target_value:
        return {"ok": False, "id": None, "message": "target_value is required"}
    ok_target, target_err = _validate_action_target(action_type, target_value)
    if not ok_target:
        return {"ok": False, "id": None, "message": target_err}
    if severity not in ("critical", "high", "medium", "low", "info"):
        severity = "medium"

    cur = conn.execute(
        """INSERT INTO soc_recommendations
           (created_at, source_alert_id, action_type, target_value,
            reason, severity, status, created_by)
           VALUES (?,?,?,?,?,?,'pending',?)""",
        (_now(), source_alert_id, action_type, target_value,
         reason, severity, created_by),
    )
    conn.commit()
    return {"ok": True, "id": cur.lastrowid,
            "message": f"recommendation #{cur.lastrowid} filed"}


def list_recommendations(conn, status=None, limit: int = 200) -> list:
    """Return recommendations, newest first, optionally filtered by status.

    ``status`` may be a single status string or an iterable of statuses.
    """
    sql = "SELECT * FROM soc_recommendations"
    params: list = []
    if status:
        statuses = [status] if isinstance(status, str) else list(status)
        sql += " WHERE status IN (%s)" % ",".join("?" * len(statuses))
        params += statuses
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(int(limit))
    return [dict(r) for r in conn.execute(sql, params).fetchall()]


def get_recommendation(conn, rec_id: int):
    row = conn.execute(
        "SELECT * FROM soc_recommendations WHERE id=?", (rec_id,)
    ).fetchone()
    return dict(row) if row else None


def _transition(conn, rec_id: int, expect, new_status: str,
                actor_col: str, actor: str) -> dict:
    """Move a recommendation to *new_status* iff its current status is allowed.

    ``expect`` is a set of acceptable current statuses (guards against double
    submission / out-of-order transitions).
    """
    rec = get_recommendation(conn, rec_id)
    if not rec:
        return {"ok": False, "message": f"recommendation #{rec_id} not found"}
    if rec["status"] not in expect:
        return {"ok": False,
                "message": f"recommendation #{rec_id} is {rec['status']}, "
                           f"cannot move to {new_status}"}
    conn.execute(
        f"UPDATE soc_recommendations SET status=?, {actor_col}=?, reviewed_at=? "
        "WHERE id=?",
        (new_status, actor, _now(), rec_id),
    )
    conn.commit()
    return {"ok": True, "message": f"recommendation #{rec_id} → {new_status}"}


# ── SOC-side review (inside the SOC Portal) ─────────────────────────────────

def soc_approve(conn, rec_id: int, analyst: str) -> dict:
    """SOC analyst endorses the recommendation and forwards it to Core."""
    res = _transition(conn, rec_id, {"pending"}, "approved_by_soc",
                       "reviewed_by", analyst)
    if res["ok"]:
        conn.execute(
            "UPDATE soc_recommendations SET status='sent_to_core', exported_at=? "
            "WHERE id=?", (_now(), rec_id),
        )
        conn.commit()
        res["message"] = f"recommendation #{rec_id} sent to SmartShield Core"
    return res


def soc_reject(conn, rec_id: int, analyst: str) -> dict:
    return _transition(conn, rec_id, {"pending"}, "rejected_by_soc",
                       "reviewed_by", analyst)


# ── Core-side review (firewall admin) ───────────────────────────────────────

def core_reject(conn, rec_id: int, admin: str) -> dict:
    return _transition(conn, rec_id, {"sent_to_core"}, "rejected_by_core",
                       "core_approved_by", admin)


def core_approve_and_apply(conn, rec_id: int, admin: str) -> dict:
    """
    Firewall admin approves a SOC recommendation; SmartShield Core applies the
    firewall action and records the outcome (``applied`` or ``failed``).
    """
    rec = get_recommendation(conn, rec_id)
    if not rec:
        return {"ok": False, "message": f"recommendation #{rec_id} not found"}
    if rec["status"] != "sent_to_core":
        return {"ok": False,
                "message": f"recommendation #{rec_id} is {rec['status']}, "
                           "expected sent_to_core"}

    conn.execute(
        "UPDATE soc_recommendations SET status='approved_by_core', "
        "core_approved_by=?, core_approved_at=? WHERE id=?",
        (admin, _now(), rec_id),
    )
    conn.commit()

    # Apply the approved firewall action via the SOC blocklist service so it
    # goes through the standard <soc_blocklist> PF table path.
    ok, message = _apply_action(conn, rec["action_type"], rec["target_value"],
                                admin)
    final = "applied" if ok else "failed"
    conn.execute(
        "UPDATE soc_recommendations SET status=? WHERE id=?", (final, rec_id),
    )
    conn.commit()
    return {"ok": ok, "message": message, "status": final}


def _apply_action(conn, action_type: str, target_value: str,
                  admin: str) -> tuple:
    """Apply an approved recommendation. Returns ``(ok, message)``.

    Blocks/unblocks are written to ``soc_blocked_ips`` (the source of truth)
    and then flushed into the ``<soc_blocklist>`` PF table — the same path the
    SOC portal's L3 quick-action uses.
    """
    ok_target, target_err = _validate_action_target(action_type, target_value)
    if not ok_target:
        return False, target_err
    try:
        if action_type == "block_ip":
            conn.execute(
                "INSERT INTO soc_blocked_ips (ip, note, blocked_by) VALUES (?,?,?) "
                "ON CONFLICT(ip) DO UPDATE SET note=excluded.note, "
                "blocked_by=excluded.blocked_by, created_at=CURRENT_TIMESTAMP",
                (target_value, f"SOC recommendation, approved by {admin}", admin),
            )
            conn.commit()
        elif action_type == "unblock_ip":
            conn.execute("DELETE FROM soc_blocked_ips WHERE ip=?", (target_value,))
            conn.commit()
        elif action_type == "reload_firewall":
            # Approved by admin — reload PF through the privileged allowlist.
            # We never shell out to `pfctl` directly from any HTTP route.
            from app.services.priv_helper import run_privileged
            r = run_privileged("service.action", service_name="pf", action="reload")
            ok = getattr(r, "returncode", 0) == 0
            msg = (getattr(r, "stderr", "") or getattr(r, "stdout", "") or "").strip()
            return ok, msg or ("PF reloaded" if ok else "PF reload failed")
        else:
            return False, f"unknown action_type {action_type!r}"

        from app.services.soc_blocklist import push_soc_blocklist_to_pf
        push = push_soc_blocklist_to_pf(conn)
        return bool(push.get("ok")), str(push.get("message", ""))
    except Exception as exc:  # pragma: no cover - defensive
        return False, f"apply failed: {exc}"
