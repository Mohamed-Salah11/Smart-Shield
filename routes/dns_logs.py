"""
routes/dns_logs.py
------------------
Dedicated DNS log views (Wave E).

Mirrors :mod:`routes.firewall_logs` but for the ``dns_events`` table
populated by the DNS collector in
:func:`app.services.siem_collector._collect_dns_queries`.

Endpoints
---------
``GET  /dns/logs``                — HTML page.
``GET  /dns/logs/api/list``       — Paginated rows.
``GET  /dns/logs/api/stats``      — Top clients / top blocked domains.
``GET  /dns/logs/api/mode``       — Current logging mode.
``POST /dns/logs/api/mode``       — Update logging mode (superuser only).
"""

from __future__ import annotations

from flask import Blueprint, jsonify, render_template, request, session

from app.api_auth import api_permission_required
from app.auth_utils import login_required, superuser_required

dns_logs_bp = Blueprint("dns_logs", __name__, url_prefix="/dns/logs")


def _conn():
    from app.audit_log import _events_db
    return _events_db()


def _parse_int(value, default=None, lo=None, hi=None):
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    if lo is not None and n < lo:
        return lo
    if hi is not None and n > hi:
        return hi
    return n


def _build_where(args) -> tuple[str, list]:
    where = ["1=1"]
    params: list = []
    if (args.get("time_from") or "").strip():
        where.append("ts >= ?"); params.append(args["time_from"].strip())
    if (args.get("time_to") or "").strip():
        where.append("ts <= ?"); params.append(args["time_to"].strip())
    client_ip = (args.get("client_ip") or "").strip()
    if client_ip:
        where.append("client_ip = ?"); params.append(client_ip)
    qtype = (args.get("qtype") or "").strip().upper()
    if qtype:
        where.append("qtype = ?"); params.append(qtype)
    rcode = (args.get("rcode") or "").strip().upper()
    if rcode:
        where.append("rcode = ?"); params.append(rcode)
    if (args.get("blocked") or "").strip().lower() in ("1", "true", "yes"):
        where.append("blocked = 1")
    search = (args.get("search") or "").strip()
    if search:
        like = f"%{search}%"
        where.append("(query LIKE ? OR matched_domain LIKE ? OR hostname LIKE ?)")
        params += [like, like, like]
    return " AND ".join(where), params


@dns_logs_bp.route("")
@login_required
def page():
    return render_template("dns_logs.html")


@dns_logs_bp.route("/api/list")
@login_required
@api_permission_required("api.logs.read")
def api_list():
    limit  = _parse_int(request.args.get("limit"),  default=100, lo=1, hi=500)
    offset = _parse_int(request.args.get("offset"), default=0,   lo=0)
    where, params = _build_where(request.args)
    conn = _conn()
    if conn is None:
        return jsonify({"ok": False, "rows": [], "total": 0}), 503
    try:
        total = conn.execute(
            f"SELECT COUNT(*) AS c FROM dns_events WHERE {where}", params
        ).fetchone()["c"]
        rows = conn.execute(
            f"SELECT * FROM dns_events WHERE {where} "
            f"ORDER BY id DESC LIMIT ? OFFSET ?",
            params + [limit, offset],
        ).fetchall()
    finally:
        conn.close()
    return jsonify({
        "ok": True,
        "rows":  [dict(r) for r in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    })


@dns_logs_bp.route("/api/stats")
@login_required
@api_permission_required("api.logs.read")
def api_stats():
    where, params = _build_where(request.args)
    conn = _conn()
    if conn is None:
        return jsonify({"ok": False}), 503
    try:
        def _top(col):
            return [
                {col: r[0], "count": r[1]}
                for r in conn.execute(
                    f"SELECT {col}, COUNT(*) FROM dns_events "
                    f"WHERE {where} AND {col} IS NOT NULL AND {col} != '' "
                    f"GROUP BY {col} ORDER BY 2 DESC LIMIT 10",
                    params,
                )
            ]
        blocked_count = conn.execute(
            f"SELECT COUNT(*) FROM dns_events WHERE {where} AND blocked = 1", params
        ).fetchone()[0]
        total = conn.execute(
            f"SELECT COUNT(*) FROM dns_events WHERE {where}", params
        ).fetchone()[0]
        result = {
            "ok":      True,
            "total":   total,
            "blocked": blocked_count,
            "top_client": _top("client_ip"),
            "top_query":  _top("query"),
            "top_qtype":  _top("qtype"),
        }
    finally:
        conn.close()
    return jsonify(result)


@dns_logs_bp.route("/api/mode", methods=["GET"])
@login_required
@api_permission_required("api.logs.read")
def api_mode_get():
    from app.services.siem_collector import _read_dns_logging_mode
    return jsonify({"ok": True, "mode": _read_dns_logging_mode()})


@dns_logs_bp.route("/api/mode", methods=["POST"])
@superuser_required
def api_mode_set():
    """Set DNS query logging mode. Restricted to superuser — high-volume
    `all` mode can expose browsing metadata and must be a deliberate choice."""
    from app.database import get_db
    from app.audit_log import log_event
    data = request.get_json(silent=True) or {}
    mode = (data.get("mode") or "").strip().lower()
    if mode not in ("off", "blocked_only", "all"):
        return jsonify({"ok": False,
                        "message": "mode must be off | blocked_only | all"}), 400
    conn = get_db()
    conn.execute(
        "INSERT INTO siem_state (key, value, updated_at) "
        "VALUES ('dns_logging_mode', ?, CURRENT_TIMESTAMP) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value, "
        "                               updated_at = CURRENT_TIMESTAMP",
        (mode,),
    )
    conn.commit()
    log_event(
        category="admin_audit", action="dns_logging_mode_changed",
        username=session.get("username") or "admin",
        remote_addr=request.remote_addr or "",
        details={"mode": mode}, severity="medium",
    )
    return jsonify({"ok": True, "mode": mode})
