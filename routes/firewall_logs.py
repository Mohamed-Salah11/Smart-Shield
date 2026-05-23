"""
routes/firewall_logs.py
-----------------------
Dedicated firewall log views (Wave B).

The generic /status/system-logs page mixes admin audit, SOC actions, system
health, and packet logs into one feed.  This blueprint exposes a focused
firewall-only view that queries the ``firewall_events`` table populated by
the pflog0 collector.

Endpoints
---------
``GET /firewall/logs``                — HTML page.
``GET /firewall/logs/api/list``       — Paginated rows for the table.
``GET /firewall/logs/api/stats``      — Top sources / dest ports / rule hits.
``GET /firewall/logs/api/timeseries`` — Hourly counts by action.

All endpoints require an authenticated admin session.  Read access is gated
by ``api.logs.read``; export by ``api.logs.export``.
"""

from __future__ import annotations

import csv
import io
from datetime import datetime, timedelta, timezone

from flask import Blueprint, jsonify, render_template, request, session, Response

from app.api_auth import api_permission_required
from app.auth_utils import login_required

firewall_logs_bp = Blueprint("firewall_logs", __name__, url_prefix="/firewall/logs")


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _conn():
    """Open a short-lived event-store connection (same path as audit_log)."""
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
    """Translate the request's filter args into a ``WHERE`` clause + params."""
    where: list = ["1=1"]
    params: list = []

    time_from = (args.get("time_from") or "").strip()
    time_to   = (args.get("time_to")   or "").strip()
    if time_from:
        where.append("ts >= ?"); params.append(time_from)
    if time_to:
        where.append("ts <= ?"); params.append(time_to)

    action = (args.get("action") or "").strip().lower()
    if action in ("pass", "block", "reject"):
        where.append("action = ?"); params.append(action)

    interface = (args.get("interface") or "").strip()
    if interface:
        where.append("interface = ?"); params.append(interface)

    direction = (args.get("direction") or "").strip().lower()
    if direction in ("in", "out"):
        where.append("direction = ?"); params.append(direction)

    protocol = (args.get("protocol") or "").strip().lower()
    if protocol:
        where.append("protocol = ?"); params.append(protocol)

    src_ip = (args.get("src_ip") or "").strip()
    if src_ip:
        where.append("src_ip = ?"); params.append(src_ip)

    dst_ip = (args.get("dst_ip") or "").strip()
    if dst_ip:
        where.append("dst_ip = ?"); params.append(dst_ip)

    dst_port = _parse_int(args.get("dst_port"), lo=0, hi=65535)
    if dst_port is not None:
        where.append("dst_port = ?"); params.append(dst_port)

    rule_id = (args.get("rule_id") or "").strip()
    if rule_id:
        where.append("rule_id = ?"); params.append(rule_id)

    # policy_source — only accept canonical sources from
    # ``siem_collector._KNOWN_POLICY_SOURCES`` plus the catch-all bucket.
    policy_source = (args.get("policy_source") or "").strip().lower()
    if policy_source in {
        "user_rule", "default_deny", "captive_portal", "content_policy",
        "hardening", "admin", "ids", "soc", "external_or_unlabeled",
    }:
        where.append("policy_source = ?"); params.append(policy_source)

    # Free-text search across raw_line + hostname + rule_label.
    search = (args.get("search") or "").strip()
    if search:
        like = f"%{search}%"
        where.append(
            "(raw_line LIKE ? OR hostname LIKE ? OR rule_label LIKE ?)"
        )
        params += [like, like, like]

    return " AND ".join(where), params


def _row_to_dict(row) -> dict:
    return {
        "id":             row["id"],
        "event_uuid":     row["event_uuid"] or "",
        "ts":             row["ts"],
        "action":         row["action"],
        "direction":      row["direction"],
        "interface":      row["interface"],
        "ip_version":     row["ip_version"],
        "protocol":       row["protocol"],
        "src_ip":         row["src_ip"],
        "src_port":       row["src_port"],
        "dst_ip":         row["dst_ip"],
        "dst_port":       row["dst_port"],
        "rule_id":        row["rule_id"],
        "rule_label":     row["rule_label"],
        "anchor":         row["anchor"],
        "reason":         row["reason"],
        "tcp_flags":      row["tcp_flags"],
        "icmp_type":      row["icmp_type"],
        "icmp_code":      row["icmp_code"],
        "packet_length":  row["packet_length"],
        "nat_src_ip":     row["nat_src_ip"],
        "nat_src_port":   row["nat_src_port"],
        "nat_dst_ip":     row["nat_dst_ip"],
        "nat_dst_port":   row["nat_dst_port"],
        "hostname":       row["hostname"],
        "mac":            row["mac"],
        "severity":       row["severity"],
        "policy_source":  row["policy_source"],
        "captive_portal": row["captive_portal"],
        "content_policy": row["content_policy"],
        "soc_origin":     row["soc_origin"],
        "raw_line":       row["raw_line"],
        "created_at":     row["created_at"],
    }


# ---------------------------------------------------------------------------
# Page
# ---------------------------------------------------------------------------

@firewall_logs_bp.route("")
@login_required
def page():
    """Render the firewall-logs HTML page (data loaded via the JSON API)."""
    return render_template("firewall_logs.html")


# ---------------------------------------------------------------------------
# JSON API
# ---------------------------------------------------------------------------

@firewall_logs_bp.route("/api/list")
@login_required
@api_permission_required("api.logs.read")
def api_list():
    """Paginated firewall events table."""
    limit  = _parse_int(request.args.get("limit"),  default=100, lo=1, hi=500)
    offset = _parse_int(request.args.get("offset"), default=0,   lo=0)
    where, params = _build_where(request.args)

    conn = _conn()
    if conn is None:
        return jsonify({"ok": False, "rows": [], "total": 0, "message": "DB unavailable"}), 503
    try:
        total = conn.execute(
            f"SELECT COUNT(*) AS c FROM firewall_events WHERE {where}",
            params,
        ).fetchone()["c"]
        rows = conn.execute(
            f"SELECT * FROM firewall_events WHERE {where} "
            f"ORDER BY id DESC LIMIT ? OFFSET ?",
            params + [limit, offset],
        ).fetchall()
    finally:
        conn.close()

    return jsonify({
        "ok":     True,
        "rows":   [_row_to_dict(r) for r in rows],
        "total":  total,
        "limit":  limit,
        "offset": offset,
    })


@firewall_logs_bp.route("/api/stats")
@login_required
@api_permission_required("api.logs.read")
def api_stats():
    """Top sources, destinations, ports, rules — bounded by current filters."""
    where, params = _build_where(request.args)
    conn = _conn()
    if conn is None:
        return jsonify({"ok": False}), 503
    try:
        def _top(group_col, alias):
            return [
                {alias: r[0], "count": r[1]}
                for r in conn.execute(
                    f"SELECT {group_col}, COUNT(*) FROM firewall_events "
                    f"WHERE {where} AND {group_col} IS NOT NULL AND {group_col} != '' "
                    f"GROUP BY {group_col} ORDER BY 2 DESC LIMIT 10",
                    params,
                )
            ]

        totals_row = conn.execute(
            f"SELECT action, COUNT(*) FROM firewall_events WHERE {where} "
            f"GROUP BY action",
            params,
        ).fetchall()
        totals = {r[0]: r[1] for r in totals_row}

        result = {
            "ok":        True,
            "totals":    totals,
            "top_src":   _top("src_ip",        "src_ip"),
            "top_dst":   _top("dst_ip",        "dst_ip"),
            "top_port":  _top("dst_port",      "dst_port"),
            "top_rule":  _top("rule_id",       "rule_id"),
            "top_proto": _top("protocol",      "protocol"),
            "top_iface": _top("interface",     "interface"),
            "top_source": _top("policy_source", "policy_source"),
        }
    finally:
        conn.close()
    return jsonify(result)


@firewall_logs_bp.route("/api/timeseries")
@login_required
@api_permission_required("api.logs.read")
def api_timeseries():
    """Hourly event counts split by action — drives the page's chart."""
    where, params = _build_where(request.args)
    bucket = (request.args.get("bucket") or "hour").lower()
    fmt = "%Y-%m-%dT%H:00" if bucket != "day" else "%Y-%m-%d"

    conn = _conn()
    if conn is None:
        return jsonify({"ok": False}), 503
    try:
        rows = conn.execute(
            f"SELECT strftime(?, ts) AS b, action, COUNT(*) AS c "
            f"FROM firewall_events WHERE {where} "
            f"GROUP BY b, action ORDER BY b",
            [fmt] + params,
        ).fetchall()
    finally:
        conn.close()

    buckets: list = []
    series: dict = {}
    for r in rows:
        b = r["b"] or ""
        if not b:
            continue
        if b not in buckets:
            buckets.append(b)
        series.setdefault(r["action"], {})[b] = r["c"]

    # Materialise series as parallel arrays so the client can render it as-is.
    out_series = {
        act: [counts.get(b, 0) for b in buckets]
        for act, counts in series.items()
    }
    return jsonify({"ok": True, "buckets": buckets, "series": out_series})


@firewall_logs_bp.route("/api/export")
@login_required
@api_permission_required("api.logs.export")
def api_export():
    """Export the current filter set as CSV (capped at 5000 rows)."""
    where, params = _build_where(request.args)
    limit = _parse_int(request.args.get("limit"), default=5000, lo=1, hi=10000)

    conn = _conn()
    if conn is None:
        return jsonify({"ok": False, "message": "DB unavailable"}), 503
    try:
        rows = conn.execute(
            f"SELECT * FROM firewall_events WHERE {where} "
            f"ORDER BY id DESC LIMIT ?",
            params + [limit],
        ).fetchall()
    finally:
        conn.close()

    buf = io.StringIO()
    fields = ["ts", "action", "direction", "interface", "ip_version",
              "protocol", "src_ip", "src_port", "dst_ip", "dst_port",
              "rule_id", "rule_label", "tcp_flags", "icmp_type",
              "packet_length", "hostname", "mac", "severity",
              "policy_source", "raw_line", "event_uuid"]
    writer = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for r in rows:
        writer.writerow({k: r[k] for k in fields})

    # Audit the export so the analyst trail captures what left the box.
    try:
        from app.audit_log import log_event
        log_event(
            category="admin_audit", action="firewall_log_export",
            username=session.get("username") or "admin",
            remote_addr=request.remote_addr or "",
            details={
                "row_count": len(rows),
                "filters": {k: request.args.get(k) for k in (
                    "time_from", "time_to", "action", "interface",
                    "src_ip", "dst_ip", "dst_port", "rule_id",
                    "policy_source", "search",
                )},
            },
            severity="medium",
        )
    except Exception:
        pass

    csv_text = buf.getvalue()
    now = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return Response(
        csv_text,
        mimetype="text/csv",
        headers={
            "Content-Disposition":
                f'attachment; filename="smartshield-firewall-{now}.csv"',
        },
    )
