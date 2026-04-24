import json as _json
from flask import Blueprint, render_template, request, jsonify
from app.auth_utils import login_required
from app.audit_log import tail_events, tail_events_since, log_stats

status_bp = Blueprint("status", __name__, url_prefix="/status")


# --------------------------------------------------
# STATUS MAIN PAGE
# --------------------------------------------------

@status_bp.route("/")
@login_required
def status_home():
    return render_template("status.html")


# --------------------------------------------------
# CARP FAILOVER
# --------------------------------------------------

@status_bp.route("/carp-failover")
@login_required
def carp_failover():
    return render_template("carp_failover.html")


# --------------------------------------------------
# DHCP LEASES (IPv4)
# --------------------------------------------------

@status_bp.route("/dhcp-leases")
@login_required
def dhcp_leases():
    return render_template("dhcp_leases.html")


# --------------------------------------------------
# DHCPv6 LEASES (IPv6)
# --------------------------------------------------

@status_bp.route("/dhcpv6-leases")
@login_required
def dhcpv6_leases():
    return render_template("dhcpv6_leases.html")


# --------------------------------------------------
# FILTER RELOAD STATUS
# --------------------------------------------------

@status_bp.route("/filter-reload")
@login_required
def filter_reload():
    return render_template("filter_reload.html")


# --------------------------------------------------
# GATEWAY STATUS
# --------------------------------------------------

@status_bp.route("/gateways")
@login_required
def gateways():
    return render_template("gateways.html")


# --------------------------------------------------
# MONITORING (GRAPHS)
# --------------------------------------------------

@status_bp.route("/monitoring")
@login_required
def monitoring():
    return render_template("monitoring.html")


# --------------------------------------------------
# SYSTEM QUEUES
# --------------------------------------------------

@status_bp.route("/queues")
@login_required
def queues():
    return render_template("queues.html")


# --------------------------------------------------
# SYSTEM LOGS
# --------------------------------------------------

@status_bp.route("/system-logs")
@login_required
def system_logs():
    active_tab = (request.args.get("tab") or "system").lower()
    if active_tab not in {"system", "sessions", "security", "browsing"}:
        active_tab = "system"

    all_events = tail_events(limit=300)
    session_events = [e for e in all_events if e.get("category") == "session"]
    system_events = [e for e in all_events if e.get("category") == "system"]
    browsing_events = [e for e in all_events if e.get("category") == "browsing"]
    security_events = [
        e for e in all_events
        if e.get("category") == "security"
        or (e.get("category") == "session" and e.get("action") == "login_failed")
    ]

    return render_template(
        "system_logs.html",
        active_tab=active_tab,
        system_events=system_events[:150],
        session_events=session_events[:150],
        browsing_events=browsing_events[:150],
        security_events=security_events[:150],
    )


# --------------------------------------------------
# TRAFFIC GRAPH (REALTIME)
# --------------------------------------------------

@status_bp.route("/traffic-graph")
@login_required
def traffic_graph():
    return render_template("traffic_graph.html")


# ══════════════════════════════════════════════════
# LIVE LOG API
# ══════════════════════════════════════════════════

@status_bp.route("/api/logs")
@login_required
def api_logs():
    """
    Polling endpoint for the live log monitor.

    Query params
    ------------
    since      ISO-8601 timestamp — return only events after this time.
               Omit or pass "" to get the most recent `limit` events.
    limit      Max events to return (default 100, max 500).
    categories Comma-separated list e.g. "session,system". Omit for all.
    search     Free-text filter applied against action, username, IP, details.
    """
    since      = request.args.get("since", "").strip()
    limit      = min(int(request.args.get("limit", 100) or 100), 500)
    cats_raw   = request.args.get("categories", "").strip()
    search     = request.args.get("search", "").lower().strip()

    categories = [c.strip() for c in cats_raw.split(",") if c.strip()] if cats_raw else None

    events = tail_events_since(
        after_ts=since,
        limit=limit * 3,          # over-fetch so search filter has room
        categories=categories,
    )

    if search:
        def _matches(e):
            haystack = " ".join([
                e.get("action", ""),
                e.get("username", ""),
                e.get("remote_addr", ""),
                e.get("category", ""),
                _json.dumps(e.get("details") or {}),
            ]).lower()
            return search in haystack
        events = [e for e in events if _matches(e)]

    events = events[:limit]
    latest_ts = events[0]["timestamp"] if events else since

    return jsonify({
        "ok":        True,
        "events":    events,
        "count":     len(events),
        "latest_ts": latest_ts,
    })


@status_bp.route("/api/logs/stats")
@login_required
def api_logs_stats():
    """Per-category event counts for the stats bar."""
    return jsonify(log_stats())
