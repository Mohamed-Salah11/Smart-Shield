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
    from app.database import get_db
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT * FROM dhcp_pools ORDER BY interface_type")
    pools = [dict(r) for r in cur.fetchall()]
    cur.execute("SELECT * FROM static_leases ORDER BY interface_type, ip_address")
    static = [dict(r) for r in cur.fetchall()]
    return render_template("dhcp_leases.html", pools=pools, static_leases=static)


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
    import sys, os
    from app.database import get_db
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT * FROM firewall_rules_wan WHERE disabled=0 ORDER BY rule_order LIMIT 1")
    has_wan = cur.fetchone() is not None
    cur.execute("SELECT * FROM firewall_rules_lan WHERE disabled=0 ORDER BY rule_order LIMIT 1")
    has_lan = cur.fetchone() is not None
    cur.execute("SELECT COUNT(*) AS c FROM firewall_rules_wan WHERE disabled=0")
    wan_count = (cur.fetchone() or {}).get("c", 0)
    cur.execute("SELECT COUNT(*) AS c FROM firewall_rules_lan WHERE disabled=0")
    lan_count = (cur.fetchone() or {}).get("c", 0)
    cur.execute("SELECT COUNT(*) AS c FROM firewall_rules_floating WHERE disabled=0")
    float_count = (cur.fetchone() or {}).get("c", 0)
    pf_enabled = sys.platform.startswith("freebsd") and os.path.exists("/dev/pf")
    return render_template("filter_reload.html",
        wan_count=wan_count, lan_count=lan_count,
        float_count=float_count, pf_enabled=pf_enabled)


# --------------------------------------------------
# FILTER RELOAD — APPLY (POST)
# --------------------------------------------------

@status_bp.route("/filter-reload/apply", methods=["POST"])
@login_required
def filter_reload_apply():
    from app.database import get_db
    from app.services.pf_generator import reload_pf_rules
    from app.audit_log import log_event
    conn = get_db()
    result = reload_pf_rules(conn)
    log_event(category="system", action="pf_reload",
              username=request.values.get("username"),
              remote_addr=request.remote_addr,
              details=result)
    return jsonify(result)


# --------------------------------------------------
# GATEWAY STATUS
# --------------------------------------------------

@status_bp.route("/gateways")
@login_required
def gateways():
    import sys
    from app.database import get_db
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT * FROM wan_config LIMIT 1")
    wan = dict(cur.fetchone() or {})
    cur.execute("SELECT * FROM lan_config LIMIT 1")
    lan = dict(cur.fetchone() or {})

    # Live route table on FreeBSD
    routes = []
    if sys.platform.startswith("freebsd"):
        try:
            from app.services.network_service import run_command
            r = run_command(["netstat", "-rn", "-f", "inet"], check=False)
            for line in (r.stdout or "").splitlines():
                parts = line.split()
                if len(parts) >= 4 and parts[0] not in ("Destination", "Internet:"):
                    routes.append({
                        "destination": parts[0], "gateway": parts[1],
                        "flags": parts[2], "iface": parts[-1],
                    })
        except Exception:
            pass

    return render_template("gateways.html", wan=wan, lan=lan, routes=routes,
                           on_freebsd=sys.platform.startswith("freebsd"))


# --------------------------------------------------
# MONITORING (GRAPHS)
# --------------------------------------------------

@status_bp.route("/monitoring")
@login_required
def monitoring():
    import sys
    from app.database import get_db
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT assigned_port, description, ipv4_address FROM lan_config LIMIT 1")
    lan = dict(cur.fetchone() or {})
    cur.execute("SELECT assigned_port, description, ipv4_address FROM wan_config LIMIT 1")
    wan = dict(cur.fetchone() or {})
    interfaces = [lan, wan]
    return render_template("monitoring.html", interfaces=interfaces,
                           on_freebsd=sys.platform.startswith("freebsd"))


# --------------------------------------------------
# MONITORING — LIVE INTERFACE STATS API
# --------------------------------------------------

@status_bp.route("/api/interface-stats")
@login_required
def api_interface_stats():
    import sys, re
    stats = []
    if sys.platform.startswith("freebsd"):
        try:
            from app.services.network_service import run_command
            r = run_command(["netstat", "-ibn"], check=False)
            for line in (r.stdout or "").splitlines():
                parts = line.split()
                if len(parts) >= 8 and not line.startswith("Name"):
                    try:
                        stats.append({
                            "name": parts[0], "mtu": parts[1],
                            "rx_pkts": int(parts[4]), "rx_errs": int(parts[5]),
                            "tx_pkts": int(parts[6]), "tx_errs": int(parts[7]),
                        })
                    except (ValueError, IndexError):
                        pass
        except Exception:
            pass
    return jsonify({"ok": True, "stats": stats, "on_freebsd": sys.platform.startswith("freebsd")})


# --------------------------------------------------
# SYSTEM QUEUES
# --------------------------------------------------

@status_bp.route("/queues")
@login_required
def queues():
    from app.database import get_db
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT * FROM traffic_shaper_configs ORDER BY interface_type, name")
    shapers = [dict(r) for r in cur.fetchall()]
    return render_template("queues.html", shapers=shapers)


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
