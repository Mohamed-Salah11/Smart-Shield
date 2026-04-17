from flask import Blueprint, render_template, request
from app.auth_utils import login_required
from app.audit_log import tail_events

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
