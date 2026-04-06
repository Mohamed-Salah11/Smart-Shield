from flask import Blueprint, render_template
from app.auth_utils import login_required

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
    return render_template("system_logs.html")


# --------------------------------------------------
# TRAFFIC GRAPH (REALTIME)
# --------------------------------------------------

@status_bp.route("/traffic-graph")
@login_required
def traffic_graph():
    return render_template("traffic_graph.html")
