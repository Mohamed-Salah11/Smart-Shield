from flask import Blueprint, render_template

status_bp = Blueprint("status", __name__, url_prefix="/status")


# --------------------------------------------------
# STATUS MAIN PAGE
# --------------------------------------------------

@status_bp.route("/")
def status_home():
    return render_template("status.html")


# --------------------------------------------------
# CARP FAILOVER
# --------------------------------------------------

@status_bp.route("/carp-failover")
def carp_failover():
    return render_template("carp_failover.html")


# --------------------------------------------------
# DHCP LEASES (IPv4)
# --------------------------------------------------

@status_bp.route("/dhcp-leases")
def dhcp_leases():
    return render_template("dhcp_leases.html")


# --------------------------------------------------
# DHCPv6 LEASES (IPv6)
# --------------------------------------------------

@status_bp.route("/dhcpv6-leases")
def dhcpv6_leases():
    return render_template("dhcpv6_leases.html")


# --------------------------------------------------
# FILTER RELOAD STATUS
# --------------------------------------------------

@status_bp.route("/filter-reload")
def filter_reload():
    return render_template("filter_reload.html")


# --------------------------------------------------
# GATEWAY STATUS
# --------------------------------------------------

@status_bp.route("/gateways")
def gateways():
    return render_template("gateways.html")


# --------------------------------------------------
# MONITORING (GRAPHS)
# --------------------------------------------------

@status_bp.route("/monitoring")
def monitoring():
    return render_template("monitoring.html")


# --------------------------------------------------
# SYSTEM QUEUES
# --------------------------------------------------

@status_bp.route("/queues")
def queues():
    return render_template("queues.html")


# --------------------------------------------------
# SYSTEM LOGS
# --------------------------------------------------

@status_bp.route("/system-logs")
def system_logs():
    return render_template("system_logs.html")


# --------------------------------------------------
# TRAFFIC GRAPH (REALTIME)
# --------------------------------------------------

@status_bp.route("/traffic-graph")
def traffic_graph():
    return render_template("traffic_graph.html")
