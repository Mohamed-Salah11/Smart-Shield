from flask import Blueprint, render_template

diagnostics_bp = Blueprint("diagnostics", __name__, url_prefix="/diagnostics")

# --------------------------------------------------
# DIAGNOSTICS MAIN PAGE
# --------------------------------------------------

@diagnostics_bp.route("/")
def diagnostics_home():
    return render_template("diagnostics.html")


# --------------------------------------------------
# ARP TABLE
# --------------------------------------------------

@diagnostics_bp.route("/arp-table")
def arp_table():
    return render_template("arp_table.html")


# --------------------------------------------------
# AUTHENTICATION TEST PAGE
# --------------------------------------------------

@diagnostics_bp.route("/authentication")
def authentication():
    return render_template("authentication.html")


# --------------------------------------------------
# BACKUP & RESTORE
# --------------------------------------------------

@diagnostics_bp.route("/backup-restore")
def backup_restore():
    return render_template("backup_restore.html")


# --------------------------------------------------
# COMMAND PROMPT
# --------------------------------------------------

@diagnostics_bp.route("/command-prompt")
def command_prompt():
    return render_template("command_prompt.html")


# --------------------------------------------------
# DNS LOOKUP
# --------------------------------------------------

@diagnostics_bp.route("/dns-lookup")
def dns_lookup():
    return render_template("dns_lookup.html")


# --------------------------------------------------
# FILE EDITOR
# --------------------------------------------------

@diagnostics_bp.route("/edit-file")
def edit_file():
    return render_template("edit_file.html")


# --------------------------------------------------
# FACTORY DEFAULTS
# --------------------------------------------------

@diagnostics_bp.route("/factory-defaults")
def factory_defaults():
    return render_template("factory_defaults.html")


# --------------------------------------------------
# SHUTDOWN / HALT SYSTEM
# --------------------------------------------------

@diagnostics_bp.route("/halt-system")
def halt_system():
    return render_template("halt_system.html")


# --------------------------------------------------
# LIMITER INFO
# --------------------------------------------------

@diagnostics_bp.route("/limiter-info")
def limiter_info():
    return render_template("limiter_info.html")


# --------------------------------------------------
# NDP TABLE (IPv6)
# --------------------------------------------------

@diagnostics_bp.route("/ndp-table")
def ndp_table():
    return render_template("ndp_table.html")


# --------------------------------------------------
# PACKET CAPTURE
# --------------------------------------------------

@diagnostics_bp.route("/packet-capture")
def packet_capture():
    return render_template("packet_capture.html")


# --------------------------------------------------
# PFINFO
# --------------------------------------------------

@diagnostics_bp.route("/pfinfo")
def pfinfo():
    return render_template("pfinfo.html")


# --------------------------------------------------
# PF TOP
# --------------------------------------------------

@diagnostics_bp.route("/pftop")
def pftop():
    return render_template("pftop.html")


# --------------------------------------------------
# PING
# --------------------------------------------------

@diagnostics_bp.route("/ping")
def ping_diag():
    return render_template("ping_diag.html")


# --------------------------------------------------
# REBOOT SYSTEM
# --------------------------------------------------

@diagnostics_bp.route("/reboot")
def reboot():
    return render_template("reboot.html")


# --------------------------------------------------
# ROUTES
# --------------------------------------------------

@diagnostics_bp.route("/routes")
def routes_diag():
    return render_template("routes_diag.html")


# --------------------------------------------------
# SMART STATUS
# --------------------------------------------------

@diagnostics_bp.route("/smart-status")
def smart_status():
    return render_template("smart_status.html")


# --------------------------------------------------
# SOCKETS
# --------------------------------------------------

@diagnostics_bp.route("/sockets")
def sockets():
    return render_template("sockets.html")


# --------------------------------------------------
# STATES
# --------------------------------------------------

@diagnostics_bp.route("/states")
def states():
    return render_template("states.html")


# --------------------------------------------------
# STATUS SUMMARY
# --------------------------------------------------

@diagnostics_bp.route("/status-summary")
def status_summary():
    return render_template("status_summary.html")


# --------------------------------------------------
# SYSTEM ACTIVITY
# --------------------------------------------------

@diagnostics_bp.route("/system-activity")
def system_activity():
    return render_template("system_activity.html")


# --------------------------------------------------
# TABLES
# --------------------------------------------------

@diagnostics_bp.route("/tables")
def tables():
    return render_template("tables.html")


# --------------------------------------------------
# TEST PORT
# --------------------------------------------------

@diagnostics_bp.route("/test-port")
def test_port():
    return render_template("test_port.html")


# --------------------------------------------------
# TUNNELS
# --------------------------------------------------

@diagnostics_bp.route("/tunnels")
def tunnels():
    return render_template("tunnels.html")
