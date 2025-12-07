from flask import Blueprint, render_template

firewall_bp = Blueprint("firewall", __name__, url_prefix="/firewall")

# ----------------------------
# FIREWALL MAIN PAGE
# ----------------------------

@firewall_bp.route("/")
def firewall_home():
    return render_template("firewall.html")


# ----------------------------
# FIREWALL RULES
# ----------------------------

@firewall_bp.route("/rules")
def rules():
    return render_template("firewall.html")


# ----------------------------
# FIREWALL NAT
# ----------------------------

@firewall_bp.route("/nat")
def nat():
    return render_template("nat.html")


# ----------------------------
# FIREWALL ALIASES
# ----------------------------

@firewall_bp.route("/aliases")
def aliases():
    # Default tab = 'ip'
    return render_template("aliases.html", tab="ip")


@firewall_bp.route("/aliases/<tab>")
def firewall_aliases_tab(tab):
    valid_tabs = ["ip", "ports", "urls", "all"]
    if tab not in valid_tabs:
        tab = "ip"
    return render_template("aliases.html", tab=tab)


# ----------------------------
# FIREWALL SCHEDULES
# ----------------------------

@firewall_bp.route("/schedules")
def schedules():
    return render_template("schedules.html")


# ----------------------------
# TRAFFIC SHAPER
# ----------------------------

@firewall_bp.route("/traffic-shaper")
def traffic_shaper():
    return render_template("traffic_shaper.html")


# ----------------------------
# VIRTUAL IPs
# ----------------------------

@firewall_bp.route("/virtual-ips")
def virtual_ips():
    return render_template("virtual_ips.html")


# ----------------------------
# FIREWALL HOME
# ----------------------------

@firewall_bp.route("/home")
def home():
    return redirect(url_for("firewall.firewall_home"))
