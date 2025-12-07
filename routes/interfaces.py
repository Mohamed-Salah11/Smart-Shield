from flask import Blueprint, render_template

interfaces_bp = Blueprint("interfaces", __name__, url_prefix="/interfaces")

# ----------------------------
# INTERFACES MAIN PAGE
# ----------------------------

@interfaces_bp.route("/")
def interfaces_home():
    return render_template("interfaces.html")

@interfaces_bp.route("/interfaces")
def interfaces():
    return render_template("interfaces.html")


# ----------------------------
# INTERFACE ASSIGNMENTS PAGE
# ----------------------------

@interfaces_bp.route("/assignments")
def interfaces_assignments():
    return render_template("interfaces_assignments.html")


# ----------------------------
# WAN INTERFACE CONFIGURATION
# ----------------------------

@interfaces_bp.route("/wan")
def interfaces_wan():
    return render_template("interfaces_wan.html")


# ----------------------------
# LAN INTERFACE CONFIGURATION
# ----------------------------

@interfaces_bp.route("/lan")
def interfaces_lan():
    return render_template("interfaces_lan.html")
