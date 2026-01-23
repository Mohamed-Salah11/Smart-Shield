from flask import Blueprint, render_template

vpn_bp = Blueprint("vpn", __name__, url_prefix="/vpn")

# ----------------------------
# VPN MAIN PAGE
# ----------------------------

@vpn_bp.route("/")
def vpn_home():
    return render_template("vpn.html")


# ----------------------------
# OPENVPN PAGE
# ----------------------------

@vpn_bp.route("/openvpn")
def openvpn():
    return render_template("openvpn.html")


# ----------------------------
# IPsec PAGE
# ----------------------------

@vpn_bp.route("/ipsec")
def ipsec():
    return render_template("ipsec.html")


# ----------------------------
# L2TP PAGE
# ----------------------------

@vpn_bp.route("/l2tp")
def l2tp():
    return render_template("l2tp.html")
