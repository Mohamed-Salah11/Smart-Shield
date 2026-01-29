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
    # OpenVPN Servers (default tab)
    return render_template("openvpn.html", active_tab="servers")


@vpn_bp.route("/openvpn/servers")
def openvpn_servers():
    return render_template("openvpn.html", active_tab="servers")


@vpn_bp.route("/openvpn/clients")
def openvpn_clients():
    return render_template("openvpn_clients.html", active_tab="clients")


@vpn_bp.route("/openvpn/cso")
def openvpn_cso():
    return render_template("openvpn_cso.html", active_tab="cso")


@vpn_bp.route("/openvpn/wizards")
def openvpn_wizards():
    return render_template("openvpn_wizards1.html", active_tab="wizards")


@vpn_bp.route("/openvpn/wizards/step2")
def openvpn_wizards_step2():
    return render_template("openvpn_wizards2.html", active_tab="wizards")


@vpn_bp.route("/openvpn/wizards/step3")
def openvpn_wizards_step3():
    return render_template("openvpn_wizards3.html", active_tab="wizards")


# ----------------------------
# IPsec PAGE
# ----------------------------

@vpn_bp.route("/ipsec")
def ipsec():
    return render_template("ipsec.html")


@vpn_bp.route("/ipsec/mobile-clients")
def ipsec_mobile_clients():
    return render_template("IPsec_mob_clients.html", active_tab="mobile_clients")


@vpn_bp.route("/ipsec/pre-shared-keys")
def ipsec_pre_shared_keys():
    return render_template("IPsec_pre_shared_keys.html", active_tab="psk")


@vpn_bp.route("/ipsec/advanced-settings")
def ipsec_advanced_settings():
    return render_template("IPsec_advanced_settings.html", active_tab="advanced")


# ----------------------------
# L2TP PAGE
# ----------------------------

@vpn_bp.route("/l2tp")
def l2tp():
    return render_template("l2tp.html")


@vpn_bp.route("/l2tp/users")
def l2tp_users():
    return render_template("l2tp_users.html")
