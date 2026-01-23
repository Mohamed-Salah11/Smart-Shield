from flask import Blueprint, render_template, request, redirect, url_for, jsonify
from app.vpn_servers_db import get_db, insert_openvpn_server, list_openvpn_servers
from app.tunnelsdb import (
    delete_ipsec_tunnel,
    init_tunnels_table,
    insert_ipsec_tunnel,
    list_ipsec_tunnels,
    update_ipsec_tunnel,
)
from app.mobclientsdb import get_mobile_clients_settings, save_mobile_clients_settings
from app.pskdb import delete_psk, init_psk_table, insert_psk, list_psks, update_psk
from app.advs import get_ipsec_advanced_settings, init_advanced_settings_table, save_ipsec_advanced_settings
from app.cscdb import (
    delete_csc_override,
    insert_csc_override,
    list_csc_overrides,
    update_csc_override,
)
from app.wizardsdb import insert_wizard_ca_form

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
    servers = list_openvpn_servers()
    csc_overrides = list_csc_overrides()
    db = get_db()
    try:
        clients = db.execute("SELECT * FROM openvpn_clients").fetchall()
    finally:
        db.close()
    return render_template(
        "openvpn.html",
        servers=servers,
        clients=clients,
        csc_overrides=csc_overrides,
    )


# ----------------------------
# OPENVPN SERVERS
# ----------------------------

@vpn_bp.route("/openvpn/add", methods=["GET", "POST"])
def openvpn_add_server():
    if request.method == "POST":
        try:
            insert_openvpn_server(request.form.to_dict(flat=True))
        except Exception as e:
            print(f"Error adding server: {e}")
            import traceback
            traceback.print_exc()
        
        return redirect(url_for("vpn.openvpn"))
    
    return redirect(url_for("vpn.openvpn"))


@vpn_bp.route("/openvpn/csc/add", methods=["POST"])
def openvpn_add_csc_override():
    try:
        insert_csc_override(request.form.to_dict(flat=True))
    except Exception as e:
        print(f"Error adding CSC override: {e}")
        import traceback

        traceback.print_exc()

        # If AJAX, return error JSON
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"ok": False, "error": str(e)}), 500
        return redirect(url_for("vpn.openvpn"))

    # If AJAX, return success JSON
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({"ok": True}), 200

    # Normal form submission fallback
    return redirect(url_for("vpn.openvpn"))


@vpn_bp.route("/openvpn/csc/delete/<int:override_id>", methods=["POST"])
def openvpn_delete_csc_override(override_id):
    try:
        delete_csc_override(override_id)
    except Exception as e:
        print(f"Error deleting CSC override: {e}")
        import traceback

        traceback.print_exc()
    return redirect(url_for("vpn.openvpn"))


@vpn_bp.route("/openvpn/csc/edit/<int:override_id>", methods=["POST"])
def openvpn_edit_csc_override(override_id):
    try:
        update_csc_override(override_id, request.form.to_dict(flat=True))
    except Exception as e:
        print(f"Error editing CSC override: {e}")
        import traceback

        traceback.print_exc()

        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"ok": False, "error": str(e)}), 500
        return redirect(url_for("vpn.openvpn"))

    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({"ok": True}), 200

    return redirect(url_for("vpn.openvpn"))


# ----------------------------
# OPENVPN WIZARD (CA FORM)
# ----------------------------

@vpn_bp.route("/openvpn/wizard/ca/add", methods=["POST"])
def openvpn_wizard_add_ca():
    try:
        insert_wizard_ca_form(request.form.to_dict(flat=True))
    except Exception as e:
        print(f"Error saving wizard CA form: {e}")
        import traceback

        traceback.print_exc()
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"ok": False, "error": str(e)}), 500
        return redirect(url_for("vpn.openvpn"))

    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({"ok": True}), 200

    return redirect(url_for("vpn.openvpn"))


@vpn_bp.route("/openvpn/edit/<int:server_id>", methods=["GET", "POST"])
def openvpn_edit_server(server_id):
    if request.method == "POST":
        db = get_db()
        try:
            print("DEBUG: Form data received:", request.form)
            print("DEBUG: Description:", request.form.get("description", ""))
            print("DEBUG: Server Mode:", request.form.get("server_mode", ""))
            
            # Helper function to convert checkbox values
            def to_int(val, default=0):
                if isinstance(val, str) and val.lower() == 'on':
                    return 1
                try:
                    return int(val)
                except:
                    return default
            
            # Mapping for certificate depth text values to integers
            cert_depth_map = {
                "one": 1,
                "no_check": 0,
                "two": 2,
                "three": 3,
                "four": 4,
                "five": 5
            }
            cert_depth_val = request.form.get("certificate_depth", "one")
            certificate_depth = cert_depth_map.get(cert_depth_val.lower(), 1)
            
            # Mapping for verbosity level text values to integers
            verbosity_map = {
                "default": 3,
                "0": 0,
                "1": 1,
                "2": 2,
                "3": 3,
                "4": 4,
                "5": 5
            }
            verbosity_val = request.form.get("verbosity_level", "default")
            verbosity_level = verbosity_map.get(verbosity_val.lower(), 3)
            
            db.execute("""
                UPDATE openvpn_servers SET
                    description = ?, disabled = ?, server_mode = ?, device_mode = ?, protocol = ?,
                    interface = ?, local_port = ?, use_tls_key = ?, auto_generate_tls_key = ?,
                    peer_cert_authority = ?, peer_cert_revocation_list = ?, ocsp_check = ?,
                    server_certificate = ?, dh_parameter_length = ?, ecdh_curve = ?,
                    data_encryption_algorithms = ?, fallback_data_encryption_algorithm = ?,
                    auth_digest_algorithm = ?, certificate_depth = ?,
                    client_cert_key_usage_validation = ?, ipv4_tunnel_network = ?,
                    ipv6_tunnel_network = ?, redirect_ipv4_gateway = ?, redirect_ipv6_gateway = ?,
                    ipv4_local_networks = ?, ipv6_local_networks = ?, ipv4_remote_networks = ?,
                    ipv6_remote_networks = ?, concurrent_connections = ?, allow_compression = ?,
                    inter_client_communication = ?, duplicate_connection = ?, dynamic_ip = ?,
                    topology = ?, inactivity_timeout = ?, ping_method = ?, ping_interval = ?,
                    ping_timeout = ?, custom_options = ?, udp_fast_io = ?, exit_notify = ?,
                    send_receive_buffer = ?, gateway_creation = ?, verbosity_level = ?
                WHERE id = ?
            """, (
                request.form.get("description", ""),
                to_int(request.form.get("disabled")),
                request.form.get("server_mode", ""),
                request.form.get("device_mode", ""),
                request.form.get("protocol", ""),
                request.form.get("interface", ""),
                int(request.form.get("local_port", 1194)),
                to_int(request.form.get("use_tls_key", 1)),
                to_int(request.form.get("auto_generate_tls_key", 1)),
                request.form.get("peer_cert_authority", ""),
                request.form.get("peer_cert_revocation_list", ""),
                to_int(request.form.get("ocsp_check")),
                request.form.get("server_certificate", ""),
                int(request.form.get("dh_parameter_length", 2048)),
                request.form.get("ecdh_curve", "default"),
                request.form.get("data_encryption_algorithms", ""),
                request.form.get("fallback_data_encryption_algorithm", ""),
                request.form.get("auth_digest_algorithm", "SHA256"),
                certificate_depth,
                to_int(request.form.get("client_cert_key_usage_validation", 1)),
                request.form.get("ipv4_tunnel_network", ""),
                request.form.get("ipv6_tunnel_network", ""),
                to_int(request.form.get("redirect_ipv4_gateway")),
                to_int(request.form.get("redirect_ipv6_gateway")),
                request.form.get("ipv4_local_networks", ""),
                request.form.get("ipv6_local_networks", ""),
                request.form.get("ipv4_remote_networks", ""),
                request.form.get("ipv6_remote_networks", ""),
                request.form.get("concurrent_connections", ""),
                request.form.get("allow_compression", "refuse"),
                to_int(request.form.get("inter_client_communication")),
                to_int(request.form.get("duplicate_connection")),
                to_int(request.form.get("dynamic_ip")),
                request.form.get("topology", "subnet"),
                int(request.form.get("inactivity_timeout", 300)),
                request.form.get("ping_method", "keepalive"),
                int(request.form.get("ping_interval", 10)),
                int(request.form.get("ping_timeout", 60)),
                request.form.get("custom_options", ""),
                to_int(request.form.get("udp_fast_io")),
                request.form.get("exit_notify", "reconnect"),
                request.form.get("send_receive_buffer", "default"),
                request.form.get("gateway_creation", "both"),
                verbosity_level,
                server_id
            ))
            db.commit()
            db.close()
            print("DEBUG: Server updated successfully")
        except Exception as e:
            db.close()
            print(f"Error editing server: {e}")
            import traceback
            traceback.print_exc()
        
        return redirect(url_for("vpn.openvpn"))
    
    return redirect(url_for("vpn.openvpn"))


@vpn_bp.route("/openvpn/delete/<int:server_id>", methods=["POST"])
def openvpn_delete_server(server_id):
    db = get_db()
    try:
        db.execute("DELETE FROM openvpn_servers WHERE id = ?", (server_id,))
        db.commit()
        db.close()
    except Exception as e:
        db.close()
        print(f"Error deleting server: {e}")
    
    return redirect(url_for("vpn.openvpn"))


# ----------------------------
# OPENVPN CLIENTS
# ----------------------------

@vpn_bp.route("/openvpn/client/add", methods=["GET", "POST"])
def openvpn_add_client():
    if request.method == "POST":
        db = get_db()
        try:
            print("DEBUG: Client form data received:", request.form)
            
            # Helper function to convert checkbox values
            def to_int(val, default=0):
                if isinstance(val, str) and val.lower() == 'on':
                    return 1
                try:
                    return int(val)
                except:
                    return default
            
            db.execute("""
                INSERT INTO openvpn_clients (
                    description, disabled, server_mode, protocol, interface, server_hostname,
                    server_port, use_tls_key, tls_key, use_certificate, client_certificate,
                    ca_certificate, ca_chain, cert_from, cert_to, data_encryption_algorithms,
                    auth_digest_algorithm, engine, crypto_hardware, ipv4_tunnel_network,
                    ipv6_tunnel_network, allow_compression, topology, inactivity_timeout,
                    ping_method, ping_interval, ping_timeout, custom_options, udp_fast_io,
                    send_receive_buffer, verbosity_level
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                request.form.get("description", ""),
                to_int(request.form.get("disabled")),
                request.form.get("server_mode", ""),
                request.form.get("protocol", ""),
                request.form.get("interface", ""),
                request.form.get("server_hostname", ""),
                int(request.form.get("server_port", 1194)),
                to_int(request.form.get("use_tls_key", 1)),
                request.form.get("tls_key", ""),
                to_int(request.form.get("use_certificate", 1)),
                request.form.get("client_certificate", ""),
                request.form.get("ca_certificate", ""),
                request.form.get("ca_chain", ""),
                request.form.get("cert_from", ""),
                request.form.get("cert_to", ""),
                request.form.get("data_encryption_algorithms", ""),
                request.form.get("auth_digest_algorithm", "SHA256"),
                request.form.get("engine", "none"),
                request.form.get("crypto_hardware", "none"),
                request.form.get("ipv4_tunnel_network", ""),
                request.form.get("ipv6_tunnel_network", ""),
                request.form.get("allow_compression", "no"),
                request.form.get("topology", "subnet"),
                int(request.form.get("inactivity_timeout", 300)),
                request.form.get("ping_method", "keepalive"),
                int(request.form.get("ping_interval", 10)),
                int(request.form.get("ping_timeout", 60)),
                request.form.get("custom_options", ""),
                to_int(request.form.get("udp_fast_io")),
                request.form.get("send_receive_buffer", "default"),
                int(request.form.get("verbosity_level", 3))
            ))
            db.commit()
            db.close()
            print("DEBUG: Client added successfully")
        except Exception as e:
            db.close()
            print(f"Error adding client: {e}")
            import traceback
            traceback.print_exc()
        
        return redirect(url_for("vpn.openvpn"))
    
    return redirect(url_for("vpn.openvpn"))


@vpn_bp.route("/openvpn/client/edit/<int:client_id>", methods=["GET", "POST"])
def openvpn_edit_client(client_id):
    if request.method == "POST":
        db = get_db()
        try:
            print("DEBUG: Client edit form data received:", request.form)
            
            # Helper function to convert checkbox values
            def to_int(val, default=0):
                if isinstance(val, str) and val.lower() == 'on':
                    return 1
                try:
                    return int(val)
                except:
                    return default
            
            db.execute("""
                UPDATE openvpn_clients SET
                    description = ?, disabled = ?, server_mode = ?, protocol = ?, interface = ?,
                    server_hostname = ?, server_port = ?, use_tls_key = ?, tls_key = ?,
                    use_certificate = ?, client_certificate = ?, ca_certificate = ?,
                    ca_chain = ?, cert_from = ?, cert_to = ?, data_encryption_algorithms = ?,
                    auth_digest_algorithm = ?, engine = ?, crypto_hardware = ?,
                    ipv4_tunnel_network = ?, ipv6_tunnel_network = ?, allow_compression = ?,
                    topology = ?, inactivity_timeout = ?, ping_method = ?, ping_interval = ?,
                    ping_timeout = ?, custom_options = ?, udp_fast_io = ?,
                    send_receive_buffer = ?, verbosity_level = ?
                WHERE id = ?
            """, (
                request.form.get("description", ""),
                to_int(request.form.get("disabled")),
                request.form.get("server_mode", ""),
                request.form.get("protocol", ""),
                request.form.get("interface", ""),
                request.form.get("server_hostname", ""),
                int(request.form.get("server_port", 1194)),
                to_int(request.form.get("use_tls_key", 1)),
                request.form.get("tls_key", ""),
                to_int(request.form.get("use_certificate", 1)),
                request.form.get("client_certificate", ""),
                request.form.get("ca_certificate", ""),
                request.form.get("ca_chain", ""),
                request.form.get("cert_from", ""),
                request.form.get("cert_to", ""),
                request.form.get("data_encryption_algorithms", ""),
                request.form.get("auth_digest_algorithm", "SHA256"),
                request.form.get("engine", "none"),
                request.form.get("crypto_hardware", "none"),
                request.form.get("ipv4_tunnel_network", ""),
                request.form.get("ipv6_tunnel_network", ""),
                request.form.get("allow_compression", "no"),
                request.form.get("topology", "subnet"),
                int(request.form.get("inactivity_timeout", 300)),
                request.form.get("ping_method", "keepalive"),
                int(request.form.get("ping_interval", 10)),
                int(request.form.get("ping_timeout", 60)),
                request.form.get("custom_options", ""),
                to_int(request.form.get("udp_fast_io")),
                request.form.get("send_receive_buffer", "default"),
                int(request.form.get("verbosity_level", 3)),
                client_id
            ))
            db.commit()
            db.close()
            print("DEBUG: Client updated successfully")
        except Exception as e:
            db.close()
            print(f"Error editing client: {e}")
            import traceback
            traceback.print_exc()
        
        return redirect(url_for("vpn.openvpn"))
    
    return redirect(url_for("vpn.openvpn"))


@vpn_bp.route("/openvpn/client/delete/<int:client_id>", methods=["POST"])
def openvpn_delete_client(client_id):
    db = get_db()
    try:
        db.execute("DELETE FROM openvpn_clients WHERE id = ?", (client_id,))
        db.commit()
        db.close()
    except Exception as e:
        db.close()
        print(f"Error deleting client: {e}")
    
    return redirect(url_for("vpn.openvpn"))


# ----------------------------
# IPsec PAGE
# ----------------------------

@vpn_bp.route("/ipsec")
def ipsec():
    # Safe lazy-init so the page works even if app init didn't run it.
    init_tunnels_table()
    tunnels = list_ipsec_tunnels()
    mobile_clients = get_mobile_clients_settings()
    psks = list_psks()
    adv_settings = get_ipsec_advanced_settings()
    return render_template(
        "ipsec.html",
        tunnels=tunnels,
        mobile_clients=mobile_clients,
        psks=psks,
        adv_settings=adv_settings,
    )


@vpn_bp.route("/ipsec/advanced-settings/save", methods=["POST"])
def ipsec_advanced_settings_save():
    init_advanced_settings_table()
    try:
        form = request.form.to_dict(flat=False)
        save_ipsec_advanced_settings(form)
    except Exception as e:
        print(f"Error saving IPsec advanced settings: {e}")
        import traceback

        traceback.print_exc()
    return redirect(url_for("vpn.ipsec"))


@vpn_bp.route("/ipsec/mobile-clients/save", methods=["POST"])
def ipsec_mobile_clients_save():
    try:
        form = request.form.to_dict(flat=False)
        save_mobile_clients_settings(form)
    except Exception as e:
        print(f"Error saving IPsec mobile clients settings: {e}")
        import traceback

        traceback.print_exc()
    return redirect(url_for("vpn.ipsec"))


@vpn_bp.route("/ipsec/psk/add", methods=["POST"])
def ipsec_psk_add():
    init_psk_table()
    try:
        form = request.form.to_dict(flat=False)
        insert_psk(form)
    except Exception as e:
        print(f"Error adding PSK: {e}")
        import traceback

        traceback.print_exc()
    return redirect(url_for("vpn.ipsec"))


@vpn_bp.route("/ipsec/psk/edit/<int:psk_id>", methods=["POST"])
def ipsec_psk_edit(psk_id):
    init_psk_table()
    try:
        form = request.form.to_dict(flat=False)
        update_psk(psk_id, form)
    except Exception as e:
        print(f"Error editing PSK: {e}")
        import traceback

        traceback.print_exc()
    return redirect(url_for("vpn.ipsec"))


@vpn_bp.route("/ipsec/psk/delete/<int:psk_id>", methods=["POST"])
def ipsec_psk_delete(psk_id):
    init_psk_table()
    try:
        delete_psk(psk_id)
    except Exception as e:
        print(f"Error deleting PSK: {e}")
        import traceback

        traceback.print_exc()
    return redirect(url_for("vpn.ipsec"))


@vpn_bp.route("/ipsec/tunnels/add", methods=["POST"])
def ipsec_add_tunnel():
    init_tunnels_table()
    try:
        # Use flat=False to allow list fields (multi algorithms), but we also accept JSON.
        form = request.form.to_dict(flat=False)
        insert_ipsec_tunnel(form)
    except Exception as e:
        print(f"Error adding IPsec tunnel: {e}")
        import traceback

        traceback.print_exc()
    return redirect(url_for("vpn.ipsec"))


@vpn_bp.route("/ipsec/tunnels/edit/<int:tunnel_id>", methods=["POST"])
def ipsec_edit_tunnel(tunnel_id):
    init_tunnels_table()
    try:
        form = request.form.to_dict(flat=False)
        update_ipsec_tunnel(tunnel_id, form)
    except Exception as e:
        print(f"Error editing IPsec tunnel: {e}")
        import traceback

        traceback.print_exc()
    return redirect(url_for("vpn.ipsec"))


@vpn_bp.route("/ipsec/tunnels/delete/<int:tunnel_id>", methods=["POST"])
def ipsec_delete_tunnel(tunnel_id):
    init_tunnels_table()
    try:
        delete_ipsec_tunnel(tunnel_id)
    except Exception as e:
        print(f"Error deleting IPsec tunnel: {e}")
        import traceback

        traceback.print_exc()
    return redirect(url_for("vpn.ipsec"))


# ----------------------------
# L2TP PAGE
# ----------------------------

@vpn_bp.route("/l2tp", methods=["GET", "POST"])
def l2tp():
    # Save L2TP configuration tab settings
    if request.method == "POST":
        try:
            from app.l2configdb import save_l2tp_config

            form = request.form.to_dict(flat=False)
            save_l2tp_config(form)
        except Exception as e:
            print(f"Error saving L2TP config: {e}")
            import traceback

            traceback.print_exc()
        return redirect(url_for("vpn.l2tp"))

    # GET: load existing config
    try:
        from app.l2configdb import get_l2tp_config

        cfg = get_l2tp_config()
    except Exception:
        cfg = {}

    # Load users list for Users tab
    try:
        from app.l2users import list_l2tp_users

        users = list_l2tp_users()
    except Exception:
        users = []

    return render_template("l2tp.html", l2tp_config=cfg, l2tp_users=users)


@vpn_bp.route("/l2tp/users/add", methods=["POST"])
def l2tp_users_add():
    try:
        from app.l2users import insert_l2tp_user

        form = request.form.to_dict(flat=False)
        insert_l2tp_user(form)
    except Exception as e:
        print(f"Error adding L2TP user: {e}")
        import traceback

        traceback.print_exc()
    return redirect(url_for("vpn.l2tp"))


@vpn_bp.route("/l2tp/users/edit/<int:user_id>", methods=["POST"])
def l2tp_users_edit(user_id: int):
    try:
        from app.l2users import update_l2tp_user

        form = request.form.to_dict(flat=False)
        update_l2tp_user(user_id, form)
    except Exception as e:
        print(f"Error editing L2TP user: {e}")
        import traceback

        traceback.print_exc()
    return redirect(url_for("vpn.l2tp"))


@vpn_bp.route("/l2tp/users/delete/<int:user_id>", methods=["POST"])
def l2tp_users_delete(user_id: int):
    try:
        from app.l2users import delete_l2tp_user

        delete_l2tp_user(user_id)
    except Exception as e:
        print(f"Error deleting L2TP user: {e}")
        import traceback

        traceback.print_exc()
    return redirect(url_for("vpn.l2tp"))
