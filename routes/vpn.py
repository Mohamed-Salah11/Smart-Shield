from flask import Blueprint, render_template, request, jsonify
from app.database import get_db
from app.auth_utils import login_required
from app.secret_store import seal
import sqlite3
from werkzeug.security import generate_password_hash

vpn_bp = Blueprint("vpn", __name__, url_prefix="/vpn")


def _payload_and_status(response):
    if isinstance(response, tuple):
        resp, status = response
    else:
        resp = response
        status = response.status_code
    return (resp.get_json(silent=True) or {}), status

# ----------------------------
# VPN MAIN PAGE
# ----------------------------

@vpn_bp.route("/")
@login_required
def vpn_home():
    return render_template("vpn.html")


# ----------------------------
# OPENVPN PAGE
# ----------------------------

@vpn_bp.route("/openvpn", methods=['GET', 'POST'])
@login_required
def openvpn():
    # OpenVPN Servers (default tab)
    return render_template("openvpn.html", active_tab="servers")


@vpn_bp.route("/openvpn/servers", methods=['GET', 'POST'])
@login_required
def openvpn_servers():
    return render_template("openvpn.html", active_tab="servers")


@vpn_bp.route("/openvpn/clients", methods=['GET', 'POST'])
@login_required
def openvpn_clients():
    return render_template("openvpn_clients.html", active_tab="clients")


@vpn_bp.route("/openvpn/cso", methods=['GET', 'POST'])
@login_required
def openvpn_cso():
    return render_template("openvpn_cso.html", active_tab="cso")


@vpn_bp.route("/openvpn/wizards", methods=['GET', 'POST'])
@login_required
def openvpn_wizards():
    return render_template("openvpn_wizards1.html", active_tab="wizards")


@vpn_bp.route("/openvpn/wizards/step2", methods=['GET', 'POST'])
@login_required
def openvpn_wizards_step2():
    return render_template("openvpn_wizards2.html", active_tab="wizards")


@vpn_bp.route("/openvpn/wizards/step3", methods=['GET', 'POST'])
@login_required
def openvpn_wizards_step3():
    return render_template("openvpn_wizards3.html", active_tab="wizards")


# ----------------------------
# IPsec PAGE
# ----------------------------

@vpn_bp.route("/ipsec", methods=['GET', 'POST'])
@login_required
def ipsec():
    active_tab = request.args.get("tab", "tunnels")
    if active_tab not in ("tunnels", "mobile_clients", "psk", "advanced"):
        active_tab = "tunnels"
    return render_template("ipsec.html", active_tab=active_tab)


# ----------------------------
# IPsec API (Phase 1)
# ----------------------------

@vpn_bp.route("/api/ipsec/p1", methods=["GET"])
@login_required
def ipsec_p1_list():
    db = None
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute(
            """
            SELECT id, disabled, ike_version, remote_gateway, auth_method,
                   internet_protocol, interface, description
            FROM ipsec_phase1
            ORDER BY id
            """
        )
        rows = cur.fetchall()
        tunnels = []
        for r in rows:
            # algorithms summary
            cur.execute(
                """SELECT encryption, key_length, hash, dh_group
                   FROM ipsec_phase1_algorithms WHERE phase1_id=? ORDER BY id""",
                (r["id"],),
            )
            algos = [dict(a) for a in cur.fetchall()]
            tunnels.append({**dict(r), "algorithms": algos})
        return jsonify({"success": True, "tunnels": tunnels})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if db is not None:
            db.close()


@vpn_bp.route("/api/ipsec/p1", methods=["POST"])
@login_required
def ipsec_p1_create():
    db = None
    try:
        data = request.get_json() or {}
        remote_gateway = (data.get("remote_gateway") or "").strip()
        if not remote_gateway:
            return jsonify({"success": False, "error": "remote_gateway is required"}), 400

        db = get_db()
        cur = db.cursor()

        cur.execute(
            """
            INSERT INTO ipsec_phase1 (
                disabled, ike_version, internet_protocol, interface, remote_gateway,
                auth_method, my_identifier, peer_identifier, pre_shared_key,
                p1_life_time, p1_rekey_time, p1_reauth_time, p1_rand_time,
                child_sa_start_action, child_sa_close_action,
                nat_traversal, mobike,
                gateway_duplicates, split_connections, prf_selection,
                remote_ike_port, remote_nat_t_port,
                dpd_enable, dpd_delay, dpd_max_failures,
                description
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                1 if data.get("disabled") else 0,
                data.get("ike_version", data.get("key_exchange", data.get("keyExchange", "ikev2"))),
                data.get("internet_protocol", data.get("protocol", "ipv4")),
                data.get("interface", "wan"),
                remote_gateway,
                data.get("auth_method", data.get("authentication_method", data.get("authMethod", "mutual-psk"))),
                data.get("my_identifier", data.get("myIdentifier", "my-ip")),
                data.get("peer_identifier", data.get("peerIdentifier", "peer-ip")),
                seal(data.get("pre_shared_key", data.get("preshared_key", ""))),
                int(data.get("p1_life_time", data.get("life_time", 28800)) or 28800),
                int(data.get("p1_rekey_time", data.get("rekey_time", 25920)) or 25920),
                int(data.get("p1_reauth_time", data.get("reauth_time", 0)) or 0),
                int(data.get("p1_rand_time", data.get("rand_time", 2880)) or 2880),
                data.get("child_sa_start_action", "default"),
                data.get("child_sa_close_action", "default"),
                data.get("nat_traversal", "auto"),
                data.get("mobike", "disable"),
                1 if data.get("gateway_duplicates") else 0,
                1 if data.get("split_connections") else 0,
                1 if data.get("prf_selection") else 0,
                (data.get("remote_ike_port") or ""),
                (data.get("remote_nat_t_port") or ""),
                1 if data.get("dpd_enable", True) else 0,
                int(data.get("dpd_delay", 10) or 10),
                int(data.get("dpd_max_failures", 5) or 5),
                (data.get("description") or ""),
            ),
        )
        p1_id = cur.lastrowid

        algos = data.get("algorithms") or []
        if isinstance(algos, list) and len(algos) > 0:
            for a in algos:
                enc = (a.get("encryption") or "").strip()
                if not enc:
                    continue
                cur.execute(
                    """
                    INSERT INTO ipsec_phase1_algorithms (phase1_id, encryption, key_length, hash, dh_group)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        p1_id,
                        enc,
                        a.get("key_length"),
                        a.get("hash"),
                        a.get("dh_group"),
                    ),
                )
        else:
            # store the first default selection if none provided
            cur.execute(
                """
                INSERT INTO ipsec_phase1_algorithms (phase1_id, encryption, key_length, hash, dh_group)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    p1_id,
                    data.get("encryption_algorithm", "aes"),
                    int(data.get("key_length", 128) or 128),
                    data.get("hash_algorithm", "sha256"),
                    data.get("dh_key_group", "14"),
                ),
            )

        db.commit()
        return jsonify({"success": True, "id": p1_id})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if db is not None:
            db.close()


@vpn_bp.route("/api/ipsec/p1/<int:p1_id>", methods=["DELETE"])
@login_required
def ipsec_p1_delete(p1_id):
    db = None
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute("DELETE FROM ipsec_phase1 WHERE id=?", (p1_id,))
        db.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if db is not None:
            db.close()


@vpn_bp.route("/ipsec/mobile-clients", methods=['GET', 'POST'])
@login_required
def ipsec_mobile_clients():
    return render_template("IPsec_mob_clients.html", active_tab="mobile_clients")


@vpn_bp.route("/ipsec/pre-shared-keys", methods=['GET', 'POST'])
@login_required
def ipsec_pre_shared_keys():
    return render_template("IPsec_pre_shared_keys.html", active_tab="psk")


@vpn_bp.route("/ipsec/advanced-settings", methods=['GET', 'POST'])
@login_required
def ipsec_advanced_settings():
    return render_template("IPsec_advanced_settings.html", active_tab="advanced")


# ----------------------------
# IPsec Mobile Clients API
# ----------------------------

@vpn_bp.route("/api/ipsec/mobile-clients", methods=["GET"])
@login_required
def ipsec_mobile_clients_get():
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute(
            """
            SELECT ike_extensions, group_auth, radius_accounting,
                   virtual_address_pool, virtual_ipv6_address_pool,
                   radius_ip_priority, radius_advanced_parameters,
                   network_list, save_xauth_password,
                   dns_default_domain, split_dns, dns_servers, wins_servers,
                   phase2_pfs_group, login_banner
            FROM ipsec_mobile_clients_settings WHERE id=1
            """
        )
        row = cur.fetchone()
        if not row:
            return jsonify({"success": True, "settings": {}})
        return jsonify({"success": True, "settings": dict(row)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@vpn_bp.route("/api/ipsec/mobile-clients", methods=["POST"])
@login_required
def ipsec_mobile_clients_save():
    try:
        data = request.get_json() or {}
        db = get_db()
        cur = db.cursor()

        def b(name, default=False):
            return 1 if bool(data.get(name, default)) else 0

        cur.execute(
            """
            UPDATE ipsec_mobile_clients_settings
            SET ike_extensions=?,
                group_auth=?,
                radius_accounting=?,
                virtual_address_pool=?,
                virtual_ipv6_address_pool=?,
                radius_ip_priority=?,
                radius_advanced_parameters=?,
                network_list=?,
                save_xauth_password=?,
                dns_default_domain=?,
                split_dns=?,
                dns_servers=?,
                wins_servers=?,
                phase2_pfs_group=?,
                login_banner=?,
                updated_at=CURRENT_TIMESTAMP
            WHERE id=1
            """,
            (
                b("ike_extensions"),
                b("group_auth"),
                b("radius_accounting"),
                b("virtual_address_pool", True),
                b("virtual_ipv6_address_pool"),
                b("radius_ip_priority"),
                b("radius_advanced_parameters"),
                b("network_list", True),
                b("save_xauth_password"),
                b("dns_default_domain"),
                b("split_dns"),
                b("dns_servers"),
                b("wins_servers"),
                b("phase2_pfs_group"),
                b("login_banner"),
            ),
        )
        db.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ----------------------------
# IPsec Pre-Shared Keys API
# ----------------------------

@vpn_bp.route("/api/ipsec/psk", methods=["GET"])
@login_required
def ipsec_psk_list():
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute(
            """
            SELECT id, identifier, secret_type
            FROM ipsec_pre_shared_keys
            ORDER BY id
            """
        )
        keys = [dict(r) for r in cur.fetchall()]
        return jsonify({"success": True, "keys": keys})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@vpn_bp.route("/api/ipsec/psk", methods=["POST"])
@login_required
def ipsec_psk_create():
    try:
        data = request.get_json() or {}
        identifier = (data.get("identifier") or "").strip()
        secret_type = (data.get("secret_type") or "psk").strip()
        pre_shared_key = (data.get("pre_shared_key") or "").strip()

        if not identifier:
            return jsonify({"success": False, "error": "identifier is required"}), 400
        if not pre_shared_key:
            return jsonify({"success": False, "error": "pre_shared_key is required"}), 400

        db = get_db()
        cur = db.cursor()
        try:
            cur.execute(
                """
                INSERT INTO ipsec_pre_shared_keys (identifier, secret_type, pre_shared_key)
                VALUES (?, ?, ?)
                """,
                (identifier, secret_type, seal(pre_shared_key)),
            )
        except sqlite3.IntegrityError:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": "A PSK with the same identifier already exists",
                    }
                ),
                409,
            )

        db.commit()
        return jsonify({"success": True, "id": cur.lastrowid})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@vpn_bp.route("/api/ipsec/psk/<int:psk_id>", methods=["DELETE"])
@login_required
def ipsec_psk_delete(psk_id):
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute("DELETE FROM ipsec_pre_shared_keys WHERE id=?", (psk_id,))
        db.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ----------------------------
# IPsec Advanced Settings API
# ----------------------------

@vpn_bp.route("/api/ipsec/advanced-settings", methods=["GET"])
@login_required
def ipsec_advanced_settings_get():
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT * FROM ipsec_advanced_settings WHERE id=1")
        row = cur.fetchone()
        return jsonify({"success": True, "settings": dict(row) if row else {}})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@vpn_bp.route("/api/ipsec/advanced-settings", methods=["POST"])
@login_required
def ipsec_advanced_settings_save():
    try:
        data = request.get_json() or {}
        db = get_db()
        cur = db.cursor()

        def b(name, default=False):
            return 1 if bool(data.get(name, default)) else 0

        cur.execute(
            """
            UPDATE ipsec_advanced_settings
            SET log_daemon=?,
                log_sa_manager=?,
                log_ike_sa=?,
                log_ike_child_sa=?,
                log_job_processing=?,
                log_config_backend=?,
                log_kernel_interface=?,
                log_networking=?,
                log_asn_encoding=?,
                log_message_encoding=?,
                log_integrity_checker=?,
                log_integrity_verifier=?,
                log_platform_trust_service=?,
                log_tls_handler=?,
                log_ipsec_traffic=?,
                log_strongswan_lib=?,
                unique_ids=?,
                ipsec_filter_mode=?,
                ikev2_retransmission=?,
                ip_compression=?,
                pkcs11_support=?,
                strict_interface_binding=?,
                ikev1_unencrypted_payloads=?,
                max_ikev1_phase2_exchanges=?,
                enable_cisco_extensions=?,
                strict_crl_checking=?,
                fqdn_endpoints_resolve_interval=?,
                make_before_break=?,
                asynchronous_cryptography=?,
                custom_ike_port=?,
                custom_nat_t_port=?,
                auto_exclude_lan_address=?,
                additional_ipsec_bypass=?,
                updated_at=CURRENT_TIMESTAMP
            WHERE id=1
            """,
            (
                data.get("log_daemon", "Control"),
                data.get("log_sa_manager", "Control"),
                data.get("log_ike_sa", "Control"),
                data.get("log_ike_child_sa", "Control"),
                data.get("log_job_processing", "Control"),
                data.get("log_config_backend", "Control"),
                data.get("log_kernel_interface", "Control"),
                data.get("log_networking", "Control"),
                data.get("log_asn_encoding", "Control"),
                data.get("log_message_encoding", "Control"),
                data.get("log_integrity_checker", "Control"),
                data.get("log_integrity_verifier", "Control"),
                data.get("log_platform_trust_service", "Control"),
                data.get("log_tls_handler", "Control"),
                data.get("log_ipsec_traffic", "Control"),
                data.get("log_strongswan_lib", "Control"),
                data.get("unique_ids", "Yes (Replace)"),
                data.get(
                    "ipsec_filter_mode",
                    "Filter [IPsec Tunnel, Transport, and VTI] on IPsec tab (enc0)",
                ),
                b("ikev2_retransmission"),
                b("ip_compression"),
                b("pkcs11_support"),
                b("strict_interface_binding"),
                b("ikev1_unencrypted_payloads"),
                int(data.get("max_ikev1_phase2_exchanges", 3) or 3),
                b("enable_cisco_extensions"),
                b("strict_crl_checking"),
                int(data.get("fqdn_endpoints_resolve_interval", 60) or 60),
                b("make_before_break"),
                b("asynchronous_cryptography"),
                (data.get("custom_ike_port") or ""),
                (data.get("custom_nat_t_port") or ""),
                b("auto_exclude_lan_address"),
                b("additional_ipsec_bypass"),
            ),
        )

        db.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ----------------------------
# L2TP PAGE
# ----------------------------

@vpn_bp.route("/l2tp", methods=['GET', 'POST'])
@login_required
def l2tp():
    return render_template("l2tp.html")


@vpn_bp.route("/l2tp/users", methods=['GET', 'POST'])
@login_required
def l2tp_users():
    return render_template("l2tp_users.html")


# ----------------------------
# L2TP API (Configuration)
# ----------------------------

@vpn_bp.route("/api/l2tp/settings", methods=["GET"])
@login_required
def l2tp_settings_get():
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT enabled FROM l2tp_settings WHERE id=1")
        row = cur.fetchone()
        return jsonify({"success": True, "settings": dict(row) if row else {}})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@vpn_bp.route("/api/l2tp/settings", methods=["POST"])
@login_required
def l2tp_settings_save():
    try:
        data = request.get_json() or {}
        enabled = 1 if bool(data.get("enabled", True)) else 0
        db = get_db()
        cur = db.cursor()
        cur.execute(
            """
            UPDATE l2tp_settings
            SET enabled=?, updated_at=CURRENT_TIMESTAMP
            WHERE id=1
            """,
            (enabled,),
        )
        db.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ----------------------------
# OPENVPN API ENDPOINTS
# ----------------------------

@vpn_bp.route("/api/openvpn/save-server", methods=['POST'])
@login_required
def save_openvpn_server():
    try:
        data = request.get_json()
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("""
            INSERT INTO openvpn_servers 
            (description, disabled, server_mode, device_mode, protocol, interface, 
             local_port, tls_key, tls_key_auto, peer_ca)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data.get('description', ''),
            1 if data.get('disabled') else 0,
            data.get('server_mode', 'peer2peer'),
            data.get('device_mode', 'tun'),
            data.get('protocol', 'udp4'),
            data.get('interface', 'wan'),
            data.get('local_port', 1194),
            1 if data.get('tls_key') else 0,
            1 if data.get('tls_key_auto') else 0,
            data.get('peer_ca', '')
        ))
        
        db.commit()
        server_id = cursor.lastrowid
        
        return jsonify({
            'status': 'success',
            'message': 'OpenVPN server saved successfully',
            'id': server_id
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@vpn_bp.route("/api/openvpn/get-servers", methods=['GET'])
@login_required
def get_openvpn_servers():
    try:
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("""
            SELECT id, description, disabled, server_mode, device_mode, protocol,
                   interface, local_port, created_at
            FROM openvpn_servers
            ORDER BY id DESC
        """)
        
        servers = []
        for row in cursor.fetchall():
            servers.append({
                'id': row[0],
                'description': row[1],
                'disabled': bool(row[2]),
                'server_mode': row[3],
                'device_mode': row[4],
                'protocol': row[5],
                'interface': row[6],
                'local_port': row[7],
                'created_at': row[8]
            })
        
        return jsonify({
            'status': 'success',
            'servers': servers
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@vpn_bp.route("/api/openvpn/delete-server/<int:server_id>", methods=['DELETE'])
@login_required
def delete_openvpn_server(server_id):
    try:
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("DELETE FROM openvpn_servers WHERE id = ?", (server_id,))
        db.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'OpenVPN server deleted successfully'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


# ----------------------------
# OPENVPN CLIENTS API ENDPOINTS
# ----------------------------

@vpn_bp.route("/api/openvpn/save-client", methods=['POST'])
@login_required
def save_openvpn_client():
    try:
        data = request.get_json()
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("""
            INSERT INTO openvpn_clients 
            (description, disabled, server_mode, protocol, interface, server_hostname,
             server_port, use_tls_key, tls_key, ca_cert, client_cert, client_key,
             encryption_algorithm, auth_digest_algorithm, inactivity_timeout, ping_method,
             ping_interval, ping_timeout, custom_options, udp_fast_io, 
             send_receive_buffer, verbosity_level)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data.get('description', ''),
            1 if data.get('disabled') else 0,
            data.get('server_mode', 'peer2peer'),
            data.get('protocol', 'udp4'),
            data.get('interface', 'wan'),
            data.get('server_hostname', ''),
            data.get('server_port', 1194),
            1 if data.get('use_tls_key') else 0,
            data.get('tls_key', ''),
            data.get('ca_cert', ''),
            data.get('client_cert', ''),
            data.get('client_key', ''),
            data.get('encryption_algorithm', 'AES-256-CBC'),
            data.get('auth_digest_algorithm', 'SHA256'),
            data.get('inactivity_timeout', 300),
            data.get('ping_method', 'keepalive'),
            data.get('ping_interval', 10),
            data.get('ping_timeout', 60),
            data.get('custom_options', ''),
            1 if data.get('udp_fast_io') else 0,
            data.get('send_receive_buffer', 'default'),
            data.get('verbosity_level', 3)
        ))
        
        db.commit()
        client_id = cursor.lastrowid
        
        return jsonify({
            'status': 'success',
            'message': 'OpenVPN client saved successfully',
            'id': client_id
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@vpn_bp.route("/api/openvpn/get-clients", methods=['GET'])
@login_required
def get_openvpn_clients():
    try:
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("""
            SELECT id, description, disabled, server_mode, protocol, interface,
                   server_hostname, server_port, created_at
            FROM openvpn_clients
            ORDER BY id DESC
        """)
        
        clients = []
        for row in cursor.fetchall():
            clients.append({
                'id': row[0],
                'description': row[1],
                'disabled': bool(row[2]),
                'server_mode': row[3],
                'protocol': row[4],
                'interface': row[5],
                'server_hostname': row[6],
                'server_port': row[7],
                'created_at': row[8]
            })
        
        return jsonify({
            'status': 'success',
            'clients': clients
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@vpn_bp.route("/api/openvpn/delete-client/<int:client_id>", methods=['DELETE'])
@login_required
def delete_openvpn_client(client_id):
    try:
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("DELETE FROM openvpn_clients WHERE id = ?", (client_id,))
        db.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'OpenVPN client deleted successfully'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


# ----------------------------
# OPENVPN CLIENT SPECIFIC OVERRIDES API ENDPOINTS
# ----------------------------

@vpn_bp.route("/api/openvpn/save-cso", methods=['POST'])
@login_required
def save_openvpn_cso():
    try:
        data = request.get_json()
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("""
            INSERT INTO openvpn_cso (
                description, disabled, common_name, connection_blocking, server_list,
                reset_server_options, ipv4_tunnel_network, ipv6_tunnel_network,
                ipv4_gateway, ipv6_gateway, redirect_ipv4_gateway, redirect_ipv6_gateway,
                ipv4_local_networks, ipv6_local_networks, ipv4_remote_networks, ipv6_remote_networks,
                inactivity_timeout, ping_interval, ping_action,
                dns_default_domain, dns_servers, block_outside_dns, force_dns_cache_update,
                ntp_servers, netbios_options, advanced
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data.get('description', ''),
            1 if data.get('disabled') else 0,
            data.get('common_name', ''),
            1 if data.get('connection_blocking') else 0,
            data.get('server_list', ''),
            data.get('reset_server_options', 'keep'),
            data.get('ipv4_tunnel_network', ''),
            data.get('ipv6_tunnel_network', ''),
            data.get('ipv4_gateway', ''),
            data.get('ipv6_gateway', ''),
            1 if data.get('redirect_ipv4_gateway') else 0,
            1 if data.get('redirect_ipv6_gateway') else 0,
            data.get('ipv4_local_networks', ''),
            data.get('ipv6_local_networks', ''),
            data.get('ipv4_remote_networks', ''),
            data.get('ipv6_remote_networks', ''),
            data.get('inactivity_timeout', 300),
            data.get('ping_interval', 10),
            data.get('ping_action', 'none'),
            1 if data.get('dns_default_domain') else 0,
            1 if data.get('dns_servers') else 0,
            1 if data.get('block_outside_dns') else 0,
            1 if data.get('force_dns_cache_update') else 0,
            1 if data.get('ntp_servers') else 0,
            1 if data.get('netbios_options') else 0,
            data.get('advanced', '')
        ))
        
        db.commit()
        cso_id = cursor.lastrowid
        
        return jsonify({
            'status': 'success',
            'message': 'Client Specific Override saved successfully',
            'id': cso_id
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@vpn_bp.route("/api/openvpn/get-csos", methods=['GET'])
@login_required
def get_openvpn_csos():
    try:
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("""
            SELECT id, description, disabled, common_name, connection_blocking, created_at
            FROM openvpn_cso
            ORDER BY id DESC
        """)
        
        csos = []
        for row in cursor.fetchall():
            csos.append({
                'id': row[0],
                'description': row[1],
                'disabled': bool(row[2]),
                'common_name': row[3],
                'connection_blocking': bool(row[4]),
                'created_at': row[5]
            })
        
        return jsonify({
            'status': 'success',
            'csos': csos
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@vpn_bp.route("/api/openvpn/delete-cso/<int:cso_id>", methods=['DELETE'])
@login_required
def delete_openvpn_cso(cso_id):
    try:
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("DELETE FROM openvpn_cso WHERE id = ?", (cso_id,))
        db.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Client Specific Override deleted successfully'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


# ----------------------------
# IPSEC API ENDPOINTS
# ----------------------------

@vpn_bp.route("/api/ipsec/save-phase1", methods=['POST'])
@login_required
def save_ipsec_phase1():
    payload, status = _payload_and_status(ipsec_p1_create())
    if payload.get("success"):
        return jsonify({"status": "success", "id": payload.get("id")}), status
    return jsonify({"status": "error", "message": payload.get("error", "Unknown error")}), status


@vpn_bp.route("/api/ipsec/get-phase1", methods=['GET'])
@login_required
def get_ipsec_phase1():
    payload, status = _payload_and_status(ipsec_p1_list())
    if not payload.get("success"):
        return jsonify({"status": "error", "message": payload.get("error", "Unknown error")}), status

    tunnels = []
    for item in payload.get("tunnels", []):
        algos = item.get("algorithms") or []
        first = algos[0] if algos else {}
        tunnels.append(
            {
                "id": item.get("id"),
                "description": item.get("description", ""),
                "disabled": bool(item.get("disabled")),
                "key_exchange": item.get("ike_version", ""),
                "remote_gateway": item.get("remote_gateway", ""),
                "auth_method": item.get("auth_method", ""),
                "encryption": first.get("encryption", ""),
                "hash": first.get("hash", ""),
                "dh_group": first.get("dh_group", ""),
            }
        )
    return jsonify({"status": "success", "tunnels": tunnels}), status


@vpn_bp.route("/api/ipsec/delete-phase1/<int:phase1_id>", methods=['DELETE'])
@login_required
def delete_ipsec_phase1(phase1_id):
    payload, status = _payload_and_status(ipsec_p1_delete(phase1_id))
    if payload.get("success"):
        return jsonify({"status": "success"}), status
    return jsonify({"status": "error", "message": payload.get("error", "Unknown error")}), status


# ----------------------------
# L2TP API ENDPOINTS
# ----------------------------

@vpn_bp.route("/api/l2tp/save-config", methods=['POST'])
@login_required
def save_l2tp_config():
    try:
        data = request.get_json()
        db = get_db()
        cursor = db.cursor()
        
        # Check if config exists
        cursor.execute("SELECT id FROM l2tp_config LIMIT 1")
        existing = cursor.fetchone()
        
        if existing:
            cursor.execute("""
                UPDATE l2tp_config SET enabled = ? WHERE id = ?
            """, (1 if data.get('enabled') else 0, existing[0]))
        else:
            cursor.execute("""
                INSERT INTO l2tp_config (enabled) VALUES (?)
            """, (1 if data.get('enabled') else 0,))
        
        db.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@vpn_bp.route("/api/l2tp/get-config", methods=['GET'])
@login_required
def get_l2tp_config():
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT enabled FROM l2tp_config LIMIT 1")
        row = cursor.fetchone()
        
        enabled = bool(row[0]) if row else True
        return jsonify({'status': 'success', 'enabled': enabled})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@vpn_bp.route("/api/l2tp/save-user", methods=['POST'])
@login_required
def save_l2tp_user():
    try:
        data = request.get_json()
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""
        if not username or not password:
            return jsonify({'status': 'error', 'message': 'username and password are required'}), 400

        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("""
            INSERT INTO l2tp_users (username, password, ip_address)
            VALUES (?, ?, ?)
        """, (
            username,
            generate_password_hash(password),
            data.get('ip_address', '')
        ))
        
        db.commit()
        return jsonify({'status': 'success', 'id': cursor.lastrowid})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@vpn_bp.route("/api/l2tp/get-users", methods=['GET'])
@login_required
def get_l2tp_users():
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT id, username, ip_address FROM l2tp_users ORDER BY id DESC")
        
        users = []
        for row in cursor.fetchall():
            users.append({
                'id': row[0],
                'username': row[1],
                'ip_address': row[2] or '-'
            })
        
        return jsonify({'status': 'success', 'users': users})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@vpn_bp.route("/api/l2tp/get-user/<int:user_id>", methods=['GET'])
@login_required
def get_l2tp_user(user_id):
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT id, username, ip_address FROM l2tp_users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        
        if row:
            user = {
                'id': row[0],
                'username': row[1],
                'ip_address': row[2] or ''
            }
            return jsonify({'status': 'success', 'user': user})
        else:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@vpn_bp.route("/api/l2tp/update-user/<int:user_id>", methods=['PUT'])
@login_required
def update_l2tp_user(user_id):
    try:
        data = request.get_json()
        db = get_db()
        cursor = db.cursor()
        
        # If password is provided, update it; otherwise, only update username and ip_address
        if data.get('password'):
            cursor.execute("""
                UPDATE l2tp_users 
                SET username = ?, password = ?, ip_address = ?
                WHERE id = ?
            """, (
                data.get('username'),
                generate_password_hash(data.get('password')),
                data.get('ip_address', ''),
                user_id
            ))
        else:
            cursor.execute("""
                UPDATE l2tp_users 
                SET username = ?, ip_address = ?
                WHERE id = ?
            """, (
                data.get('username'),
                data.get('ip_address', ''),
                user_id
            ))
        
        db.commit()
        return jsonify({'status': 'success', 'message': 'L2TP user updated successfully'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@vpn_bp.route("/api/l2tp/delete-user/<int:user_id>", methods=['DELETE'])
@login_required
def delete_l2tp_user(user_id):
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("DELETE FROM l2tp_users WHERE id = ?", (user_id,))
        db.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ----------------------------
# OPENVPN WIZARD API ENDPOINTS
# ----------------------------

@vpn_bp.route("/api/wizard/save-auth-type", methods=['POST'])
@login_required
def save_wizard_auth_type():
    try:
        data = request.get_json()
        db = get_db()
        cursor = db.cursor()
        
        # Check if wizard config exists
        cursor.execute("SELECT id FROM openvpn_wizard_configs ORDER BY id DESC LIMIT 1")
        existing = cursor.fetchone()
        
        if existing:
            cursor.execute("""
                UPDATE openvpn_wizard_configs 
                SET type_of_server = ?
                WHERE id = ?
            """, (data.get('type_of_server', 'local'), existing[0]))
        else:
            cursor.execute("""
                INSERT INTO openvpn_wizard_configs (type_of_server)
                VALUES (?)
            """, (data.get('type_of_server', 'local'),))
        
        db.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@vpn_bp.route("/api/wizard/save-ca", methods=['POST'])
@login_required
def save_wizard_ca():
    try:
        data = request.get_json()
        db = get_db()
        cursor = db.cursor()
        
        # Insert CA
        cursor.execute("""
            INSERT INTO certificate_authorities (
                descriptive_name, randomize_serial, key_length, lifetime,
                common_name, country_code, state_or_province, city,
                organization, organizational_unit, ca_data
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data.get('descriptive_name', ''),
            1 if data.get('randomize_serial', True) else 0,
            data.get('key_length', 2048),
            data.get('lifetime', 3650),
            data.get('common_name', ''),
            data.get('country_code', ''),
            data.get('state_or_province', ''),
            data.get('city', ''),
            data.get('organization', ''),
            data.get('organizational_unit', ''),
            'Generated CA Data - ' + data.get('descriptive_name', '')
        ))
        
        ca_id = cursor.lastrowid
        
        # Update wizard config with CA
        cursor.execute("SELECT id FROM openvpn_wizard_configs ORDER BY id DESC LIMIT 1")
        wizard_config = cursor.fetchone()
        
        if wizard_config:
            cursor.execute("""
                UPDATE openvpn_wizard_configs 
                SET ca_id = ?
                WHERE id = ?
            """, (ca_id, wizard_config[0]))
        
        db.commit()
        return jsonify({'status': 'success', 'ca_id': ca_id})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@vpn_bp.route("/api/wizard/get-cas", methods=['GET'])
@login_required
def get_wizard_cas():
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("""
            SELECT id, descriptive_name, common_name, key_length, lifetime, created_at
            FROM certificate_authorities
            ORDER BY id DESC
        """)
        
        cas = []
        for row in cursor.fetchall():
            cas.append({
                'id': row[0],
                'descriptive_name': row[1],
                'common_name': row[2],
                'key_length': row[3],
                'lifetime': row[4],
                'created_at': row[5]
            })
        
        return jsonify({'status': 'success', 'cas': cas})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@vpn_bp.route("/api/wizard/delete-ca/<int:ca_id>", methods=['DELETE'])
@login_required
def delete_wizard_ca(ca_id):
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("DELETE FROM certificate_authorities WHERE id = ?", (ca_id,))
        db.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ══════════════════════════════════════════════════════════════════════════════
# VPN APPLY & STATUS — FreeBSD service control
# ══════════════════════════════════════════════════════════════════════════════

# ── OpenVPN ───────────────────────────────────────────────────────────────────

@vpn_bp.route("/api/openvpn/apply", methods=["POST"])
@login_required
def openvpn_apply():
    """Write all OpenVPN configs and restart the service on FreeBSD."""
    try:
        from app.services.openvpn_writer import apply_openvpn
        from app.audit_log import log_event
        conn = get_db()
        result = apply_openvpn(conn)
        log_event(category="system", action="openvpn_apply",
                  username=request.values.get("username"),
                  remote_addr=request.remote_addr,
                  details={"ok": result["ok"], "message": result["message"]})
        return jsonify(result)
    except Exception as exc:
        return jsonify({"ok": False, "message": str(exc)}), 500


@vpn_bp.route("/api/openvpn/status", methods=["GET"])
@login_required
def openvpn_status():
    """Return running state of OpenVPN instances."""
    try:
        from app.services.openvpn_writer import get_openvpn_status
        return jsonify(get_openvpn_status())
    except Exception as exc:
        return jsonify({"running": False, "error": str(exc)}), 500


@vpn_bp.route("/api/openvpn/generate-config/<int:server_id>", methods=["GET"])
@login_required
def openvpn_generate_config(server_id):
    """Return generated .conf text for a specific server (preview)."""
    try:
        from app.services.openvpn_writer import generate_server_conf
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM openvpn_servers WHERE id=?", (server_id,))
        row = cur.fetchone()
        if not row:
            return jsonify({"ok": False, "error": "Server not found"}), 404
        conf = generate_server_conf(dict(row))
        return jsonify({"ok": True, "conf": conf})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


# ── IPsec ─────────────────────────────────────────────────────────────────────

@vpn_bp.route("/api/ipsec/apply", methods=["POST"])
@login_required
def ipsec_apply():
    """Write ipsec.conf + ipsec.secrets and reload strongSwan."""
    try:
        from app.services.ipsec_writer import apply_ipsec
        from app.audit_log import log_event
        conn = get_db()
        result = apply_ipsec(conn)
        log_event(category="system", action="ipsec_apply",
                  username=request.values.get("username"),
                  remote_addr=request.remote_addr,
                  details={"ok": result["ok"], "message": result["message"]})
        return jsonify(result)
    except Exception as exc:
        return jsonify({"ok": False, "message": str(exc)}), 500


@vpn_bp.route("/api/ipsec/status", methods=["GET"])
@login_required
def ipsec_status():
    """Return live IPsec tunnel states from 'ipsec statusall'."""
    try:
        from app.services.ipsec_writer import get_ipsec_status
        return jsonify(get_ipsec_status())
    except Exception as exc:
        return jsonify({"running": False, "error": str(exc)}), 500


@vpn_bp.route("/api/ipsec/preview", methods=["GET"])
@login_required
def ipsec_preview():
    """Return generated ipsec.conf text for review."""
    try:
        from app.services.ipsec_writer import generate_ipsec_conf, generate_ipsec_secrets
        conn = get_db()
        return jsonify({
            "ok": True,
            "conf": generate_ipsec_conf(conn),
            "secrets": "[hidden — contains PSKs]",
        })
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@vpn_bp.route("/api/ipsec/p2", methods=["GET"])
@login_required
def ipsec_p2_list():
    """List Phase 2 (child SA) entries for a given phase1_id."""
    try:
        p1_id = request.args.get("p1_id", type=int)
        conn = get_db()
        cur = conn.cursor()
        if p1_id:
            cur.execute("SELECT * FROM ipsec_phase2 WHERE phase1_id=? ORDER BY id", (p1_id,))
        else:
            cur.execute("SELECT * FROM ipsec_phase2 ORDER BY id")
        rows = [dict(r) for r in cur.fetchall()]
        return jsonify({"success": True, "entries": rows})
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500


@vpn_bp.route("/api/ipsec/p2", methods=["POST"])
@login_required
def ipsec_p2_create():
    """Create or update a Phase 2 child SA."""
    try:
        data  = request.get_json() or {}
        p1_id = data.get("phase1_id")
        if not p1_id:
            return jsonify({"success": False, "error": "phase1_id required"}), 400
        conn = get_db()
        cur = conn.cursor()
        rid = data.get("id")
        fields = {
            "phase1_id":             p1_id,
            "description":           data.get("description", ""),
            "disabled":              1 if data.get("disabled") else 0,
            "mode":                  data.get("mode", "tunnel"),
            "local_network":         data.get("local_network", ""),
            "remote_network":        data.get("remote_network", ""),
            "protocol":              data.get("protocol", "esp"),
            "encryption_algorithms": data.get("encryption_algorithms", "aes256"),
            "hash_algorithms":       data.get("hash_algorithms", "sha256"),
            "pfs_key_group":         data.get("pfs_key_group", "14"),
            "lifetime":              data.get("lifetime", 3600),
        }
        if rid:
            sets = ", ".join(f"{k}=?" for k in fields)
            cur.execute(f"UPDATE ipsec_phase2 SET {sets} WHERE id=?",
                        list(fields.values()) + [rid])
            conn.commit()
            return jsonify({"success": True, "id": rid})
        cols = ", ".join(fields.keys())
        vals = ", ".join("?" * len(fields))
        cur.execute(f"INSERT INTO ipsec_phase2 ({cols}) VALUES ({vals})",
                    list(fields.values()))
        conn.commit()
        return jsonify({"success": True, "id": cur.lastrowid})
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500


@vpn_bp.route("/api/ipsec/p2/<int:p2_id>", methods=["DELETE"])
@login_required
def ipsec_p2_delete(p2_id):
    try:
        conn = get_db()
        conn.execute("DELETE FROM ipsec_phase2 WHERE id=?", (p2_id,))
        conn.commit()
        return jsonify({"success": True})
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500


# ── L2TP ─────────────────────────────────────────────────────────────────────

@vpn_bp.route("/api/l2tp/apply", methods=["POST"])
@login_required
def l2tp_apply():
    """Write mpd5 config and restart L2TP service."""
    try:
        from app.services.l2tp_writer import apply_l2tp
        from app.audit_log import log_event
        conn = get_db()
        result = apply_l2tp(conn)
        log_event(category="system", action="l2tp_apply",
                  username=request.values.get("username"),
                  remote_addr=request.remote_addr,
                  details={"ok": result["ok"], "message": result["message"]})
        return jsonify(result)
    except Exception as exc:
        return jsonify({"ok": False, "message": str(exc)}), 500


@vpn_bp.route("/api/l2tp/status", methods=["GET"])
@login_required
def l2tp_status():
    """Return mpd5 running state and active sessions."""
    try:
        from app.services.l2tp_writer import get_l2tp_status
        return jsonify(get_l2tp_status())
    except Exception as exc:
        return jsonify({"running": False, "error": str(exc)}), 500


@vpn_bp.route("/api/l2tp/preview", methods=["GET"])
@login_required
def l2tp_preview():
    """Return generated mpd.conf text for review."""
    try:
        from app.services.l2tp_writer import generate_mpd_conf
        conn = get_db()
        return jsonify({"ok": True, "conf": generate_mpd_conf(conn)})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500
