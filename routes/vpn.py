from flask import Blueprint, render_template, request, jsonify
from app.database import get_db

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

@vpn_bp.route("/openvpn", methods=['GET', 'POST'])
def openvpn():
    # OpenVPN Servers (default tab)
    return render_template("openvpn.html", active_tab="servers")


@vpn_bp.route("/openvpn/servers", methods=['GET', 'POST'])
def openvpn_servers():
    return render_template("openvpn.html", active_tab="servers")


@vpn_bp.route("/openvpn/clients", methods=['GET', 'POST'])
def openvpn_clients():
    return render_template("openvpn_clients.html", active_tab="clients")


@vpn_bp.route("/openvpn/cso", methods=['GET', 'POST'])
def openvpn_cso():
    return render_template("openvpn_cso.html", active_tab="cso")


@vpn_bp.route("/openvpn/wizards", methods=['GET', 'POST'])
def openvpn_wizards():
    return render_template("openvpn_wizards1.html", active_tab="wizards")


@vpn_bp.route("/openvpn/wizards/step2", methods=['GET', 'POST'])
def openvpn_wizards_step2():
    return render_template("openvpn_wizards2.html", active_tab="wizards")


@vpn_bp.route("/openvpn/wizards/step3", methods=['GET', 'POST'])
def openvpn_wizards_step3():
    return render_template("openvpn_wizards3.html", active_tab="wizards")


# ----------------------------
# IPsec PAGE
# ----------------------------

@vpn_bp.route("/ipsec", methods=['GET', 'POST'])
def ipsec():
    return render_template("ipsec.html")


@vpn_bp.route("/ipsec/mobile-clients", methods=['GET', 'POST'])
def ipsec_mobile_clients():
    return render_template("IPsec_mob_clients.html", active_tab="mobile_clients")


@vpn_bp.route("/ipsec/pre-shared-keys", methods=['GET', 'POST'])
def ipsec_pre_shared_keys():
    return render_template("IPsec_pre_shared_keys.html", active_tab="psk")


@vpn_bp.route("/ipsec/advanced-settings", methods=['GET', 'POST'])
def ipsec_advanced_settings():
    return render_template("IPsec_advanced_settings.html", active_tab="advanced")


# ----------------------------
# L2TP PAGE
# ----------------------------

@vpn_bp.route("/l2tp", methods=['GET', 'POST'])
def l2tp():
    return render_template("l2tp.html")


@vpn_bp.route("/l2tp/users", methods=['GET', 'POST'])
def l2tp_users():
    return render_template("l2tp_users.html")


# ----------------------------
# OPENVPN API ENDPOINTS
# ----------------------------

@vpn_bp.route("/api/openvpn/save-server", methods=['POST'])
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
def save_ipsec_phase1():
    try:
        data = request.get_json()
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("""
            INSERT INTO ipsec_phase1 
            (description, disabled, key_exchange, internet_protocol, interface, 
             remote_gateway, authentication_method, my_identifier, peer_identifier, 
             preshared_key, encryption_algorithm, hash_algorithm, dh_key_group, lifetime)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data.get('description', ''),
            1 if data.get('disabled') else 0,
            data.get('key_exchange', 'ikev2'),
            data.get('internet_protocol', 'ipv4'),
            data.get('interface', 'wan'),
            data.get('remote_gateway', ''),
            data.get('authentication_method', 'preshared_key'),
            data.get('my_identifier', ''),
            data.get('peer_identifier', ''),
            data.get('preshared_key', ''),
            data.get('encryption_algorithm', 'aes256'),
            data.get('hash_algorithm', 'sha256'),
            data.get('dh_key_group', '14'),
            data.get('lifetime', 28800)
        ))
        
        db.commit()
        return jsonify({'status': 'success', 'id': cursor.lastrowid})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@vpn_bp.route("/api/ipsec/get-phase1", methods=['GET'])
def get_ipsec_phase1():
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("""
            SELECT id, description, disabled, key_exchange, remote_gateway, 
                   authentication_method, encryption_algorithm, hash_algorithm, dh_key_group
            FROM ipsec_phase1 ORDER BY id DESC
        """)
        
        tunnels = []
        for row in cursor.fetchall():
            tunnels.append({
                'id': row[0],
                'description': row[1],
                'disabled': bool(row[2]),
                'key_exchange': row[3],
                'remote_gateway': row[4],
                'auth_method': row[5],
                'encryption': row[6],
                'hash': row[7],
                'dh_group': row[8]
            })
        
        return jsonify({'status': 'success', 'tunnels': tunnels})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@vpn_bp.route("/api/ipsec/delete-phase1/<int:phase1_id>", methods=['DELETE'])
def delete_ipsec_phase1(phase1_id):
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("DELETE FROM ipsec_phase2 WHERE phase1_id = ?", (phase1_id,))
        cursor.execute("DELETE FROM ipsec_phase1 WHERE id = ?", (phase1_id,))
        db.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ----------------------------
# L2TP API ENDPOINTS
# ----------------------------

@vpn_bp.route("/api/l2tp/save-config", methods=['POST'])
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
def save_l2tp_user():
    try:
        data = request.get_json()
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("""
            INSERT INTO l2tp_users (username, password, ip_address)
            VALUES (?, ?, ?)
        """, (
            data.get('username', ''),
            data.get('password', ''),
            data.get('ip_address', '')
        ))
        
        db.commit()
        return jsonify({'status': 'success', 'id': cursor.lastrowid})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@vpn_bp.route("/api/l2tp/get-users", methods=['GET'])
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
                data.get('password'),
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
def delete_wizard_ca(ca_id):
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("DELETE FROM certificate_authorities WHERE id = ?", (ca_id,))
        db.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

