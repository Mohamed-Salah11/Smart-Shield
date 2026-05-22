from routes.vpn import vpn_bp
from routes.vpn._common import *  # noqa: F401,F403
from routes.vpn._common import _payload_and_status  # noqa: F401


@vpn_bp.route("/api/openvpn/save-server", methods=['POST'])
@api_permission_required("api.vpn.edit")
def save_openvpn_server():
    try:
        data = request.get_json(silent=True) or {}
        db = get_db()
        cursor = db.cursor()

        cursor.execute("""
            INSERT INTO openvpn_servers
            (description, disabled, server_mode, device_mode, protocol, interface,
             local_port, tls_key, tls_key_auto, peer_ca,
             tunnel_network, tunnel_network_v6, local_network, remote_network,
             redirect_gateway, max_clients, compression,
             inter_client_communication, duplicate_connection,
             dynamic_ip, topology,
             inactivity_timeout, ping_method, ping_interval, ping_timeout,
             custom_options, verbosity_level,
             dh_parameter_length, ecdh_curve,
             data_encryption_algorithms, fallback_data_encryption_algorithm,
             auth_digest_algorithm, ca_id, server_cert_id)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            data.get('description', ''),
            1 if data.get('disabled') else 0,
            data.get('server_mode', 'peer2peer'),
            data.get('device_mode', 'tun'),
            data.get('protocol', 'udp4'),
            data.get('interface', 'wan'),
            int(data.get('local_port') or 1194),
            1 if data.get('tls_key') else 0,
            1 if data.get('tls_key_auto') else 0,
            data.get('peer_ca', ''),
            data.get('tunnel_network', ''),
            data.get('tunnel_network_v6', ''),
            data.get('local_network', ''),
            data.get('remote_network', ''),
            1 if data.get('redirect_gateway') else 0,
            int(data.get('max_clients') or 0) or None,
            data.get('compression', 'refuse'),
            1 if data.get('inter_client_communication') else 0,
            1 if data.get('duplicate_connection') else 0,
            1 if data.get('dynamic_ip') else 0,
            data.get('topology', 'subnet'),
            int(data.get('inactivity_timeout') or 300),
            data.get('ping_method', 'keepalive'),
            int(data.get('ping_interval') or 10),
            int(data.get('ping_timeout') or 60),
            data.get('custom_options', ''),
            int(data.get('verbosity_level') or 1),
            data.get('dh_parameter_length', '2048'),
            data.get('ecdh_curve', 'default'),
            data.get('data_encryption_algorithms', 'AES-256-GCM'),
            data.get('fallback_data_encryption_algorithm', 'AES-256-CBC'),
            data.get('auth_digest_algorithm', 'SHA256'),
            int(data['ca_id']) if data.get('ca_id') else None,
            int(data['server_cert_id']) if data.get('server_cert_id') else None,
        ))

        db.commit()
        server_id = cursor.lastrowid
        return jsonify({'status': 'success', 'message': 'OpenVPN server saved successfully', 'id': server_id})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


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


@vpn_bp.route("/api/openvpn/get-server/<int:server_id>", methods=['GET'])
@login_required
def get_openvpn_server(server_id):
    """Get a single OpenVPN server by ID for editing."""
    try:
        db = get_db()
        row = db.execute("SELECT * FROM openvpn_servers WHERE id=?", (server_id,)).fetchone()
        if not row:
            return jsonify({'status': 'error', 'message': 'Server not found'}), 404
        return jsonify({'status': 'success', 'server': dict(row)})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@vpn_bp.route("/api/openvpn/certificates", methods=['GET'])
@login_required
def openvpn_get_certificates():
    """Return CA and server certificates available for OpenVPN configuration."""
    try:
        db = get_db()
        try:
            cas = db.execute(
                "SELECT id, name FROM certificates WHERE cert_type='ca' AND revoked=0 ORDER BY name"
            ).fetchall()
            server_certs = db.execute(
                "SELECT id, name FROM certificates WHERE cert_type='server' AND revoked=0 ORDER BY name"
            ).fetchall()
        except Exception:
            cas, server_certs = [], []
        return jsonify({
            'ok': True,
            'cas': [dict(r) for r in cas],
            'server_certs': [dict(r) for r in server_certs],
        })
    except Exception as e:
        return jsonify({'ok': False, 'message': str(e)}), 500


@vpn_bp.route("/api/openvpn/update-server/<int:server_id>", methods=['PUT'])
@api_permission_required("api.vpn.edit")
def update_openvpn_server(server_id):
    """Update an existing OpenVPN server."""
    try:
        data = request.get_json(silent=True) or {}
        db = get_db()
        db.execute(
            """UPDATE openvpn_servers SET
               description=?, disabled=?, server_mode=?, device_mode=?,
               protocol=?, interface=?, local_port=?, tls_key=?, tls_key_auto=?, peer_ca=?,
               tunnel_network=?, tunnel_network_v6=?, local_network=?, remote_network=?,
               redirect_gateway=?, max_clients=?, compression=?,
               inter_client_communication=?, duplicate_connection=?,
               dynamic_ip=?, topology=?,
               inactivity_timeout=?, ping_method=?, ping_interval=?, ping_timeout=?,
               custom_options=?, verbosity_level=?,
               dh_parameter_length=?, ecdh_curve=?,
               data_encryption_algorithms=?, fallback_data_encryption_algorithm=?,
               auth_digest_algorithm=?, ca_id=?, server_cert_id=?
               WHERE id=?""",
            (
                data.get('description', ''),
                1 if data.get('disabled') else 0,
                data.get('server_mode', 'peer2peer'),
                data.get('device_mode', 'tun'),
                data.get('protocol', 'udp4'),
                data.get('interface', 'wan'),
                int(data.get('local_port') or 1194),
                1 if data.get('tls_key') else 0,
                1 if data.get('tls_key_auto') else 0,
                data.get('peer_ca', ''),
                data.get('tunnel_network', ''),
                data.get('tunnel_network_v6', ''),
                data.get('local_network', ''),
                data.get('remote_network', ''),
                1 if data.get('redirect_gateway') else 0,
                int(data.get('max_clients') or 0) or None,
                data.get('compression', 'refuse'),
                1 if data.get('inter_client_communication') else 0,
                1 if data.get('duplicate_connection') else 0,
                1 if data.get('dynamic_ip') else 0,
                data.get('topology', 'subnet'),
                int(data.get('inactivity_timeout') or 300),
                data.get('ping_method', 'keepalive'),
                int(data.get('ping_interval') or 10),
                int(data.get('ping_timeout') or 60),
                data.get('custom_options', ''),
                int(data.get('verbosity_level') or 1),
                data.get('dh_parameter_length', '2048'),
                data.get('ecdh_curve', 'default'),
                data.get('data_encryption_algorithms', 'AES-256-GCM'),
                data.get('fallback_data_encryption_algorithm', 'AES-256-CBC'),
                data.get('auth_digest_algorithm', 'SHA256'),
                int(data['ca_id']) if data.get('ca_id') else None,
                int(data['server_cert_id']) if data.get('server_cert_id') else None,
                server_id,
            )
        )
        db.commit()
        return jsonify({'status': 'success', 'message': 'OpenVPN server updated successfully'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@vpn_bp.route("/api/openvpn/delete-server/<int:server_id>", methods=['DELETE'])
@api_permission_required("api.vpn.edit")
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
@api_permission_required("api.vpn.edit")
def save_openvpn_client():
    try:
        data = request.get_json(silent=True) or {}
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


@vpn_bp.route("/api/openvpn/get-client/<int:client_id>", methods=['GET'])
@login_required
def get_openvpn_client(client_id):
    """Get a single OpenVPN client by ID for editing."""
    try:
        db = get_db()
        row = db.execute(
            "SELECT id, description, disabled, server_mode, protocol, interface, "
            "server_hostname, server_port, encryption_algorithm, auth_digest_algorithm, "
            "inactivity_timeout, ping_method, ping_interval, ping_timeout, "
            "custom_options, udp_fast_io, send_receive_buffer, verbosity_level "
            "FROM openvpn_clients WHERE id=?", (client_id,)
        ).fetchone()
        if not row:
            return jsonify({'status': 'error', 'message': 'Client not found'}), 404
        return jsonify({'status': 'success', 'client': dict(row)})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@vpn_bp.route("/api/openvpn/update-client/<int:client_id>", methods=['PUT'])
@api_permission_required("api.vpn.edit")
def update_openvpn_client(client_id):
    """Update an existing OpenVPN client."""
    try:
        data = request.get_json(silent=True) or {}
        db = get_db()
        db.execute(
            """UPDATE openvpn_clients SET
               description=?, disabled=?, server_mode=?, protocol=?, interface=?,
               server_hostname=?, server_port=?, encryption_algorithm=?,
               auth_digest_algorithm=?, inactivity_timeout=?, ping_method=?,
               ping_interval=?, ping_timeout=?, custom_options=?, udp_fast_io=?,
               send_receive_buffer=?, verbosity_level=?
               WHERE id=?""",
            (
                data.get('description', ''),
                1 if data.get('disabled') else 0,
                data.get('server_mode', 'peer2peer'),
                data.get('protocol', 'udp4'),
                data.get('interface', 'wan'),
                data.get('server_hostname', ''),
                data.get('server_port', 1194),
                data.get('encryption_algorithm', 'AES-256-CBC'),
                data.get('auth_digest_algorithm', 'SHA256'),
                data.get('inactivity_timeout', 300),
                data.get('ping_method', 'keepalive'),
                data.get('ping_interval', 10),
                data.get('ping_timeout', 60),
                data.get('custom_options', ''),
                1 if data.get('udp_fast_io') else 0,
                data.get('send_receive_buffer', 'default'),
                data.get('verbosity_level', 3),
                client_id,
            )
        )
        db.commit()
        return jsonify({'status': 'success', 'message': 'OpenVPN client updated successfully'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@vpn_bp.route("/api/openvpn/delete-client/<int:client_id>", methods=['DELETE'])
@api_permission_required("api.vpn.edit")
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
@api_permission_required("api.vpn.edit")
def save_openvpn_cso():
    try:
        data = request.get_json(silent=True) or {}
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


@vpn_bp.route("/api/openvpn/get-cso/<int:cso_id>", methods=['GET'])
@login_required
def get_openvpn_cso(cso_id):
    """Get a single CSO by ID for editing."""
    try:
        db = get_db()
        row = db.execute(
            "SELECT id, description, disabled, common_name, connection_blocking, "
            "server_list, reset_server_options, ipv4_tunnel_network, ipv6_tunnel_network, "
            "ipv4_gateway, ipv6_gateway, redirect_ipv4_gateway, redirect_ipv6_gateway, "
            "ipv4_local_networks, ipv6_local_networks, ipv4_remote_networks, ipv6_remote_networks, "
            "inactivity_timeout, ping_interval, ping_action, advanced "
            "FROM openvpn_cso WHERE id=?", (cso_id,)
        ).fetchone()
        if not row:
            return jsonify({'status': 'error', 'message': 'CSO not found'}), 404
        return jsonify({'status': 'success', 'cso': dict(row)})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@vpn_bp.route("/api/openvpn/update-cso/<int:cso_id>", methods=['PUT'])
@api_permission_required("api.vpn.edit")
def update_openvpn_cso(cso_id):
    """Update an existing OpenVPN CSO."""
    try:
        data = request.get_json(silent=True) or {}
        db = get_db()
        db.execute(
            """UPDATE openvpn_cso SET
               description=?, disabled=?, common_name=?, connection_blocking=?,
               server_list=?, reset_server_options=?, ipv4_tunnel_network=?,
               ipv6_tunnel_network=?, ipv4_gateway=?, ipv6_gateway=?,
               redirect_ipv4_gateway=?, redirect_ipv6_gateway=?,
               ipv4_local_networks=?, ipv6_local_networks=?,
               ipv4_remote_networks=?, ipv6_remote_networks=?,
               inactivity_timeout=?, ping_interval=?, ping_action=?, advanced=?
               WHERE id=?""",
            (
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
                data.get('advanced', ''),
                cso_id,
            )
        )
        db.commit()
        return jsonify({'status': 'success', 'message': 'CSO updated successfully'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@vpn_bp.route("/api/openvpn/delete-cso/<int:cso_id>", methods=['DELETE'])
@api_permission_required("api.vpn.edit")
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
@api_permission_required("api.vpn.edit")
def save_ipsec_phase1():
    from app.services import ipsec_service
    payload, status = ipsec_service.create_phase1(get_db(), request.get_json(silent=True) or {})
    if payload.get("success"):
        return jsonify({"status": "success", "id": payload.get("id")}), status
    return jsonify({"status": "error", "message": payload.get("error", "Unknown error")}), status


@vpn_bp.route("/api/ipsec/get-phase1", methods=['GET'])
@login_required
def get_ipsec_phase1():
    from app.services import ipsec_service
    payload, status = ipsec_service.list_phase1(get_db())
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
@api_permission_required("api.vpn.edit")
def delete_ipsec_phase1(phase1_id):
    from app.services import ipsec_service
    payload, status = ipsec_service.delete_phase1(get_db(), phase1_id)
    if payload.get("success"):
        return jsonify({"status": "success"}), status
    return jsonify({"status": "error", "message": payload.get("error", "Unknown error")}), status


# ----------------------------
# L2TP API ENDPOINTS
# ----------------------------

@vpn_bp.route("/api/l2tp/save-config", methods=['POST'])
@api_permission_required("api.vpn.edit")
def save_l2tp_config():
    import ipaddress
    try:
        data = request.get_json(silent=True) or {}
        db = get_db()
        cursor = db.cursor()

        enabled              = 1 if data.get('enabled') else 0
        interface            = (data.get('interface') or 'wan').strip()
        server_address       = (data.get('server_address') or '').strip()
        remote_address_range = (data.get('remote_address_range') or '').strip()
        subnet_mask          = (data.get('subnet_mask') or '').strip()
        dns_server1          = (data.get('dns_server1') or '').strip()
        dns_server2          = (data.get('dns_server2') or '').strip()
        wins_server          = (data.get('wins_server') or '').strip()
        authentication       = (data.get('authentication') or 'chap').strip().lower()
        require_chap         = 1 if data.get('require_chap') else 0
        require_pap          = 1 if data.get('require_pap') else 0
        radius_server        = (data.get('radius_server') or '').strip()
        radius_secret_raw    = (data.get('radius_secret') or '').strip()
        pre_shared_key_raw   = (data.get('pre_shared_key') or '').strip()

        errors = []
        for label, val in [
            ('server_address', server_address),
            ('remote_address_range', remote_address_range),
            ('dns_server1', dns_server1),
            ('dns_server2', dns_server2),
        ]:
            if val:
                try:
                    ipaddress.ip_address(val)
                except ValueError:
                    errors.append(f'{label}: {val!r} is not a valid IP address')

        if authentication not in ('chap', 'pap', 'mschapv2'):
            errors.append("authentication must be 'chap', 'pap', or 'mschapv2'")

        if errors:
            return jsonify({'status': 'error', 'message': '; '.join(errors)}), 400

        cursor.execute("SELECT id, radius_secret, pre_shared_key FROM l2tp_config LIMIT 1")
        existing = cursor.fetchone()

        if radius_secret_raw:
            radius_secret_enc = encrypt_secret(radius_secret_raw)
        elif existing and existing[1]:
            radius_secret_enc = existing[1]
        else:
            radius_secret_enc = ''

        if pre_shared_key_raw:
            psk_enc = encrypt_secret(pre_shared_key_raw)
        elif existing and existing[2]:
            psk_enc = existing[2]
        else:
            psk_enc = ''

        if existing:
            cursor.execute("""
                UPDATE l2tp_config SET
                    enabled=?, interface=?, server_address=?, remote_address_range=?,
                    subnet_mask=?, dns_server1=?, dns_server2=?, wins_server=?,
                    authentication=?, require_chap=?, require_pap=?,
                    radius_server=?, radius_secret=?, pre_shared_key=?
                WHERE id=?
            """, (
                enabled, interface, server_address, remote_address_range,
                subnet_mask, dns_server1, dns_server2, wins_server,
                authentication, require_chap, require_pap,
                radius_server, radius_secret_enc, psk_enc,
                existing[0],
            ))
        else:
            cursor.execute("""
                INSERT INTO l2tp_config (
                    enabled, interface, server_address, remote_address_range,
                    subnet_mask, dns_server1, dns_server2, wins_server,
                    authentication, require_chap, require_pap,
                    radius_server, radius_secret, pre_shared_key
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                enabled, interface, server_address, remote_address_range,
                subnet_mask, dns_server1, dns_server2, wins_server,
                authentication, require_chap, require_pap,
                radius_server, radius_secret_enc, psk_enc,
            ))

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
        cursor.execute("SELECT * FROM l2tp_config LIMIT 1")
        row = cursor.fetchone()

        if row:
            cfg = dict(row)
            cfg.pop('radius_secret', None)         # never expose encrypted secret to UI
            psk_enc = cfg.pop('pre_shared_key', '')
            cfg['has_psk'] = bool(psk_enc)         # tell UI whether a PSK is saved
        else:
            cfg = {
                'enabled': True, 'interface': 'wan',
                'server_address': '', 'remote_address_range': '',
                'subnet_mask': '', 'dns_server1': '', 'dns_server2': '',
                'wins_server': '', 'authentication': 'chap',
                'require_chap': False, 'require_pap': False,
                'radius_server': '', 'has_psk': False,
            }
        cfg['status'] = 'success'
        return jsonify(cfg)
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@vpn_bp.route("/api/l2tp/save-user", methods=['POST'])
@api_permission_required("api.vpn.edit")
def save_l2tp_user():
    try:
        data = request.get_json(silent=True) or {}
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
            encrypt_secret(password),
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
@api_permission_required("api.vpn.edit")
def update_l2tp_user(user_id):
    try:
        data = request.get_json(silent=True) or {}
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
                encrypt_secret(data.get('password')),
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
@api_permission_required("api.vpn.edit")
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
@api_permission_required("api.vpn.edit")
def save_wizard_auth_type():
    try:
        data = request.get_json(silent=True) or {}
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
@api_permission_required("api.vpn.edit")
def save_wizard_ca():
    try:
        data = request.get_json(silent=True) or {}
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
@api_permission_required("api.vpn.edit")
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
@api_permission_required("api.vpn.apply")
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
    """Return generated .conf for a specific server.

    Default behaviour is JSON for the preview pane. Pass ``?download=1`` to
    receive the raw text with a ``Content-Disposition: attachment`` header
    so the browser saves it as ``server-<id>.conf`` instead of dumping JSON
    into the file.
    """
    try:
        from app.services.openvpn_writer import generate_server_conf
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM openvpn_servers WHERE id=?", (server_id,))
        row = cur.fetchone()
        if not row:
            if request.args.get("download"):
                return Response("Server not found", status=404, mimetype="text/plain")
            return jsonify({"ok": False, "error": "Server not found"}), 404
        conf = generate_server_conf(dict(row))
        if request.args.get("download"):
            log_event(
                category="vpn", action="openvpn_config_downloaded",
                username=session.get("username", ""),
                remote_addr=request.remote_addr,
                details={"server_id": server_id},
            )
            return Response(
                conf,
                mimetype="text/plain",
                headers={
                    "Content-Disposition": (
                        f'attachment; filename="server-{server_id}.conf"'
                    ),
                    "Cache-Control": "no-store",
                },
            )
        return jsonify({"ok": True, "conf": conf})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


# ── VPN portal — admin-side user CRUD ────────────────────────────────────────

@vpn_bp.route("/api/portal/config", methods=["GET", "POST"])
@login_required
def vpn_portal_config_route():
    """GET or update the singleton vpn_portal_config row (admin only)."""
    db = get_db()
    if request.method == "POST":
        if not session.get("is_superuser"):
            return jsonify({"ok": False, "error": "admin-only"}), 403
        data = request.get_json(silent=True) or {}
        db.execute(
            "UPDATE vpn_portal_config SET enabled=?, public_hostname=?, "
            "updated_at=CURRENT_TIMESTAMP WHERE id=1",
            (1 if data.get("enabled") else 0,
             (data.get("public_hostname") or "").strip()),
        )
        db.commit()
        log_event(category="vpn_portal", action="vpn_portal_config_updated",
                  username=session.get("username", ""),
                  remote_addr=request.remote_addr or "",
                  details={"enabled": bool(data.get("enabled"))})
        return jsonify({"ok": True})
    row = db.execute("SELECT * FROM vpn_portal_config WHERE id=1").fetchone()
    return jsonify({"ok": True, "config": dict(row) if row else {}})


@vpn_bp.route("/api/portal/users", methods=["GET"])
@login_required
def vpn_portal_users_list():
    db = get_db()
    rows = db.execute(
        "SELECT id, username, email, full_name, totp_enrolled, "
        "client_cert_id, ovpn_server_id, disabled, created_at, last_login_at "
        "FROM vpn_portal_users ORDER BY id"
    ).fetchall()
    return jsonify({"ok": True, "users": [dict(r) for r in rows]})


@vpn_bp.route("/api/portal/users", methods=["POST"])
@api_permission_required("api.vpn.edit")
def vpn_portal_users_create():
    from werkzeug.security import generate_password_hash
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username or len(password) < 10:
        return jsonify({"ok": False,
                        "error": "username and password (10+ chars) are required"}), 400
    db = get_db()
    try:
        cur = db.execute(
            "INSERT INTO vpn_portal_users "
            "(username, password_hash, email, full_name, "
            " client_cert_id, ovpn_server_id, disabled) "
            "VALUES (?,?,?,?,?,?,?)",
            (username, generate_password_hash(password),
             (data.get("email") or "").strip(),
             (data.get("full_name") or "").strip(),
             int(data["client_cert_id"]) if data.get("client_cert_id") else None,
             int(data["ovpn_server_id"]) if data.get("ovpn_server_id") else None,
             1 if data.get("disabled") else 0),
        )
        db.commit()
        log_event(category="vpn_portal", action="vpn_portal_user_created",
                  username=session.get("username", ""),
                  remote_addr=request.remote_addr or "",
                  details={"new_user": username})
        return jsonify({"ok": True, "id": cur.lastrowid})
    except sqlite3.IntegrityError:
        return jsonify({"ok": False, "error": "username already exists"}), 409
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@vpn_bp.route("/api/portal/users/<int:uid>", methods=["PUT"])
@api_permission_required("api.vpn.edit")
def vpn_portal_users_update(uid):
    from werkzeug.security import generate_password_hash
    data = request.get_json(silent=True) or {}
    db = get_db()
    sets = ["email=?", "full_name=?", "client_cert_id=?",
            "ovpn_server_id=?", "disabled=?"]
    vals = [
        (data.get("email") or "").strip(),
        (data.get("full_name") or "").strip(),
        int(data["client_cert_id"]) if data.get("client_cert_id") else None,
        int(data["ovpn_server_id"]) if data.get("ovpn_server_id") else None,
        1 if data.get("disabled") else 0,
    ]
    if data.get("password"):
        if len(data["password"]) < 10:
            return jsonify({"ok": False,
                            "error": "password must be 10+ chars"}), 400
        sets.append("password_hash=?")
        vals.append(generate_password_hash(data["password"]))
    if data.get("reset_mfa"):
        sets.append("totp_enrolled=0")
        sets.append("totp_secret_enc=''")
    try:
        db.execute(
            f"UPDATE vpn_portal_users SET {', '.join(sets)} WHERE id=?",
            (*vals, uid),
        )
        db.commit()
        log_event(category="vpn_portal", action="vpn_portal_user_updated",
                  username=session.get("username", ""),
                  remote_addr=request.remote_addr or "",
                  details={"target_id": uid,
                           "reset_mfa": bool(data.get("reset_mfa"))})
        return jsonify({"ok": True})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@vpn_bp.route("/api/portal/users/<int:uid>", methods=["DELETE"])
@api_permission_required("api.vpn.edit")
def vpn_portal_users_delete(uid):
    db = get_db()
    try:
        db.execute("DELETE FROM vpn_portal_users WHERE id=?", (uid,))
        db.commit()
        log_event(category="vpn_portal", action="vpn_portal_user_deleted",
                  username=session.get("username", ""),
                  remote_addr=request.remote_addr or "",
                  details={"target_id": uid})
        return jsonify({"ok": True})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


# ── OpenVPN lifecycle hook (called by openvpn-hook.sh on connect/disconnect) ─

@vpn_bp.route("/api/openvpn/hook", methods=["POST"])
def openvpn_hook():
    """
    Receive client-connect / client-disconnect events from openvpn-hook.sh.

    Auth: HMAC-SHA256 of the raw request body under the shared secret stored
    in siem_state.openvpn_hook_secret. The hook script computes the same
    digest and sends it in ``X-SmartShield-Sig``. Loopback-bound — the
    daemon runs on the appliance and POSTs to 127.0.0.1, so we don't need
    cookies or session state.
    """
    import hmac, hashlib
    raw = request.get_data() or b""
    sig = (request.headers.get("X-SmartShield-Sig") or "").strip()
    try:
        conn = get_db()
        row = conn.execute(
            "SELECT value FROM siem_state WHERE key='openvpn_hook_secret'"
        ).fetchone()
        secret = row["value"] if row and row["value"] else ""
    except Exception:
        secret = ""
    if not secret or not sig:
        return jsonify({"ok": False, "error": "unauthenticated"}), 401
    expected = hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        return jsonify({"ok": False, "error": "bad-signature"}), 401

    # Mark this request as machine-authenticated. The CSRF guard already let
    # us through via CSRF_EXEMPT_ENDPOINTS, but downstream code (audit
    # log filters, future request hooks) can check `g.hmac_authenticated`
    # without re-running the HMAC compare.
    g.hmac_authenticated = True

    try:
        data = request.get_json(silent=True) or {}
    except Exception:
        data = {}

    event = (data.get("event") or "").lower()
    action_map = {
        "client-connect":    ("vpn_connect",    "info"),
        "client-disconnect": ("vpn_disconnect", "info"),
    }
    action, severity = action_map.get(event, ("vpn_event", "info"))

    log_event(
        category="vpn", action=action, severity=severity,
        username=str(data.get("cn") or ""),
        remote_addr=str(data.get("trusted_ip") or ""),
        details={
            "instance":      data.get("instance"),
            "trusted_port":  data.get("trusted_port"),
            "bytes_sent":    data.get("bytes_sent"),
            "bytes_recv":    data.get("bytes_received"),
            "duration":      data.get("duration"),
            "source":        "openvpn-hook",
        },
    )
    return jsonify({"ok": True})


# ── IPsec ─────────────────────────────────────────────────────────────────────

@vpn_bp.route("/api/ipsec/apply", methods=["POST"])
@api_permission_required("api.vpn.apply")
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
    from app.services import ipsec_service
    payload, status = ipsec_service.list_phase2(get_db(), request.args.get("p1_id", type=int))
    return jsonify(payload), status


@vpn_bp.route("/api/ipsec/p2", methods=["POST"])
@vpn_bp.route("/api/ipsec/p2/<int:p2_id>", methods=["PUT"])
@api_permission_required("api.vpn.edit")
def ipsec_p2_create(p2_id=None):
    """Create or update a Phase 2 child SA."""
    from app.services import ipsec_service
    payload, status = ipsec_service.upsert_phase2(get_db(), request.get_json(silent=True) or {}, p2_id)
    return jsonify(payload), status


@vpn_bp.route("/api/ipsec/p2/<int:p2_id>", methods=["DELETE"])
@api_permission_required("api.vpn.edit")
def ipsec_p2_delete(p2_id):
    from app.services import ipsec_service
    payload, status = ipsec_service.delete_phase2(get_db(), p2_id)
    return jsonify(payload), status


# ── L2TP ─────────────────────────────────────────────────────────────────────

@vpn_bp.route("/api/l2tp/apply", methods=["POST"])
@api_permission_required("api.vpn.apply")
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


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 3 — Validation / Preview / Connected-clients endpoints
# ══════════════════════════════════════════════════════════════════════════════

@vpn_bp.route("/api/openvpn/validate", methods=["GET"])
@login_required
def openvpn_validate():
    """Validate all enabled OpenVPN server and client configs."""
    try:
        from app.services.openvpn_writer import validate_server, validate_client
        conn = get_db()
        cur  = conn.cursor()
        cur.execute("SELECT * FROM openvpn_servers WHERE disabled=0 ORDER BY id")
        servers = [dict(r) for r in cur.fetchall()]
        cur.execute("SELECT * FROM openvpn_clients WHERE disabled=0 ORDER BY id")
        clients = [dict(r) for r in cur.fetchall()]

        errors = []
        for row in servers:
            errs = validate_server(row)
            if errs:
                errors.append({"kind": "server", "id": row["id"],
                                "description": row.get("description", ""),
                                "errors": errs})
        for row in clients:
            errs = validate_client(row)
            if errs:
                errors.append({"kind": "client", "id": row["id"],
                                "description": row.get("description", ""),
                                "errors": errs})
        return jsonify({"ok": not errors, "issues": errors})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@vpn_bp.route("/api/openvpn/preview-server/<int:server_id>", methods=["GET"])
@login_required
def openvpn_preview_server(server_id):
    """Return the generated config for a single OpenVPN server."""
    try:
        from app.services.openvpn_writer import generate_server_conf, validate_server
        conn = get_db()
        cur  = conn.cursor()
        cur.execute("SELECT * FROM openvpn_servers WHERE id=?", (server_id,))
        row = cur.fetchone()
        if not row:
            return jsonify({"ok": False, "error": "Server not found"}), 404
        row  = dict(row)
        errs = validate_server(row)
        conf = generate_server_conf(row)
        return jsonify({"ok": True, "conf": conf,
                        "validation_errors": errs, "valid": not errs})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@vpn_bp.route("/api/openvpn/clients-connected/<int:server_id>", methods=["GET"])
@login_required
def openvpn_connected_clients(server_id):
    """Return currently connected clients for an OpenVPN server (from status file)."""
    from app.services.openvpn_writer import get_connected_clients
    clients = get_connected_clients(server_id)
    return jsonify({"ok": True, "server_id": server_id,
                    "clients": clients, "count": len(clients)})


@vpn_bp.route("/api/openvpn/logs/<int:server_id>", methods=["GET"])
@login_required
def openvpn_logs(server_id):
    """Return the last N lines of the OpenVPN server log."""
    try:
        lines = min(int(request.args.get("lines", 100) or 100), 1000)
    except (TypeError, ValueError):
        lines = 100
    from app.services.openvpn_writer import get_openvpn_log
    log_text = get_openvpn_log(server_id, lines)
    return jsonify({"ok": True, "server_id": server_id, "log": log_text})
