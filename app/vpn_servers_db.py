"""VPN Servers database module - OpenVPN servers table."""

import sqlite3

DATABASE = "data.db"


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_vpn_servers_db():
    """Initialize the OpenVPN servers table."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS openvpn_servers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            description TEXT,
            disabled INTEGER DEFAULT 0,
            server_mode TEXT,
            device_mode TEXT,
            protocol TEXT,
            interface TEXT,
            local_port INTEGER DEFAULT 1194,
            use_tls_key INTEGER DEFAULT 1,
            auto_generate_tls_key INTEGER DEFAULT 1,
            peer_cert_authority TEXT,
            peer_cert_revocation_list TEXT,
            ocsp_check INTEGER DEFAULT 0,
            server_certificate TEXT,
            dh_parameter_length INTEGER DEFAULT 2048,
            ecdh_curve TEXT DEFAULT 'default',
            data_encryption_algorithms TEXT,
            fallback_data_encryption_algorithm TEXT,
            auth_digest_algorithm TEXT DEFAULT 'SHA256',
            certificate_depth INTEGER DEFAULT 1,
            client_cert_key_usage_validation INTEGER DEFAULT 1,
            ipv4_tunnel_network TEXT,
            ipv6_tunnel_network TEXT,
            redirect_ipv4_gateway INTEGER DEFAULT 0,
            redirect_ipv6_gateway INTEGER DEFAULT 0,
            ipv4_local_networks TEXT,
            ipv6_local_networks TEXT,
            ipv4_remote_networks TEXT,
            ipv6_remote_networks TEXT,
            concurrent_connections TEXT,
            allow_compression TEXT DEFAULT 'refuse',
            inter_client_communication INTEGER DEFAULT 0,
            duplicate_connection INTEGER DEFAULT 0,
            dynamic_ip INTEGER DEFAULT 0,
            topology TEXT DEFAULT 'subnet',
            inactivity_timeout INTEGER DEFAULT 300,
            ping_method TEXT DEFAULT 'keepalive',
            ping_interval INTEGER DEFAULT 10,
            ping_timeout INTEGER DEFAULT 60,
            custom_options TEXT,
            udp_fast_io INTEGER DEFAULT 0,
            exit_notify TEXT DEFAULT 'reconnect',
            send_receive_buffer TEXT DEFAULT 'default',
            gateway_creation TEXT DEFAULT 'both',
            verbosity_level INTEGER DEFAULT 3
        )
    """)
    conn.commit()
    conn.close()


def list_openvpn_servers():
    """List all OpenVPN servers."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM openvpn_servers")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def insert_openvpn_server(form_data):
    """Insert a new OpenVPN server."""
    conn = get_db()
    cursor = conn.cursor()
    
    def to_int(val, default=0):
        if isinstance(val, str) and val.lower() == 'on':
            return 1
        try:
            return int(val)
        except:
            return default
    
    cursor.execute("""
        INSERT INTO openvpn_servers (
            description, disabled, server_mode, device_mode, protocol,
            interface, local_port, use_tls_key, auto_generate_tls_key,
            peer_cert_authority, peer_cert_revocation_list, ocsp_check,
            server_certificate, dh_parameter_length, ecdh_curve,
            data_encryption_algorithms, fallback_data_encryption_algorithm,
            auth_digest_algorithm, certificate_depth,
            client_cert_key_usage_validation, ipv4_tunnel_network,
            ipv6_tunnel_network, redirect_ipv4_gateway, redirect_ipv6_gateway,
            ipv4_local_networks, ipv6_local_networks, ipv4_remote_networks,
            ipv6_remote_networks, concurrent_connections, allow_compression,
            inter_client_communication, duplicate_connection, dynamic_ip,
            topology, inactivity_timeout, ping_method, ping_interval,
            ping_timeout, custom_options, udp_fast_io, exit_notify,
            send_receive_buffer, gateway_creation, verbosity_level
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        form_data.get("description", ""),
        to_int(form_data.get("disabled")),
        form_data.get("server_mode", ""),
        form_data.get("device_mode", ""),
        form_data.get("protocol", ""),
        form_data.get("interface", ""),
        int(form_data.get("local_port", 1194)),
        to_int(form_data.get("use_tls_key", 1)),
        to_int(form_data.get("auto_generate_tls_key", 1)),
        form_data.get("peer_cert_authority", ""),
        form_data.get("peer_cert_revocation_list", ""),
        to_int(form_data.get("ocsp_check")),
        form_data.get("server_certificate", ""),
        int(form_data.get("dh_parameter_length", 2048)),
        form_data.get("ecdh_curve", "default"),
        form_data.get("data_encryption_algorithms", ""),
        form_data.get("fallback_data_encryption_algorithm", ""),
        form_data.get("auth_digest_algorithm", "SHA256"),
        int(form_data.get("certificate_depth", 1)),
        to_int(form_data.get("client_cert_key_usage_validation", 1)),
        form_data.get("ipv4_tunnel_network", ""),
        form_data.get("ipv6_tunnel_network", ""),
        to_int(form_data.get("redirect_ipv4_gateway")),
        to_int(form_data.get("redirect_ipv6_gateway")),
        form_data.get("ipv4_local_networks", ""),
        form_data.get("ipv6_local_networks", ""),
        form_data.get("ipv4_remote_networks", ""),
        form_data.get("ipv6_remote_networks", ""),
        form_data.get("concurrent_connections", ""),
        form_data.get("allow_compression", "refuse"),
        to_int(form_data.get("inter_client_communication")),
        to_int(form_data.get("duplicate_connection")),
        to_int(form_data.get("dynamic_ip")),
        form_data.get("topology", "subnet"),
        int(form_data.get("inactivity_timeout", 300)),
        form_data.get("ping_method", "keepalive"),
        int(form_data.get("ping_interval", 10)),
        int(form_data.get("ping_timeout", 60)),
        form_data.get("custom_options", ""),
        to_int(form_data.get("udp_fast_io")),
        form_data.get("exit_notify", "reconnect"),
        form_data.get("send_receive_buffer", "default"),
        form_data.get("gateway_creation", "both"),
        int(form_data.get("verbosity_level", 3))
    ))
    conn.commit()
    server_id = cursor.lastrowid
    conn.close()
    return server_id
