import sqlite3

DATABASE = "data.db"

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_vpn_servers_db():
    """Initialize OpenVPN servers database table"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(""" 
    CREATE TABLE IF NOT EXISTS openvpn_servers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        description TEXT,
        disabled INTEGER DEFAULT 0,
        server_mode TEXT NOT NULL,
        device_mode TEXT NOT NULL,
        protocol TEXT NOT NULL,
        interface TEXT NOT NULL,
        local_port INTEGER NOT NULL,
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
        ipv4_tunnel_network text,
        ipv6_tunnel_network text,
        redirect_ipv4_gateway INTEGER DEFAULT 0,
        redirect_ipv6_gateway INTEGER DEFAULT 0,
        ipv4_local_networks text,
        ipv6_local_networks text,
        ipv4_remote_networks text,
        ipv6_remote_networks text,
        concurrent_connections INTEGER,
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
        verbosity_level INTEGER DEFAULT 3,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    
    conn.commit()
    conn.close()


def list_openvpn_servers():
    """Return all OpenVPN servers (newest first)."""
    conn = get_db()
    try:
        return conn.execute(
            "SELECT * FROM openvpn_servers ORDER BY id DESC"
        ).fetchall()
    finally:
        conn.close()


def insert_openvpn_server(payload: dict) -> int:
    """Insert an OpenVPN server row.

    Contract:
    - payload: dict containing the same keys as the HTML form names.
    - returns: inserted row id.
    """
    # Helper function to convert checkbox values
    def to_int(val, default=0):
        if isinstance(val, str) and val.lower() == "on":
            return 1
        try:
            return int(val)
        except Exception:
            return default

    # Mapping for certificate depth text values to integers
    cert_depth_map = {
        "one": 1,
        "no_check": 0,
        "two": 2,
        "three": 3,
        "four": 4,
        "five": 5,
    }
    cert_depth_val = (payload.get("certificate_depth") or "one").lower()
    certificate_depth = cert_depth_map.get(cert_depth_val, 1)

    # Mapping for verbosity level text values to integers
    verbosity_map = {
        "default": 3,
        "0": 0,
        "1": 1,
        "2": 2,
        "3": 3,
        "4": 4,
        "5": 5,
    }
    verbosity_val = (payload.get("verbosity_level") or "default").lower()
    verbosity_level = verbosity_map.get(verbosity_val, 3)

    conn = get_db()
    try:
        init_vpn_servers_db()
        cur = conn.execute(
            """
            INSERT INTO openvpn_servers (
                description, disabled, server_mode, device_mode, protocol, interface,
                local_port, use_tls_key, auto_generate_tls_key, peer_cert_authority,
                peer_cert_revocation_list, ocsp_check, server_certificate, dh_parameter_length,
                ecdh_curve, data_encryption_algorithms, fallback_data_encryption_algorithm,
                auth_digest_algorithm, certificate_depth, client_cert_key_usage_validation,
                ipv4_tunnel_network, ipv6_tunnel_network, redirect_ipv4_gateway,
                redirect_ipv6_gateway, ipv4_local_networks, ipv6_local_networks,
                ipv4_remote_networks, ipv6_remote_networks, concurrent_connections,
                allow_compression, inter_client_communication, duplicate_connection,
                dynamic_ip, topology, inactivity_timeout, ping_method, ping_interval,
                ping_timeout, custom_options, udp_fast_io, exit_notify, send_receive_buffer,
                gateway_creation, verbosity_level
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                payload.get("description", ""),
                to_int(payload.get("disabled")),
                payload.get("server_mode", ""),
                payload.get("device_mode", ""),
                payload.get("protocol", ""),
                payload.get("interface", ""),
                int(payload.get("local_port", 1194) or 1194),
                to_int(payload.get("use_tls_key"), 1),
                to_int(payload.get("auto_generate_tls_key"), 1),
                payload.get("peer_cert_authority", ""),
                payload.get("peer_cert_revocation_list", ""),
                to_int(payload.get("ocsp_check")),
                payload.get("server_certificate", ""),
                int(payload.get("dh_parameter_length", 2048) or 2048),
                payload.get("ecdh_curve", "default"),
                payload.get("data_encryption_algorithms", ""),
                payload.get("fallback_data_encryption_algorithm", ""),
                payload.get("auth_digest_algorithm", "SHA256"),
                certificate_depth,
                to_int(payload.get("client_cert_key_usage_validation"), 1),
                payload.get("ipv4_tunnel_network", ""),
                payload.get("ipv6_tunnel_network", ""),
                to_int(payload.get("redirect_ipv4_gateway")),
                to_int(payload.get("redirect_ipv6_gateway")),
                payload.get("ipv4_local_networks", ""),
                payload.get("ipv6_local_networks", ""),
                payload.get("ipv4_remote_networks", ""),
                payload.get("ipv6_remote_networks", ""),
                payload.get("concurrent_connections"),
                payload.get("allow_compression", "refuse"),
                to_int(payload.get("inter_client_communication")),
                to_int(payload.get("duplicate_connection")),
                to_int(payload.get("dynamic_ip")),
                payload.get("topology", "subnet"),
                int(payload.get("inactivity_timeout", 300) or 300),
                payload.get("ping_method", "keepalive"),
                int(payload.get("ping_interval", 10) or 10),
                int(payload.get("ping_timeout", 60) or 60),
                payload.get("custom_options", ""),
                to_int(payload.get("udp_fast_io")),
                payload.get("exit_notify", "reconnect"),
                payload.get("send_receive_buffer", "default"),
                payload.get("gateway_creation", "both"),
                verbosity_level,
            ),
        )
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()
