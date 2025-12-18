import sqlite3

DATABASE = "data.db"

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_vpn_db():
    """Initialize VPN client database table (servers table moved to vpn_servers_db.py)"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS openvpn_clients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        description TEXT,
        disabled INTEGER DEFAULT 0,
        server_mode TEXT NOT NULL,
        protocol TEXT NOT NULL,
        interface TEXT NOT NULL,
        server_hostname TEXT NOT NULL,
        server_port INTEGER NOT NULL,
        use_tls_key INTEGER DEFAULT 1,
        tls_key TEXT,
        use_certificate INTEGER DEFAULT 1,
        client_certificate TEXT,
        ca_certificate TEXT,
        ca_chain TEXT,
        cert_from TEXT,
        cert_to TEXT,
        data_encryption_algorithms TEXT,
        auth_digest_algorithm TEXT DEFAULT 'SHA256',
        engine TEXT DEFAULT 'none',
        crypto_hardware TEXT DEFAULT 'none',
        ipv4_tunnel_network TEXT,
        ipv6_tunnel_network TEXT,
        allow_compression TEXT DEFAULT 'no',
        topology TEXT DEFAULT 'subnet',
        inactivity_timeout INTEGER DEFAULT 300,
        ping_method TEXT DEFAULT 'keepalive',
        ping_interval INTEGER DEFAULT 10,
        ping_timeout INTEGER DEFAULT 60,
        custom_options TEXT,
        udp_fast_io INTEGER DEFAULT 0,
        send_receive_buffer TEXT DEFAULT 'default',
        verbosity_level INTEGER DEFAULT 3,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    
    conn.commit()
    conn.close()
