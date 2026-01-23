"""CSC (Client Specific Configuration) database module."""

import sqlite3

DATABASE = "data.db"


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_csc_db():
    """Initialize the CSC overrides table."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS csc_overrides (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            common_name TEXT NOT NULL,
            description TEXT,
            disabled INTEGER DEFAULT 0,
            block INTEGER DEFAULT 0,
            server_id INTEGER,
            tunnel_network TEXT,
            ipv6_tunnel_network TEXT,
            local_network TEXT,
            ipv6_local_network TEXT,
            remote_network TEXT,
            ipv6_remote_network TEXT,
            redirect_gateway INTEGER DEFAULT 0,
            prevent_server_definitions INTEGER DEFAULT 0,
            dns_domain TEXT,
            dns_servers TEXT,
            ntp_servers TEXT,
            netbios_scope TEXT,
            wins_servers TEXT
        )
    """)
    conn.commit()
    conn.close()


def list_csc_overrides():
    """List all CSC overrides."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM csc_overrides")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def insert_csc_override(form_data):
    """Insert a new CSC override."""
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
        INSERT INTO csc_overrides (
            common_name, description, disabled, block, server_id,
            tunnel_network, ipv6_tunnel_network, local_network,
            ipv6_local_network, remote_network, ipv6_remote_network,
            redirect_gateway, prevent_server_definitions, dns_domain,
            dns_servers, ntp_servers, netbios_scope, wins_servers
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        form_data.get("common_name", ""),
        form_data.get("description", ""),
        to_int(form_data.get("disabled")),
        to_int(form_data.get("block")),
        form_data.get("server_id"),
        form_data.get("tunnel_network", ""),
        form_data.get("ipv6_tunnel_network", ""),
        form_data.get("local_network", ""),
        form_data.get("ipv6_local_network", ""),
        form_data.get("remote_network", ""),
        form_data.get("ipv6_remote_network", ""),
        to_int(form_data.get("redirect_gateway")),
        to_int(form_data.get("prevent_server_definitions")),
        form_data.get("dns_domain", ""),
        form_data.get("dns_servers", ""),
        form_data.get("ntp_servers", ""),
        form_data.get("netbios_scope", ""),
        form_data.get("wins_servers", "")
    ))
    conn.commit()
    override_id = cursor.lastrowid
    conn.close()
    return override_id


def update_csc_override(override_id, form_data):
    """Update an existing CSC override."""
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
        UPDATE csc_overrides SET
            common_name = ?, description = ?, disabled = ?, block = ?,
            server_id = ?, tunnel_network = ?, ipv6_tunnel_network = ?,
            local_network = ?, ipv6_local_network = ?, remote_network = ?,
            ipv6_remote_network = ?, redirect_gateway = ?,
            prevent_server_definitions = ?, dns_domain = ?, dns_servers = ?,
            ntp_servers = ?, netbios_scope = ?, wins_servers = ?
        WHERE id = ?
    """, (
        form_data.get("common_name", ""),
        form_data.get("description", ""),
        to_int(form_data.get("disabled")),
        to_int(form_data.get("block")),
        form_data.get("server_id"),
        form_data.get("tunnel_network", ""),
        form_data.get("ipv6_tunnel_network", ""),
        form_data.get("local_network", ""),
        form_data.get("ipv6_local_network", ""),
        form_data.get("remote_network", ""),
        form_data.get("ipv6_remote_network", ""),
        to_int(form_data.get("redirect_gateway")),
        to_int(form_data.get("prevent_server_definitions")),
        form_data.get("dns_domain", ""),
        form_data.get("dns_servers", ""),
        form_data.get("ntp_servers", ""),
        form_data.get("netbios_scope", ""),
        form_data.get("wins_servers", ""),
        override_id
    ))
    conn.commit()
    conn.close()


def delete_csc_override(override_id):
    """Delete a CSC override."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM csc_overrides WHERE id = ?", (override_id,))
    conn.commit()
    conn.close()
