"""IPsec Tunnels database module."""

import sqlite3
import json

DATABASE = "data.db"


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_tunnels_table():
    """Initialize the IPsec tunnels table."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ipsec_tunnels (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            description TEXT,
            disabled INTEGER DEFAULT 0,
            key_exchange_version TEXT DEFAULT 'ikev2',
            internet_protocol TEXT DEFAULT 'ipv4',
            interface TEXT,
            remote_gateway TEXT,
            authentication_method TEXT DEFAULT 'mutual_psk',
            my_identifier_type TEXT,
            my_identifier TEXT,
            peer_identifier_type TEXT,
            peer_identifier TEXT,
            pre_shared_key TEXT,
            my_certificate TEXT,
            peer_certificate_authority TEXT,
            encryption_algorithms TEXT,
            hash_algorithms TEXT,
            dh_groups TEXT,
            lifetime INTEGER DEFAULT 28800,
            disable_rekey INTEGER DEFAULT 0,
            margintime INTEGER,
            disable_reauth INTEGER DEFAULT 0,
            responder_only INTEGER DEFAULT 0,
            nat_traversal TEXT DEFAULT 'auto',
            mobike INTEGER DEFAULT 0,
            split_connections INTEGER DEFAULT 0,
            dead_peer_detection INTEGER DEFAULT 1,
            dpd_delay INTEGER DEFAULT 10,
            dpd_max_failures INTEGER DEFAULT 5,
            child_sa_start_action TEXT DEFAULT 'none',
            child_sa_close_action TEXT DEFAULT 'none',
            phase2_mode TEXT DEFAULT 'tunnel',
            phase2_protocol TEXT DEFAULT 'esp',
            phase2_encryption_algorithms TEXT,
            phase2_hash_algorithms TEXT,
            phase2_pfs_group TEXT,
            phase2_lifetime INTEGER DEFAULT 3600,
            local_network TEXT,
            nat_local_network TEXT,
            remote_network TEXT,
            ping_host TEXT
        )
    """)
    conn.commit()
    conn.close()


def _first(val):
    """Extract first element from list or return as-is."""
    if isinstance(val, list):
        return val[0] if val else ""
    return val


def _to_int(val, default=0):
    """Convert value to int, handling 'on' checkbox values."""
    val = _first(val)
    if isinstance(val, str) and val.lower() == 'on':
        return 1
    try:
        return int(val)
    except:
        return default


def list_ipsec_tunnels():
    """List all IPsec tunnels."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ipsec_tunnels")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def insert_ipsec_tunnel(form_data):
    """Insert a new IPsec tunnel."""
    conn = get_db()
    cursor = conn.cursor()
    
    # Handle multi-select fields (lists)
    def get_list_as_json(key):
        val = form_data.get(key, [])
        if isinstance(val, list):
            return json.dumps(val)
        return json.dumps([val]) if val else "[]"
    
    cursor.execute("""
        INSERT INTO ipsec_tunnels (
            description, disabled, key_exchange_version, internet_protocol,
            interface, remote_gateway, authentication_method,
            my_identifier_type, my_identifier, peer_identifier_type,
            peer_identifier, pre_shared_key, my_certificate,
            peer_certificate_authority, encryption_algorithms, hash_algorithms,
            dh_groups, lifetime, disable_rekey, margintime, disable_reauth,
            responder_only, nat_traversal, mobike, split_connections,
            dead_peer_detection, dpd_delay, dpd_max_failures,
            child_sa_start_action, child_sa_close_action, phase2_mode,
            phase2_protocol, phase2_encryption_algorithms, phase2_hash_algorithms,
            phase2_pfs_group, phase2_lifetime, local_network, nat_local_network,
            remote_network, ping_host
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        _first(form_data.get("description", "")),
        _to_int(form_data.get("disabled")),
        _first(form_data.get("key_exchange_version", "ikev2")),
        _first(form_data.get("internet_protocol", "ipv4")),
        _first(form_data.get("interface", "")),
        _first(form_data.get("remote_gateway", "")),
        _first(form_data.get("authentication_method", "mutual_psk")),
        _first(form_data.get("my_identifier_type", "")),
        _first(form_data.get("my_identifier", "")),
        _first(form_data.get("peer_identifier_type", "")),
        _first(form_data.get("peer_identifier", "")),
        _first(form_data.get("pre_shared_key", "")),
        _first(form_data.get("my_certificate", "")),
        _first(form_data.get("peer_certificate_authority", "")),
        get_list_as_json("encryption_algorithms"),
        get_list_as_json("hash_algorithms"),
        get_list_as_json("dh_groups"),
        _to_int(form_data.get("lifetime", 28800), 28800),
        _to_int(form_data.get("disable_rekey")),
        _to_int(form_data.get("margintime"), None),
        _to_int(form_data.get("disable_reauth")),
        _to_int(form_data.get("responder_only")),
        _first(form_data.get("nat_traversal", "auto")),
        _to_int(form_data.get("mobike")),
        _to_int(form_data.get("split_connections")),
        _to_int(form_data.get("dead_peer_detection", 1), 1),
        _to_int(form_data.get("dpd_delay", 10), 10),
        _to_int(form_data.get("dpd_max_failures", 5), 5),
        _first(form_data.get("child_sa_start_action", "none")),
        _first(form_data.get("child_sa_close_action", "none")),
        _first(form_data.get("phase2_mode", "tunnel")),
        _first(form_data.get("phase2_protocol", "esp")),
        get_list_as_json("phase2_encryption_algorithms"),
        get_list_as_json("phase2_hash_algorithms"),
        _first(form_data.get("phase2_pfs_group", "")),
        _to_int(form_data.get("phase2_lifetime", 3600), 3600),
        _first(form_data.get("local_network", "")),
        _first(form_data.get("nat_local_network", "")),
        _first(form_data.get("remote_network", "")),
        _first(form_data.get("ping_host", ""))
    ))
    conn.commit()
    tunnel_id = cursor.lastrowid
    conn.close()
    return tunnel_id


def update_ipsec_tunnel(tunnel_id, form_data):
    """Update an existing IPsec tunnel."""
    conn = get_db()
    cursor = conn.cursor()
    
    def get_list_as_json(key):
        val = form_data.get(key, [])
        if isinstance(val, list):
            return json.dumps(val)
        return json.dumps([val]) if val else "[]"
    
    cursor.execute("""
        UPDATE ipsec_tunnels SET
            description = ?, disabled = ?, key_exchange_version = ?,
            internet_protocol = ?, interface = ?, remote_gateway = ?,
            authentication_method = ?, my_identifier_type = ?, my_identifier = ?,
            peer_identifier_type = ?, peer_identifier = ?, pre_shared_key = ?,
            my_certificate = ?, peer_certificate_authority = ?,
            encryption_algorithms = ?, hash_algorithms = ?, dh_groups = ?,
            lifetime = ?, disable_rekey = ?, margintime = ?, disable_reauth = ?,
            responder_only = ?, nat_traversal = ?, mobike = ?, split_connections = ?,
            dead_peer_detection = ?, dpd_delay = ?, dpd_max_failures = ?,
            child_sa_start_action = ?, child_sa_close_action = ?, phase2_mode = ?,
            phase2_protocol = ?, phase2_encryption_algorithms = ?,
            phase2_hash_algorithms = ?, phase2_pfs_group = ?, phase2_lifetime = ?,
            local_network = ?, nat_local_network = ?, remote_network = ?, ping_host = ?
        WHERE id = ?
    """, (
        _first(form_data.get("description", "")),
        _to_int(form_data.get("disabled")),
        _first(form_data.get("key_exchange_version", "ikev2")),
        _first(form_data.get("internet_protocol", "ipv4")),
        _first(form_data.get("interface", "")),
        _first(form_data.get("remote_gateway", "")),
        _first(form_data.get("authentication_method", "mutual_psk")),
        _first(form_data.get("my_identifier_type", "")),
        _first(form_data.get("my_identifier", "")),
        _first(form_data.get("peer_identifier_type", "")),
        _first(form_data.get("peer_identifier", "")),
        _first(form_data.get("pre_shared_key", "")),
        _first(form_data.get("my_certificate", "")),
        _first(form_data.get("peer_certificate_authority", "")),
        get_list_as_json("encryption_algorithms"),
        get_list_as_json("hash_algorithms"),
        get_list_as_json("dh_groups"),
        _to_int(form_data.get("lifetime", 28800), 28800),
        _to_int(form_data.get("disable_rekey")),
        _to_int(form_data.get("margintime"), None),
        _to_int(form_data.get("disable_reauth")),
        _to_int(form_data.get("responder_only")),
        _first(form_data.get("nat_traversal", "auto")),
        _to_int(form_data.get("mobike")),
        _to_int(form_data.get("split_connections")),
        _to_int(form_data.get("dead_peer_detection", 1), 1),
        _to_int(form_data.get("dpd_delay", 10), 10),
        _to_int(form_data.get("dpd_max_failures", 5), 5),
        _first(form_data.get("child_sa_start_action", "none")),
        _first(form_data.get("child_sa_close_action", "none")),
        _first(form_data.get("phase2_mode", "tunnel")),
        _first(form_data.get("phase2_protocol", "esp")),
        get_list_as_json("phase2_encryption_algorithms"),
        get_list_as_json("phase2_hash_algorithms"),
        _first(form_data.get("phase2_pfs_group", "")),
        _to_int(form_data.get("phase2_lifetime", 3600), 3600),
        _first(form_data.get("local_network", "")),
        _first(form_data.get("nat_local_network", "")),
        _first(form_data.get("remote_network", "")),
        _first(form_data.get("ping_host", "")),
        tunnel_id
    ))
    conn.commit()
    conn.close()


def delete_ipsec_tunnel(tunnel_id):
    """Delete an IPsec tunnel."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM ipsec_tunnels WHERE id = ?", (tunnel_id,))
    conn.commit()
    conn.close()
