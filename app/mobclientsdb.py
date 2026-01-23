"""Mobile Clients database module - IPsec mobile clients settings."""

import sqlite3

DATABASE = "data.db"


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_mobile_clients_table():
    """Initialize the IPsec mobile clients settings table."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ipsec_mobile_clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            enable_mobile_clients INTEGER DEFAULT 0,
            user_authentication TEXT DEFAULT 'local_database',
            group_authentication TEXT,
            virtual_address_pool INTEGER DEFAULT 0,
            virtual_address_pool_network TEXT,
            virtual_ipv6_address_pool INTEGER DEFAULT 0,
            virtual_ipv6_address_pool_network TEXT,
            network_list INTEGER DEFAULT 0,
            save_xauth_password INTEGER DEFAULT 0,
            dns_default_domain INTEGER DEFAULT 0,
            dns_default_domain_value TEXT,
            dns_servers INTEGER DEFAULT 0,
            dns_server1 TEXT,
            dns_server2 TEXT,
            dns_server3 TEXT,
            dns_server4 TEXT,
            wins_servers INTEGER DEFAULT 0,
            wins_server1 TEXT,
            wins_server2 TEXT,
            phase2_pfs_group INTEGER DEFAULT 0,
            phase2_pfs_group_value TEXT,
            login_banner INTEGER DEFAULT 0,
            login_banner_value TEXT
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


def get_mobile_clients_settings():
    """Get the mobile clients settings (single row)."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ipsec_mobile_clients LIMIT 1")
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else {}


def save_mobile_clients_settings(form_data):
    """Save mobile clients settings (upsert)."""
    conn = get_db()
    cursor = conn.cursor()
    
    # Check if row exists
    cursor.execute("SELECT id FROM ipsec_mobile_clients LIMIT 1")
    existing = cursor.fetchone()
    
    if existing:
        cursor.execute("""
            UPDATE ipsec_mobile_clients SET
                enable_mobile_clients = ?,
                user_authentication = ?,
                group_authentication = ?,
                virtual_address_pool = ?,
                virtual_address_pool_network = ?,
                virtual_ipv6_address_pool = ?,
                virtual_ipv6_address_pool_network = ?,
                network_list = ?,
                save_xauth_password = ?,
                dns_default_domain = ?,
                dns_default_domain_value = ?,
                dns_servers = ?,
                dns_server1 = ?,
                dns_server2 = ?,
                dns_server3 = ?,
                dns_server4 = ?,
                wins_servers = ?,
                wins_server1 = ?,
                wins_server2 = ?,
                phase2_pfs_group = ?,
                phase2_pfs_group_value = ?,
                login_banner = ?,
                login_banner_value = ?
            WHERE id = ?
        """, (
            _to_int(form_data.get("enable_mobile_clients")),
            _first(form_data.get("user_authentication", "local_database")),
            _first(form_data.get("group_authentication", "")),
            _to_int(form_data.get("virtual_address_pool")),
            _first(form_data.get("virtual_address_pool_network", "")),
            _to_int(form_data.get("virtual_ipv6_address_pool")),
            _first(form_data.get("virtual_ipv6_address_pool_network", "")),
            _to_int(form_data.get("network_list")),
            _to_int(form_data.get("save_xauth_password")),
            _to_int(form_data.get("dns_default_domain")),
            _first(form_data.get("dns_default_domain_value", "")),
            _to_int(form_data.get("dns_servers")),
            _first(form_data.get("dns_server1", "")),
            _first(form_data.get("dns_server2", "")),
            _first(form_data.get("dns_server3", "")),
            _first(form_data.get("dns_server4", "")),
            _to_int(form_data.get("wins_servers")),
            _first(form_data.get("wins_server1", "")),
            _first(form_data.get("wins_server2", "")),
            _to_int(form_data.get("phase2_pfs_group")),
            _first(form_data.get("phase2_pfs_group_value", "")),
            _to_int(form_data.get("login_banner")),
            _first(form_data.get("login_banner_value", "")),
            existing["id"]
        ))
    else:
        cursor.execute("""
            INSERT INTO ipsec_mobile_clients (
                enable_mobile_clients, user_authentication, group_authentication,
                virtual_address_pool, virtual_address_pool_network,
                virtual_ipv6_address_pool, virtual_ipv6_address_pool_network,
                network_list, save_xauth_password, dns_default_domain,
                dns_default_domain_value, dns_servers, dns_server1, dns_server2,
                dns_server3, dns_server4, wins_servers, wins_server1, wins_server2,
                phase2_pfs_group, phase2_pfs_group_value, login_banner, login_banner_value
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            _to_int(form_data.get("enable_mobile_clients")),
            _first(form_data.get("user_authentication", "local_database")),
            _first(form_data.get("group_authentication", "")),
            _to_int(form_data.get("virtual_address_pool")),
            _first(form_data.get("virtual_address_pool_network", "")),
            _to_int(form_data.get("virtual_ipv6_address_pool")),
            _first(form_data.get("virtual_ipv6_address_pool_network", "")),
            _to_int(form_data.get("network_list")),
            _to_int(form_data.get("save_xauth_password")),
            _to_int(form_data.get("dns_default_domain")),
            _first(form_data.get("dns_default_domain_value", "")),
            _to_int(form_data.get("dns_servers")),
            _first(form_data.get("dns_server1", "")),
            _first(form_data.get("dns_server2", "")),
            _first(form_data.get("dns_server3", "")),
            _first(form_data.get("dns_server4", "")),
            _to_int(form_data.get("wins_servers")),
            _first(form_data.get("wins_server1", "")),
            _first(form_data.get("wins_server2", "")),
            _to_int(form_data.get("phase2_pfs_group")),
            _first(form_data.get("phase2_pfs_group_value", "")),
            _to_int(form_data.get("login_banner")),
            _first(form_data.get("login_banner_value", ""))
        ))
    
    conn.commit()
    conn.close()
