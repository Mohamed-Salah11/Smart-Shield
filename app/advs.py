"""IPsec Advanced Settings database module."""

import sqlite3

DATABASE = "data.db"


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_advanced_settings_table():
    """Initialize the IPsec advanced settings table."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ipsec_advanced_settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ipsec_debug INTEGER DEFAULT 0,
            uniqueids TEXT DEFAULT 'yes',
            interface TEXT,
            port INTEGER DEFAULT 500,
            port_nat_t INTEGER DEFAULT 4500,
            make_before_break INTEGER DEFAULT 0,
            async_crypto INTEGER DEFAULT 0,
            nics_max_crypto_workers INTEGER,
            ignore_routes INTEGER DEFAULT 0,
            max_ikesa INTEGER,
            max_childsa INTEGER,
            compression INTEGER DEFAULT 0,
            strictpolicy INTEGER DEFAULT 0,
            strictcrlpolicy INTEGER DEFAULT 0,
            auto_exclude_lan INTEGER DEFAULT 1,
            passthrough_networks TEXT
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


def _to_int_or_none(val):
    """Convert value to int or None."""
    val = _first(val)
    if val == "" or val is None:
        return None
    try:
        return int(val)
    except:
        return None


def get_ipsec_advanced_settings():
    """Get the IPsec advanced settings (single row)."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ipsec_advanced_settings LIMIT 1")
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else {}


def save_ipsec_advanced_settings(form_data):
    """Save IPsec advanced settings (upsert)."""
    conn = get_db()
    cursor = conn.cursor()
    
    # Check if row exists
    cursor.execute("SELECT id FROM ipsec_advanced_settings LIMIT 1")
    existing = cursor.fetchone()
    
    if existing:
        cursor.execute("""
            UPDATE ipsec_advanced_settings SET
                ipsec_debug = ?,
                uniqueids = ?,
                interface = ?,
                port = ?,
                port_nat_t = ?,
                make_before_break = ?,
                async_crypto = ?,
                nics_max_crypto_workers = ?,
                ignore_routes = ?,
                max_ikesa = ?,
                max_childsa = ?,
                compression = ?,
                strictpolicy = ?,
                strictcrlpolicy = ?,
                auto_exclude_lan = ?,
                passthrough_networks = ?
            WHERE id = ?
        """, (
            _to_int(form_data.get("ipsec_debug")),
            _first(form_data.get("uniqueids", "yes")),
            _first(form_data.get("interface", "")),
            _to_int(form_data.get("port", 500), 500),
            _to_int(form_data.get("port_nat_t", 4500), 4500),
            _to_int(form_data.get("make_before_break")),
            _to_int(form_data.get("async_crypto")),
            _to_int_or_none(form_data.get("nics_max_crypto_workers")),
            _to_int(form_data.get("ignore_routes")),
            _to_int_or_none(form_data.get("max_ikesa")),
            _to_int_or_none(form_data.get("max_childsa")),
            _to_int(form_data.get("compression")),
            _to_int(form_data.get("strictpolicy")),
            _to_int(form_data.get("strictcrlpolicy")),
            _to_int(form_data.get("auto_exclude_lan", 1), 1),
            _first(form_data.get("passthrough_networks", "")),
            existing["id"]
        ))
    else:
        cursor.execute("""
            INSERT INTO ipsec_advanced_settings (
                ipsec_debug, uniqueids, interface, port, port_nat_t,
                make_before_break, async_crypto, nics_max_crypto_workers,
                ignore_routes, max_ikesa, max_childsa, compression,
                strictpolicy, strictcrlpolicy, auto_exclude_lan, passthrough_networks
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            _to_int(form_data.get("ipsec_debug")),
            _first(form_data.get("uniqueids", "yes")),
            _first(form_data.get("interface", "")),
            _to_int(form_data.get("port", 500), 500),
            _to_int(form_data.get("port_nat_t", 4500), 4500),
            _to_int(form_data.get("make_before_break")),
            _to_int(form_data.get("async_crypto")),
            _to_int_or_none(form_data.get("nics_max_crypto_workers")),
            _to_int(form_data.get("ignore_routes")),
            _to_int_or_none(form_data.get("max_ikesa")),
            _to_int_or_none(form_data.get("max_childsa")),
            _to_int(form_data.get("compression")),
            _to_int(form_data.get("strictpolicy")),
            _to_int(form_data.get("strictcrlpolicy")),
            _to_int(form_data.get("auto_exclude_lan", 1), 1),
            _first(form_data.get("passthrough_networks", ""))
        ))
    
    conn.commit()
    conn.close()
