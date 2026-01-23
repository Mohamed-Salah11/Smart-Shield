"""L2TP Configuration database module."""

import sqlite3
import json

DATABASE = "data.db"


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_l2tp_config_table():
    """Initialize the L2TP configuration table."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS l2tp_config (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            enabled INTEGER DEFAULT 0,
            interface TEXT,
            local_ip TEXT,
            remote_ip_range TEXT,
            dns_servers TEXT,
            wins_servers TEXT,
            auth_method TEXT DEFAULT 'pap',
            secret TEXT,
            pfs INTEGER DEFAULT 0,
            require_128_bit INTEGER DEFAULT 0,
            l2tp_subnet TEXT,
            radius_server TEXT,
            radius_secret TEXT,
            extras TEXT
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


def get_l2tp_config():
    """Get the L2TP configuration (single row)."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM l2tp_config LIMIT 1")
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return {}
    
    result = dict(row)
    # Parse extras JSON if present
    if result.get("extras"):
        try:
            result["extras"] = json.loads(result["extras"])
        except:
            result["extras"] = {}
    else:
        result["extras"] = {}
    
    return result


def save_l2tp_config(form_data):
    """Save L2TP configuration (upsert)."""
    conn = get_db()
    cursor = conn.cursor()
    
    # Known fields
    known_fields = {
        "l2tp_enabled", "interface", "local_ip", "remote_ip_range",
        "dns_servers", "wins_servers", "auth_method", "secret",
        "pfs", "require_128_bit", "l2tp_subnet", "radius_server", "radius_secret"
    }
    
    # Extract extras (unknown fields)
    extras = {}
    for key, val in form_data.items():
        if key not in known_fields:
            extras[key] = _first(val)
    
    # Check if row exists
    cursor.execute("SELECT id FROM l2tp_config LIMIT 1")
    existing = cursor.fetchone()
    
    enabled = _to_int(form_data.get("l2tp_enabled"))
    
    if existing:
        cursor.execute("""
            UPDATE l2tp_config SET
                enabled = ?,
                interface = ?,
                local_ip = ?,
                remote_ip_range = ?,
                dns_servers = ?,
                wins_servers = ?,
                auth_method = ?,
                secret = ?,
                pfs = ?,
                require_128_bit = ?,
                l2tp_subnet = ?,
                radius_server = ?,
                radius_secret = ?,
                extras = ?
            WHERE id = ?
        """, (
            enabled,
            _first(form_data.get("interface", "")),
            _first(form_data.get("local_ip", "")),
            _first(form_data.get("remote_ip_range", "")),
            _first(form_data.get("dns_servers", "")),
            _first(form_data.get("wins_servers", "")),
            _first(form_data.get("auth_method", "pap")),
            _first(form_data.get("secret", "")),
            _to_int(form_data.get("pfs")),
            _to_int(form_data.get("require_128_bit")),
            _first(form_data.get("l2tp_subnet", "")),
            _first(form_data.get("radius_server", "")),
            _first(form_data.get("radius_secret", "")),
            json.dumps(extras) if extras else None,
            existing["id"]
        ))
    else:
        cursor.execute("""
            INSERT INTO l2tp_config (
                enabled, interface, local_ip, remote_ip_range, dns_servers,
                wins_servers, auth_method, secret, pfs, require_128_bit,
                l2tp_subnet, radius_server, radius_secret, extras
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            enabled,
            _first(form_data.get("interface", "")),
            _first(form_data.get("local_ip", "")),
            _first(form_data.get("remote_ip_range", "")),
            _first(form_data.get("dns_servers", "")),
            _first(form_data.get("wins_servers", "")),
            _first(form_data.get("auth_method", "pap")),
            _first(form_data.get("secret", "")),
            _to_int(form_data.get("pfs")),
            _to_int(form_data.get("require_128_bit")),
            _first(form_data.get("l2tp_subnet", "")),
            _first(form_data.get("radius_server", "")),
            _first(form_data.get("radius_secret", "")),
            json.dumps(extras) if extras else None
        ))
    
    conn.commit()
    conn.close()
    return get_l2tp_config()
