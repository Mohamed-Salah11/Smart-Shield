"""Pre-Shared Keys database module."""

import sqlite3

DATABASE = "data.db"


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_psk_table():
    """Initialize the Pre-Shared Keys table."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ipsec_psks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            identifier TEXT NOT NULL,
            secret_type TEXT DEFAULT 'psk',
            pre_shared_key TEXT,
            description TEXT
        )
    """)
    conn.commit()
    conn.close()


def _first(val):
    """Extract first element from list or return as-is."""
    if isinstance(val, list):
        return val[0] if val else ""
    return val


def list_psks():
    """List all Pre-Shared Keys."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ipsec_psks")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def insert_psk(form_data):
    """Insert a new Pre-Shared Key."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO ipsec_psks (identifier, secret_type, pre_shared_key, description)
        VALUES (?, ?, ?, ?)
    """, (
        _first(form_data.get("identifier", "")),
        _first(form_data.get("secret_type", "psk")),
        _first(form_data.get("pre_shared_key", "")),
        _first(form_data.get("description", ""))
    ))
    conn.commit()
    psk_id = cursor.lastrowid
    conn.close()
    return psk_id


def update_psk(psk_id, form_data):
    """Update an existing Pre-Shared Key."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE ipsec_psks SET
            identifier = ?,
            secret_type = ?,
            pre_shared_key = ?,
            description = ?
        WHERE id = ?
    """, (
        _first(form_data.get("identifier", "")),
        _first(form_data.get("secret_type", "psk")),
        _first(form_data.get("pre_shared_key", "")),
        _first(form_data.get("description", "")),
        psk_id
    ))
    conn.commit()
    conn.close()


def delete_psk(psk_id):
    """Delete a Pre-Shared Key."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM ipsec_psks WHERE id = ?", (psk_id,))
    conn.commit()
    conn.close()
