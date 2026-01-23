"""L2TP Users database module."""

import sqlite3

DATABASE = "data.db"


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_l2tp_users_table():
    """Initialize the L2TP users table."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS l2tp_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT,
            ip_address TEXT,
            enabled INTEGER DEFAULT 1,
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


def list_l2tp_users():
    """List all L2TP users."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM l2tp_users")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def insert_l2tp_user(form_data):
    """Insert a new L2TP user."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO l2tp_users (username, password, ip_address, enabled, description)
        VALUES (?, ?, ?, ?, ?)
    """, (
        _first(form_data.get("username", "")),
        _first(form_data.get("password", "")),
        _first(form_data.get("ip_address", "")),
        1,  # enabled by default
        _first(form_data.get("description", ""))
    ))
    conn.commit()
    user_id = cursor.lastrowid
    conn.close()
    return user_id


def update_l2tp_user(user_id, form_data):
    """Update an existing L2TP user."""
    conn = get_db()
    cursor = conn.cursor()
    
    # Get current user to preserve password if not provided
    cursor.execute("SELECT password FROM l2tp_users WHERE id = ?", (user_id,))
    current = cursor.fetchone()
    
    new_password = _first(form_data.get("password", ""))
    # Keep existing password if new one is empty
    if not new_password and current:
        new_password = current["password"]
    
    cursor.execute("""
        UPDATE l2tp_users SET
            username = ?,
            password = ?,
            ip_address = ?,
            description = ?
        WHERE id = ?
    """, (
        _first(form_data.get("username", "")),
        new_password,
        _first(form_data.get("ip_address", "")),
        _first(form_data.get("description", "")),
        user_id
    ))
    conn.commit()
    conn.close()


def delete_l2tp_user(user_id):
    """Delete an L2TP user."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM l2tp_users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
