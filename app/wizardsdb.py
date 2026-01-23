"""Wizards database module - OpenVPN wizard forms."""

import sqlite3

DATABASE = "data.db"


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_wizards_db():
    """Initialize the wizard CA form table."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS wizard_ca_forms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            descriptive_name TEXT,
            key_type TEXT DEFAULT 'RSA',
            key_length INTEGER DEFAULT 2048,
            digest_algorithm TEXT DEFAULT 'SHA256',
            lifetime_days INTEGER DEFAULT 3650,
            common_name TEXT,
            country_code TEXT,
            state TEXT,
            city TEXT,
            organization TEXT,
            organizational_unit TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()


def insert_wizard_ca_form(form_data):
    """Insert a new wizard CA form entry."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO wizard_ca_forms (
            descriptive_name, key_type, key_length, digest_algorithm,
            lifetime_days, common_name, country_code, state, city,
            organization, organizational_unit
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        form_data.get("descriptive_name", ""),
        form_data.get("key_type", "RSA"),
        int(form_data.get("key_length", 2048)),
        form_data.get("digest_algorithm", "SHA256"),
        int(form_data.get("lifetime_days", 3650)),
        form_data.get("common_name", ""),
        form_data.get("country_code", ""),
        form_data.get("state", ""),
        form_data.get("city", ""),
        form_data.get("organization", ""),
        form_data.get("organizational_unit", "")
    ))
    conn.commit()
    ca_id = cursor.lastrowid
    conn.close()
    return ca_id


def list_wizard_ca_forms():
    """List all wizard CA forms."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM wizard_ca_forms")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]
