import json

from flask import Blueprint, render_template, request, redirect, url_for, jsonify, session

from app.database import get_db
from app.auth_utils import login_required
from app.api_auth import api_permission_required
from app.audit_log import log_event
from app.secret_store import seal, encrypt_secret, mask_secret




def _load_service_state(key_name, default):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT value_json FROM service_state WHERE key_name = ?", (key_name,))
    row = cur.fetchone()
    if not row:
        return default
    try:
        return json.loads(row["value_json"])
    except (TypeError, json.JSONDecodeError):
        return default


def _save_service_state(key_name, value):
    db = get_db()
    cur = db.cursor()
    cur.execute(
        """
        INSERT INTO service_state (key_name, value_json, updated_at)
        VALUES (?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(key_name) DO UPDATE SET
            value_json = excluded.value_json,
            updated_at = CURRENT_TIMESTAMP
        """,
        (key_name, json.dumps(value)),
    )
    db.commit()

# ----------------------------
# SERVICES MAIN PAGE
# ----------------------------
