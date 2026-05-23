from flask import Blueprint, render_template, request, jsonify, Response, session, g
from app.database import get_db
from app.auth_utils import login_required
from app.api_auth import api_permission_required
from app.secret_store import seal, decrypt_secret
from app.validators import validate_ip, validate_port, validate_username, collect_errors
import sqlite3
from app.secret_store import encrypt_secret
from app.audit_log import log_event




def _payload_and_status(response):
    if isinstance(response, tuple):
        resp, status = response
    else:
        resp = response
        status = response.status_code
    return (resp.get_json(silent=True) or {}), status

# ----------------------------
# VPN MAIN PAGE
# ----------------------------
