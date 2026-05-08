"""
routes/chatbot.py
-----------------
SmartShield AI chatbot endpoints.

  POST /chatbot/api/chat        — agentic chat (requires GROQ_API_KEY)
  GET  /chatbot/api/settings    — check whether Groq key is configured
  POST /chatbot/api/settings    — save / clear the Groq API key (encrypted in DB)
"""

import json
import os

from flask import Blueprint, jsonify, request, session

from app.auth_utils import login_required
from app.audit_log import log_event
from app.database import get_db

chatbot_bp = Blueprint("chatbot", __name__, url_prefix="/chatbot")


# ---------------------------------------------------------------------------
# Chat endpoint
# ---------------------------------------------------------------------------

@chatbot_bp.route("/api/chat", methods=["POST"])
@login_required
def api_chat():
    data     = request.get_json(force=True) or {}
    messages = data.get("messages", [])
    if not messages:
        return jsonify({"ok": False, "message": "No messages provided."}), 400

    from app.services.chatbot_service import process_chat
    conn   = get_db()
    result = process_chat(conn, messages, session.get("username", ""))

    log_event(
        category="system",
        action="chatbot_query",
        username=session.get("username"),
        remote_addr=request.remote_addr,
        details={"turns": len(messages), "ok": result.get("ok", False)},
    )
    return jsonify(result)


# ---------------------------------------------------------------------------
# Settings endpoints (key management)
# ---------------------------------------------------------------------------

def _load_raw_key(conn) -> str:
    """Return the decrypted Groq key or empty string."""
    try:
        row = conn.execute(
            "SELECT value_json FROM service_state WHERE key_name='chatbot_settings'"
        ).fetchone()
        if row:
            settings = json.loads(row["value_json"])
            encrypted = settings.get("groq_api_key", "")
            if encrypted:
                from app.secret_store import decrypt_secret
                return decrypt_secret(encrypted)
    except Exception:
        pass
    return os.environ.get("GROQ_API_KEY", "")


@chatbot_bp.route("/api/settings", methods=["GET"])
@login_required
def api_get_settings():
    conn = get_db()
    key  = _load_raw_key(conn)
    return jsonify({"ok": True, "has_key": bool(key)})


@chatbot_bp.route("/api/settings", methods=["POST"])
@login_required
def api_save_settings():
    data    = request.get_json(force=True) or {}
    raw_key = (data.get("groq_api_key") or "").strip()

    from app.secret_store import encrypt_secret
    conn = get_db()
    conn.execute(
        "INSERT OR REPLACE INTO service_state (key_name, value_json) VALUES (?, ?)",
        ("chatbot_settings", json.dumps({"groq_api_key": encrypt_secret(raw_key) if raw_key else ""})),
    )
    conn.commit()

    log_event(
        category="system",
        action="chatbot_key_update",
        username=session.get("username"),
        remote_addr=request.remote_addr,
        details={"key_set": bool(raw_key)},
    )
    return jsonify({"ok": True, "has_key": bool(raw_key)})


# ---------------------------------------------------------------------------
# Approve / reject a pending agent action
# ---------------------------------------------------------------------------

@chatbot_bp.route("/api/approve_action", methods=["POST"])
@login_required
def api_approve_action():
    data     = request.get_json(force=True) or {}
    action   = data.get("action")
    approved = bool(data.get("approved", False))

    if not action or not isinstance(action, dict):
        return jsonify({"ok": False, "message": "Invalid action payload."}), 400

    if not approved:
        return jsonify({"ok": True, "reply": "Action cancelled."})

    from app.services.chatbot_service import execute_approved_action
    conn   = get_db()
    result = execute_approved_action(conn, action, session.get("username", ""))

    log_event(
        category="system",
        action="chatbot_action_executed",
        username=session.get("username"),
        remote_addr=request.remote_addr,
        details={"tool": action.get("tool"), "args": action.get("args"), "ok": result.get("ok")},
    )
    return jsonify(result)
