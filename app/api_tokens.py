"""
app/api_tokens.py
-----------------
Service-account API tokens for programmatic surfaces (HEC ingest, alerts
read, etc.). Tokens are sha-256-hashed at rest; the plaintext value is
shown to the operator exactly once at creation time.

Token shape: ``ss_<48-hex-chars>`` — the ``ss_`` prefix lets secret scanners
recognize the credential without revealing its scope.

Scopes are a comma-separated string. The well-known set:

  ``hec.ingest``     POST events into the audit log via /api/hec/*
  ``alerts.read``    GET /soc-portal/api/alerts (and the SOC-portal feed)
  ``cases.read``     GET /soc-portal/api/cases
  ``cases.write``    POST /soc-portal/api/cases…  (create/note/escalate)
  ``ioc.lookup``     GET /soc-portal/api/ioc-lookup

A wildcard ``*`` scope grants everything. Otherwise the route's required
scope must appear verbatim in the token's scope list, or as a parent
prefix (``alerts.* ⊇ alerts.read``).
"""

from __future__ import annotations

import hashlib
import os
import secrets
from functools import wraps

from flask import g, jsonify, request


_PREFIX = "ss_"


# ---------------------------------------------------------------------------
# Token lifecycle
# ---------------------------------------------------------------------------

def hash_token(token: str) -> str:
    return hashlib.sha256((token or "").encode("utf-8")).hexdigest()


def generate_token() -> tuple:
    """Return (plaintext, sha256). Caller stores only the hash."""
    raw   = _PREFIX + secrets.token_hex(24)
    return raw, hash_token(raw)


def create_token(conn, name: str, scopes: str, created_by: str) -> dict:
    """Persist a new token row. Returns dict with the *plaintext* token."""
    plaintext, token_hash = generate_token()
    conn.execute(
        "INSERT INTO api_tokens (name, token_hash, scopes, created_by) "
        "VALUES (?,?,?,?)",
        (name.strip()[:120] or "untitled",
         token_hash,
         (scopes or "").strip()[:512],
         created_by or "admin"),
    )
    conn.commit()
    return {"name": name, "token": plaintext, "scopes": scopes}


def revoke_token(conn, token_id: int) -> bool:
    cur = conn.execute(
        "UPDATE api_tokens SET revoked_at = CURRENT_TIMESTAMP "
        "WHERE id = ? AND revoked_at IS NULL",
        (int(token_id),),
    )
    conn.commit()
    return (cur.rowcount or 0) > 0


def list_tokens(conn) -> list:
    rows = conn.execute(
        "SELECT id, name, scopes, created_by, created_at, last_used_at, "
        "revoked_at FROM api_tokens ORDER BY id DESC"
    ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Authentication / scope check
# ---------------------------------------------------------------------------

def _extract_bearer() -> str:
    """Return the bearer token from Authorization or X-API-Key header."""
    auth = request.headers.get("Authorization") or ""
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return (request.headers.get("X-API-Key") or "").strip()


def _scope_matches(granted: str, required: str) -> bool:
    granted_set = {s.strip() for s in (granted or "").split(",") if s.strip()}
    if "*" in granted_set:
        return True
    if required in granted_set:
        return True
    for s in granted_set:
        if s.endswith(".*"):
            prefix = s[:-2]
            if required == prefix or required.startswith(prefix + "."):
                return True
    return False


def authenticate(conn, required_scope: str):
    """
    Return (ok: bool, status: int, payload: dict, token_row: dict|None).

    Does NOT raise. Records ``last_used_at`` on successful auth.
    """
    token = _extract_bearer()
    if not token:
        return False, 401, {"ok": False, "message": "Missing API token."}, None

    token_hash = hash_token(token)
    try:
        row = conn.execute(
            "SELECT id, name, scopes, revoked_at FROM api_tokens "
            "WHERE token_hash = ?",
            (token_hash,),
        ).fetchone()
    except Exception:
        return False, 503, {"ok": False, "message": "Token store unavailable."}, None
    if not row:
        return False, 401, {"ok": False, "message": "Unknown API token."}, None
    if row["revoked_at"]:
        return False, 401, {"ok": False, "message": "Token has been revoked."}, None
    if required_scope and not _scope_matches(row["scopes"], required_scope):
        return False, 403, {
            "ok": False,
            "message": f"Token lacks required scope '{required_scope}'.",
        }, row

    try:
        conn.execute(
            "UPDATE api_tokens SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?",
            (row["id"],),
        )
        conn.commit()
    except Exception:
        pass
    return True, 200, {"ok": True}, row


def require_api_scope(scope: str):
    """
    Decorator: gate a Flask view on an API token carrying *scope*.

    On success, sets ``g.api_token`` to the token row dict. Always returns
    JSON 401/403 — these endpoints are machine-to-machine and never browser
    redirects.
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            from app.database import get_db
            conn = get_db()
            ok, status, payload, row = authenticate(conn, scope)
            if not ok:
                return jsonify(payload), status
            g.api_token = dict(row) if row else None
            return view_func(*args, **kwargs)
        return wrapped
    return decorator
