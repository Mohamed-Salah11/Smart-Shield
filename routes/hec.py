"""
routes/hec.py
-------------
HTTP Event Collector — a Splunk-HEC-style ingest surface so external
applications, cloud workloads, or SOAR tools can POST structured events
into the Smart Shield SIEM.

Auth: bearer/X-API-Key token carrying the ``hec.ingest`` scope. Tokens
are managed from System → API Tokens.

Endpoints:
  POST /api/hec/event   — accept one event (JSON object)
  POST /api/hec/events  — accept a batch (JSON array, up to 500 items)
  GET  /api/hec/health  — auth check used by monitoring probes

Body shape (per event):
  {
    "category": "...",            # required
    "action":   "...",            # required
    "severity": "info|low|medium|high|critical",  # default 'info'
    "username": "...",            # optional
    "remote_addr": "...",         # optional
    "source": "...",              # optional — recorded into details.source
    "details": {...}              # optional — arbitrary JSON
  }
"""

from __future__ import annotations

from flask import Blueprint, g, jsonify, request

from app.api_tokens import require_api_scope
from app.audit_log import log_event

hec_bp = Blueprint("hec", __name__, url_prefix="/api/hec")


_ALLOWED_SEV = {"info", "low", "medium", "high", "critical"}
_MAX_DETAIL_BYTES = 16 * 1024
_MAX_BATCH = 500


def _normalize(event) -> tuple:
    """Return (ok, normalized_event | error_message)."""
    if not isinstance(event, dict):
        return False, "event must be a JSON object"
    category = (event.get("category") or "").strip()
    action   = (event.get("action")   or "").strip()
    if not category or not action:
        return False, "category and action are required"

    severity = (event.get("severity") or "info").strip().lower()
    if severity not in _ALLOWED_SEV:
        severity = "info"

    details = event.get("details") or {}
    if not isinstance(details, dict):
        return False, "details must be an object"

    source = (event.get("source") or "").strip()
    if source:
        details.setdefault("source", source)

    # Reject pathologically large details so a single client can't blow up
    # the audit log file.
    import json as _json
    try:
        if len(_json.dumps(details, ensure_ascii=True)) > _MAX_DETAIL_BYTES:
            return False, f"details exceeds {_MAX_DETAIL_BYTES} bytes"
    except (TypeError, ValueError):
        return False, "details is not JSON-serializable"

    return True, {
        "category": category[:64],
        "action":   action[:64],
        "severity": severity,
        "username": (event.get("username") or "")[:120],
        "remote_addr": (event.get("remote_addr") or request.remote_addr or "")[:64],
        "details":  details,
    }


def _ingest(events: list) -> tuple:
    accepted, rejected = 0, []
    for i, ev in enumerate(events):
        ok, payload = _normalize(ev)
        if not ok:
            rejected.append({"index": i, "error": payload})
            continue
        try:
            log_event(
                category=payload["category"],
                action=payload["action"],
                severity=payload["severity"],
                username=payload["username"] or (g.api_token or {}).get("name") or "hec",
                remote_addr=payload["remote_addr"],
                details=payload["details"],
            )
            accepted += 1
        except Exception as exc:
            rejected.append({"index": i, "error": f"write failed: {exc}"})
    return accepted, rejected


@hec_bp.route("/health", methods=["GET"])
@require_api_scope("hec.ingest")
def health():
    token = g.api_token or {}
    return jsonify({"ok": True, "token": token.get("name"), "scopes": token.get("scopes")})


@hec_bp.route("/event", methods=["POST"])
@require_api_scope("hec.ingest")
def event():
    body = request.get_json(silent=True)
    if body is None:
        return jsonify({"ok": False, "message": "JSON body required"}), 400
    accepted, rejected = _ingest([body])
    status = 202 if accepted else 400
    return jsonify({"ok": accepted == 1, "accepted": accepted, "rejected": rejected}), status


@hec_bp.route("/events", methods=["POST"])
@require_api_scope("hec.ingest")
def events_batch():
    body = request.get_json(silent=True)
    if not isinstance(body, list):
        return jsonify({"ok": False, "message": "JSON array required"}), 400
    if len(body) > _MAX_BATCH:
        return jsonify({"ok": False,
                        "message": f"batch exceeds {_MAX_BATCH} events"}), 400
    accepted, rejected = _ingest(body)
    return jsonify({"ok": True, "accepted": accepted, "rejected": rejected}), 202
