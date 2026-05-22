import sqlite3

from flask import Blueprint, render_template, request, jsonify, session
from app.database import get_db
from app.auth_utils import login_required
from app.api_auth import api_permission_required
from app.validators import (
    validate_ip, validate_cidr, validate_protocol,
    validate_description, validate_name, collect_errors,
    validate_port_list,
)


def _validate_rule(data: dict) -> str | None:
    """Return the first validation error message, or None if all fields are valid."""
    action = (data.get("action") or "").lower()
    if action and action not in {"pass", "block", "reject"}:
        return f"Invalid action: {action!r}"
    try:
        validate_protocol(data.get("protocol") or "")
    except ValueError as exc:
        return str(exc)
    for field in ("source", "destination"):
        val = (data.get(field) or "").strip()
        if val and val.lower() != "any":
            try:
                validate_cidr(val) if "/" in val else validate_ip(val)
            except ValueError as exc:
                return f"Invalid {field}: {exc}"
    for field in ("source_port", "dest_port", "dst_port", "redirect_port"):
        val = (data.get(field) or "").strip()
        if val:
            try:
                validate_port_list(val)
            except ValueError as exc:
                return f"Invalid {field}: {exc}"
    desc = data.get("description") or ""
    if desc:
        try:
            validate_description(desc)
        except ValueError as exc:
            return str(exc)
    # PF constraint: port filtering requires an explicit protocol
    proto_val = (data.get("protocol") or "").strip().lower()
    has_port  = bool(
        (data.get("dest_port") or "").strip() or
        (data.get("source_port") or "").strip()
    )
    if has_port and proto_val in ("", "any", "all"):
        return "Port filtering requires an explicit protocol (e.g. tcp, udp, tcp/udp)"
    # PF constraint: ICMP and other portless protocols cannot use port filtering
    _portless = {"icmp", "icmpv6", "ipv6-icmp", "esp", "ah", "gre"}
    if has_port and proto_val in _portless:
        return f"Protocol '{proto_val}' does not support port filtering — remove the port values"
    return None
