from routes.services import services_bp
from routes.services._common import *  # noqa: F401,F403
from routes.services._common import _load_service_state, _save_service_state  # noqa: F401

import ipaddress as _ipaddress
import re as _re


_LAN_IFACE_RE = _re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,15}$")


def _validate_cp_settings(data: dict) -> dict:
    """
    Validate captive portal settings submitted from the UI/API.

    Returns a dict containing only the validated keys (so callers can merge it
    over the previously stored settings without dropping fields). Raises
    ValueError on any bad value.
    """
    out: dict = {}

    if "portal_ip" in data and data["portal_ip"] != "":
        ip_str = str(data["portal_ip"]).strip()
        _ipaddress.ip_address(ip_str)
        out["portal_ip"] = ip_str

    if "portal_port" in data and data["portal_port"] not in ("", None):
        p = int(data["portal_port"])
        if not 1 <= p <= 65535:
            raise ValueError("portal_port must be 1-65535")
        out["portal_port"] = p

    if "http_redirect_port" in data and data["http_redirect_port"] not in ("", None):
        p = int(data["http_redirect_port"])
        if not 1 <= p <= 65535:
            raise ValueError("http_redirect_port must be 1-65535")
        out["http_redirect_port"] = p

    if "session_duration_minutes" in data and data["session_duration_minutes"] not in ("", None):
        m = int(data["session_duration_minutes"])
        if not 1 <= m <= 1440:
            raise ValueError("session_duration_minutes must be 1-1440")
        out["session_duration_minutes"] = m

    if "upstream_dns" in data and data["upstream_dns"] != "":
        dns_str = str(data["upstream_dns"]).strip()
        _ipaddress.ip_address(dns_str)
        out["upstream_dns"] = dns_str

    if "lan_interface" in data and data["lan_interface"] != "":
        lan = str(data["lan_interface"]).strip()
        if not _LAN_IFACE_RE.match(lan):
            raise ValueError(f"Invalid LAN interface: {lan!r}")
        out["lan_interface"] = lan

    if "radius_server" in data and data["radius_server"]:
        rsrv = str(data["radius_server"]).strip()
        host, sep, port = rsrv.partition(":")
        if not host:
            raise ValueError("radius_server must include a host")
        if sep and port:
            try:
                pn = int(port)
            except ValueError:
                raise ValueError("radius_server port must be numeric")
            if not 1 <= pn <= 65535:
                raise ValueError("radius_server port must be 1-65535")
        out["radius_server"] = rsrv

    for bool_key in ("enabled", "allow_dns", "strict_mode", "dns_bypass_for_admin"):
        if bool_key in data:
            out[bool_key] = bool(data[bool_key])

    if "whitelist_users" in data:
        wl = data["whitelist_users"]
        if not isinstance(wl, list):
            raise ValueError("whitelist_users must be a list")
        out["whitelist_users"] = [str(u).strip() for u in wl if str(u).strip()]

    return out


@services_bp.route("/api/captive-portal/settings", methods=["GET"])
@login_required
def api_cp_get_settings():
    """Return current captive portal settings, falling back to auto-detected defaults."""
    conn  = get_db()
    row   = conn.execute(
        "SELECT value_json FROM service_state WHERE key_name='captive_portal_settings'"
    ).fetchone()
    stored = json.loads(row["value_json"]) if row else {}
    from app.services.captive_portal import _default_portal_ip, _CP_REDIRECT_PORT
    defaults = {
        "portal_ip":                _default_portal_ip(conn),
        "portal_port":              _CP_REDIRECT_PORT,
        "http_redirect_port":       80,
        "lan_interface":            "em1",
        "allow_dns":                True,
        "enabled":                  False,
        "strict_mode":              True,
        "dns_bypass_for_admin":     False,
        "session_duration_minutes": 60,
        "upstream_dns":             "8.8.8.8",
    }
    settings = {**defaults, **stored}
    return jsonify({"ok": True, "settings": settings})


@services_bp.route("/api/captive-portal/settings", methods=["POST"])
@api_permission_required("api.network.edit")
def api_cp_save_settings():
    """Persist captive portal settings (portal_ip, portal_port, lan_interface, enabled, RADIUS).

    Validates every submitted field server-side and merges the result over the
    previously stored settings so partial submissions (e.g. the UI omitting
    radius_secret when no new secret was typed) never wipe existing values.
    """
    data = request.get_json(force=True) or {}
    conn = get_db()

    try:
        validated = _validate_cp_settings(data)
    except (ValueError, AssertionError, TypeError) as exc:
        return jsonify({"ok": False, "message": f"Invalid settings: {exc}"}), 400

    existing_row = conn.execute(
        "SELECT value_json FROM service_state WHERE key_name='captive_portal_settings'"
    ).fetchone()
    existing = json.loads(existing_row["value_json"]) if existing_row else {}

    settings = {**existing, **validated}

    # Preserve the previously stored RADIUS secret unless the client explicitly
    # provided one. An empty string is treated as "Clear secret".
    if "radius_secret" in data:
        settings["radius_secret"] = str(data["radius_secret"])
    else:
        settings["radius_secret"] = existing.get("radius_secret", "")

    conn.execute(
        """
        INSERT INTO service_state (key_name, value_json, updated_at)
        VALUES ('captive_portal_settings', ?, CURRENT_TIMESTAMP)
        ON CONFLICT(key_name) DO UPDATE SET
            value_json = excluded.value_json,
            updated_at = CURRENT_TIMESTAMP
        """,
        (json.dumps(settings),),
    )
    conn.commit()
    log_event(category="system", action="captive_portal_settings_save",
              username=session.get("username"), remote_addr=request.remote_addr,
              details={"enabled": settings.get("enabled")})
    return jsonify({"ok": True, "message": "Captive portal settings saved."})


@services_bp.route("/api/captive-portal/status", methods=["GET"])
@login_required
def api_cp_status():
    conn = get_db()
    from app.services.captive_portal import get_captive_status
    return jsonify({"ok": True, **get_captive_status(conn)})


@services_bp.route("/api/captive-portal/sessions", methods=["GET"])
@login_required
def api_cp_sessions():
    conn = get_db()
    from app.services.captive_portal import get_active_sessions, expire_sessions
    expire_sessions(conn)
    sessions = get_active_sessions(conn)
    return jsonify({"ok": True, "sessions": sessions, "count": len(sessions)})


@services_bp.route("/api/captive-portal/sessions/<int:session_id>/logout", methods=["POST"])
@api_permission_required("api.network.edit")
def api_cp_logout(session_id):
    conn = get_db()
    from app.services.captive_portal import logout_session
    result = logout_session(conn, session_id)
    log_event(category="system", action="captive_portal_logout",
              username=session.get("username"), remote_addr=request.remote_addr,
              details={"session_id": session_id})
    return jsonify(result)

@services_bp.route("/api/captive-portal/sessions/logout-all", methods=["POST"])
@api_permission_required("api.network.edit")
def api_cp_logout_all():
    conn = get_db()
    from app.services.captive_portal import get_active_sessions, logout_session

    sessions = get_active_sessions(conn)
    count = 0

    for s in sessions:
        result = logout_session(conn, s["id"])
        if result.get("ok"):
            count += 1

    log_event(
        category="system",
        action="captive_portal_logout_all",
        username=session.get("username"),
        remote_addr=request.remote_addr,
        details={"count": count},
    )

    return jsonify({"ok": True, "count": count})

@services_bp.route("/api/captive-portal/vouchers", methods=["POST"])
@api_permission_required("api.network.edit")
def api_cp_create_voucher():
    data = request.get_json(force=True) or {}
    conn = get_db()
    from app.services.captive_portal import generate_voucher
    result = generate_voucher(
        conn,
        duration_minutes=int(data.get("duration_minutes", 60) or 60),
        bandwidth_kbps=int(data.get("bandwidth_kbps", 0) or 0),
    )
    return jsonify(result)


@services_bp.route("/api/captive-portal/vouchers", methods=["GET"])
@login_required
def api_cp_list_vouchers():
    conn = get_db()
    vouchers = [dict(r) for r in conn.execute(
        "SELECT id, code, duration_minutes, bandwidth_kbps, redeemed, redeemed_at, created_at, disabled"
        " FROM captive_vouchers ORDER BY created_at DESC LIMIT 200"
    )]
    return jsonify({"ok": True, "vouchers": vouchers})


@services_bp.route("/api/captive-portal/vouchers/<int:voucher_id>", methods=["DELETE"])
@api_permission_required("api.network.edit")
def api_cp_delete_voucher(voucher_id):
    conn = get_db()
    row = conn.execute("SELECT id FROM captive_vouchers WHERE id=?", (voucher_id,)).fetchone()
    if not row:
        return jsonify({"ok": False, "message": "Voucher not found."}), 404
    conn.execute("DELETE FROM captive_vouchers WHERE id=?", (voucher_id,))
    conn.commit()
    log_event(category="system", action="captive_portal_voucher_delete",
              username=session.get("username"), remote_addr=request.remote_addr,
              details={"voucher_id": voucher_id})
    return jsonify({"ok": True, "message": "Voucher deleted."})


@services_bp.route("/api/captive-portal/vouchers/<int:voucher_id>/disabled", methods=["PATCH"])
@api_permission_required("api.network.edit")
def api_cp_toggle_voucher_disabled(voucher_id):
    data = request.get_json(force=True) or {}
    disabled = bool(data.get("disabled", True))
    conn = get_db()
    from app.services.captive_portal import disable_voucher
    result = disable_voucher(conn, voucher_id, disabled)
    if result.get("ok"):
        log_event(category="system", action="captive_portal_voucher_disable",
                  username=session.get("username"), remote_addr=request.remote_addr,
                  details={"voucher_id": voucher_id, "disabled": disabled})
    return jsonify(result)


@services_bp.route("/api/captive-portal/apply", methods=["POST"])
@api_permission_required("api.network.edit")
def api_cp_apply():
    conn = get_db()

    # Reload the main PF config first so rdr-anchor/anchor hooks exist.
    from app.services.pf_generator import reload_pf_rules
    pf_result = reload_pf_rules(conn)
    if not pf_result.get("ok"):
        return jsonify(pf_result), 500

    from app.services.captive_portal import apply_captive_portal
    result = apply_captive_portal(conn)
    return jsonify(result)


@services_bp.route("/api/captive-portal/preview", methods=["GET"])
@login_required
def api_cp_preview():
    conn = get_db()
    from app.services.captive_portal import generate_pf_anchor_preview
    return jsonify({"ok": True, "conf": generate_pf_anchor_preview(conn)})


@services_bp.route("/api/captive-portal/authenticate", methods=["POST"])
def api_cp_authenticate():
    """
    Browser-AJAX endpoint that authenticates a captive-portal client against
    RADIUS-then-local without requiring an *admin* session.

    Auth/CSRF model (Option A — browser CSRF):
      * The caller must hold a Flask session with `_csrf_token` set. Hitting
        any portal page (e.g. GET /portal/login) seeds that token via
        ``get_csrf_token()`` and exposes it as ``<meta name="csrf-token">``.
      * Mutating POST requests must send ``X-CSRF-Token`` matching the session
        value; the global ``_csrf_guard`` enforces this. External (non-browser)
        consumers without a Flask session cannot call this endpoint — they
        must use a token-auth API path instead (out of scope for this route).
      * Rate-limited per source IP (10/5min) below.
    """
    conn     = get_db()
    data     = request.get_json(silent=True) or request.form
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    ip       = request.remote_addr or ""

    if not username or not password:
        return jsonify({"ok": False, "message": "Username and password are required."}), 400

    from app.services.captive_portal import (
        try_password_auth, authenticate_session,
        too_many_recent_attempts, record_captive_auth_attempt,
    )
    if too_many_recent_attempts(conn, ip, window_seconds=300, max_attempts=10):
        log_event(
            category="security", action="captive_portal_rate_limited",
            remote_addr=ip, severity="medium",
            details={"endpoint": "api_cp_authenticate"},
        )
        return jsonify({"ok": False, "message": "Too many attempts. Try again later."}), 429

    # Same RADIUS-then-local fallback the portal HTML route uses. The two surfaces
    # MUST stay in lockstep — clients that can log in via the portal must also
    # log in via this API.
    auth_result = try_password_auth(conn, username, password)
    if auth_result.get("ok"):
        from routes.portal import _client_mac
        mac = _client_mac(ip)
        is_superuser = (
            auth_result.get("auth_type") == "local"
            and bool(auth_result.get("is_superuser", False))
        )
        sess_result = authenticate_session(
            conn, mac, ip, username=username, is_superuser=is_superuser,
        )
        record_captive_auth_attempt(
            conn, ip, username=username,
            auth_type=f"api_{auth_result.get('auth_type', '')}",
            success=bool(sess_result.get("ok")),
        )
        # Sanitize: don't leak session-internal errors (PF table push, etc.) verbatim.
        if not sess_result.get("ok"):
            log_event(
                category="security", action="captive_portal_session_failed",
                remote_addr=ip, severity="medium",
                details={"reason": sess_result.get("message", "")},
            )
            return jsonify({"ok": False, "message": "Could not establish session."}), 500
        return jsonify({"ok": True, "message": "Authenticated."})

    # Log detailed reason internally, return generic string to the client.
    log_event(
        category="security", action="captive_portal_login_failed",
        remote_addr=ip, severity="medium",
        details={
            "endpoint": "api_cp_authenticate",
            "reason": auth_result.get("message", ""),
        },
    )
    record_captive_auth_attempt(conn, ip, username=username, auth_type="api", success=False)
    return jsonify({"ok": False, "message": "Authentication failed."}), 401
