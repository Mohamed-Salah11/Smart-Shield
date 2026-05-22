import json

from flask import Blueprint, render_template, request, redirect, url_for, jsonify, session

from app.database import get_db
from app.auth_utils import login_required
from app.api_auth import api_permission_required
from app.audit_log import log_event
from app.secret_store import seal, encrypt_secret, mask_secret

services_bp = Blueprint("services", __name__, url_prefix="/services")


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

@services_bp.route("/")
@login_required
def services_home():
    # services.html is a placeholder stub — redirect to the DHCP server
    # page (the most-used services sub-route) so the Services nav lands
    # on a working screen.
    return redirect(url_for("services.dhcp_server"))


# ----------------------------
# AUTO CONFIG BACKUP
# ----------------------------

@services_bp.route("/auto-config-backup")
@login_required
def auto_config_backup():
    return render_template("auto_config_backup.html")


@services_bp.route("/api/config-backup", methods=["POST"])
@api_permission_required("api.system.edit")
def api_config_backup_create():
    """Trigger an immediate config backup (DB export + generated configs)."""
    import shutil, hashlib, time as _time, os as _os
    from app.services.config_history import save_config_version

    conn = get_db()
    results = []

    # Save a versioned snapshot of the three core generated configs
    for service, gen_fn_path in [
        ("pf",     ("app.services.pf_generator",  "generate_pf_conf")),
        ("dhcpd",  ("app.services.dhcp_writer",   "generate_dhcpd_conf")),
        ("unbound",("app.services.dns_writer",    "generate_unbound_conf")),
    ]:
        try:
            import importlib
            mod  = importlib.import_module(gen_fn_path[0])
            fn   = getattr(mod, gen_fn_path[1])
            text = fn(conn)
            result = save_config_version(conn, service=service, content=text, notes="manual backup")
            results.append({"service": service, "ok": bool(result), "message": "saved"})
        except Exception as exc:
            results.append({"service": service, "ok": False, "message": str(exc)})

    log_event(category="system", action="config_backup", username=session.get("username"),
              remote_addr=request.remote_addr, details={"results": results})
    overall_ok = all(r["ok"] for r in results)
    return jsonify({"ok": overall_ok, "results": results})


@services_bp.route("/api/config-backup/list", methods=["GET"])
@login_required
def api_config_backup_list():
    """List saved config versions."""
    conn = get_db()
    try:
        rows = [dict(r) for r in conn.execute(
            """
            SELECT id, service, version_num, notes, content_hash, applied_at
            FROM config_versions
            ORDER BY applied_at DESC
            LIMIT 200
            """
        )]
        return jsonify({"ok": True, "versions": rows})
    except Exception as exc:
        return jsonify({"ok": False, "message": str(exc)}), 500


@services_bp.route("/api/config-backup/<int:version_id>/restore", methods=["POST"])
@api_permission_required("api.system.edit")
def api_config_backup_restore(version_id):
    """Restore a previously saved config version and re-apply it."""
    from app.services.config_history import rollback_to_config_version
    conn = get_db()
    result = rollback_to_config_version(conn, version_id=version_id)
    log_event(category="system", action="config_restore", username=session.get("username"),
              remote_addr=request.remote_addr, details={"version_id": version_id, "ok": result.get("ok")})
    return jsonify(result)


# ----------------------------
# CAPTIVE PORTAL
# ----------------------------

@services_bp.route("/captive-portal")
@login_required
def captive_portal():
    return render_template("captive_portal.html")


# ----------------------------
# PPPoE
# ----------------------------

@services_bp.route("/api/pppoe/apply", methods=["POST"])
@api_permission_required("api.network.edit")
def api_pppoe_apply():
    """Write ppp.conf and (re)start the PPPoE session."""
    conn = get_db()
    from app.services.pppoe_writer import apply_pppoe
    result = apply_pppoe(conn)
    log_event(category="system", action="pppoe_apply", username=session.get("username"),
              remote_addr=request.remote_addr, details={"ok": result.get("ok")})
    return jsonify(result)


@services_bp.route("/api/pppoe/status", methods=["GET"])
@login_required
def api_pppoe_status():
    """Return the live PPPoE session status."""
    from app.services.pppoe_writer import get_pppoe_status
    return jsonify({"ok": True, **get_pppoe_status()})


@services_bp.route("/api/pppoe/disconnect", methods=["POST"])
@api_permission_required("api.network.edit")
def api_pppoe_disconnect():
    """Tear down the active PPPoE session."""
    from app.services.pppoe_writer import disconnect_pppoe
    result = disconnect_pppoe()
    log_event(category="system", action="pppoe_disconnect", username=session.get("username"),
              remote_addr=request.remote_addr, details={"ok": result.get("ok")})
    return jsonify(result)


@services_bp.route("/api/pppoe/preview", methods=["GET"])
@login_required
def api_pppoe_preview():
    """Preview the generated ppp.conf (passwords redacted)."""
    import re as _re
    conn = get_db()
    from app.services.pppoe_writer import generate_ppp_conf
    conf = generate_ppp_conf(conn)
    masked = _re.sub(r'(set authkey\s+")[^"]+"', r'\1••••••••"', conf)
    return jsonify({"ok": True, "conf": masked})


# ----------------------------
# DHCP RELAY
# ----------------------------

@services_bp.route("/dhcp-relay")
@login_required
def dhcp_relay():
    return render_template("dhcp_relay.html")


@services_bp.route("/api/dhcp-relay", methods=["GET"])
@login_required
def get_dhcp_relay_settings():
    """Return DHCP Relay settings + list of upstream servers."""
    try:
        db = get_db()
        cur = db.cursor()

        cur.execute("SELECT enabled, downstream_interfaces, carp_status_vip, append_circuit_id FROM dhcp_relay_settings WHERE id = 1")
        row = cur.fetchone()
        if row is None:
            # default empty settings
            settings = {
                "enabled": False,
                "downstream_interfaces": "",
                "carp_status_vip": "none",
                "append_circuit_id": False,
            }
        else:
            settings = {
                "enabled": bool(row[0]),
                "downstream_interfaces": row[1] or "",
                "carp_status_vip": row[2] or "none",
                "append_circuit_id": bool(row[3]),
            }

        cur.execute("SELECT server_address FROM dhcp_relay_upstream_servers ORDER BY id")
        servers = [r[0] for r in cur.fetchall()]

        return jsonify({"success": True, "settings": settings, "upstream_servers": servers})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@services_bp.route("/api/dhcp-relay", methods=["POST"])
@login_required
@api_permission_required("api.network.edit")
def save_dhcp_relay_settings():
    """Save DHCP Relay settings + upstream servers.

    Expects JSON:
      {
        enabled: bool,
        downstream_interfaces: string,
        carp_status_vip: string,
        append_circuit_id: bool,
        upstream_servers: string[]
      }
    """
    try:
        data = request.get_json() or {}
        enabled = 1 if data.get("enabled") else 0
        downstream_interfaces = (data.get("downstream_interfaces") or "").strip()
        carp_status_vip = (data.get("carp_status_vip") or "none").strip() or "none"
        append_circuit_id = 1 if data.get("append_circuit_id") else 0
        upstream_servers = data.get("upstream_servers") or []
        if not isinstance(upstream_servers, list):
            return jsonify({"success": False, "error": "upstream_servers must be a list"}), 400

        # normalize/unique, keep order
        cleaned = []
        seen = set()
        for s in upstream_servers:
            addr = str(s).strip()
            if not addr:
                continue
            if addr in seen:
                continue
            cleaned.append(addr)
            seen.add(addr)

        db = get_db()
        cur = db.cursor()

        cur.execute(
            """
            INSERT INTO dhcp_relay_settings (id, enabled, downstream_interfaces, carp_status_vip, append_circuit_id, updated_at)
            VALUES (1, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(id) DO UPDATE SET
              enabled=excluded.enabled,
              downstream_interfaces=excluded.downstream_interfaces,
              carp_status_vip=excluded.carp_status_vip,
              append_circuit_id=excluded.append_circuit_id,
              updated_at=CURRENT_TIMESTAMP
            """,
            (enabled, downstream_interfaces, carp_status_vip, append_circuit_id),
        )

        # replace servers list
        cur.execute("DELETE FROM dhcp_relay_upstream_servers")
        for addr in cleaned:
            cur.execute("INSERT OR IGNORE INTO dhcp_relay_upstream_servers (server_address) VALUES (?)", (addr,))

        db.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ----------------------------
# DHCP SERVER (General)
# ----------------------------

@services_bp.route("/dhcp-server")
@login_required
def dhcp_server():
    return render_template("dhcp_server.html")


# LAN DHCP SERVER
@services_bp.route("/dhcp-server-lan")
@login_required
def dhcp_server_lan():
    return render_template("dhcp_server_lan.html")


@services_bp.route("/api/dhcp-server/<string:iface>", methods=["GET"])
@login_required
def api_get_dhcp_server_settings(iface):
    """Load DHCP server settings for an interface (wan/lan)."""
    try:
        iface = (iface or '').lower()
        if iface not in ('wan', 'lan'):
            return jsonify({"success": False, "error": "Invalid interface"}), 400

        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT settings_json FROM dhcp_server_settings WHERE interface=?", (iface,))
        row = cur.fetchone()
        settings = {}
        if row and row[0]:
            try:
                settings = json.loads(row[0])
            except Exception:
                settings = {}
        return jsonify({"success": True, "interface": iface, "settings": settings})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@services_bp.route("/api/dhcp-server/<string:iface>", methods=["POST"])
@login_required
@api_permission_required("api.network.edit")
def api_save_dhcp_server_settings(iface):
    """Save DHCP server settings for an interface (wan/lan). Expects JSON: { settings: {...} }"""
    try:
        iface = (iface or '').lower()
        if iface not in ('wan', 'lan'):
            return jsonify({"success": False, "error": "Invalid interface"}), 400

        data = request.get_json() or {}
        settings = data.get('settings') or {}
        if not isinstance(settings, dict):
            return jsonify({"success": False, "error": "settings must be an object"}), 400

        db = get_db()
        cur = db.cursor()
        cur.execute(
            """
            INSERT INTO dhcp_server_settings (interface, settings_json, updated_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(interface) DO UPDATE SET
              settings_json=excluded.settings_json,
              updated_at=CURRENT_TIMESTAMP
            """,
            (iface, json.dumps(settings)),
        )
        db.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# DHCP Static Mapping (global)
@services_bp.route("/dhcp-server/static-mapping")
@login_required
def dhcp_static_mapping():
    return render_template("dhcp_static_mapping.html")


# DHCP Static Mapping (LAN)
@services_bp.route("/dhcp-server-lan/static-mapping")
@login_required
def dhcp_static_mapping_lan():
    return render_template("dhcp_static_mapping_lan.html")


# ----------------------------
# DHCPv6 SERVICES
# ----------------------------

@services_bp.route("/dhcpv6-relay")
@login_required
def dhcpv6_relay():
    return render_template("dhcpv6_relay.html")


@services_bp.route("/dhcpv6-server")
@login_required
def dhcpv6_server():
    return render_template("dhcpv6_server.html")


# ----------------------------
# DNS FORWARDER
# ----------------------------

@services_bp.route("/dns-forwarder")
@login_required
def dns_forwarder():
    return render_template("dns_forwarder.html")


@services_bp.route("/dns-forwarder/edit-host-override", methods=["GET", "POST"])
@login_required
def dns_forwarder_edit_host():
    if request.method == "POST":
        return redirect(url_for("services.dns_forwarder"))
    return render_template("dns_forwarder_edit_host.html")


@services_bp.route("/dns-forwarder/edit-domain-override", methods=["GET", "POST"])
@login_required
def dns_forwarder_edit_domain():
    if request.method == "POST":
        return redirect(url_for("services.dns_forwarder"))
    return render_template("dns_forwarder_edit_domain.html")


# ----------------------------
# DNS RESOLVER
# ----------------------------

@services_bp.route("/dns-resolver")
@login_required
def dns_resolver():
    hosts = _load_service_state("resolver_host_overrides", [])
    domains = _load_service_state("resolver_domain_overrides", [])
    lists = _load_service_state("resolver_access_lists", [])
    return render_template("dns_resolver.html", hosts=hosts, domains=domains, lists=lists)


@services_bp.route("/dns-resolver/edit-host", methods=["GET", "POST"])
@login_required
def dns_resolver_edit_host():
    if request.method == "POST":
        hosts = _load_service_state("resolver_host_overrides", [])
        host = request.form.get("host")
        domain = request.form.get("domain")
        ip = request.form.get("ip")
        description = request.form.get("description", "")
        if host or domain:
            hosts.append({"host": host, "domain": domain, "ip": ip, "description": description})
            _save_service_state("resolver_host_overrides", hosts)
        return redirect(url_for("services.dns_resolver"))
    return render_template("dns_resolver_edit_host.html")


@services_bp.route("/dns-resolver/edit-domain", methods=["GET", "POST"])
@login_required
def dns_resolver_edit_domain():
    if request.method == "POST":
        domains = _load_service_state("resolver_domain_overrides", [])
        domain = request.form.get("domain")
        server = request.form.get("server")
        tls_queries = bool(request.form.get("tls_queries"))
        tls_hostname = request.form.get("tls_hostname")
        description = request.form.get("description", "")
        if domain:
            domains.append({"domain": domain, "server": server, "tls_queries": tls_queries,
                            "tls_hostname": tls_hostname, "description": description})
            _save_service_state("resolver_domain_overrides", domains)
        return redirect(url_for("services.dns_resolver"))
    return render_template("dns_resolver_edit_domain.html")


@services_bp.route("/dns-resolver/advanced", methods=["GET", "POST"])
@login_required
def dns_resolver_advanced():
    if request.method == "POST":
        return redirect(url_for("services.dns_resolver_advanced"))
    return render_template("dns_resolver_advanced.html")


@services_bp.route("/dns-resolver/access-lists")
@login_required
def dns_resolver_access_lists():
    lists = _load_service_state("resolver_access_lists", [])
    return render_template("dns_resolver_access_lists.html", lists=lists)


@services_bp.route("/dns-resolver/access-lists/edit", methods=["GET", "POST"])
@login_required
def dns_resolver_access_lists_edit():
    if request.method == "POST":
        lists = _load_service_state("resolver_access_lists", [])
        name = request.form.get("name")
        action = request.form.get("action")
        description = request.form.get("description")
        if name:
            lists.append({"name": name, "action": action, "description": description})
            _save_service_state("resolver_access_lists", lists)
        return redirect(url_for("services.dns_resolver_access_lists"))
    return render_template("dns_resolver_access_lists_edit.html")


# ----------------------------
# DYNAMIC DNS
# ----------------------------

@services_bp.route("/dynamic-dns", methods=["GET", "POST"])
@login_required
def dynamic_dns():
    if request.method == "POST":
        clients = _load_service_state("dynamic_dns_clients", [])
        client = {
            "disabled": bool(request.form.get("disabled")),
            "service_type": request.form.get("service_type"),
            "interface": request.form.get("interface"),
            "check_ip_mode": request.form.get("check_ip_mode"),
            "hostname": request.form.get("hostname"),
            "mx": request.form.get("mx"),
            "wildcards": bool(request.form.get("wildcards")),
            "verbose": bool(request.form.get("verbose")),
            "username": request.form.get("username"),
            "password": seal(request.form.get("password", "")),
            "description": request.form.get("description", "")
        }
        clients.append(client)
        _save_service_state("dynamic_dns_clients", clients)
        return redirect(url_for("services.dynamic_dns"))
    clients = _load_service_state("dynamic_dns_clients", [])
    return render_template("dynamic_dns.html", clients=clients)


@services_bp.route("/dynamic-dns/rfc2136", methods=["GET", "POST"])
@login_required
def dynamic_dns_rfc2136():
    if request.method == "POST":
        clients = _load_service_state("rfc2136_clients", [])
        client = {
            "enabled": bool(request.form.get("enable")),
            "interface": request.form.get("interface"),
            "hostname": request.form.get("hostname"),
            "zone": request.form.get("zone"),
            "ttl": request.form.get("ttl"),
            "key_name": request.form.get("key_name"),
            "key_algorithm": request.form.get("key_algorithm"),
            "key": seal(request.form.get("key", "")),
            "server": request.form.get("server"),
            "protocol_tcp": bool(request.form.get("protocol_tcp")),
            "use_public_ip": bool(request.form.get("use_public_ip")),
            "update_source": request.form.get("update_source"),
            "update_source_family": request.form.get("update_source_family"),
            "record_type": request.form.get("record_type"),
            "description": request.form.get("description", "")
        }
        clients.append(client)
        _save_service_state("rfc2136_clients", clients)
        return redirect(url_for("services.dynamic_dns_rfc2136"))
    clients = _load_service_state("rfc2136_clients", [])
    return render_template("dynamic_dns_rfc2136.html", clients=clients)


@services_bp.route("/dynamic-dns/checkip", methods=["GET", "POST"])
@login_required
def dynamic_dns_checkip():
    services = _load_service_state("checkip_services", [])
    if not services:
        services = [
            {"name": "Default", "url": "http://checkip.dyndns.org", "verify_ssl": False,
             "description": "Default Check IP Service"}
        ]
        _save_service_state("checkip_services", services)
    if request.method == "POST":
        services = _load_service_state("checkip_services", [])
        svc = {
            "enabled": bool(request.form.get("enable")),
            "name": request.form.get("name"),
            "url": request.form.get("url"),
            "username": request.form.get("username"),
            "password": seal(request.form.get("password", "")),
            "verify_ssl": bool(request.form.get("verify_ssl")),
            "description": request.form.get("description", "")
        }
        services.append(svc)
        _save_service_state("checkip_services", services)
        return redirect(url_for("services.dynamic_dns_checkip"))
    services = _load_service_state("checkip_services", services)
    return render_template("dynamic_dns_checkip.html", services=services)


# ----------------------------
# IGMP PROXY
# ----------------------------

@services_bp.route("/igmp-proxy", methods=["GET", "POST"])
@login_required
def igmp_proxy():
    if request.method == "POST":
        if request.is_json:
            return jsonify({"success": True, "message": "IGMP Proxy settings saved."})
        return redirect(url_for("services.igmp_proxy"))
    return render_template("igmp_proxy.html")


# ----------------------------
# NTP SERVICE
# ----------------------------

@services_bp.route("/ntp")
@login_required
def ntp():
    return render_template("ntp.html")


# ----------------------------
# OPENVPN SERVER
# ----------------------------

@services_bp.route("/openvpn-server")
@login_required
def openvpn_server():
    return render_template("openvpn_server.html")


# ----------------------------
# ROUTER ADVERTISEMENT
# ----------------------------

@services_bp.route("/router-advertisement")
@login_required
def router_advertisement():
    return render_template("router_advertisement.html")


# ----------------------------
# SNMP SERVICE
# ----------------------------

@services_bp.route("/snmp")
@login_required
def snmp():
    return render_template("snmp.html")


# ----------------------------
# UPnP / IGD / PCP
# ----------------------------

@services_bp.route("/upnp-igd-pcp")
@login_required
def upnp_igd_pcp():
    return render_template("upnp_igd_pcp.html")


# ----------------------------
# WAKE ON LAN
# ----------------------------

@services_bp.route("/wake-on-lan", methods=["GET", "POST"])
@login_required
def wake_on_lan():
    interfaces = ["WAN", "LAN"]
    devices = []
    if request.method == "POST":
        if request.is_json:
            payload = request.get_json(silent=True) or {}
            mac = (payload.get("mac_address") or "").strip()
            iface = (payload.get("interface") or "").strip()
            if not mac or not iface:
                return jsonify({"success": False, "message": "MAC address and interface are required."}), 400
            return jsonify(
                {
                    "success": True,
                    "message": f"Wake-on-LAN packet queued for {mac} on {iface}.",
                }
            )
        return redirect(url_for("services.wake_on_lan"))
    return render_template("wake_on_lan.html", interfaces=interfaces, devices=devices)


# ----------------------------
# ADDITIONAL HELPER ROUTES
# ----------------------------

@services_bp.route("/services")
@login_required
def services():
    return redirect(url_for("services.services_home"))

@services_bp.route("/dns-host-edit", methods=["GET", "POST"])
@login_required
def dns_host_edit():
    return redirect(url_for("services.dns_forwarder_edit_host"))

@services_bp.route("/dns-domain-edit", methods=["GET", "POST"])
@login_required
def dns_domain_edit():
    return redirect(url_for("services.dns_forwarder_edit_domain"))


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 4 — Advanced service APIs
# ══════════════════════════════════════════════════════════════════════════════

# ---------------------------------------------------------------------------
# NTP
# ---------------------------------------------------------------------------

@services_bp.route("/api/ntp", methods=["GET"])
@login_required
def api_get_ntp():
    import json as _json
    conn = get_db()
    row  = conn.execute(
        "SELECT value_json FROM service_state WHERE key_name='ntp_settings'"
    ).fetchone()
    from app.services.ntp_writer import DEFAULT_SETTINGS
    settings = _json.loads(row["value_json"]) if row else dict(DEFAULT_SETTINGS)
    return jsonify({"ok": True, "settings": settings})


@services_bp.route("/api/ntp", methods=["POST"])
@api_permission_required("api.network.edit")
def api_save_ntp():
    data = request.get_json(force=True) or {}
    conn = get_db()
    conn.execute(
        "INSERT INTO service_state (key_name, value_json, updated_at) VALUES ('ntp_settings', ?, CURRENT_TIMESTAMP)"
        " ON CONFLICT(key_name) DO UPDATE SET value_json=excluded.value_json, updated_at=CURRENT_TIMESTAMP",
        (json.dumps(data),),
    )
    conn.commit()
    try:
        from app.services.ntp_writer import apply_ntp
        apply_result = apply_ntp(conn)
        if not apply_result.get("ok"):
            return jsonify({"ok": True, "message": "NTP settings saved. Apply warning: " + apply_result.get("message", "")})
    except Exception as exc:
        return jsonify({"ok": True, "message": f"NTP settings saved. Apply skipped: {exc}"})
    return jsonify({"ok": True, "message": "NTP settings saved and applied."})


@services_bp.route("/api/ntp/validate", methods=["GET"])
@login_required
def api_validate_ntp():
    import json as _json
    conn     = get_db()
    row      = conn.execute("SELECT value_json FROM service_state WHERE key_name='ntp_settings'").fetchone()
    from app.services.ntp_writer import DEFAULT_SETTINGS
    settings = _json.loads(row["value_json"]) if row else dict(DEFAULT_SETTINGS)
    from app.services.ntp_writer import validate_ntp
    errors = validate_ntp(settings)
    return jsonify({"ok": not errors, "errors": errors})


@services_bp.route("/api/ntp/preview", methods=["GET"])
@login_required
def api_preview_ntp():
    import json as _json
    conn = get_db()
    row  = conn.execute("SELECT value_json FROM service_state WHERE key_name='ntp_settings'").fetchone()
    from app.services.ntp_writer import DEFAULT_SETTINGS, generate_ntp_conf
    settings = _json.loads(row["value_json"]) if row else dict(DEFAULT_SETTINGS)
    conf = generate_ntp_conf(settings)
    return jsonify({"ok": True, "conf": conf})


@services_bp.route("/api/ntp/apply", methods=["POST"])
@api_permission_required("api.network.edit")
def api_apply_ntp():
    conn   = get_db()
    from app.services.ntp_writer import apply_ntp
    result = apply_ntp(conn)
    log_event(category="system", action="ntp_apply", username=session.get("username"),
              remote_addr=request.remote_addr, details={"ok": result["ok"]})
    return jsonify(result)


@services_bp.route("/api/ntp/status", methods=["GET"])
@login_required
def api_ntp_status():
    from app.services.ntp_writer import get_ntp_status, get_ntp_sync_status
    status = get_ntp_status()
    status["peers"] = get_ntp_sync_status().get("peers", [])
    return jsonify({"ok": True, **status})


@services_bp.route("/api/ntp/force-sync", methods=["POST"])
@api_permission_required("api.network.edit")
def api_ntp_force_sync():
    from app.services.ntp_writer import force_ntp_sync
    result = force_ntp_sync()
    log_event(category="system", action="ntp_force_sync", username=session.get("username"),
              remote_addr=request.remote_addr, details={"ok": result["ok"]})
    return jsonify(result)


# ---------------------------------------------------------------------------
# DHCPv6
# ---------------------------------------------------------------------------

@services_bp.route("/api/dhcpv6", methods=["GET"])
@login_required
def api_get_dhcpv6():
    conn   = get_db()
    pools  = [dict(r) for r in conn.execute("SELECT * FROM dhcpv6_pools ORDER BY interface_type")]
    return jsonify({"ok": True, "pools": pools})


@services_bp.route("/api/dhcpv6/<interface_type>", methods=["POST"])
@api_permission_required("api.network.edit")
def api_save_dhcpv6(interface_type):
    if interface_type.upper() not in ("LAN", "WAN"):
        return jsonify({"ok": False, "error": "interface_type must be LAN or WAN"}), 400
    data = request.get_json(force=True) or {}
    conn = get_db()
    conn.execute(
        """
        INSERT INTO dhcpv6_pools (interface_type, interface_name, enabled, prefix,
            start_address, end_address, valid_lifetime, preferred_lifetime,
            dns_servers, domain_search, pd_prefix, pd_prefix_len, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(interface_type) DO UPDATE SET
            interface_name=excluded.interface_name,
            enabled=excluded.enabled, prefix=excluded.prefix,
            start_address=excluded.start_address, end_address=excluded.end_address,
            valid_lifetime=excluded.valid_lifetime,
            preferred_lifetime=excluded.preferred_lifetime,
            dns_servers=excluded.dns_servers, domain_search=excluded.domain_search,
            pd_prefix=excluded.pd_prefix, pd_prefix_len=excluded.pd_prefix_len,
            updated_at=CURRENT_TIMESTAMP
        """,
        (interface_type.upper(),
         data.get("interface_name",""), int(bool(data.get("enabled",0))),
         data.get("prefix","::/64"), data.get("start_address",""), data.get("end_address",""),
         int(data.get("valid_lifetime",86400)), int(data.get("preferred_lifetime",3600)),
         data.get("dns_servers",""), data.get("domain_search",""),
         data.get("pd_prefix",""), int(data.get("pd_prefix_len",64))),
    )
    conn.commit()
    return jsonify({"ok": True, "message": f"DHCPv6 {interface_type} settings saved."})


@services_bp.route("/api/dhcpv6/validate", methods=["GET"])
@login_required
def api_validate_dhcpv6():
    conn   = get_db()
    from app.services.dhcpv6_writer import validate_dhcpv6
    errors = validate_dhcpv6(conn)
    return jsonify({"ok": not errors, "errors": errors})


@services_bp.route("/api/dhcpv6/preview", methods=["GET"])
@login_required
def api_preview_dhcpv6():
    conn = get_db()
    from app.services.dhcpv6_writer import generate_kea_dhcp6_conf
    return jsonify({"ok": True, "conf": generate_kea_dhcp6_conf(conn)})


@services_bp.route("/api/dhcpv6/apply", methods=["POST"])
@api_permission_required("api.network.edit")
def api_apply_dhcpv6():
    conn   = get_db()
    from app.services.dhcpv6_writer import apply_dhcpv6
    result = apply_dhcpv6(conn)
    log_event(category="system", action="dhcpv6_apply", username=session.get("username"),
              remote_addr=request.remote_addr, details={"ok": result["ok"]})
    return jsonify(result)


@services_bp.route("/api/dhcpv6/status", methods=["GET"])
@login_required
def api_dhcpv6_status():
    from app.services.dhcpv6_writer import get_dhcpv6_status, get_dhcpv6_leases
    status = get_dhcpv6_status()
    status["leases"] = get_dhcpv6_leases()
    return jsonify({"ok": True, **status})


@services_bp.route("/api/dhcpv6/leases", methods=["GET"])
@login_required
def api_dhcpv6_leases():
    from app.services.dhcpv6_writer import get_dhcpv6_leases
    leases = get_dhcpv6_leases()
    return jsonify({"ok": True, "leases": leases, "count": len(leases)})


@services_bp.route("/api/dhcpv6-ra/apply", methods=["POST"])
@api_permission_required("api.network.edit")
def api_apply_dhcpv6_and_ra():
    """Apply DHCPv6 (Kea) and Router Advertisements (rtadvd) together.
    Ensures M/O flags in RA are consistent with whether Kea pools are enabled."""
    conn   = get_db()
    from app.services.dhcpv6_writer import apply_dhcpv6_and_ra
    result = apply_dhcpv6_and_ra(conn)
    log_event(category="system", action="dhcpv6_ra_apply", username=session.get("username"),
              remote_addr=request.remote_addr, details={"ok": result["ok"]})
    return jsonify(result)


# ---------------------------------------------------------------------------
# Router Advertisement
# ---------------------------------------------------------------------------

@services_bp.route("/api/ra", methods=["GET"])
@login_required
def api_get_ra():
    conn = get_db()
    ifaces = [dict(r) for r in conn.execute("SELECT * FROM ra_settings ORDER BY interface_name")]
    return jsonify({"ok": True, "interfaces": ifaces})


@services_bp.route("/api/ra/<interface_name>", methods=["POST"])
@api_permission_required("api.network.edit")
def api_save_ra(interface_name):
    data = request.get_json(force=True) or {}
    conn = get_db()
    conn.execute(
        """
        INSERT INTO ra_settings
            (interface_name, enabled, prefix, autonomous_flag, managed_flag,
             other_flag, router_priority, min_interval, max_interval,
             default_lifetime, dns_servers, domain_search)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(interface_name) DO UPDATE SET
            enabled=excluded.enabled, prefix=excluded.prefix,
            autonomous_flag=excluded.autonomous_flag,
            managed_flag=excluded.managed_flag, other_flag=excluded.other_flag,
            router_priority=excluded.router_priority,
            min_interval=excluded.min_interval, max_interval=excluded.max_interval,
            default_lifetime=excluded.default_lifetime,
            dns_servers=excluded.dns_servers, domain_search=excluded.domain_search
        """,
        (interface_name,
         int(bool(data.get("enabled",0))), data.get("prefix",""),
         int(bool(data.get("autonomous_flag",1))), int(bool(data.get("managed_flag",0))),
         int(bool(data.get("other_flag",0))), data.get("router_priority","medium"),
         int(data.get("min_interval",200)), int(data.get("max_interval",600)),
         int(data.get("default_lifetime",1800)),
         data.get("dns_servers",""), data.get("domain_search","")),
    )
    conn.commit()
    return jsonify({"ok": True, "message": f"RA settings for {interface_name} saved."})


@services_bp.route("/api/ra/validate", methods=["GET"])
@login_required
def api_validate_ra():
    conn   = get_db()
    from app.services.rtadvd_writer import validate_rtadvd
    errors = validate_rtadvd(conn)
    return jsonify({"ok": not errors, "errors": errors})


@services_bp.route("/api/ra/preview", methods=["GET"])
@login_required
def api_preview_ra():
    conn = get_db()
    from app.services.rtadvd_writer import generate_rtadvd_conf
    return jsonify({"ok": True, "conf": generate_rtadvd_conf(conn)})


@services_bp.route("/api/ra/apply", methods=["POST"])
@api_permission_required("api.network.edit")
def api_apply_ra():
    conn   = get_db()
    from app.services.rtadvd_writer import apply_rtadvd
    result = apply_rtadvd(conn)
    log_event(category="system", action="ra_apply", username=session.get("username"),
              remote_addr=request.remote_addr, details={"ok": result["ok"]})
    return jsonify(result)


@services_bp.route("/api/ra/status", methods=["GET"])
@login_required
def api_ra_status():
    from app.services.rtadvd_writer import get_rtadvd_status
    return jsonify({"ok": True, **get_rtadvd_status()})


# ---------------------------------------------------------------------------
# Dynamic DNS
# ---------------------------------------------------------------------------

@services_bp.route("/api/ddns/preview", methods=["GET"])
@login_required
def api_preview_ddns():
    conn = get_db()
    from app.services.ddns_writer import generate_ddclient_conf
    # Return masked conf — no passwords in the preview
    import re
    conf = generate_ddclient_conf(conn)
    masked = re.sub(r"^(password=)(.+)$", r"\1••••••••", conf, flags=re.MULTILINE)
    return jsonify({"ok": True, "conf": masked})


@services_bp.route("/api/ddns/apply", methods=["POST"])
@api_permission_required("api.network.edit")
def api_apply_ddns():
    conn   = get_db()
    from app.services.ddns_writer import apply_ddns
    result = apply_ddns(conn)
    # Never include the full conf (has passwords) in audit log
    log_event(category="system", action="ddns_apply", username=session.get("username"),
              remote_addr=request.remote_addr, details={"ok": result["ok"]})
    result.pop("conf", None)   # strip secrets from response
    return jsonify(result)


@services_bp.route("/api/ddns/status", methods=["GET"])
@login_required
def api_ddns_status():
    from app.services.ddns_writer import get_ddns_status
    return jsonify({"ok": True, **get_ddns_status()})


@services_bp.route("/api/ddns/force-update", methods=["POST"])
@api_permission_required("api.network.edit")
def api_ddns_force_update():
    from app.services.ddns_writer import force_ddns_update
    result = force_ddns_update()
    log_event(category="system", action="ddns_force_update", username=session.get("username"),
              remote_addr=request.remote_addr, details={"ok": result["ok"]})
    return jsonify(result)


@services_bp.route("/api/ddns/validate", methods=["GET"])
@login_required
def api_validate_ddns():
    import json as _json
    conn   = get_db()
    row    = conn.execute(
        "SELECT value_json FROM service_state WHERE key_name='dynamic_dns_clients'"
    ).fetchone()
    clients = _json.loads(row["value_json"]) if row else []
    from app.services.ddns_writer import validate_ddns
    errors = validate_ddns([c for c in clients if not c.get("disabled")])
    return jsonify({"ok": not errors, "errors": errors})


# ---------------------------------------------------------------------------
# SNMP
# ---------------------------------------------------------------------------

@services_bp.route("/api/snmp", methods=["GET"])
@login_required
def api_get_snmp():
    import json as _json
    conn = get_db()
    row  = conn.execute("SELECT value_json FROM service_state WHERE key_name='snmp_settings'").fetchone()
    settings = _json.loads(row["value_json"]) if row else {}
    from app.services.snmp_writer import mask_snmp_settings
    return jsonify({"ok": True, "settings": mask_snmp_settings(settings)})


@services_bp.route("/api/snmp", methods=["POST"])
@api_permission_required("api.network.edit")
def api_save_snmp():
    data = request.get_json(force=True) or {}
    conn = get_db()
    conn.execute(
        "INSERT INTO service_state (key_name, value_json, updated_at) VALUES ('snmp_settings', ?, CURRENT_TIMESTAMP)"
        " ON CONFLICT(key_name) DO UPDATE SET value_json=excluded.value_json, updated_at=CURRENT_TIMESTAMP",
        (json.dumps(data),),
    )
    conn.commit()
    try:
        from app.services.snmp_writer import apply_snmp
        apply_result = apply_snmp(conn)
        if not apply_result.get("ok"):
            return jsonify({"ok": True, "message": "SNMP settings saved. Apply warning: " + apply_result.get("message", "")})
    except Exception as exc:
        return jsonify({"ok": True, "message": f"SNMP settings saved. Apply skipped: {exc}"})
    return jsonify({"ok": True, "message": "SNMP settings saved and applied."})


@services_bp.route("/api/snmp/validate", methods=["GET"])
@login_required
def api_validate_snmp():
    import json as _json
    conn = get_db()
    row  = conn.execute("SELECT value_json FROM service_state WHERE key_name='snmp_settings'").fetchone()
    settings = _json.loads(row["value_json"]) if row else {}
    from app.services.snmp_writer import validate_snmp, validate_snmp_config
    errors   = validate_snmp(settings)
    warnings = validate_snmp_config(conn)
    return jsonify({"ok": not errors, "errors": errors, "warnings": warnings})


@services_bp.route("/api/snmp/preview", methods=["GET"])
@login_required
def api_preview_snmp():
    import json as _json
    conn = get_db()
    row  = conn.execute("SELECT value_json FROM service_state WHERE key_name='snmp_settings'").fetchone()
    settings = _json.loads(row["value_json"]) if row else {}
    from app.services.snmp_writer import generate_snmpd_config, mask_snmp_settings
    safe_settings = mask_snmp_settings(settings)
    # Re-insert masked community for preview (won't be written to disk)
    conf = generate_snmpd_config({**settings, "community": "••••••••"})
    return jsonify({"ok": True, "conf": conf})


@services_bp.route("/api/snmp/apply", methods=["POST"])
@api_permission_required("api.network.edit")
def api_apply_snmp():
    conn   = get_db()
    from app.services.snmp_writer import apply_snmp
    result = apply_snmp(conn)
    log_event(category="system", action="snmp_apply", username=session.get("username"),
              remote_addr=request.remote_addr, details={"ok": result["ok"]})
    result.pop("conf", None)
    return jsonify(result)


@services_bp.route("/api/snmp/status", methods=["GET"])
@login_required
def api_snmp_status():
    from app.services.snmp_writer import get_snmp_status
    return jsonify({"ok": True, **get_snmp_status()})


# ---------------------------------------------------------------------------
# UPnP / NAT-PMP
# ---------------------------------------------------------------------------

@services_bp.route("/api/upnp", methods=["GET"])
@login_required
def api_get_upnp():
    import json as _json
    conn = get_db()
    row  = conn.execute("SELECT value_json FROM service_state WHERE key_name='upnp_settings'").fetchone()
    settings = _json.loads(row["value_json"]) if row else {}
    return jsonify({"ok": True, "settings": settings})


@services_bp.route("/api/upnp", methods=["POST"])
@api_permission_required("api.network.edit")
def api_save_upnp():
    data = request.get_json(force=True) or {}
    conn = get_db()
    conn.execute(
        "INSERT INTO service_state (key_name, value_json, updated_at) VALUES ('upnp_settings', ?, CURRENT_TIMESTAMP)"
        " ON CONFLICT(key_name) DO UPDATE SET value_json=excluded.value_json, updated_at=CURRENT_TIMESTAMP",
        (json.dumps(data),),
    )
    conn.commit()
    try:
        from app.services.upnp_writer import apply_upnp
        apply_result = apply_upnp(conn)
        if not apply_result.get("ok"):
            return jsonify({"ok": True, "message": "UPnP settings saved. Apply warning: " + apply_result.get("message", "")})
    except Exception as exc:
        return jsonify({"ok": True, "message": f"UPnP settings saved. Apply skipped: {exc}"})
    return jsonify({"ok": True, "message": "UPnP settings saved and applied."})


@services_bp.route("/api/upnp/validate", methods=["GET"])
@login_required
def api_validate_upnp():
    import json as _json
    conn = get_db()
    row  = conn.execute("SELECT value_json FROM service_state WHERE key_name='upnp_settings'").fetchone()
    settings = _json.loads(row["value_json"]) if row else {}
    from app.services.upnp_writer import validate_upnp
    errors = validate_upnp(settings)
    return jsonify({"ok": not errors, "errors": errors})


@services_bp.route("/api/upnp/preview", methods=["GET"])
@login_required
def api_preview_upnp():
    import json as _json
    conn = get_db()
    row  = conn.execute("SELECT value_json FROM service_state WHERE key_name='upnp_settings'").fetchone()
    settings = _json.loads(row["value_json"]) if row else {}
    from app.services.upnp_writer import generate_miniupnpd_conf
    return jsonify({"ok": True, "conf": generate_miniupnpd_conf(settings)})


@services_bp.route("/api/upnp/apply", methods=["POST"])
@api_permission_required("api.network.edit")
def api_apply_upnp():
    conn   = get_db()
    from app.services.upnp_writer import apply_upnp
    result = apply_upnp(conn)
    log_event(category="system", action="upnp_apply", username=session.get("username"),
              remote_addr=request.remote_addr, details={"ok": result["ok"]})
    return jsonify(result)


@services_bp.route("/api/upnp/status", methods=["GET"])
@login_required
def api_upnp_status():
    from app.services.upnp_writer import get_upnp_status, get_active_mappings
    status = get_upnp_status()
    status["mappings"] = get_active_mappings()
    return jsonify({"ok": True, **status})


# ---------------------------------------------------------------------------
# IGMP Proxy
# ---------------------------------------------------------------------------

@services_bp.route("/api/igmp", methods=["GET"])
@login_required
def api_get_igmp():
    import json as _json
    conn = get_db()
    row  = conn.execute("SELECT value_json FROM service_state WHERE key_name='igmp_settings'").fetchone()
    settings = _json.loads(row["value_json"]) if row else {}
    return jsonify({"ok": True, "settings": settings})


@services_bp.route("/api/igmp", methods=["POST"])
@api_permission_required("api.network.edit")
def api_save_igmp():
    data = request.get_json(force=True) or {}
    conn = get_db()
    conn.execute(
        "INSERT INTO service_state (key_name, value_json, updated_at) VALUES ('igmp_settings', ?, CURRENT_TIMESTAMP)"
        " ON CONFLICT(key_name) DO UPDATE SET value_json=excluded.value_json, updated_at=CURRENT_TIMESTAMP",
        (json.dumps(data),),
    )
    conn.commit()
    try:
        from app.services.igmp_writer import apply_igmp
        apply_result = apply_igmp(conn)
        if not apply_result.get("ok"):
            return jsonify({"ok": True, "message": "IGMP Proxy settings saved. Apply warning: " + apply_result.get("message", "")})
    except Exception as exc:
        return jsonify({"ok": True, "message": f"IGMP Proxy settings saved. Apply skipped: {exc}"})
    return jsonify({"ok": True, "message": "IGMP Proxy settings saved and applied."})


@services_bp.route("/api/igmp/validate", methods=["GET"])
@login_required
def api_validate_igmp():
    import json as _json
    conn = get_db()
    row  = conn.execute("SELECT value_json FROM service_state WHERE key_name='igmp_settings'").fetchone()
    settings = _json.loads(row["value_json"]) if row else {}
    from app.services.igmp_writer import validate_igmp
    errors = validate_igmp(settings)
    return jsonify({"ok": not errors, "errors": errors})


@services_bp.route("/api/igmp/preview", methods=["GET"])
@login_required
def api_preview_igmp():
    import json as _json
    conn = get_db()
    row  = conn.execute("SELECT value_json FROM service_state WHERE key_name='igmp_settings'").fetchone()
    settings = _json.loads(row["value_json"]) if row else {}
    from app.services.igmp_writer import generate_igmpproxy_conf
    return jsonify({"ok": True, "conf": generate_igmpproxy_conf(settings)})


@services_bp.route("/api/igmp/apply", methods=["POST"])
@api_permission_required("api.network.edit")
def api_apply_igmp():
    conn   = get_db()
    from app.services.igmp_writer import apply_igmp
    result = apply_igmp(conn)
    log_event(category="system", action="igmp_apply", username=session.get("username"),
              remote_addr=request.remote_addr, details={"ok": result["ok"]})
    return jsonify(result)


@services_bp.route("/api/igmp/status", methods=["GET"])
@login_required
def api_igmp_status():
    from app.services.igmp_writer import get_igmp_status
    return jsonify({"ok": True, **get_igmp_status()})


# ---------------------------------------------------------------------------
# Wake-on-LAN
# ---------------------------------------------------------------------------

@services_bp.route("/api/wol/hosts", methods=["GET"])
@login_required
def api_wol_hosts():
    conn  = get_db()
    hosts = [dict(r) for r in conn.execute(
        "SELECT * FROM wol_hosts ORDER BY name"
    )]
    return jsonify({"ok": True, "hosts": hosts})


@services_bp.route("/api/wol/hosts", methods=["POST"])
@api_permission_required("api.network.edit")
def api_wol_add_host():
    data = request.get_json(force=True) or {}
    mac  = (data.get("mac_address") or "").strip().lower()
    name = (data.get("name") or "").strip()
    iface = (data.get("interface") or "LAN").strip()
    bcast = (data.get("broadcast_ip") or "255.255.255.255").strip()
    desc  = (data.get("description") or "").strip()
    from app.services.wol_sender import validate_wol
    errors = validate_wol(mac, iface)
    if errors:
        return jsonify({"ok": False, "errors": errors}), 400
    try:
        conn = get_db()
        conn.execute(
            "INSERT OR REPLACE INTO wol_hosts (name, mac_address, interface, broadcast_ip, description)"
            " VALUES (?, ?, ?, ?, ?)",
            (name or mac, mac, iface, bcast, desc),
        )
        conn.commit()
        return jsonify({"ok": True, "message": f"WoL host {name or mac} saved."})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@services_bp.route("/api/wol/send", methods=["POST"])
@api_permission_required("api.network.edit")
def api_wol_send():
    data  = request.get_json(force=True) or {}
    mac   = (data.get("mac_address") or "").strip()
    iface = (data.get("interface") or "LAN").strip()
    bcast = (data.get("broadcast_ip") or "255.255.255.255").strip()
    from app.services.wol_sender import send_wol
    result = send_wol(mac, iface, bcast)
    log_event(category="system", action="wol_send", username=session.get("username"),
              remote_addr=request.remote_addr,
              details={"mac": mac, "interface": iface, "ok": result["ok"]})
    if result["ok"]:
        conn = get_db()
        conn.execute(
            "UPDATE wol_hosts SET last_sent_at=CURRENT_TIMESTAMP WHERE mac_address=?",
            (mac,),
        )
        conn.commit()
    return jsonify(result)


@services_bp.route("/api/wol/hosts/<int:host_id>", methods=["DELETE"])
@api_permission_required("api.network.edit")
def api_wol_delete_host(host_id):
    conn = get_db()
    conn.execute("DELETE FROM wol_hosts WHERE id=?", (host_id,))
    conn.commit()
    return jsonify({"ok": True, "message": "WoL host deleted."})


# ---------------------------------------------------------------------------
# Captive Portal
# ---------------------------------------------------------------------------

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
        "strict_mode":              False,
        "session_duration_minutes": 60,
        "upstream_dns":             "8.8.8.8",
    }
    settings = {**defaults, **stored}
    return jsonify({"ok": True, "settings": settings})


@services_bp.route("/api/captive-portal/settings", methods=["POST"])
@api_permission_required("api.network.edit")
def api_cp_save_settings():
    """Persist captive portal settings (portal_ip, portal_port, lan_interface, enabled, RADIUS)."""
    data = request.get_json(force=True) or {}
    conn = get_db()

    allowed_keys = {
        "enabled", "lan_interface", "portal_ip", "portal_port",
        "http_redirect_port", "allow_dns", "radius_server", "radius_secret",
        "whitelist_users", "strict_mode", "session_duration_minutes", "upstream_dns",
    }
    settings = {k: v for k, v in data.items() if k in allowed_keys}

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
    from app.services.captive_portal import generate_pf_anchor
    return jsonify({"ok": True, "conf": generate_pf_anchor(conn)})


@services_bp.route("/api/captive-portal/authenticate", methods=["POST"])
def api_cp_authenticate():
    """
    Public endpoint — called by the portal login form via AJAX or by external
    systems that need to authenticate a client against RADIUS.
    Does NOT require admin login.
    """
    conn     = get_db()
    data     = request.get_json(silent=True) or request.form
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    ip       = request.remote_addr or ""

    if not username or not password:
        return jsonify({"ok": False, "message": "Username and password are required."}), 400

    from app.services.captive_portal import authenticate_radius, authenticate_session
    result = authenticate_radius(conn, username, password)
    if result.get("ok"):
        from routes.portal import _client_mac
        mac = _client_mac(ip)
        auth_result = authenticate_session(conn, mac, ip, username=username)
        return jsonify({"ok": auth_result.get("ok"), "message": auth_result.get("message", "")})

    return jsonify({"ok": False, "message": result.get("message", "Authentication failed.")}), 401
