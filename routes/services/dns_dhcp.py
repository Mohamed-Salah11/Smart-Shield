from routes.services import services_bp
from routes.services._common import *  # noqa: F401,F403
from routes.services._common import _load_service_state, _save_service_state  # noqa: F401


@services_bp.route("/")
@login_required
def services_home():
    # services.html is a placeholder stub — redirect to the DHCP server
    # page (the most-used services sub-route) so the Services nav lands
    # on a working screen.
    from flask import redirect, url_for
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
        data = request.get_json(silent=True) or {}
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

        data = request.get_json(silent=True) or {}
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
@api_permission_required("api.network.edit")
def dns_forwarder_edit_host():
    if request.method == "POST":
        return redirect(url_for("services.dns_forwarder"))
    return render_template("dns_forwarder_edit_host.html")


@services_bp.route("/dns-forwarder/edit-domain-override", methods=["GET", "POST"])
@login_required
@api_permission_required("api.network.edit")
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
@api_permission_required("api.network.edit")
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
@api_permission_required("api.network.edit")
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
@api_permission_required("api.network.edit")
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
@api_permission_required("api.network.edit")
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
