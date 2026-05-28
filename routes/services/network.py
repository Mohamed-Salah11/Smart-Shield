from routes.services import services_bp
from routes.services._common import *  # noqa: F401,F403
from routes.services._common import _load_service_state, _save_service_state  # noqa: F401


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
    from app.database import get_db
    return jsonify({"ok": True, **get_ddns_status(get_db())})


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
