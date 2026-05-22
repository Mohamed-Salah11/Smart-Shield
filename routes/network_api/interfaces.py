from routes.network_api import network_api_bp
from routes.network_api._common import *  # noqa: F401,F403
from routes.network_api._common import _network_apply_enabled, _as_bool, _normalize_interface_name, _parse_ipv4_network, _safe_ip_address, _split_selector_values, _source_selector_matches, _load_interface_context, _classify_host_interface, _fetch_active_firewall_rules, _evaluate_host_policy, _merge_host_record, _refresh_tracked_hosts, _list_tracked_hosts, _capture_interfaces, _aggregate_web_activity  # noqa: F401


@network_api_bp.route("/interfaces", methods=["GET"])
@login_required
def get_interfaces():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT interface_type, network_port FROM interface_assignments")
    assignments = {row["interface_type"]: row["network_port"] for row in cur.fetchall()}

    cur.execute(
        """
        SELECT enable_interface, description, ipv4_config_type, ipv6_config_type,
               mac_address, mtu, mss, speed_and_duplex, ipv4_address,
               ipv4_upstream_gateway, block_private_networks, block_bogon_networks
        FROM lan_config WHERE id = 1
        """
    )
    lan = cur.fetchone()

    cur.execute(
        """
        SELECT enable_interface, description, ipv4_config_type, ipv6_config_type,
               mac_address, mtu, mss, speed_and_duplex, ipv4_address,
               ipv4_upstream_gateway, username, password, dial_on_demand,
               idle_timeout, block_private_networks, block_bogon_networks
        FROM wan_config WHERE id = 1
        """
    )
    wan = cur.fetchone()

    return jsonify(
        {
            "status": "success",
            "data": {
                "LAN": {
                    "assigned_port": assignments.get("LAN"),
                    "enable_interface": row_to_bool(lan, "enable_interface", True),
                    "description": lan["description"] if lan else "LAN",
                    "ipv4_config_type": lan["ipv4_config_type"] if lan else "static",
                    "ipv6_config_type": lan["ipv6_config_type"] if lan else "none",
                    "mac_address": lan["mac_address"] if lan else "",
                    "mtu": lan["mtu"] if lan else "",
                    "mss": lan["mss"] if lan else "",
                    "speed_and_duplex": lan["speed_and_duplex"] if lan else "default",
                    "ipv4_address": lan["ipv4_address"] if lan else "192.168.1.1/24",
                    "ipv4_upstream_gateway": lan["ipv4_upstream_gateway"] if lan else "",
                    "block_private_networks": row_to_bool(lan, "block_private_networks"),
                    "block_bogon_networks": row_to_bool(lan, "block_bogon_networks"),
                },
                "WAN": {
                    "assigned_port": assignments.get("WAN"),
                    "enable_interface": row_to_bool(wan, "enable_interface", True),
                    "description": wan["description"] if wan else "WAN",
                    "ipv4_config_type": wan["ipv4_config_type"] if wan else "dhcp",
                    "ipv6_config_type": wan["ipv6_config_type"] if wan else "none",
                    "mac_address": wan["mac_address"] if wan else "",
                    "mtu": wan["mtu"] if wan else "",
                    "mss": wan["mss"] if wan else "",
                    "speed_and_duplex": wan["speed_and_duplex"] if wan else "default",
                    "ipv4_address": wan["ipv4_address"] if wan else "",
                    "ipv4_upstream_gateway": wan["ipv4_upstream_gateway"] if wan else "",
                    "username": wan["username"] if wan else "",
                    "has_password": bool(wan and wan["password"]),
                    "password_placeholder": mask_secret(wan["password"] if wan else ""),
                    "dial_on_demand": row_to_bool(wan, "dial_on_demand"),
                    "idle_timeout": wan["idle_timeout"] if wan else 0,
                    "block_private_networks": row_to_bool(wan, "block_private_networks", True),
                    "block_bogon_networks": row_to_bool(wan, "block_bogon_networks", True),
                },
            },
        }
    )


@network_api_bp.route("/interfaces/<interface_type>", methods=["PUT"])
@api_permission_required("api.network.edit")
def update_interface(interface_type):
    try:
        validate_interface_type(interface_type)
        data = request.get_json(force=True) or {}
        payload = normalize_interface_payload(data, interface_type)

        ipv4_address = (payload["ipv4_address"] or "").strip()
        gateway = (payload["ipv4_upstream_gateway"] or "").strip()
        validate_cidr(ipv4_address)
        validate_ip(gateway)

        conn = get_db()
        cur  = conn.cursor()

        # Save pre-apply snapshot for rollback support
        import json as _json
        _snap_table = "lan_config" if interface_type == "LAN" else "wan_config"
        cur.execute(f"SELECT * FROM {_snap_table} WHERE id=1")
        _snap_row = cur.fetchone()
        if _snap_row:
            cur.execute(
                """
                INSERT INTO pending_interface_changes
                    (interface_type, snapshot_json, confirmed)
                VALUES (?, ?, 0)
                """,
                (interface_type, _json.dumps(dict(_snap_row))),
            )

        if interface_type == "LAN":
            cur.execute(
                """
                UPDATE lan_config
                SET enable_interface = ?,
                    description = ?,
                    ipv4_config_type = ?,
                    ipv6_config_type = ?,
                    mac_address = ?,
                    mtu = ?,
                    mss = ?,
                    speed_and_duplex = ?,
                    ipv4_address = ?,
                    ipv4_upstream_gateway = ?,
                    block_private_networks = ?,
                    block_bogon_networks = ?
                WHERE id = 1
                """,
                (
                    int(payload["enable_interface"]),
                    payload["description"],
                    payload["ipv4_config_type"],
                    payload["ipv6_config_type"],
                    payload["mac_address"],
                    payload["mtu"],
                    payload["mss"],
                    payload["speed_and_duplex"],
                    ipv4_address,
                    gateway,
                    int(payload["block_private_networks"]),
                    int(payload["block_bogon_networks"]),
                ),
            )
        else:
            cur.execute(
                """
                UPDATE wan_config
                SET enable_interface = ?,
                    description = ?,
                    ipv4_config_type = ?,
                    ipv6_config_type = ?,
                    mac_address = ?,
                    mtu = ?,
                    mss = ?,
                    speed_and_duplex = ?,
                    ipv4_address = ?,
                    ipv4_upstream_gateway = ?,
                    username = ?,
                    password = COALESCE(NULLIF(?, ''), password),
                    dial_on_demand = ?,
                    idle_timeout = ?,
                    block_private_networks = ?,
                    block_bogon_networks = ?
                WHERE id = 1
                """,
                (
                    int(payload["enable_interface"]),
                    payload["description"],
                    payload["ipv4_config_type"],
                    payload["ipv6_config_type"],
                    payload["mac_address"],
                    payload["mtu"],
                    payload["mss"],
                    payload["speed_and_duplex"],
                    ipv4_address,
                    gateway,
                    payload["username"],
                    # Encrypt on save; pass None so COALESCE keeps existing value when empty.
                    encrypt_secret(payload["password"]) if payload.get("password") else None,
                    int(payload["dial_on_demand"]),
                    payload["idle_timeout"],
                    int(payload["block_private_networks"]),
                    int(payload["block_bogon_networks"]),
                ),
            )

        assigned_port = payload["assigned_port"]
        if assigned_port:
            validate_interface_name(assigned_port)
            opposite = "LAN" if interface_type == "WAN" else "WAN"
            cur.execute(
                "SELECT network_port FROM interface_assignments WHERE interface_type = ?",
                (opposite,),
            )
            other = cur.fetchone()
            if other and (other["network_port"] or "").strip() == assigned_port:
                raise ValueError(f"{assigned_port} is already assigned to {opposite}")

            cur.execute(
                """
                INSERT INTO interface_assignments (interface_type, network_port)
                VALUES (?, ?)
                ON CONFLICT(interface_type) DO UPDATE SET network_port = excluded.network_port
                """,
                (interface_type, assigned_port),
            )
            if interface_type == "WAN":
                cur.execute(
                    "UPDATE wan_config SET assigned_port = ? WHERE id = 1",
                    (assigned_port,),
                )
            else:
                cur.execute(
                    "UPDATE lan_config SET assigned_port = ? WHERE id = 1",
                    (assigned_port,),
                )

        conn.commit()
        return jsonify({"status": "success", "message": f"{interface_type} updated"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


@network_api_bp.route("/dhcp/auto/<interface_type>", methods=["POST"])
@api_permission_required("api.network.edit")
def dhcp_auto_configure(interface_type):
    """
    Auto-configure the DHCP pool from the interface CIDR and run an ARP scan
    to discover already-online devices.  Saves the derived pool to the DB and
    enables it.
    """
    try:
        validate_interface_type(interface_type)
        conn = get_db()
        from app.services.dhcp_writer import auto_configure_pool
        result = auto_configure_pool(conn, interface_type)
        status = "success" if result["ok"] else "error"
        code   = 200 if result["ok"] else 400
        return jsonify({"status": status, **result}), code
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


@network_api_bp.route("/dhcp", methods=["GET"])
@login_required
def get_dhcp():
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT interface_type, enabled, start_ip, end_ip, gateway_ip, dns_servers, lease_time FROM dhcp_pools"
    )
    rows = cur.fetchall()

    data = {}
    for row in rows:
        data[row["interface_type"]] = {
            "enabled": bool(row["enabled"]),
            "start_ip": row["start_ip"],
            "end_ip": row["end_ip"],
            "gateway_ip": row["gateway_ip"],
            "dns_servers": [x for x in (row["dns_servers"] or "").split(",") if x],
            "lease_time": row["lease_time"],
        }

    return jsonify({"status": "success", "data": data})


@network_api_bp.route("/dhcp/<interface_type>", methods=["PUT"])
@api_permission_required("api.network.edit")
def update_dhcp(interface_type):
    try:
        validate_interface_type(interface_type)
        data = request.get_json(force=True) or {}

        validate_ip(data.get("start_ip", ""))
        validate_ip(data.get("end_ip", ""))
        validate_ip(data.get("gateway_ip", ""))

        dns_servers = data.get("dns_servers", [])
        for dns in dns_servers:
            validate_ip(dns)

        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO dhcp_pools (interface_type, enabled, start_ip, end_ip, gateway_ip, dns_servers, lease_time)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(interface_type) DO UPDATE SET
                enabled = excluded.enabled,
                start_ip = excluded.start_ip,
                end_ip = excluded.end_ip,
                gateway_ip = excluded.gateway_ip,
                dns_servers = excluded.dns_servers,
                lease_time = excluded.lease_time,
                updated_at = CURRENT_TIMESTAMP
            """,
            (
                interface_type,
                int(bool(data.get("enabled", False))),
                data.get("start_ip", ""),
                data.get("end_ip", ""),
                data.get("gateway_ip", ""),
                ",".join(dns_servers),
                int(data.get("lease_time", 86400)),
            ),
        )
        conn.commit()
        return jsonify({"status": "success", "message": f"DHCP updated for {interface_type}"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


@network_api_bp.route("/leases", methods=["GET"])
@login_required
def get_leases():
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, interface_type, hostname, mac_address, ip_address, description, created_at
        FROM static_leases
        ORDER BY id DESC
        """
    )
    rows = cur.fetchall()
    return jsonify({"status": "success", "data": [dict(row) for row in rows]})


@network_api_bp.route("/leases", methods=["POST"])
@api_permission_required("api.network.edit")
def add_lease():
    try:
        data = request.get_json(force=True) or {}
        validate_interface_type(data["interface_type"])
        validate_mac(data["mac_address"])
        validate_ip(data["ip_address"])

        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO static_leases (interface_type, hostname, mac_address, ip_address, description)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                data["interface_type"],
                data.get("hostname", ""),
                data["mac_address"].lower(),
                data["ip_address"],
                data.get("description", ""),
            ),
        )
        conn.commit()
        return jsonify({"status": "success", "message": "Static lease added"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


@network_api_bp.route("/leases/<int:lease_id>", methods=["DELETE"])
@api_permission_required("api.network.edit")
def delete_lease(lease_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM static_leases WHERE id = ?", (lease_id,))
    conn.commit()
    return jsonify({"status": "success", "message": "Static lease deleted"})


@network_api_bp.route("/hosts", methods=["GET"])
@login_required
def list_hosts():
    conn = None
    try:
        requested_type = (request.args.get("interface_type") or "").strip().upper()
        if requested_type and requested_type not in {"LAN", "WAN", "UNKNOWN"}:
            return jsonify({"status": "error", "message": "invalid interface_type"}), 400

        refresh = _as_bool(request.args.get("refresh"), default=False)
        conn = get_db()
        cur = conn.cursor()

        discovered = 0
        if refresh:
            discovered = _refresh_tracked_hosts(cur)
            conn.commit()
            log_event(
                category="system",
                action="hosts_refresh",
                username=session.get("username", "anonymous"),
                remote_addr=request.remote_addr,
                details={"discovered_hosts": discovered},
            )

        hosts = _list_tracked_hosts(cur, interface_type_filter=requested_type or None)
        return jsonify(
            {
                "status": "success",
                "data": hosts,
                "count": len(hosts),
                "refreshed": refresh,
                "discovered_hosts": discovered,
                "live_discovery_available": sys.platform.startswith("freebsd"),
            }
        )
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@network_api_bp.route("/hosts/refresh", methods=["POST"])
@api_permission_required("api.network.edit")
def refresh_hosts():
    conn = None
    try:
        conn = get_db()
        cur = conn.cursor()
        discovered = _refresh_tracked_hosts(cur)
        conn.commit()

        log_event(
            category="system",
            action="hosts_refresh",
            username=session.get("username", "anonymous"),
            remote_addr=request.remote_addr,
            details={"discovered_hosts": discovered},
        )
        return jsonify(
            {
                "status": "success",
                "message": "Host inventory refreshed.",
                "discovered_hosts": discovered,
                "live_discovery_available": sys.platform.startswith("freebsd"),
            }
        )
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


def _sync_pf_table_from_query(conn, table_name: str, sql: str):
    """Flush and repopulate a PF table from a single-column IP query."""
    if not sys.platform.startswith("freebsd"):
        return
    try:
        from app.services.priv_helper import run_privileged
        ips = [r["ip_address"] for r in conn.execute(sql).fetchall()]
        run_privileged("pf.table_flush", table=table_name)
        for ip in ips:
            run_privileged("pf.table_add", table=table_name, ip=ip)
    except Exception as exc:
        current_app.logger.warning("Failed to sync %s PF table: %s", table_name, exc)


def sync_device_whitelist_pf(conn):
    """
    Flush and repopulate the <device_whitelist> and <access_whitelist> PF tables
    from is_whitelisted hosts.

    Phase 3.2 renamed the concept: access_whitelist is the canonical name (captive
    portal bypass). device_whitelist is kept as an alias for one release so external
    callers / pf.conf snapshots keep working until the UI rename lands.
    """
    sql = "SELECT ip_address FROM tracked_hosts WHERE is_whitelisted=1"
    _sync_pf_table_from_query(conn, "device_whitelist", sql)
    _sync_pf_table_from_query(conn, "access_whitelist", sql)


def sync_policy_exemption_pf(conn):
    """Flush and repopulate the <policy_exemption> PF table from is_policy_exempt hosts."""
    _sync_pf_table_from_query(
        conn,
        "policy_exemption",
        "SELECT ip_address FROM tracked_hosts WHERE is_policy_exempt=1",
    )


@network_api_bp.route("/hosts/<int:host_id>/whitelist", methods=["PATCH"])
@login_required
@api_permission_required("api.network.edit")
def toggle_whitelist(host_id):
    """Set or clear is_whitelisted for a tracked host and sync the PF table."""
    data = request.get_json(force=True) or {}
    whitelisted = 1 if data.get("whitelisted") else 0
    conn = get_db()
    row = conn.execute("SELECT id FROM tracked_hosts WHERE id=?", (host_id,)).fetchone()
    if not row:
        return jsonify({"ok": False, "message": "Host not found."}), 404
    conn.execute("UPDATE tracked_hosts SET is_whitelisted=? WHERE id=?", (whitelisted, host_id))
    conn.commit()
    sync_device_whitelist_pf(conn)
    # captive_bypass_toggle: clients with is_whitelisted=1 land in the PF
    # <device_whitelist> table, which bypass_policy maps to captive_portal_http
    # — DNS/content policy still applies. Logged at admin_audit so compliance
    # reviews can see who granted portal bypass to whom.
    log_event(
        category="admin_audit", action="captive_bypass_toggle",
        username=session.get("username"), remote_addr=request.remote_addr,
        details={"host_id": host_id, "whitelisted": bool(whitelisted),
                 "bypass_scope": "captive_portal_http_only"},
        severity="medium",
    )
    return jsonify({"ok": True, "whitelisted": bool(whitelisted)})


@network_api_bp.route("/hosts/<int:host_id>/policy-exempt", methods=["PATCH"])
@login_required
@api_permission_required("api.network.edit")
def toggle_policy_exempt(host_id):
    """Set or clear is_policy_exempt for a tracked host and sync the PF table."""
    data = request.get_json(force=True) or {}
    exempt = 1 if data.get("policy_exempt") else 0
    conn = get_db()
    row = conn.execute("SELECT id FROM tracked_hosts WHERE id=?", (host_id,)).fetchone()
    if not row:
        return jsonify({"ok": False, "message": "Host not found."}), 404
    conn.execute("UPDATE tracked_hosts SET is_policy_exempt=? WHERE id=?", (exempt, host_id))
    conn.commit()
    sync_policy_exemption_pf(conn)
    # policy_exemption_toggle: clients with is_policy_exempt=1 land in PF
    # <policy_exemption> AND in Unbound's policy_exemption_view — they bypass
    # DNS/web/app filtering. They do *not* automatically bypass captive portal
    # auth. Logged at admin_audit so compliance can see who was excused.
    log_event(
        category="admin_audit", action="policy_exemption_toggle",
        username=session.get("username"), remote_addr=request.remote_addr,
        details={"host_id": host_id, "policy_exempt": bool(exempt),
                 "bypass_scope": "dns_web_app_policy"},
        severity="medium",
    )
    return jsonify({"ok": True, "policy_exempt": bool(exempt)})


@network_api_bp.route("/devices", methods=["GET"])
@login_required
def devices_page():
    """Render the network devices page."""
    return render_template("network_devices.html")


@network_api_bp.route("/web-activity", methods=["GET"])
@login_required
def web_activity():
    conn = None
    try:
        if not sys.platform.startswith("freebsd"):
            return jsonify(
                {
                    "status": "success",
                    "data": [],
                    "count": 0,
                    "message": "Live network web-activity capture is available only on FreeBSD.",
                }
            )

        requested_type = (request.args.get("interface_type") or "").strip().upper()
        if requested_type and requested_type not in {"LAN", "WAN"}:
            return jsonify({"status": "error", "message": "invalid interface_type"}), 400

        try:
            total_dns_limit = int(request.args.get("dns_limit", 120) or 120)
            total_http_limit = int(request.args.get("http_limit", 80) or 80)
        except ValueError:
            return jsonify({"status": "error", "message": "dns_limit/http_limit must be integers"}), 400

        total_dns_limit = max(10, min(total_dns_limit, 500))
        total_http_limit = max(10, min(total_http_limit, 300))
        refresh_hosts = _as_bool(request.args.get("refresh_hosts"), default=True)

        conn = get_db()
        cur = conn.cursor()

        if refresh_hosts:
            _refresh_tracked_hosts(cur)
            conn.commit()

        interfaces = _capture_interfaces(cur, requested_type)
        if not interfaces:
            return jsonify(
                {
                    "status": "success",
                    "data": [],
                    "count": 0,
                    "message": (
                        "No assigned interface ports found for capture. "
                        "Set LAN/WAN assignments first."
                    ),
                }
            )

        per_iface_dns = max(10, total_dns_limit // max(1, len(interfaces)))
        per_iface_http = max(10, total_http_limit // max(1, len(interfaces)))

        dns_rows = []
        http_rows = []
        capture_errors = []

        for _, iface_name in interfaces:
            try:
                dns_rows.extend(capture_dns_activity(iface_name, limit=per_iface_dns))
            except FreeBSDNetworkError as e:
                capture_errors.append(f"{iface_name}: {str(e)}")

            try:
                http_rows.extend(capture_http_activity(iface_name, limit=per_iface_http))
            except FreeBSDNetworkError as e:
                capture_errors.append(f"{iface_name}: {str(e)}")

        cur.execute(
            """
            SELECT ip_address, interface_type, interface_name, hostname, mac_address, policy_state, policy_note
            FROM tracked_hosts
            ORDER BY last_seen DESC
            """
        )
        host_lookup = {}
        for row in cur.fetchall():
            ip = (row["ip_address"] or "").strip()
            if not ip or ip in host_lookup:
                continue
            host_lookup[ip] = dict(row)

        rows = _aggregate_web_activity(dns_rows, http_rows, host_lookup)

        log_event(
            category="system",
            action="web_activity_sample",
            username=session.get("username", "anonymous"),
            remote_addr=request.remote_addr,
            details={
                "hosts": len(rows),
                "interfaces": [name for _, name in interfaces],
                "dns_events": len(dns_rows),
                "http_events": len(http_rows),
            },
        )

        return jsonify(
            {
                "status": "success",
                "data": rows,
                "count": len(rows),
                "interfaces": [{"interface_type": t, "interface_name": n} for t, n in interfaces],
                "dns_events": len(dns_rows),
                "http_events": len(http_rows),
                "capture_errors": capture_errors,
                "message": (
                    "Best-effort visibility: DNS domains and plain HTTP links are shown. "
                    "HTTPS full links are encrypted unless TLS interception proxy is used."
                ),
            }
        )
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@network_api_bp.route("/apply", methods=["POST"])
@api_permission_required("api.network.apply")
def apply_network():
    try:
        from app.services.network_service import run_command

        data = request.get_json(force=True) or {}
        interface_name = data["interface_name"]
        # config_type distinguishes DHCP ("dhcp") from static ("static").
        # Callers that omit it but provide an ipv4_address are treated as static.
        config_type = (data.get("config_type") or "static").lower().strip()
        ipv4_address = (data.get("ipv4_address") or "").strip()
        gateway_ip = (data.get("gateway_ip") or "").strip()

        validate_interface_name(interface_name)
        if config_type != "dhcp":
            validate_cidr(ipv4_address)
        validate_ip(gateway_ip)

        if not _network_apply_enabled():
            return jsonify(
                {
                    "status": "success",
                    "message": (
                        "Configuration saved. Live FreeBSD network apply is disabled. "
                        "Set SMARTSHIELD_ENABLE_NETWORK_APPLY=1 to enable it."
                    ),
                }
            )

        ensure_freebsd()

        if config_type == "dhcp":
            # FreeBSD 13: dhclient is in base (/sbin/dhclient).
            # FreeBSD 14: dhclient was removed; dhcpcd is the base replacement.
            # Accept whichever is present.
            import shutil
            dhcp_bin = shutil.which("dhclient") or shutil.which("dhcpcd")
            if not dhcp_bin:
                raise FreeBSDNetworkError(
                    "No DHCP client found. FreeBSD 13: dhclient is in base. "
                    "FreeBSD 14: install dhcpcd via: pkg install dhcpcd"
                )
            run_command(["ifconfig", interface_name, "up"], check=True)
            run_command([dhcp_bin, interface_name], check=True)
            return jsonify(
                {
                    "status": "success",
                    "message": f"DHCP lease requested on {interface_name} via {dhcp_bin}.",
                }
            )

        if config_type == "pppoe":
            # Write /etc/ppp/ppp.conf from DB and (re)start the ppp daemon.
            # The physical NIC name is read from wan_config; interface_name
            # in the request is ignored for PPPoE (ppp manages tun0 itself).
            from app.services.pppoe_writer import apply_pppoe
            conn = get_db()
            result = apply_pppoe(conn)
            status = "success" if result["ok"] else "error"
            code = 200 if result["ok"] else 400
            return jsonify({"status": status, "message": result["message"]}), code

        # Static: apply explicit address, then optional default gateway.
        apply_interface_ipv4(interface_name, ipv4_address)

        if gateway_ip:
            set_default_gateway(gateway_ip)

        return jsonify(
            {
                "status": "success",
                "message": f"Static address {ipv4_address} applied on {interface_name}.",
            }
        )
    except FreeBSDNetworkError as e:
        return jsonify({"status": "error", "message": str(e)}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


@network_api_bp.route("/pppoe/status", methods=["GET"])
@login_required
def pppoe_status():
    """Return live PPPoE session state (running, tun0 IP, etc.)."""
    from app.services.pppoe_writer import get_pppoe_status
    return jsonify({"status": "success", "data": get_pppoe_status()})


@network_api_bp.route("/pppoe/disconnect", methods=["POST"])
@api_permission_required("api.network.edit")
def pppoe_disconnect():
    """Tear down the active PPPoE session."""
    from app.services.pppoe_writer import disconnect_pppoe
    result = disconnect_pppoe()
    status = "success" if result["ok"] else "error"
    return jsonify({"status": status, "message": result["message"]})


@network_api_bp.route("/interfaces/<interface_type>/snapshot", methods=["GET"])
@login_required
def get_interface_snapshot(interface_type: str):
    """Return the last pre-apply snapshot for an interface (for rollback UI)."""
    try:
        validate_interface_type(interface_type)
        conn = get_db()
        cur  = conn.cursor()
        cur.execute(
            """
            SELECT id, snapshot_json, applied_at, confirmed, rollback_by
            FROM pending_interface_changes
            WHERE interface_type = ?
            ORDER BY applied_at DESC LIMIT 1
            """,
            (interface_type,),
        )
        row = cur.fetchone()
        if not row:
            return jsonify({"status": "success", "snapshot": None})
        import json as _json
        return jsonify({
            "status": "success",
            "snapshot": {
                "id":          row["id"],
                "config":      _json.loads(row["snapshot_json"]),
                "applied_at":  row["applied_at"],
                "confirmed":   bool(row["confirmed"]),
                "rollback_by": row["rollback_by"],
            },
        })
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400


@network_api_bp.route("/interfaces/<interface_type>/confirm", methods=["POST"])
@api_permission_required("api.network.edit")
def confirm_interface_apply(interface_type: str):
    """
    Mark the most recent interface apply as confirmed (administrator can still
    reach the management interface after the change).
    Clears the rollback window.
    """
    try:
        validate_interface_type(interface_type)
        conn = get_db()
        cur  = conn.cursor()
        cur.execute(
            """
            UPDATE pending_interface_changes
            SET confirmed = 1
            WHERE interface_type = ? AND confirmed = 0
            """,
            (interface_type,),
        )
        conn.commit()
        return jsonify({"status": "success", "message": f"{interface_type} change confirmed."})
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400


@network_api_bp.route("/interfaces/<interface_type>/rollback", methods=["POST"])
@api_permission_required("api.network.edit")
def rollback_interface(interface_type: str):
    """
    Restore the last pre-apply snapshot for an interface.
    Writes the saved config back to the DB (does not re-apply to OS — use /apply
    after rollback if live apply is desired).
    """
    try:
        validate_interface_type(interface_type)
        import json as _json
        conn = get_db()
        cur  = conn.cursor()
        cur.execute(
            """
            SELECT id, snapshot_json FROM pending_interface_changes
            WHERE interface_type = ? ORDER BY applied_at DESC LIMIT 1
            """,
            (interface_type,),
        )
        row = cur.fetchone()
        if not row:
            return jsonify({"status": "error", "message": "No snapshot to roll back to."}), 404

        snap = _json.loads(row["snapshot_json"])

        if interface_type == "LAN":
            cur.execute(
                """
                UPDATE lan_config SET
                    ipv4_config_type=?, ipv4_address=?, ipv4_upstream_gateway=?,
                    block_private_networks=?, block_bogon_networks=?
                WHERE id=1
                """,
                (
                    snap.get("ipv4_config_type", "static"),
                    snap.get("ipv4_address", ""),
                    snap.get("ipv4_upstream_gateway", ""),
                    int(snap.get("block_private_networks", 0)),
                    int(snap.get("block_bogon_networks", 0)),
                ),
            )
        else:
            cur.execute(
                """
                UPDATE wan_config SET
                    ipv4_config_type=?, ipv4_address=?, ipv4_upstream_gateway=?,
                    username=?, block_private_networks=?, block_bogon_networks=?
                WHERE id=1
                """,
                (
                    snap.get("ipv4_config_type", "dhcp"),
                    snap.get("ipv4_address", ""),
                    snap.get("ipv4_upstream_gateway", ""),
                    snap.get("username", ""),
                    int(snap.get("block_private_networks", 1)),
                    int(snap.get("block_bogon_networks", 1)),
                ),
            )

        # Delete the snapshot after rollback
        cur.execute("DELETE FROM pending_interface_changes WHERE id=?", (row["id"],))
        conn.commit()

        from app.audit_log import log_event
        log_event(
            category="system", action="interface_rollback",
            username=session.get("username", "anonymous"),
            remote_addr=request.remote_addr,
            details={"interface_type": interface_type},
        )
        return jsonify({"status": "success", "message": f"{interface_type} rolled back to previous config."})
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400
