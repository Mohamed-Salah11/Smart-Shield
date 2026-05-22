from routes.diagnostics import diagnostics_bp
from routes.diagnostics._common import *  # noqa: F401,F403
from routes.diagnostics._common import _env_int, _env_bool, _max_backup_upload_bytes, _pbkdf2_iterations, _default_backup_dir, _backup_dir, _usb_backup_dir, _ensure_yaml_support, _ensure_crypto_support, _general_config_path, _database_path, _audit_log_path, _load_general_config_file, _safe_slug, _normalize_abs, _is_same_or_ancestor, _is_overly_broad_directory, _b64_encode, _b64_decode, _payload_to_bytes, _normalize_yaml_value, _is_text_like_path, _mask_secrets_in_text, _maybe_mask_bytes, _derive_key, _collect_log_roots, _collect_config_roots, _master_key_path, _snapshot_component_definitions, _safe_relative_path, _is_dangerous_target, _path_within_root, _snapshot_file_component, _snapshot_directory_component, _build_full_snapshot_payload, _serialize_snapshot_envelope, _decode_snapshot_envelope, _build_backup_filename, _save_safety_backup, _write_usb_backup, _atomic_write, _apply_fs_metadata, _decode_file_blob, _restore_file_component, _force_rmtree, _restore_directory_component, _restore_full_snapshot, _restart_services_after_restore, _backup_page_context  # noqa: F401


@diagnostics_bp.route("/command-prompt")
@login_required
def command_prompt():
    return render_template("command_prompt.html")


# --------------------------------------------------
# DNS LOOKUP
# --------------------------------------------------

@diagnostics_bp.route("/dns-lookup")
@login_required
def dns_lookup():
    return render_template("dns_lookup.html")


@diagnostics_bp.route("/api/dns-lookup", methods=["POST"])
@login_required
def api_dns_lookup():
    import socket
    data    = request.get_json(silent=True) or {}
    host    = (data.get("host") or "").strip()
    rtype   = (data.get("type") or "A").strip().upper()
    if not host:
        return jsonify({"ok": False, "message": "Host is required"}), 400
    results = []
    try:
        if rtype in ("A", "ANY"):
            for ai in socket.getaddrinfo(host, None, socket.AF_INET):
                ip = ai[4][0]
                if ip not in results:
                    results.append({"type": "A", "value": ip})
        if rtype in ("AAAA", "ANY"):
            for ai in socket.getaddrinfo(host, None, socket.AF_INET6):
                ip = ai[4][0]
                if not any(r["value"] == ip for r in results):
                    results.append({"type": "AAAA", "value": ip})
    except socket.gaierror as e:
        return jsonify({"ok": False, "message": str(e), "results": []})
    return jsonify({"ok": True, "host": host, "results": results})


# --------------------------------------------------
# FILE EDITOR
# --------------------------------------------------

@diagnostics_bp.route("/edit-file")
@login_required
def edit_file():
    from flask import abort, current_app
    if not current_app.config.get("ENABLE_UNFINISHED_PAGES"):
        abort(404)
    return render_template("edit_file.html")


# --------------------------------------------------
# FACTORY DEFAULTS
# --------------------------------------------------

@diagnostics_bp.route("/factory-defaults")
@login_required
def factory_defaults():
    return render_template("factory_defaults.html")


@diagnostics_bp.route("/factory-defaults/reset", methods=["POST"])
@superuser_required
@reauth_required(reason="factory reset")
def factory_defaults_reset():
    """Wipe all firewall rules, NAT, VPN config — keep users. Requires password re-auth."""
    from werkzeug.security import check_password_hash
    from app.database import get_db
    data     = request.get_json(silent=True) or {}
    password = (data.get("confirm_password") or "").strip()
    if not password:
        return jsonify({"ok": False, "message": "confirm_password is required."}), 400

    conn    = get_db()
    user_id = session.get("user_id")
    row     = conn.execute(
        "SELECT password FROM users WHERE id=?", (user_id,)
    ).fetchone()
    if not row or not check_password_hash(row["password"], password):
        log_event(category="security", action="factory_reset_reauth_failed",
                  username=session.get("username"), remote_addr=request.remote_addr)
        return jsonify({"ok": False, "message": "Password confirmation failed."}), 403

    cur = conn.cursor()
    tables_to_clear = [
        "firewall_rules_wan", "firewall_rules_lan", "firewall_rules_floating",
        "firewall_aliases", "firewall_schedules", "nat_pf", "nat_1to1",
        "nat_outbound", "nat_npt", "openvpn_servers", "openvpn_clients",
        "ipsec_phase1", "ipsec_phase2", "ipsec_pre_shared_keys",
        "l2tp_config", "dhcp_pools", "static_leases",
    ]
    for t in tables_to_clear:
        try:
            cur.execute(f"DELETE FROM {t}")
        except Exception:
            pass
    conn.commit()
    log_event(category="system", action="factory_reset",
              username=session.get("username"), remote_addr=request.remote_addr,
              details={"tables_cleared": tables_to_clear})
    return jsonify({"ok": True, "message": "Factory defaults applied. Firewall rules and VPN config cleared."})


# --------------------------------------------------
# SHUTDOWN / HALT SYSTEM
# --------------------------------------------------

@diagnostics_bp.route("/halt-system")
@login_required
def halt_system():
    return render_template("halt_system.html")


@diagnostics_bp.route("/halt-system/execute", methods=["POST"])
@superuser_required
@reauth_required(reason="halt/reboot system")
def halt_system_execute():
    import sys
    from werkzeug.security import check_password_hash
    from app.database import get_db
    data     = request.get_json(silent=True) or {}
    action   = (data.get("action") or "halt").lower()
    password = (data.get("confirm_password") or "").strip()
    if action not in ("halt", "reboot"):
        return jsonify({"ok": False, "message": "Invalid action"}), 400
    if not password:
        return jsonify({"ok": False, "message": "confirm_password is required."}), 400

    conn    = get_db()
    user_id = session.get("user_id")
    row     = conn.execute(
        "SELECT password FROM users WHERE id=?", (user_id,)
    ).fetchone()
    if not row or not check_password_hash(row["password"], password):
        log_event(category="security", action=f"system_{action}_reauth_failed",
                  username=session.get("username"), remote_addr=request.remote_addr)
        return jsonify({"ok": False, "message": "Password confirmation failed."}), 403

    log_event(category="system", action=f"system_{action}",
              username=session.get("username"), remote_addr=request.remote_addr)
    if not sys.platform.startswith("freebsd"):
        return jsonify({"ok": True, "message": f"Non-FreeBSD: {action} would run here."})
    try:
        from app.services.network_service import run_command
        cmd = ["shutdown", "-r", "now"] if action == "reboot" else ["shutdown", "-h", "now"]
        run_command(cmd, check=False, timeout_seconds=5)
        return jsonify({"ok": True, "message": f"System {action} initiated."})
    except Exception as e:
        return jsonify({"ok": False, "message": str(e)})


# --------------------------------------------------
# LIMITER INFO
# --------------------------------------------------

@diagnostics_bp.route("/limiter-info")
@login_required
def limiter_info():
    from app.database import get_db
    conn = get_db()
    cur  = conn.cursor()
    try:
        cur.execute("SELECT * FROM limiters_configs ORDER BY name")
        limiters = [dict(r) for r in cur.fetchall()]
    except Exception:
        limiters = []
    return render_template("limiter_info.html", limiters=limiters)


# --------------------------------------------------
# NDP TABLE (IPv6)
# --------------------------------------------------

@diagnostics_bp.route("/ndp-table")
@login_required
def ndp_table():
    import sys, re
    neighbors = []
    on_freebsd = sys.platform.startswith("freebsd")
    if on_freebsd:
        try:
            from app.services.network_service import run_command
            r = run_command(["ndp", "-an"], check=False)
            for line in (r.stdout or "").splitlines():
                parts = line.split()
                if len(parts) >= 3 and not line.startswith("Neighbor"):
                    neighbors.append({
                        "ip": parts[0].rstrip("%0"), "mac": parts[1],
                        "iface": parts[2] if len(parts) > 2 else "",
                        "state": parts[3] if len(parts) > 3 else "",
                    })
        except Exception:
            pass
    return render_template("ndp_table.html", neighbors=neighbors, on_freebsd=on_freebsd)


# --------------------------------------------------
# PACKET CAPTURE
# --------------------------------------------------

@diagnostics_bp.route("/packet-capture")
@login_required
def packet_capture():
    import sys
    from app.database import get_db
    conn = get_db()
    cur  = conn.cursor()
    ifaces = []
    cur.execute("SELECT assigned_port, description FROM lan_config LIMIT 1")
    lan = cur.fetchone()
    cur.execute("SELECT assigned_port, description FROM wan_config LIMIT 1")
    wan = cur.fetchone()
    if lan and lan["assigned_port"]: ifaces.append({"name": lan["assigned_port"], "label": "LAN"})
    if wan and wan["assigned_port"]: ifaces.append({"name": wan["assigned_port"], "label": "WAN"})
    if not ifaces:
        ifaces = [{"name": "em0", "label": "WAN"}, {"name": "em1", "label": "LAN"}]
    return render_template("packet_capture.html", interfaces=ifaces,
                           on_freebsd=sys.platform.startswith("freebsd"))


def _validate_pcap_filter(filter_str: str) -> bool:
    """
    Allow only safe BPF filter characters.

    Permits: alphanumeric, spaces, dots, colons, dashes, underscores, slashes.
    Blocks shell-injection characters: ; & | $ ` ( ) ' " > < newlines etc.
    An empty filter string is always valid (means "capture everything").
    """
    if not filter_str:
        return True
    return bool(re.match(r'^[a-zA-Z0-9 .:/_\-]+$', filter_str))


def _validate_pcap_iface(iface: str) -> bool:
    """Allow only safe FreeBSD interface names (alphanumeric, up to 16 chars)."""
    return bool(re.match(r'^[a-zA-Z][a-zA-Z0-9]{0,15}$', iface))


@diagnostics_bp.route("/api/packet-capture", methods=["POST"])
@login_required
def api_packet_capture():
    import sys
    data    = request.get_json(silent=True) or {}
    iface   = (data.get("interface") or "em0").strip()
    count   = min(int(data.get("count") or 50), 200)
    filt    = (data.get("filter") or "").strip()

    # Input validation — prevent shell injection via interface name or BPF filter
    if not _validate_pcap_iface(iface):
        return jsonify({"ok": False, "message": "Invalid interface name.", "lines": []}), 400
    if not _validate_pcap_filter(filt):
        return jsonify({
            "ok": False,
            "message": "Invalid BPF filter: only alphanumeric characters, spaces, "
                       "dots, colons, dashes, underscores and slashes are allowed.",
            "lines": [],
        }), 400

    if not sys.platform.startswith("freebsd"):
        return jsonify({"ok": True, "lines": ["Non-FreeBSD host — packet capture not available."]})
    try:
        from app.services.network_service import run_command
        cmd = ["tcpdump", "-nn", "-l", "-c", str(count), "-i", iface]
        if filt:
            cmd += filt.split()
        r = run_command(cmd, check=False, timeout_seconds=15)
        lines = [l for l in (r.stdout or "").splitlines() if l.strip()]
        return jsonify({"ok": True, "lines": lines})
    except Exception as e:
        return jsonify({"ok": False, "message": str(e), "lines": []})


# --------------------------------------------------
# PFINFO
# --------------------------------------------------

@diagnostics_bp.route("/pfinfo")
@login_required
def pfinfo():
    import sys
    pf_output = ""
    on_freebsd = sys.platform.startswith("freebsd")
    if on_freebsd:
        try:
            from app.services.network_service import run_command
            r = run_command(["pfctl", "-s", "info"], check=False)
            pf_output = r.stdout or ""
        except Exception:
            pass
    return render_template("pfinfo.html", pf_output=pf_output, on_freebsd=on_freebsd)


# --------------------------------------------------
# PF TOP
# --------------------------------------------------

@diagnostics_bp.route("/pftop")
@login_required
def pftop():
    import sys
    states = []
    on_freebsd = sys.platform.startswith("freebsd")
    if on_freebsd:
        try:
            from app.services.network_service import run_command
            r = run_command(["pfctl", "-s", "states"], check=False)
            for line in (r.stdout or "").splitlines():
                line = line.strip()
                if line:
                    states.append(line)
        except Exception:
            pass
    return render_template("pftop.html", states=states[:200], on_freebsd=on_freebsd)


# --------------------------------------------------
# PING
# --------------------------------------------------

@diagnostics_bp.route("/ping")
@login_required
def ping_diag():
    return render_template("ping_diag.html")


@diagnostics_bp.route("/api/ping", methods=["POST"])
@login_required
def api_ping():
    import sys, re
    data  = request.get_json(silent=True) or {}
    host  = (data.get("host") or "").strip()
    count = min(int(data.get("count") or 4), 10)
    if not host:
        return jsonify({"ok": False, "message": "Host is required"}), 400
    # Validate: only allow hostnames/IPs (no shell injection)
    if not re.match(r'^[a-zA-Z0-9.\-:]+$', host):
        return jsonify({"ok": False, "message": "Invalid host"}), 400
    try:
        from app.services.network_service import run_command
        if sys.platform.startswith("freebsd"):
            cmd = ["ping", "-c", str(count), "-W", "3000", host]
        elif sys.platform.startswith("win"):
            cmd = ["ping", "-n", str(count), host]
        else:
            cmd = ["ping", "-c", str(count), "-W", "3", host]
        r = run_command(cmd, check=False, timeout_seconds=count * 4 + 5)
        lines = (r.stdout or r.stderr or "no output").splitlines()
        return jsonify({"ok": r.returncode == 0, "lines": lines, "host": host})
    except Exception as e:
        return jsonify({"ok": False, "message": str(e), "lines": []})


# --------------------------------------------------
# REBOOT SYSTEM
# --------------------------------------------------

@diagnostics_bp.route("/reboot")
@login_required
def reboot():
    return render_template("reboot.html")


# --------------------------------------------------
# ROUTES TABLE
# --------------------------------------------------

@diagnostics_bp.route("/routes")
@login_required
def routes_diag():
    import sys
    routes = []
    on_freebsd = sys.platform.startswith("freebsd")
    if on_freebsd:
        try:
            from app.services.network_service import run_command
            r = run_command(["netstat", "-rn"], check=False)
            section = ""
            for line in (r.stdout or "").splitlines():
                if line.startswith("Internet"):
                    section = "IPv4"
                elif line.startswith("Internet6"):
                    section = "IPv6"
                parts = line.split()
                if len(parts) >= 4 and not line.startswith(("Routing", "Internet", "Destination")):
                    routes.append({
                        "proto": section, "destination": parts[0],
                        "gateway": parts[1], "flags": parts[2],
                        "iface": parts[-1],
                    })
        except Exception:
            pass
    return render_template("routes_diag.html", routes=routes, on_freebsd=on_freebsd)


# --------------------------------------------------
# SMART STATUS
# --------------------------------------------------

@diagnostics_bp.route("/smart-status")
@login_required
def smart_status():
    import sys
    from app.services.freebsd_setup import preflight_check
    report = preflight_check()
    return render_template("smart_status.html", report=report,
                           on_freebsd=sys.platform.startswith("freebsd"))


# --------------------------------------------------
# SOCKETS
# --------------------------------------------------

@diagnostics_bp.route("/sockets")
@login_required
def sockets():
    import sys
    connections = []
    on_freebsd = sys.platform.startswith("freebsd")
    if on_freebsd:
        try:
            from app.services.network_service import run_command
            r = run_command(["sockstat", "-46"], check=False)
            for line in (r.stdout or "").splitlines():
                parts = line.split()
                if len(parts) >= 6 and not line.startswith("USER"):
                    connections.append({
                        "user": parts[0], "command": parts[1], "pid": parts[2],
                        "proto": parts[4], "local": parts[5],
                        "remote": parts[6] if len(parts) > 6 else "—",
                    })
        except Exception:
            pass
    return render_template("sockets.html", connections=connections, on_freebsd=on_freebsd)


# --------------------------------------------------
# PF STATES
# --------------------------------------------------

@diagnostics_bp.route("/states")
@login_required
def states():
    import sys
    states_list = []
    state_count = 0
    on_freebsd = sys.platform.startswith("freebsd")
    if on_freebsd:
        try:
            from app.services.network_service import run_command
            r = run_command(["pfctl", "-s", "states"], check=False)
            for line in (r.stdout or "").splitlines():
                line = line.strip()
                if line:
                    parts = line.split()
                    states_list.append({
                        "proto": parts[0] if parts else "",
                        "direction": parts[1] if len(parts) > 1 else "",
                        "detail": " ".join(parts[2:]) if len(parts) > 2 else line,
                    })
            state_count = len(states_list)
        except Exception:
            pass
    return render_template("states.html", states=states_list[:500],
                           state_count=state_count, on_freebsd=on_freebsd)


# --------------------------------------------------
# STATUS SUMMARY
# --------------------------------------------------

@diagnostics_bp.route("/status-summary")
@login_required
def status_summary():
    import sys
    from app.database import get_db
    conn = get_db()
    cur  = conn.cursor()
    counts = {}
    for tbl in ["firewall_rules_wan", "firewall_rules_lan", "firewall_rules_floating",
                "nat_pf", "openvpn_servers", "ipsec_phase1", "users"]:
        try:
            cur.execute(f"SELECT COUNT(*) AS c FROM {tbl} WHERE disabled=0")
            row = cur.fetchone()
            counts[tbl] = (row or {}).get("c", 0)
        except Exception:
            counts[tbl] = 0
    return render_template("status_summary.html", counts=counts,
                           on_freebsd=sys.platform.startswith("freebsd"))


# --------------------------------------------------
# SYSTEM ACTIVITY
# --------------------------------------------------

@diagnostics_bp.route("/system-activity")
@login_required
def system_activity():
    from app.audit_log import tail_events, log_stats
    events = tail_events(limit=100)
    stats  = log_stats()
    return render_template("system_activity.html", events=events, stats=stats)


# --------------------------------------------------
# PF TABLES
# --------------------------------------------------

@diagnostics_bp.route("/tables")
@login_required
def tables():
    import sys
    from app.database import get_db
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT name, type, alias_values, description FROM firewall_aliases ORDER BY name")
    aliases = [dict(r) for r in cur.fetchall()]
    pf_tables = []
    on_freebsd = sys.platform.startswith("freebsd")
    if on_freebsd:
        try:
            from app.services.network_service import run_command
            r = run_command(["pfctl", "-s", "Tables"], check=False)
            for line in (r.stdout or "").splitlines():
                tname = line.strip()
                if tname:
                    r2 = run_command(["pfctl", "-t", tname, "-T", "show"], check=False)
                    entries = [e.strip() for e in (r2.stdout or "").splitlines() if e.strip()]
                    pf_tables.append({"name": tname, "entries": entries})
        except Exception:
            pass
    return render_template("tables.html", aliases=aliases,
                           pf_tables=pf_tables, on_freebsd=on_freebsd)


# --------------------------------------------------
# TEST PORT
# --------------------------------------------------

@diagnostics_bp.route("/test-port")
@login_required
def test_port():
    return render_template("test_port.html")


@diagnostics_bp.route("/api/test-port", methods=["POST"])
@login_required
def api_test_port():
    import socket, re
    data = request.get_json(silent=True) or {}
    host = (data.get("host") or "").strip()
    port = int(data.get("port") or 80)
    if not host or not re.match(r'^[a-zA-Z0-9.\-:]+$', host):
        return jsonify({"ok": False, "message": "Invalid host"}), 400
    if not (1 <= port <= 65535):
        return jsonify({"ok": False, "message": "Invalid port"}), 400
    try:
        sock = socket.create_connection((host, port), timeout=5)
        sock.close()
        return jsonify({"ok": True, "message": f"Port {port} on {host} is open."})
    except OSError as e:
        return jsonify({"ok": False, "message": f"Port {port} on {host} is closed or unreachable: {e}"})


# --------------------------------------------------
# TUNNELS / VPN STATUS
# --------------------------------------------------

@diagnostics_bp.route("/tunnels")
@login_required
def tunnels():
    import sys
    from app.database import get_db
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT id, description, disabled, protocol, local_port, tunnel_network FROM openvpn_servers ORDER BY id")
    ovpn = [dict(r) for r in cur.fetchall()]
    cur.execute("SELECT id, description, disabled, remote_gateway, ike_version, auth_method FROM ipsec_phase1 ORDER BY id")
    ipsec = [dict(r) for r in cur.fetchall()]
    cur.execute("SELECT * FROM l2tp_config LIMIT 1")
    l2tp = dict(cur.fetchone() or {})
    return render_template("tunnels.html", openvpn=ovpn, ipsec=ipsec, l2tp=l2tp,
                           on_freebsd=sys.platform.startswith("freebsd"))
