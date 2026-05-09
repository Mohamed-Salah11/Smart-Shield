import json as _json
from flask import Blueprint, render_template, request, jsonify, session
from app.auth_utils import login_required
from app.audit_log import tail_events, tail_events_since, log_stats

status_bp = Blueprint("status", __name__, url_prefix="/status")


# --------------------------------------------------
# STATUS MAIN PAGE
# --------------------------------------------------

@status_bp.route("/")
@login_required
def status_home():
    return render_template("status.html")


# --------------------------------------------------
# CARP FAILOVER
# --------------------------------------------------

@status_bp.route("/carp-failover")
@login_required
def carp_failover():
    return render_template("carp_failover.html")


# --------------------------------------------------
# DHCP LEASES (IPv4)
# --------------------------------------------------

@status_bp.route("/dhcp-leases")
@login_required
def dhcp_leases():
    from app.database import get_db
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT * FROM dhcp_pools ORDER BY interface_type")
    pools = [dict(r) for r in cur.fetchall()]
    cur.execute("SELECT * FROM static_leases ORDER BY interface_type, ip_address")
    static = [dict(r) for r in cur.fetchall()]
    return render_template("dhcp_leases.html", pools=pools, static_leases=static)


# --------------------------------------------------
# DHCPv6 LEASES (IPv6)
# --------------------------------------------------

@status_bp.route("/dhcpv6-leases")
@login_required
def dhcpv6_leases():
    return render_template("dhcpv6_leases.html")


# --------------------------------------------------
# FILTER RELOAD STATUS
# --------------------------------------------------

@status_bp.route("/filter-reload")
@login_required
def filter_reload():
    import sys, os
    from app.database import get_db
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT * FROM firewall_rules_wan WHERE disabled=0 ORDER BY rule_order LIMIT 1")
    has_wan = cur.fetchone() is not None
    cur.execute("SELECT * FROM firewall_rules_lan WHERE disabled=0 ORDER BY rule_order LIMIT 1")
    has_lan = cur.fetchone() is not None
    cur.execute("SELECT COUNT(*) AS c FROM firewall_rules_wan WHERE disabled=0")
    wan_count = (cur.fetchone() or {}).get("c", 0)
    cur.execute("SELECT COUNT(*) AS c FROM firewall_rules_lan WHERE disabled=0")
    lan_count = (cur.fetchone() or {}).get("c", 0)
    cur.execute("SELECT COUNT(*) AS c FROM firewall_rules_floating WHERE disabled=0")
    float_count = (cur.fetchone() or {}).get("c", 0)
    pf_enabled = sys.platform.startswith("freebsd") and os.path.exists("/dev/pf")
    return render_template("filter_reload.html",
        wan_count=wan_count, lan_count=lan_count,
        float_count=float_count, pf_enabled=pf_enabled)


# --------------------------------------------------
# FILTER RELOAD — APPLY (POST)
# --------------------------------------------------

@status_bp.route("/filter-reload/apply", methods=["POST"])
@login_required
def filter_reload_apply():
    from app.database import get_db
    from app.services.pf_generator import reload_pf_rules
    from app.audit_log import log_event
    conn = get_db()
    result = reload_pf_rules(conn)
    log_event(category="system", action="pf_reload",
              username=request.values.get("username"),
              remote_addr=request.remote_addr,
              details=result)
    return jsonify(result)


# --------------------------------------------------
# GATEWAY STATUS
# --------------------------------------------------

@status_bp.route("/gateways")
@login_required
def gateways():
    import sys
    from app.database import get_db
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT * FROM wan_config LIMIT 1")
    wan = dict(cur.fetchone() or {})
    cur.execute("SELECT * FROM lan_config LIMIT 1")
    lan = dict(cur.fetchone() or {})

    # Live route table on FreeBSD
    routes = []
    if sys.platform.startswith("freebsd"):
        try:
            from app.services.network_service import run_command
            r = run_command(["netstat", "-rn", "-f", "inet"], check=False)
            for line in (r.stdout or "").splitlines():
                parts = line.split()
                if len(parts) >= 4 and parts[0] not in ("Destination", "Internet:"):
                    routes.append({
                        "destination": parts[0], "gateway": parts[1],
                        "flags": parts[2], "iface": parts[-1],
                    })
        except Exception:
            pass

    return render_template("gateways.html", wan=wan, lan=lan, routes=routes,
                           on_freebsd=sys.platform.startswith("freebsd"))


# --------------------------------------------------
# MONITORING (GRAPHS)
# --------------------------------------------------

@status_bp.route("/monitoring")
@login_required
def monitoring():
    import sys
    from app.database import get_db
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT assigned_port, description, ipv4_address FROM lan_config LIMIT 1")
    lan = dict(cur.fetchone() or {})
    cur.execute("SELECT assigned_port, description, ipv4_address FROM wan_config LIMIT 1")
    wan = dict(cur.fetchone() or {})
    interfaces = [lan, wan]
    return render_template("monitoring.html", interfaces=interfaces,
                           on_freebsd=sys.platform.startswith("freebsd"))


# --------------------------------------------------
# MONITORING — LIVE INTERFACE STATS API
# --------------------------------------------------

@status_bp.route("/api/interface-stats")
@login_required
def api_interface_stats():
    import sys, re
    stats = []
    if sys.platform.startswith("freebsd"):
        try:
            from app.services.network_service import run_command
            r = run_command(["netstat", "-ibn"], check=False)
            for line in (r.stdout or "").splitlines():
                parts = line.split()
                # Filter to link-layer rows only (<Link#N>) to avoid duplicate
                # entries per interface (netstat outputs one row per address family).
                # FreeBSD netstat -ibn columns:
                #   Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll
                #   [0]  [1] [2]     [3]     [4]   [5]   [6]    [7]   [8]   [9]   [10]
                if len(parts) >= 10 and re.match(r"<Link#\d+>", parts[2], re.IGNORECASE):
                    try:
                        stats.append({
                            "name":     parts[0],
                            "mtu":      parts[1],
                            "rx_pkts":  int(parts[4]),
                            "rx_errs":  int(parts[5]),
                            "rx_bytes": int(parts[6]),
                            "tx_pkts":  int(parts[7]),
                            "tx_errs":  int(parts[8]),
                            "tx_bytes": int(parts[9]),
                        })
                    except (ValueError, IndexError):
                        pass
        except Exception:
            pass
    return jsonify({"ok": True, "stats": stats, "on_freebsd": sys.platform.startswith("freebsd")})


# --------------------------------------------------
# SYSTEM QUEUES
# --------------------------------------------------

@status_bp.route("/queues")
@login_required
def queues():
    from app.database import get_db
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT * FROM traffic_shaper_configs ORDER BY interface_type, name")
    shapers = [dict(r) for r in cur.fetchall()]
    return render_template("queues.html", shapers=shapers)


# --------------------------------------------------
# SYSTEM LOGS
# --------------------------------------------------

@status_bp.route("/system-logs")
@login_required
def system_logs():
    active_tab = (request.args.get("tab") or "system").lower()
    if active_tab not in {"system", "sessions", "security", "browsing"}:
        active_tab = "system"

    all_events = tail_events(limit=300)
    session_events = [e for e in all_events if e.get("category") == "session"]
    system_events = [e for e in all_events if e.get("category") == "system"]
    browsing_events = [e for e in all_events if e.get("category") == "browsing"]
    security_events = [
        e for e in all_events
        if e.get("category") == "security"
        or (e.get("category") == "session" and e.get("action") == "login_failed")
    ]

    return render_template(
        "system_logs.html",
        active_tab=active_tab,
        system_events=system_events[:150],
        session_events=session_events[:150],
        browsing_events=browsing_events[:150],
        security_events=security_events[:150],
    )


# --------------------------------------------------
# TRAFFIC GRAPH (REALTIME)
# --------------------------------------------------

@status_bp.route("/traffic-graph")
@login_required
def traffic_graph():
    return render_template("traffic_graph.html")


# ══════════════════════════════════════════════════
# LIVE LOG API
# ══════════════════════════════════════════════════

@status_bp.route("/api/logs")
@login_required
def api_logs():
    """
    Polling endpoint for the live log monitor.

    Query params
    ------------
    since      ISO-8601 timestamp — return only events after this time.
               Omit or pass "" to get the most recent `limit` events.
    limit      Max events to return (default 100, max 500).
    categories Comma-separated list e.g. "session,system". Omit for all.
    search     Free-text filter applied against action, username, IP, details.
    """
    since      = request.args.get("since", "").strip()
    limit      = min(int(request.args.get("limit", 100) or 100), 500)
    cats_raw   = request.args.get("categories", "").strip()
    search     = request.args.get("search", "").lower().strip()

    categories = [c.strip() for c in cats_raw.split(",") if c.strip()] if cats_raw else None

    events = tail_events_since(
        after_ts=since,
        limit=limit * 3,          # over-fetch so search filter has room
        categories=categories,
    )

    if search:
        def _matches(e):
            haystack = " ".join([
                e.get("action", ""),
                e.get("username", ""),
                e.get("remote_addr", ""),
                e.get("category", ""),
                _json.dumps(e.get("details") or {}),
            ]).lower()
            return search in haystack
        events = [e for e in events if _matches(e)]

    events = events[:limit]
    latest_ts = events[0]["timestamp"] if events else since

    return jsonify({
        "ok":        True,
        "events":    events,
        "count":     len(events),
        "latest_ts": latest_ts,
    })


@status_bp.route("/api/logs/stats")
@login_required
def api_logs_stats():
    """Per-category event counts for the stats bar."""
    return jsonify(log_stats())


# ══════════════════════════════════════════════════
# SERVICE HEALTH API
# ══════════════════════════════════════════════════

@status_bp.route("/api/health")
@login_required
def api_health():
    """
    Return a health snapshot for all Smart Shield services.

    Response shape::

        {
          "ok": true,
          "services": {
            "pf":      {"running": bool, "state": str, "message": str},
            "dhcpd":   {...},
            "unbound": {...},
            "openvpn": {...},
            "ipsec":   {...},
            "ids":     {...}
          },
          "interfaces": [{"name": str, "port": str, "ip": str, "state": str}]
        }

    Safe to call on non-FreeBSD — returns ``state: "dry-run"`` for all
    services that require the OS.
    """
    from app.database import get_db
    from app.services.service_manager import get_all_service_health
    conn  = get_db()
    data  = get_all_service_health(conn)
    ifaces = data.pop("interfaces", [])
    return jsonify({"ok": True, "services": data, "interfaces": ifaces})


@status_bp.route("/api/health/<service_name>")
@login_required
def api_health_service(service_name: str):
    """Return health for a single named service (pf, dhcpd, unbound, openvpn, ipsec, ids)."""
    from app.database import get_db
    from app.services.service_manager import get_all_service_health
    conn = get_db()
    all_health = get_all_service_health(conn)
    svc = all_health.get(service_name)
    if svc is None:
        return jsonify({"ok": False, "error": f"Unknown service: {service_name}"}), 404
    return jsonify({"ok": True, "service": service_name, "health": svc})


# ══════════════════════════════════════════════════
# PF CONFIG PREVIEW
# ══════════════════════════════════════════════════

@status_bp.route("/api/pf/preview")
@login_required
def api_pf_preview():
    """Return the pf.conf that would be applied (no filesystem writes)."""
    from app.database import get_db
    from app.services.pf_generator import generate_pf_conf, validate_pf_conf
    conn = get_db()
    conf = generate_pf_conf(conn)
    ok, err = validate_pf_conf(conf)
    return jsonify({"ok": ok, "conf": conf, "validation_message": err})


# ══════════════════════════════════════════════════
# PF ROLLBACK
# ══════════════════════════════════════════════════

@status_bp.route("/api/pf/rollback", methods=["POST"])
@login_required
def api_pf_rollback():
    """Restore the last known-good pf.conf."""
    from app.database import get_db
    from app.services.pf_generator import rollback_pf
    from app.audit_log import log_event
    result = rollback_pf()
    log_event(
        category="system", action="pf_rollback",
        username=request.values.get("username"),
        remote_addr=request.remote_addr,
        details=result,
    )
    return jsonify(result)


# ══════════════════════════════════════════════════
# DHCP apply + status
# ══════════════════════════════════════════════════

@status_bp.route("/api/dhcp/apply", methods=["POST"])
@login_required
def api_dhcp_apply():
    """Validate, write, and restart isc-dhcpd."""
    from app.database import get_db
    from app.services.dhcp_writer import apply_dhcpd
    from app.audit_log import log_event
    conn   = get_db()
    result = apply_dhcpd(conn)
    log_event(
        category="system", action="dhcp_apply",
        username=request.values.get("username"),
        remote_addr=request.remote_addr,
        details={"ok": result["ok"], "errors": result.get("errors", [])},
    )
    return jsonify(result)


@status_bp.route("/api/dhcp/preview")
@login_required
def api_dhcp_preview():
    """Return the dhcpd.conf that would be applied."""
    from app.database import get_db
    from app.services.dhcp_writer import generate_dhcpd_conf, validate_dhcp_config
    conn   = get_db()
    conf   = generate_dhcpd_conf(conn)
    errors = validate_dhcp_config(conn)
    return jsonify({"ok": not errors, "conf": conf, "errors": errors})


@status_bp.route("/api/dhcp/leases")
@login_required
def api_dhcp_leases():
    """Return live DHCP leases (parsed from lease file on FreeBSD)."""
    from app.services.dhcp_writer import get_live_leases
    from app.database import get_db
    leases = get_live_leases()
    # Fall back to static leases from DB when live file is not available
    if not leases:
        conn = get_db()
        cur  = conn.cursor()
        cur.execute("SELECT * FROM static_leases ORDER BY interface_type, ip_address")
        leases = [dict(r) for r in cur.fetchall()]
    return jsonify({"ok": True, "leases": leases, "count": len(leases)})


# ══════════════════════════════════════════════════
# DNS apply + test
# ══════════════════════════════════════════════════

@status_bp.route("/api/dns/apply", methods=["POST"])
@login_required
def api_dns_apply():
    """Validate, write, and reload Unbound."""
    from app.database import get_db
    from app.services.dns_writer import apply_unbound
    from app.audit_log import log_event
    conn   = get_db()
    result = apply_unbound(conn)
    log_event(
        category="system", action="dns_apply",
        username=request.values.get("username"),
        remote_addr=request.remote_addr,
        details={"ok": result["ok"]},
    )
    return jsonify(result)


@status_bp.route("/api/dns/preview")
@login_required
def api_dns_preview():
    """Return the unbound.conf that would be applied."""
    from app.database import get_db
    from app.services.dns_writer import generate_unbound_conf, validate_unbound_conf
    conn = get_db()
    conf = generate_unbound_conf(conn)
    ok, err = validate_unbound_conf(conf)
    return jsonify({"ok": ok, "conf": conf, "validation_message": err})


@status_bp.route("/api/dns/test")
@login_required
def api_dns_test():
    """
    Resolve a hostname via the local DNS resolver.
    Query params: hostname (required), server (optional, default 127.0.0.1).
    """
    from app.services.dns_writer import test_dns_resolution
    hostname = request.args.get("hostname", "").strip()
    server   = request.args.get("server", "127.0.0.1").strip()
    if not hostname:
        return jsonify({"ok": False, "error": "hostname is required"}), 400
    result = test_dns_resolution(hostname, server)
    return jsonify(result)


# ══════════════════════════════════════════════════
# APP LOG API
# ══════════════════════════════════════════════════

@status_bp.route("/api/app-logs")
@login_required
def api_app_logs():
    """
    Paginated operational app log viewer.

    Query params
    ------------
    limit     : Max entries (default 100, max 500).
    level     : Filter by level: INFO / WARNING / ERROR.
    component : Filter by component name prefix.
    search    : Free-text search across message + details.
    """
    from app.app_log import tail_app_events, app_log_stats
    limit     = min(int(request.args.get("limit", 100) or 100), 500)
    level     = request.args.get("level", "").strip()
    component = request.args.get("component", "").strip()
    search    = request.args.get("search", "").strip()

    events = tail_app_events(limit=limit, level=level, component=component, search=search)
    return jsonify({"ok": True, "events": events, "count": len(events)})


@status_bp.route("/api/app-logs/stats")
@login_required
def api_app_logs_stats():
    from app.app_log import app_log_stats
    return jsonify(app_log_stats())


# ══════════════════════════════════════════════════
# CONFIG HISTORY API
# ══════════════════════════════════════════════════

@status_bp.route("/api/config-history")
@login_required
def api_config_history_services():
    """List all services that have saved config versions."""
    from app.database import get_db
    from app.services.config_history import list_all_services_with_history
    conn = get_db()
    return jsonify({"ok": True, "services": list_all_services_with_history(conn)})


@status_bp.route("/api/config-history/<service>")
@login_required
def api_config_history_list(service: str):
    """
    List saved versions for a service (content excluded, newest first).

    Query params: limit (default 20, max 100).
    """
    from app.database import get_db
    from app.services.config_history import list_config_versions
    limit = min(int(request.args.get("limit", 20) or 20), 100)
    conn  = get_db()
    versions = list_config_versions(conn, service, limit=limit)
    return jsonify({"ok": True, "service": service, "versions": versions, "count": len(versions)})


@status_bp.route("/api/config-history/<int:version_id>")
@login_required
def api_config_history_get(version_id: int):
    """Return a single config version including full content."""
    from app.database import get_db
    from app.services.config_history import get_config_version
    conn = get_db()
    ver  = get_config_version(conn, version_id)
    if not ver:
        return jsonify({"ok": False, "error": "Version not found"}), 404
    return jsonify({"ok": True, "version": ver})


@status_bp.route("/api/config-history/<int:version_id>/rollback", methods=["POST"])
@login_required
def api_config_history_rollback(version_id: int):
    """
    Roll back a service config to a previously saved version.

    Writes the stored config to disk and reloads the service.
    Records the rollback in the audit log.
    """
    from app.database import get_db
    from app.services.config_history import rollback_to_config_version
    from app.audit_log import log_event
    conn     = get_db()
    username = session.get("username", "anonymous")
    result   = rollback_to_config_version(conn, version_id, rolled_back_by=username)
    log_event(
        category="system", action="config_rollback",
        username=username, remote_addr=request.remote_addr,
        details={"version_id": version_id, "ok": result["ok"]},
    )
    status = 200 if result["ok"] else 500
    return jsonify(result), status


@status_bp.route("/api/config-history/<service>/prune", methods=["POST"])
@login_required
def api_config_history_prune(service: str):
    """
    Delete old config versions beyond the most-recent ``keep``.

    JSON body: {"keep": 20}
    """
    from app.database import get_db
    from app.services.config_history import prune_config_versions
    data    = request.get_json(silent=True) or {}
    keep    = int(data.get("keep", 20))
    conn    = get_db()
    deleted = prune_config_versions(conn, service, keep=keep)
    return jsonify({"ok": True, "service": service, "deleted": deleted})


# ══════════════════════════════════════════════════
# HEALTH MONITOR API
# ══════════════════════════════════════════════════

@status_bp.route("/api/health/full")
@login_required
def api_health_full():
    """
    Run a comprehensive health check and return the result.

    This is heavier than ``/api/health`` — it also checks disk,
    memory/CPU, config drift, and all Phase 4 services.
    """
    from app.database import get_db
    from app.services.health_monitor import full_health_check, store_health_snapshot
    conn     = get_db()
    snapshot = full_health_check(conn)
    store_health_snapshot(conn, snapshot)
    return jsonify({"ok": True, **snapshot})


@status_bp.route("/api/health/history")
@login_required
def api_health_history():
    """
    Return stored health snapshots (no service restart check — read only).

    Query params: limit (default 24, max 168).
    """
    from app.database import get_db
    from app.services.health_monitor import get_health_history
    limit = min(int(request.args.get("limit", 24) or 24), 168)
    conn  = get_db()
    return jsonify({"ok": True, "history": get_health_history(conn, limit=limit)})


@status_bp.route("/api/health/disk")
@login_required
def api_health_disk():
    """Return disk usage for key filesystem paths."""
    from app.services.health_monitor import check_disk_usage
    return jsonify({"ok": True, **check_disk_usage()})


@status_bp.route("/api/health/system")
@login_required
def api_health_system():
    """Return memory and CPU load averages."""
    from app.services.health_monitor import check_memory_cpu
    return jsonify({"ok": True, **check_memory_cpu()})


# ══════════════════════════════════════════════════
# MRTG TRAFFIC HISTORY GRAPHS
# ══════════════════════════════════════════════════

@status_bp.route("/mrtg")
@login_required
def mrtg_graphs():
    """MRTG historical bandwidth graphs page."""
    import sys
    from app.database import get_db
    conn = get_db()
    wan_row = conn.execute("SELECT assigned_port, description FROM wan_config LIMIT 1").fetchone()
    lan_row = conn.execute("SELECT assigned_port, description FROM lan_config LIMIT 1").fetchone()

    interfaces = []
    seen = set()
    for row, label in [(wan_row, "WAN"), (lan_row, "LAN")]:
        if not row:
            continue
        name = (row["assigned_port"] or "").strip()
        if name and name not in seen:
            seen.add(name)
            interfaces.append({
                "name": name,
                "label": label,
                "description": (row["description"] or "").strip(),
            })

    iface_names = [i["name"] for i in interfaces]
    import time
    return render_template(
        "mrtg_graphs.html",
        interfaces=interfaces,
        iface_names=iface_names,
        on_freebsd=sys.platform.startswith("freebsd"),
        now_ts=int(time.time()),
    )


@status_bp.route("/mrtg/apply", methods=["POST"])
@login_required
def mrtg_apply():
    """Regenerate mrtg.cfg and do a first run to initialise log files."""
    from app.database import get_db
    from app.services.mrtg_writer import apply_mrtg
    from app.audit_log import log_event
    conn   = get_db()
    result = apply_mrtg(conn)
    log_event(
        category="system", action="mrtg_apply",
        username=request.values.get("username"),
        remote_addr=request.remote_addr,
        details={"ok": result["ok"], "message": result.get("message", "")},
    )
    from flask import flash, redirect, url_for
    if result.get("ok"):
        flash("MRTG configuration regenerated successfully.", "success")
    else:
        flash(f"MRTG error: {result.get('message', 'Unknown error')}", "danger")
    return redirect(url_for("status.mrtg_graphs"))


@status_bp.route("/mrtg/image/<path:filename>")
@login_required
def mrtg_image(filename):
    """Serve MRTG-generated PNG graph files from the MRTG work directory."""
    from flask import send_from_directory, abort, make_response
    if ".." in filename or filename.startswith("/"):
        abort(400)
    mrtg_dir = "/var/db/smart-shield/mrtg"
    resp = make_response(send_from_directory(mrtg_dir, filename))
    resp.cache_control.no_store = True
    resp.cache_control.max_age = 0
    return resp


@status_bp.route("/api/mrtg/reinitialize", methods=["POST"])
@login_required
def mrtg_reinitialize():
    """Re-run apply_mrtg() to regenerate MRTG config and prime graph files."""
    try:
        from app.database import get_db
        from app.services.mrtg_writer import apply_mrtg
        conn   = get_db()
        result = apply_mrtg(conn)
        return jsonify({"ok": result.get("ok", False), "message": result.get("message", "")})
    except Exception as exc:
        return jsonify({"ok": False, "message": str(exc)})
