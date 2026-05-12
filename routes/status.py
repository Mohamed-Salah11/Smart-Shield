import json as _json
from flask import Blueprint, render_template, request, jsonify, session
from app.auth_utils import login_required
from app.api_auth import api_permission_required
from app.audit_log import tail_events, tail_events_since, log_stats

status_bp = Blueprint("status", __name__, url_prefix="/status")

# Interfaces to exclude from network stats (loopback, PF log, IPsec enc).
# VPN tunnel interfaces (tun*, gif*, gre*) are kept — they carry real user traffic.
_VIRTUAL_IFACE_PREFIXES = frozenset(("lo", "pflog", "enc"))


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
                    if parts[0].rstrip("0123456789").lower() in _VIRTUAL_IFACE_PREFIXES:
                        continue
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
@api_permission_required("api.network.edit")
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


@status_bp.route("/api/health/services")
@login_required
def api_health_services():
    """
    Return pgrep-based running/stopped status for all known daemons.

    Response::

        {
          "ok": true,
          "services": {
            "dhcpd":     {"running": true},
            "unbound":   {"running": true},
            "openvpn":   {"running": false},
            "charon":    {"running": false},
            "mpd5":      {"running": false},
            "suricata":  {"running": true},
            "ddclient":  {"running": false},
            "miniupnpd": {"running": false},
            "igmpproxy": {"running": false},
            "kea-dhcp6": {"running": false},
            "rtadvd":    {"running": false},
            "bsnmpd":    {"running": false},
            "ntpd":      {"running": true},
            "nginx":     {"running": true}
          }
        }
    """
    from app.services.health_monitor import check_daemon_processes
    return jsonify({"ok": True, "services": check_daemon_processes()})


@status_bp.route("/api/health/metrics")
@login_required
def api_health_metrics():
    """
    Return disk, memory and CPU percentage metrics.

    Response::

        {"ok": true, "disk_pct": 45, "mem_pct": 67, "cpu_pct": 12, "warnings": [...]}
    """
    from app.services.health_monitor import get_system_metrics
    return jsonify({"ok": True, **get_system_metrics()})


@status_bp.route("/api/health/interfaces")
@login_required
def api_health_interfaces():
    """
    Return link up/down state for each network interface.

    Response::

        {"ok": true, "interfaces": [{"iface": "em0", "link": "active"}, ...]}
    """
    from app.services.health_monitor import get_interface_link_status
    return jsonify({"ok": True, "interfaces": get_interface_link_status()})


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


# --------------------------------------------------
# FEATURE REGISTRY  (Phase 0)
# --------------------------------------------------

@status_bp.route("/api/features")
@login_required
def api_features():
    """
    Return the complete feature capability registry.

    Response shape:
    {
      "features": [{"key", "name", "mode", "color", "category", ...}, ...],
      "by_category": {"core": [...], "vpn": [...], ...},
      "summary": {"live": N, "dry-run": N, ..., "total": N},
      "runtime_mode": "live" | "dry-run" | "degraded" | "development"
    }
    """
    from app.services.feature_registry import (
        get_all_features, get_features_by_category, feature_summary,
    )
    from app.services.runtime_mode import current_mode
    return jsonify({
        "features":     get_all_features(),
        "by_category":  get_features_by_category(),
        "summary":      feature_summary(),
        "runtime_mode": current_mode(),
    })


@status_bp.route("/api/features/<feature_key>")
@login_required
def api_feature_detail(feature_key: str):
    """Return status for a single feature plus its recent apply history."""
    from app.services.feature_registry import get_feature_status
    from app.services.apply_state import get_feature_state, get_recent_jobs
    from app.database import get_db

    feat = get_feature_status(feature_key)
    if feat is None:
        return jsonify({"ok": False, "error": f"Unknown feature: {feature_key}"}), 404

    conn         = get_db()
    apply_state  = get_feature_state(conn, feature_key)
    recent_jobs  = get_recent_jobs(conn, feature_key=feature_key, limit=10)

    return jsonify({
        "feature":    feat,
        "state":      apply_state,
        "recent_jobs": recent_jobs,
    })


@status_bp.route("/api/apply-jobs")
@login_required
def api_apply_jobs():
    """Return the most recent apply job records across all features."""
    from app.services.apply_state import get_recent_jobs
    from app.database import get_db

    limit = min(int(request.args.get("limit", 50)), 200)
    feature_key = request.args.get("feature") or None
    conn  = get_db()
    jobs  = get_recent_jobs(conn, feature_key=feature_key, limit=limit)
    return jsonify({"jobs": jobs, "count": len(jobs)})


@status_bp.route("/api/schedules")
@login_required
def api_schedules():
    """Return current active/inactive state for all firewall schedules."""
    from app.services.schedule_service import get_all_schedule_states
    from app.database import get_db
    conn   = get_db()
    states = get_all_schedule_states(conn)
    return jsonify({"schedules": states})


@status_bp.route("/api/preflight")
@login_required
def api_preflight():
    """
    Return the full FreeBSD preflight report including kernel capabilities
    and syntax validator results.
    """
    from app.services.freebsd_setup import preflight_check
    from app.services.runtime_mode import production_ready, current_mode
    report          = preflight_check()
    prod_ok, issues = production_ready()
    report["production_ready"] = prod_ok
    report["production_issues"] = issues
    report["runtime_mode"] = current_mode()
    return jsonify(report)


# --------------------------------------------------
# PRODUCTION GATE  (Phase 42)
# --------------------------------------------------

@status_bp.route("/api/production-gate")
@login_required
def api_production_gate():
    """
    Comprehensive production-readiness checklist.

    Returns a list of gate items, each with:
      id, label, ok (bool), severity ('critical'|'warning'|'info'), detail
    And a top-level ok=True only when ALL critical gates pass.
    """
    import os as _os
    import sys as _sys
    from app.services.runtime_mode import current_mode, startup_warnings
    from app.services.freebsd_setup import preflight_check
    from app.database import get_db
    from app.migrations import CURRENT_SCHEMA_VERSION

    mode    = current_mode()
    report  = preflight_check()
    warns   = startup_warnings()
    conn    = get_db()
    gates   = []

    def _gate(gid, label, ok, severity="critical", detail=""):
        gates.append({"id": gid, "label": label, "ok": bool(ok),
                      "severity": severity, "detail": str(detail)})

    # ── Platform ──────────────────────────────────────────────────────────────
    _gate("platform_freebsd", "Running on FreeBSD",
          _sys.platform.startswith("freebsd"), "critical",
          f"Current platform: {_sys.platform}")

    # ── Mode ──────────────────────────────────────────────────────────────────
    _gate("mode_live", "Runtime mode is live",
          mode == "live", "critical", f"Current mode: {mode}")

    # ── Required tools ────────────────────────────────────────────────────────
    missing_req = report.get("missing_required", [])
    _gate("tools_required", "All required daemons installed",
          len(missing_req) == 0, "critical",
          f"Missing: {', '.join(missing_req)}" if missing_req else "All present")

    missing_opt = report.get("missing_optional", [])
    _gate("tools_optional", "All optional daemons present",
          len(missing_opt) == 0, "warning",
          f"Missing optional: {', '.join(missing_opt)}" if missing_opt else "All present")

    # ── Directories ───────────────────────────────────────────────────────────
    dir_ok = report.get("dirs_ok", True)
    missing_dirs = report.get("missing_dirs", [])
    _gate("dirs", "Required directories exist",
          dir_ok, "critical",
          f"Missing: {', '.join(missing_dirs)}" if missing_dirs else "All present")

    # ── Kernel capabilities ───────────────────────────────────────────────────
    kernel_caps = report.get("kernel_caps", [])
    if isinstance(kernel_caps, dict):
        kernel_caps = [{"cap": k, "ok": v} for k, v in kernel_caps.items()]
    for entry in kernel_caps:
        cap    = entry.get("cap", "unknown")
        cap_ok = bool(entry.get("ok", True))
        _gate(f"kernel_{cap}", f"Kernel capability: {cap}",
              cap_ok, "warning", "Check sysctl / kernel module" if not cap_ok else "OK")

    # ── Syntax validators ────────────────────────────────────────────────────
    validators = report.get("validators", [])
    if isinstance(validators, dict):
        validators = [{"name": k, **v} for k, v in validators.items()]
    for v in validators:
        tool_name = v.get("name", "unknown")
        v_ok      = bool(v.get("ok", True))
        _gate(f"validator_{tool_name}", f"Config syntax: {tool_name}",
              v_ok, "critical", v.get("warning", "") if not v_ok else "OK")

    # ── Environment / secrets ────────────────────────────────────────────────
    _gate("secret_key_set", "SECRET_KEY is set",
          bool(_os.getenv("SECRET_KEY")), "critical")
    secret_key = _os.getenv("SECRET_KEY", "")
    _weak = {"change-me", "replace-this", "changeme", "secret", "dev", "test",
             "flask-secret", "insecure", "please-change"}
    weak_key = any(m in secret_key.lower() for m in _weak) or len(secret_key) < 24
    _gate("secret_key_strong", "SECRET_KEY is strong (≥24 chars, not default)",
          not weak_key, "critical",
          "Generate: python3 -c \"import secrets; print(secrets.token_hex(32))\"" if weak_key else "OK")

    _gate("master_key", "SMARTSHIELD_MASTER_KEY is set",
          bool(_os.getenv("SMARTSHIELD_MASTER_KEY")), "warning",
          "Auto-generated key will not survive reboots")

    _gate("debug_off", "FLASK_DEBUG is not 1 in production",
          _os.getenv("FLASK_DEBUG", "0") != "1", "critical",
          "Set FLASK_DEBUG=0 in .env")

    _gate("network_apply_enabled", "SMARTSHIELD_ENABLE_NETWORK_APPLY=1",
          _os.getenv("SMARTSHIELD_ENABLE_NETWORK_APPLY", "0") == "1", "critical",
          "Set SMARTSHIELD_ENABLE_NETWORK_APPLY=1 to enable live config application")

    # ── Database schema ───────────────────────────────────────────────────────
    try:
        db_ver = conn.execute(
            "SELECT MAX(version) FROM schema_version"
        ).fetchone()[0] or 0
        schema_ok = db_ver >= CURRENT_SCHEMA_VERSION
        _gate("schema_version", f"DB schema is current (v{CURRENT_SCHEMA_VERSION})",
              schema_ok, "critical",
              f"DB at v{db_ver}, expected v{CURRENT_SCHEMA_VERSION}" if not schema_ok else f"v{db_ver}")
    except Exception as exc:
        _gate("schema_version", "DB schema check", False, "critical", str(exc))

    # ── Startup warnings ─────────────────────────────────────────────────────
    for w in warns:
        if w["level"] == "critical":
            _gate(f"warn_{w['feature']}", f"Startup check: {w['feature']}",
                  False, "critical", w["message"])

    critical_failed = [g for g in gates if g["severity"] == "critical" and not g["ok"]]
    return jsonify({
        "ok":             len(critical_failed) == 0,
        "mode":           mode,
        "gates":          gates,
        "critical_failed": len(critical_failed),
        "total":          len(gates),
    })


@status_bp.route("/api/mrtg/status")
@login_required
def api_mrtg_status():
    """Return MRTG daemon status — binary presence, config mtime, graph availability."""
    from app.services.mrtg_writer import get_mrtg_status
    result = get_mrtg_status()
    return jsonify({"ok": True, **result})


@status_bp.route("/api/feature-states")
@login_required
def api_feature_states():
    """
    Return applied/pending state for all features.

    Response::

        {
          "states": {
            "<feature_key>": {
              "status": "applied" | "pending" | "never_applied" | "saved" | ...,
              "last_applied": "<ISO timestamp or null>",
              "last_saved":   "<ISO timestamp or null>",
              "color":        "<badge colour>",
              "label":        "<human-readable label>",
              "message":      "<detail string>"
            },
            ...
          }
        }
    """
    from app.database import get_db
    from app.services.apply_state import get_all_feature_states
    conn   = get_db()
    raw    = get_all_feature_states(conn)
    states = {}
    for key, d in raw.items():
        states[key] = {
            "status":       d.get("state", "never_applied"),
            "last_applied": d.get("updated_at") if d.get("state") == "applied" else None,
            "last_saved":   d.get("updated_at") if d.get("state") == "saved"   else None,
            "color":        d.get("color", "gray"),
            "label":        d.get("label", d.get("state", "")),
            "message":      d.get("message", ""),
        }
    return jsonify({"ok": True, "states": states})


@status_bp.route("/api/pending-changes")
@login_required
def api_pending_changes():
    """Return features that have been saved but not yet applied."""
    from app.database import get_db
    from app.services.apply_state import get_all_feature_states
    conn   = get_db()
    states = get_all_feature_states(conn)
    pending = {k: v for k, v in states.items() if v.get("state") == "saved"}
    return jsonify({"ok": True, "pending_count": len(pending), "pending": pending})


@status_bp.route("/api/certificates/expiry")
@login_required
def api_certificates_expiry():
    """
    Return a summary of certificate expiry across all managed certs.

    Response:
      {
        "ok": bool,
        "certs": [{"id", "name", "days_remaining", "status", ...}, ...],
        "expired": N,
        "expiring_soon": N,
        "total": N
      }
    """
    from app.database import get_db
    from app.services.cert_manager import get_expiring_certs
    conn   = get_db()
    result = get_expiring_certs(conn)
    return jsonify({"ok": True, **result})
