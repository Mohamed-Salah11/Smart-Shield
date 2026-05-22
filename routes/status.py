import json as _json
from flask import Blueprint, render_template, request, jsonify, session, abort, current_app
from app.auth_utils import login_required, superuser_required
from app.api_auth import api_permission_required
from app.audit_log import tail_events, tail_events_since, log_stats, events_timeseries

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
    if not current_app.config.get("ENABLE_UNFINISHED_PAGES"):
        abort(404)
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
    row = cur.fetchone()
    wan_count = row["c"] if row else 0
    cur.execute("SELECT COUNT(*) AS c FROM firewall_rules_lan WHERE disabled=0")
    row = cur.fetchone()
    lan_count = row["c"] if row else 0
    cur.execute("SELECT COUNT(*) AS c FROM firewall_rules_floating WHERE disabled=0")
    row = cur.fetchone()
    float_count = row["c"] if row else 0
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
                # FreeBSD 12+ added Idrop column between Ierrs and Ibytes:
                #   Old: Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll  (11 cols)
                #   New: Name Mtu Network Address Ipkts Ierrs Idrop  Ibytes Opkts Oerrs Obytes Coll  (12 cols)
                if len(parts) >= 10 and re.match(r"<Link#\d+>", parts[2], re.IGNORECASE):
                    if parts[0].rstrip("0123456789").lower() in _VIRTUAL_IFACE_PREFIXES:
                        continue
                    try:
                        # FreeBSD 12+: Idrop shifts Ibytes/Opkts/Oerrs/Obytes each by 1
                        off = 1 if len(parts) >= 12 else 0
                        stats.append({
                            "name":     parts[0],
                            "mtu":      parts[1],
                            "rx_pkts":  int(parts[4]),
                            "rx_errs":  int(parts[5]),
                            "rx_bytes": int(parts[6 + off]),
                            "tx_pkts":  int(parts[7 + off]),
                            "tx_errs":  int(parts[8 + off]),
                            "tx_bytes": int(parts[9 + off]),
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
    from app.database import get_db
    conn = get_db()
    row = conn.execute("SELECT assigned_port FROM lan_config LIMIT 1").fetchone()
    lan_iface = (row["assigned_port"] or "em1").strip() if row else "em1"
    return render_template("system_logs.html", lan_iface=lan_iface)


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
    Polling endpoint for the SIEM log monitor.

    Query params
    ------------
    since      ISO-8601 timestamp — return only events after this time.
    limit      Max events to return (default 100, max 500).
    categories Comma-separated list e.g. "session,system,ids". Omit for all.
    severities Comma-separated severity filter e.g. "critical,high". Omit for all.
    search     Free-text filter against action, username, IP, details.
    start_ts   ISO-8601 lower bound (time-range mode).
    end_ts     ISO-8601 upper bound (time-range mode).
    """
    since      = request.args.get("since",      "").strip()
    start_ts   = request.args.get("start_ts",   "").strip()
    end_ts     = request.args.get("end_ts",     "").strip()
    try:
        limit = min(int(request.args.get("limit", 100) or 100), 500)
    except (ValueError, TypeError):
        limit = 100
    cats_raw    = request.args.get("categories", "").strip()
    sevs_raw    = request.args.get("severities", "").strip()
    actions_raw = request.args.get("actions",    "").strip()
    search      = request.args.get("search",     "").lower().strip()

    categories    = [c.strip() for c in cats_raw.split(",")    if c.strip()] if cats_raw    else None
    severities    = [s.strip() for s in sevs_raw.split(",")    if s.strip()] if sevs_raw    else None
    action_filter = {a.strip() for a in actions_raw.split(",") if a.strip()} if actions_raw else None

    events = tail_events_since(
        after_ts=since,
        limit=limit * 3,
        categories=categories,
        severities=severities,
        start_ts=start_ts,
        end_ts=end_ts,
    )

    # Action-level filter (used by the Firewall category pill).
    if action_filter:
        events = [e for e in events if e.get("action") in action_filter]

    # SOC-origin events are hidden from /status/api/logs **by default**. The
    # firewall dashboard, alerts, and log views consume this endpoint, and SOC
    # analyst activity belongs in the SOC portal — not in the appliance log.
    # A superuser may explicitly opt in by passing ``hide_soc=0``; for any
    # other caller (or non-superuser) we filter SOC-tagged events out.
    _hide_soc_raw = request.args.get("hide_soc")
    _is_superuser = bool(session.get("is_superuser"))
    _show_soc = (
        _hide_soc_raw is not None
        and _hide_soc_raw.strip().lower() in ("0", "false", "no")
        and _is_superuser
    )
    if not _show_soc:
        events = [e for e in events
                  if not (e.get("details") or {}).get("soc_origin")]

    if search:
        def _matches(e):
            haystack = " ".join([
                e.get("action", ""),
                e.get("username", ""),
                e.get("remote_addr", ""),
                e.get("category", ""),
                e.get("severity", ""),
                _json.dumps(e.get("details") or {}),
            ]).lower()
            return search in haystack
        events = [e for e in events if _matches(e)]

    events    = events[:limit]
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
    """Per-category event counts + critical/high totals for the SIEM header."""
    return jsonify(log_stats())


@status_bp.route("/api/logs/timeseries")
@login_required
def api_logs_timeseries():
    """
    Event counts grouped by time bucket and severity, for the log charts.

    Query params: bucket (hour|day), categories, severities, start_ts, end_ts.
    """
    bucket   = request.args.get("bucket", "hour").strip()
    if bucket not in ("hour", "day"):
        bucket = "hour"
    start_ts = request.args.get("start_ts", "").strip()
    end_ts   = request.args.get("end_ts",   "").strip()
    cats_raw = request.args.get("categories", "").strip()
    sevs_raw = request.args.get("severities", "").strip()
    categories = [c.strip() for c in cats_raw.split(",") if c.strip()] if cats_raw else None
    severities = [s.strip() for s in sevs_raw.split(",") if s.strip()] if sevs_raw else None

    data = events_timeseries(
        bucket=bucket,
        categories=categories,
        severities=severities,
        start_ts=start_ts,
        end_ts=end_ts,
    )
    return jsonify({"ok": True, **data})


@status_bp.route("/api/logs/stream")
@login_required
def api_logs_stream():
    """
    Server-Sent Events stream of new audit events for the live log monitor.

    Query params: categories, severities (comma-separated), since_id.
    Emits `event: ready` (the starting id) then `event: log` per new event.
    The connection recycles after 10 minutes; EventSource auto-reconnects.
    """
    from flask import Response, stream_with_context
    import time as _time

    cats_raw = request.args.get("categories", "").strip()
    sevs_raw = request.args.get("severities", "").strip()
    categories = {c.strip() for c in cats_raw.split(",") if c.strip()} if cats_raw else None
    severities = {s.strip() for s in sevs_raw.split(",") if s.strip()} if sevs_raw else None
    try:
        since_id = int(request.args.get("since_id", 0) or 0)
    except (ValueError, TypeError):
        since_id = 0

    # SOC-origin filtering mirrors /api/logs (paginated): hide SOC-tagged
    # events from the firewall live feed unless a superuser explicitly opts
    # in with ?hide_soc=0. Capture in locals so the streaming generator does
    # not have to read request/session inside its long-lived loop.
    _hide_soc_raw = request.args.get("hide_soc")
    _is_superuser = bool(session.get("is_superuser"))
    _show_soc = (
        _hide_soc_raw is not None
        and _hide_soc_raw.strip().lower() in ("0", "false", "no")
        and _is_superuser
    )

    def _gen():
        from app.audit_log import _events_db
        conn = _events_db()
        last_id = since_id
        if conn is not None and last_id == 0:
            try:
                last_id = conn.execute(
                    "SELECT COALESCE(MAX(id), 0) AS m FROM events"
                ).fetchone()["m"]
            except Exception:
                last_id = 0
        yield "event: ready\ndata: %d\n\n" % last_id

        start = last_beat = _time.time()
        while _time.time() - start < 600:          # recycle after 10 min
            try:
                if conn is None:
                    conn = _events_db()
                rows = conn.execute(
                    "SELECT id, ts, severity, category, action, username, "
                    "remote_addr, details, event_uuid, soc_origin "
                    "FROM events WHERE id > ? "
                    "ORDER BY id LIMIT 200", (last_id,),
                ).fetchall() if conn is not None else []
                for r in rows:
                    last_id = r["id"]
                    # Indexed soc_origin filter — preferred over JSON parse.
                    # Falls back to details.soc_origin for any pre-v34 row
                    # the backfill missed.
                    if not _show_soc:
                        try:
                            if r["soc_origin"]:
                                continue
                        except (IndexError, KeyError):
                            pass
                    if categories and (r["category"] or "") not in categories:
                        continue
                    if severities and (r["severity"] or "info") not in severities:
                        continue
                    try:
                        details = _json.loads(r["details"]) if r["details"] else {}
                    except Exception:
                        details = {}
                    # Belt-and-braces: catch pre-v34 rows where the indexed
                    # soc_origin column is NULL but the details JSON still
                    # carries the marker.
                    if not _show_soc and (details or {}).get("soc_origin"):
                        continue
                    try:
                        event_uuid = r["event_uuid"] or ""
                    except (IndexError, KeyError):
                        event_uuid = ""
                    ev = {
                        "timestamp":   r["ts"],
                        "event_uuid":  event_uuid,
                        "severity":    r["severity"] or "info",
                        "category":    r["category"] or "",
                        "action":      r["action"] or "",
                        "username":    r["username"] or "anonymous",
                        "remote_addr": r["remote_addr"] or "",
                        "details":     details,
                    }
                    yield "event: log\ndata: %s\n\n" % _json.dumps(ev)
            except Exception:
                pass
            now = _time.time()
            if now - last_beat >= 15:
                last_beat = now
                yield ": keepalive\n\n"
            _time.sleep(1.5)

        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

    resp = Response(stream_with_context(_gen()), mimetype="text/event-stream")
    resp.headers["Cache-Control"]   = "no-cache"
    resp.headers["X-Accel-Buffering"] = "no"   # tell nginx not to buffer the stream
    return resp


@status_bp.route("/collector-health")
@login_required
def collector_health_page():
    """Render the collector-health page (data loaded via JSON below)."""
    return render_template("collector_health.html")


@status_bp.route("/api/collector-health")
@login_required
def api_collector_health():
    """Per-collector status + dead-letter rows for the health page."""
    from app.services.collector_health import list_state, list_dead_letter
    limit_dlq = 50
    try:
        limit_dlq = min(int(request.args.get("dlq_limit", 50) or 50), 500)
    except (ValueError, TypeError):
        pass
    source_name = (request.args.get("source") or "").strip()
    return jsonify({
        "ok":           True,
        "collectors":   list_state(),
        "dead_letter":  list_dead_letter(limit=limit_dlq,
                                         source_name=source_name),
    })


@status_bp.route("/api/collector-health/dlq/<int:dlq_id>/replay",
                 methods=["POST"])
@superuser_required
def api_collector_dlq_replay(dlq_id: int):
    """Re-run the parser on a single DLQ row and re-ingest on success."""
    from app.services.collector_health import replay_dead_letter
    from app.audit_log import log_event
    result = replay_dead_letter(dlq_id)
    log_event(
        category="admin_audit", action="dlq_replay",
        username=session.get("username") or "admin",
        remote_addr=request.remote_addr or "",
        details={"dlq_id": dlq_id, "ok": result.get("ok"),
                 "message": (result.get("message") or "")[:200]},
        severity="low",
    )
    return jsonify(result)


@status_bp.route("/api/collector-health/dlq/purge", methods=["POST"])
@superuser_required
def api_collector_dlq_purge():
    """Purge DLQ rows older than ``older_than_days`` (default 0 = all)."""
    from app.services.collector_health import purge_dead_letter
    from app.audit_log import log_event
    data = request.get_json(silent=True) or {}
    try:
        days = max(0, int(data.get("older_than_days", 0) or 0))
    except (TypeError, ValueError):
        days = 0
    source = (data.get("source") or "").strip()
    deleted = purge_dead_letter(older_than_days=days, source_name=source)
    log_event(
        category="admin_audit", action="dlq_purge",
        username=session.get("username") or "admin",
        remote_addr=request.remote_addr or "",
        details={"older_than_days": days, "source": source,
                 "deleted": deleted},
        severity="low",
    )
    return jsonify({"ok": True, "deleted": deleted,
                    "older_than_days": days, "source": source})


@status_bp.route("/api/migration-health")
@login_required
def api_migration_health():
    """Schema health report — version, missing tables/columns, last error.

    Wave N of the Fv5 plan. Surfaces what ``run_migrations`` did so an
    operator can confirm the DB is upgraded without grepping the audit log.
    """
    from app.database import get_db
    from app.migrations import CURRENT_SCHEMA_VERSION

    conn = get_db()

    # current applied version
    try:
        row = conn.execute(
            "SELECT COALESCE(MAX(version), 0) AS v FROM schema_version"
        ).fetchone()
        db_version = int(row["v"] if row else 0)
    except Exception:
        db_version = 0

    # required tables vs missing
    required = [
        "events", "firewall_events", "dns_events", "alerts",
        "alert_actions", "alert_suppressions", "alert_observations",
        "case_alerts", "siem_cases", "collector_state",
        "event_dead_letter", "tracked_hosts", "lan_config",
    ]
    present = {r["name"] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()}
    missing_tables = [t for t in required if t not in present]

    # last migration audit entry (if any)
    last_err = None
    try:
        from app.audit_log import _events_db
        evdb = _events_db()
        if evdb is not None:
            try:
                rerr = evdb.execute(
                    "SELECT ts, details FROM events "
                    "WHERE category = 'system' AND action = 'db_migration' "
                    "  AND details LIKE '%WARNING%' "
                    "ORDER BY id DESC LIMIT 1"
                ).fetchone()
                if rerr:
                    last_err = {"ts": rerr["ts"], "details": rerr["details"]}
            finally:
                try: evdb.close()
                except Exception: pass
    except Exception as exc:
        from app.app_log import log_warning
        log_warning("status", "db_migration last-error lookup failed", {"error": str(exc)})

    return jsonify({
        "ok":              True,
        "current_version": CURRENT_SCHEMA_VERSION,
        "db_version":      db_version,
        "up_to_date":      db_version == CURRENT_SCHEMA_VERSION,
        "missing_tables":  missing_tables,
        "last_error":      last_err,
    })


@status_bp.route("/log-forwarding", methods=["GET", "POST"])
@superuser_required
def log_forwarding_settings():
    """Configure log forwarding, events retention, and the syslog listener."""
    from flask import flash, redirect, url_for
    from app.database import get_db
    from app.audit_log import log_event
    from app.services.log_forwarder import load_config, save_config
    from app.services import events_retention, syslog_listener

    conn = get_db()
    if request.method == "POST":
        cfg = save_config(conn, {
            "enabled":     request.form.get("enabled") == "on",
            "host":        request.form.get("host", ""),
            "port":        request.form.get("port", 514),
            "protocol":    request.form.get("protocol", "udp"),
            "format":      request.form.get("format", "rfc5424"),
            "tls_verify":  request.form.get("tls_verify") == "on",
            "tls_ca_path": request.form.get("tls_ca_path", ""),
        })
        ret_cfg = events_retention.save_config(conn, {
            "enabled": request.form.get("retention_enabled") == "on",
            "days":    request.form.get("retention_days", 90),
        })
        listen_cfg = syslog_listener.save_config(conn, {
            "enabled":               request.form.get("listener_enabled") == "on",
            "bind_ip":               request.form.get("listener_bind_ip", "0.0.0.0"),
            "bind_port":             request.form.get("listener_bind_port", 5140),
            "trust_remote_hostname": request.form.get("listener_trust_host") == "on",
        })
        log_event(
            category="system", action="log_forwarding_saved",
            username=session.get("username"), remote_addr=request.remote_addr,
            details={"enabled": cfg["enabled"], "host": cfg["host"],
                     "port": cfg["port"], "protocol": cfg["protocol"],
                     "format": cfg["format"], "tls_verify": cfg["tls_verify"],
                     "retention_enabled": ret_cfg["enabled"],
                     "retention_days": ret_cfg["days"],
                     "listener_enabled":  listen_cfg["enabled"],
                     "listener_port":     listen_cfg["bind_port"]},
        )
        flash("SIEM settings saved.", "success")
        return redirect(url_for("status.log_forwarding_settings"))

    return render_template("log_forwarding.html",
                           cfg=load_config(conn),
                           retention=events_retention.load_config(conn),
                           listener=syslog_listener.load_config(conn))


# ---------------------------------------------------------------------------
# Correlation rules — drive correlation_engine.py
# ---------------------------------------------------------------------------

@status_bp.route("/correlation-rules")
@superuser_required
def correlation_rules():
    """Manage the SIEM correlation rules."""
    from app.database import get_db
    rules = get_db().execute(
        "SELECT * FROM correlation_rules ORDER BY id"
    ).fetchall()
    return render_template("correlation_rules.html", rules=rules)


@status_bp.route("/correlation-rules/add", methods=["POST"])
@superuser_required
def correlation_rules_add():
    from flask import flash, redirect, url_for
    from app.database import get_db
    from app.audit_log import log_event

    name = (request.form.get("name") or "").strip()
    if not name:
        flash("Rule name is required.", "danger")
        return redirect(url_for("status.correlation_rules"))
    try:
        threshold = max(1, int(request.form.get("threshold") or 5))
        window    = max(10, int(request.form.get("window_seconds") or 300))
    except (ValueError, TypeError):
        threshold, window = 5, 300
    severity = request.form.get("severity", "high")
    if severity not in ("low", "medium", "high", "critical"):
        severity = "high"

    conn = get_db()
    conn.execute(
        "INSERT INTO correlation_rules (name, category_filter, action_filter, "
        "group_by, threshold, window_seconds, severity, mitre_technique, "
        "prerequisite_action, auto_case) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)",
        (name,
         (request.form.get("category_filter") or "").strip(),
         (request.form.get("action_filter") or "").strip(),
         (request.form.get("group_by") or "remote_addr").strip(),
         threshold, window, severity,
         (request.form.get("mitre_technique") or "").strip(),
         (request.form.get("prerequisite_action") or "").strip(),
         1 if request.form.get("auto_case") == "on" else 0),
    )
    conn.commit()
    log_event(category="system", action="correlation_rule_added",
              username=session.get("username"), remote_addr=request.remote_addr,
              details={"name": name})
    flash(f"Correlation rule '{name}' added.", "success")
    return redirect(url_for("status.correlation_rules"))


@status_bp.route("/correlation-rules/test", methods=["POST"])
@superuser_required
def correlation_rules_test():
    """Backtest a (saved or draft) rule against the last 24h without firing."""
    from app.services.correlation_engine import simulate
    payload = request.get_json(silent=True) or {}
    try:
        hours = int(payload.get("hours") or 24)
    except (TypeError, ValueError):
        hours = 24
    return jsonify(simulate(payload, hours=hours))


@status_bp.route("/correlation-rules/<int:rule_id>/toggle", methods=["POST"])
@superuser_required
def correlation_rules_toggle(rule_id):
    from flask import redirect, url_for
    from app.database import get_db
    conn = get_db()
    conn.execute(
        "UPDATE correlation_rules SET enabled = 1 - enabled WHERE id = ?",
        (rule_id,),
    )
    conn.commit()
    return redirect(url_for("status.correlation_rules"))


@status_bp.route("/correlation-rules/<int:rule_id>/delete", methods=["POST"])
@superuser_required
def correlation_rules_delete(rule_id):
    from flask import flash, redirect, url_for
    from app.database import get_db
    from app.audit_log import log_event
    conn = get_db()
    conn.execute("DELETE FROM correlation_rules WHERE id = ?", (rule_id,))
    conn.commit()
    log_event(category="system", action="correlation_rule_deleted",
              username=session.get("username"), remote_addr=request.remote_addr,
              details={"rule_id": rule_id})
    flash("Correlation rule deleted.", "success")
    return redirect(url_for("status.correlation_rules"))


@status_bp.route("/api/logs/export")
@login_required
def api_logs_export():
    """
    Server-side bulk export of the audit log.
    Respects same category/severity/time-range filters as /api/logs.
    Returns full filtered log as a downloadable JSON file.
    """
    import datetime as _dt
    cats_raw   = request.args.get("categories", "").strip()
    sevs_raw   = request.args.get("severities", "").strip()
    start_ts   = request.args.get("start_ts",   "").strip()
    end_ts     = request.args.get("end_ts",     "").strip()
    search     = request.args.get("search",     "").lower().strip()

    categories = [c.strip() for c in cats_raw.split(",") if c.strip()] if cats_raw else None
    severities = [s.strip() for s in sevs_raw.split(",") if s.strip()] if sevs_raw else None

    events = tail_events_since(
        limit=0,                   # 0 = no limit
        categories=categories,
        severities=severities,
        start_ts=start_ts,
        end_ts=end_ts,
    )

    if search:
        events = [
            e for e in events
            if search in " ".join([
                e.get("action", ""), e.get("username", ""),
                e.get("remote_addr", ""), e.get("category", ""),
                _json.dumps(e.get("details") or {}),
            ]).lower()
        ]

    date_str  = _dt.date.today().isoformat()
    filename  = f"smartshield-siem-{date_str}.json"
    body      = _json.dumps(events, indent=2, ensure_ascii=True)

    from flask import Response
    return Response(
        body,
        mimetype="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


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
# LIVENESS / READINESS  (for service managers & load balancers)
# ══════════════════════════════════════════════════
# These are intentionally UNAUTHENTICATED so an external supervisor (rc.d
# health probe, load balancer, monitoring) can reach them. They return only
# booleans and an overall status — never secrets or config detail.

@status_bp.route("/health")
def status_health():
    """Liveness probe: the process is up and the database answers a trivial
    query. Returns 200 when alive, 503 otherwise."""
    alive = True
    db_ok = False
    try:
        from app.database import get_db
        get_db().execute("SELECT 1")
        db_ok = True
    except Exception:
        alive = False
    return jsonify({"ok": alive, "status": "ok" if alive else "fail", "db": db_ok}), (200 if alive else 503)


@status_bp.route("/readiness")
def status_readiness():
    """Readiness probe: deeper checks that must pass before the appliance
    should receive traffic — DB connectivity, schema at the expected version,
    writable data/log directories, and a readable master key. Returns 200 when
    ready, 503 when any required check fails."""
    import os as _os
    checks: dict[str, bool] = {}

    # DB connectivity + schema version.
    schema_ok = False
    try:
        from app.database import get_db
        from app.migrations import CURRENT_SCHEMA_VERSION
        conn = get_db()
        conn.execute("SELECT 1")
        checks["db"] = True
        try:
            row = conn.execute(
                "SELECT MAX(version) AS v FROM schema_version"
            ).fetchone()
            schema_ok = bool(row) and (row["v"] is not None) and int(row["v"]) >= CURRENT_SCHEMA_VERSION
        except Exception:
            schema_ok = False
    except Exception:
        checks["db"] = False
    checks["schema"] = schema_ok

    cfg = current_app.config

    # Writable data dir (DB parent) and log dirs.
    def _dir_writable(path: str) -> bool:
        try:
            d = _os.path.dirname(path) or "."
            return _os.path.isdir(d) and _os.access(d, _os.W_OK)
        except Exception:
            return False

    db_path = cfg.get("DB_PATH") or ""
    # In-memory test DB has no real directory; treat as writable.
    checks["data_dir_writable"] = True if "memory" in db_path else _dir_writable(db_path)
    checks["audit_log_writable"] = _dir_writable(cfg.get("AUDIT_LOG_PATH") or "")
    checks["app_log_writable"] = _dir_writable(cfg.get("APP_LOG_PATH") or "") if cfg.get("APP_LOG_PATH") else True

    # Master key readable (env value present, or key file readable).
    master_ok = True
    try:
        if not cfg.get("MASTER_KEY"):
            key_path = _os.getenv("SMARTSHIELD_MASTER_KEY_PATH", "")
            if key_path:
                master_ok = _os.path.isfile(key_path) and _os.access(key_path, _os.R_OK)
            # If neither env value nor explicit path is set, the app auto-manages
            # the key elsewhere; don't fail readiness on that account.
    except Exception:
        master_ok = False
    checks["master_key"] = master_ok

    ready = all(checks.values())
    return jsonify({
        "ok": ready,
        "status": "ready" if ready else "not_ready",
        "checks": checks,
    }), (200 if ready else 503)


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

    # Fill in hostnames for leases the client never announced, by actively
    # probing the device (NetBIOS / mDNS). Cached, and never fatal.
    try:
        from app.services.hostname_resolver import resolve_hostnames
        missing = [
            l["ip_address"]
            for l in leases
            if not (l.get("hostname") or "").strip() and l.get("ip_address")
        ]
        if missing:
            probed = resolve_hostnames(missing)
            for l in leases:
                if not (l.get("hostname") or "").strip():
                    name = probed.get(l.get("ip_address"))
                    if name:
                        l["hostname"] = name
    except Exception:
        pass

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
    import sys, time
    from app.database import get_db
    from app.services.mrtg_writer import get_mrtg_status
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

    # Fall back to em0/em1 when DB has no interface assignments yet —
    # matches the bootstrap config written by install.sh and _discover_interfaces().
    if not interfaces:
        for name, label in [("em0", "WAN"), ("em1", "LAN")]:
            interfaces.append({"name": name, "label": label, "description": ""})

    iface_names = [i["name"] for i in interfaces]
    return render_template(
        "mrtg_graphs.html",
        interfaces=interfaces,
        iface_names=iface_names,
        on_freebsd=sys.platform.startswith("freebsd"),
        now_ts=int(time.time()),
        mrtg_status=get_mrtg_status(),
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
        username=session.get("username", "unknown"),
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
    from app.services.mrtg_writer import _MRTG_WORK_DIR
    resp = make_response(send_from_directory(_MRTG_WORK_DIR, filename))
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

    from app.secret_store import has_master_key as _has_master_key
    _gate("master_key", "Master key is available (env var or key file)",
          _has_master_key(), "warning",
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
