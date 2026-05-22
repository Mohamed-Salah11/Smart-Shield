from flask import (
    Blueprint, render_template, redirect, url_for, request, session,
    jsonify, flash, abort, current_app,
)
from app.database import get_db
from app.auth_utils import login_required, superuser_required
from app.audit_log import tail_events, log_event
import json, os
import sys
from datetime import datetime, timezone


GENERAL_SETUP_DEFAULTS = {
    "hostname": "Smart Shield",
    "domain": "home.arpa",
    "dns_servers": [],
    "dns_override": True,
    "dns_behavior": "Use local DNS (127.0.0.1), fall back to remote DNS Servers (Default)",
    "timezone": "Etc/UTC",
    "timeservers": "2.pool.ntp.org",
    "language": "English",
    "theme": "Smart Shield",
    "login_color": "Dark Blue",
    "show_hostname": True,
    "login_message": "",
    "dashboard_columns": 2,
    "widgets": True,
    "log_filter": True,
    "manage_log": True,
    "monitoring": True,
}


def _general_config_path():
    if sys.platform.startswith("freebsd"):
        from app.config import _ss_dir
        default_config_path = os.path.join(_ss_dir("/usr/local/etc"), "config.json")
    else:
        default_config_path = "config.json"
    return os.getenv("SMARTSHIELD_CONFIG_PATH", default_config_path)


def _config_bool(value, default=False):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _load_general_config():
    config = GENERAL_SETUP_DEFAULTS.copy()
    config_path = _general_config_path()

    if os.path.exists(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            if isinstance(loaded, dict):
                config.update(loaded)
        except (OSError, json.JSONDecodeError):
            pass

    return config


def _safe_count(cursor, table_name):
    try:
        cursor.execute(f"SELECT COUNT(*) AS c FROM {table_name}")
        row = cursor.fetchone()
        return int(row["c"]) if row and "c" in row.keys() else 0
    except Exception:
        return 0


def _build_dashboard_payload(include_health: bool = True):
    config = _load_general_config()
    # Firewall dashboard is SmartShield Core-only — exclude SOC team activity
    # (events tagged details.soc_origin by the SOC portal).
    events = [e for e in tail_events(limit=300)
              if not (e.get("details") or {}).get("soc_origin")]
    session_events = [e for e in events if e.get("category") == "session"]

    session_summary = {
        "successful_logins": sum(1 for e in session_events if e.get("action") == "login_success"),
        "failed_logins": sum(1 for e in session_events if e.get("action") == "login_failed"),
        "logouts": sum(1 for e in session_events if e.get("action") == "logout"),
    }

    conn = get_db()
    cur = conn.cursor()
    object_counts = {
        # Users & auth
        "users":              _safe_count(cur, "users"),
        "groups":             _safe_count(cur, "groups"),
        # Firewall
        "wan_rules":          _safe_count(cur, "firewall_rules_wan"),
        "lan_rules":          _safe_count(cur, "firewall_rules_lan"),
        "floating_rules":     _safe_count(cur, "firewall_rules_floating"),
        "aliases":            _safe_count(cur, "firewall_aliases"),
        # NAT
        "nat_port_forwards":  _safe_count(cur, "nat_pf"),
        "nat_outbound":       _safe_count(cur, "nat_outbound"),
        "nat_1to1":           _safe_count(cur, "nat_1to1"),
        # VPN
        "openvpn_servers":    _safe_count(cur, "openvpn_servers"),
        "openvpn_clients":    _safe_count(cur, "openvpn_clients"),
        "ipsec_tunnels":      _safe_count(cur, "ipsec_phase1"),
        # Routing
        "gateways":           _safe_count(cur, "gateways"),
        "static_routes":      _safe_count(cur, "static_routes"),
        # Services
        "dhcp_pools":         _safe_count(cur, "dhcp_pools"),
        "static_leases":      _safe_count(cur, "static_leases"),
        # Security Profiles
        "dns_filter_rules":   _safe_count(cur, "filter_dns_rules"),
        "web_filter_rules":   _safe_count(cur, "filter_web_rules"),
        "app_filter_rules":   _safe_count(cur, "filter_app_rules"),
        # IDS/IPS
        "ids_rulesets":       _safe_count(cur, "ids_rulesets"),
    }

    # Interface assignments
    try:
        cur.execute("SELECT interface_type, network_port FROM interface_assignments")
        iface_rows = {r["interface_type"]: r["network_port"] for r in cur.fetchall()}
    except Exception:
        iface_rows = {}

    # WAN/LAN config summary
    try:
        cur.execute("SELECT ipv4_config_type, ipv4_address, assigned_port FROM wan_config WHERE id=1")
        wan_row = dict(cur.fetchone() or {})
    except Exception:
        wan_row = {}
    try:
        cur.execute("SELECT ipv4_address, assigned_port FROM lan_config WHERE id=1")
        lan_row = dict(cur.fetchone() or {})
    except Exception:
        lan_row = {}

    # IDS enabled state
    try:
        cur.execute("SELECT enabled, mode, interface FROM ids_config WHERE id=1")
        ids_row = dict(cur.fetchone() or {})
    except Exception:
        ids_row = {}

    # DHCP enabled pools
    try:
        cur.execute("SELECT COUNT(*) AS c FROM dhcp_pools WHERE enabled=1")
        row = cur.fetchone()
        dhcp_enabled = int(row["c"]) if row else 0
    except Exception:
        dhcp_enabled = 0

    try:
        dashboard_columns = int(config.get("dashboard_columns", 2))
    except (TypeError, ValueError):
        dashboard_columns = 2
    dashboard_columns = min(max(dashboard_columns, 1), 4)

    # Live health snapshot (services, disk, CPU/memory)
    health = {}
    if include_health:
        try:
            from app.services.health_monitor import full_health_check, store_health_snapshot
            health = full_health_check(conn)
            try:
                store_health_snapshot(conn, health)
            except Exception:
                pass
        except Exception:
            health = {}

    # SOC Portal service status — SmartShield Core firewall admin controls the
    # SOC Portal service, so a small service-status card is allowed here. SOC
    # team work (cases, alerts, investigations) is never shown on the firewall
    # dashboard (separation Rule 2).
    soc_portal = {"enabled": False, "bind_ip": "", "port": 8443}
    try:
        soc_row = conn.execute(
            "SELECT enabled, bind_ip, bind_port FROM soc_portal_config WHERE id=1"
        ).fetchone()
        if soc_row:
            soc_portal = {
                "enabled": bool(soc_row["enabled"]),
                "bind_ip": soc_row["bind_ip"] or "",
                "port":    soc_row["bind_port"] or 8443,
            }
    except Exception:
        pass

    return {
        "generated_at":       datetime.now(timezone.utc).isoformat(),
        "dashboard_columns":  dashboard_columns,
        "widgets_enabled":    _config_bool(config.get("widgets"), True),
        "log_filter_enabled": _config_bool(config.get("log_filter"), True),
        "manage_log_enabled": _config_bool(config.get("manage_log"), True),
        "monitoring_enabled": _config_bool(config.get("monitoring"), True),
        "hostname":           config.get("hostname") or "Smart Shield",
        "timezone":           config.get("timezone") or "Etc/UTC",
        "theme":              config.get("theme") or "Smart Shield",
        "session_summary":    session_summary,
        "object_counts":      object_counts,
        "interface_assignments": iface_rows,
        "wan": wan_row,
        "lan": lan_row,
        "ids": ids_row,
        "dhcp_enabled_pools": dhcp_enabled,
        "recent_session_events": session_events[:25],
        "recent_events":      events[:25],
        "health":             health,
        "soc_portal":         soc_portal,
    }

# ----------------------------
# SYSTEM MAIN PAGES
# ----------------------------
