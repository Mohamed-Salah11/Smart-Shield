from flask import Blueprint, render_template, redirect, url_for, request, session, jsonify, flash
from app.database import get_db
from app.auth_utils import login_required, superuser_required, feature_unfinished
from app.audit_log import tail_events, log_event
import json, os
import sys
from datetime import datetime, timezone

system_bp = Blueprint("system", __name__, url_prefix="/system")

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
    default_config_path = "/usr/local/etc/smart-shield/config.json" if sys.platform.startswith("freebsd") else "config.json"
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
    events = tail_events(limit=300)
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
        dhcp_enabled = int((cur.fetchone() or {}).get("c", 0))
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
    }

# ----------------------------
# SYSTEM MAIN PAGES
# ----------------------------

@system_bp.route("/")
@login_required
def system_home():
    return redirect(url_for("system.general_setup"))


@system_bp.route("/theme-editor")
@login_required
def theme_editor():
    return render_template("theme_editor.html", title="Theme Editor")

@system_bp.route("/dashboard")
@login_required
def dashboard():
    payload = _build_dashboard_payload()
    return render_template(
        "dashboard.html",
        dashboard_columns=payload["dashboard_columns"],
        dashboard_payload=payload,
    )


@system_bp.route("/dashboard/data", methods=["GET"])
@login_required
def dashboard_data():
    return jsonify({"status": "success", "data": _build_dashboard_payload()})


@system_bp.route("/dashboard/stream")
@login_required
def dashboard_stream():
    """Server-Sent Events endpoint — pushes a health snapshot every 10 s."""
    import time as _time

    def _event_stream():
        while True:
            try:
                payload = _build_dashboard_payload(include_health=True)
                data = json.dumps({"status": "success", "data": payload})
                yield f"data: {data}\n\n"
            except Exception as exc:
                yield f"data: {json.dumps({'status': 'error', 'message': str(exc)})}\n\n"
            _time.sleep(10)

    from flask import Response
    return Response(
        _event_stream(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )

@system_bp.route("/logout")
def logout():
    log_event(
        category="session",
        action="logout",
        username=session.get("username", "anonymous"),
        remote_addr=request.remote_addr,
        details={"user_id": session.get("user_id")},
    )
    session.clear()
    return redirect(url_for("auth.login"))


# ----------------------------
# HELP PAGES
# ----------------------------

# Placeholder admin pages — gated behind SMARTSHIELD_ENABLE_UNFINISHED_PAGES.
# Each template is a 6-line stub today; enable the env var on a dev box to
# wire up real content without exposing half-finished pages in production.
@system_bp.route("/docs")
@feature_unfinished
def docs():
    return render_template("docs.html")

@system_bp.route("/about")
@feature_unfinished
def about():
    return render_template("about.html")

@system_bp.route("/bug")
@feature_unfinished
def bug():
    return render_template("bug.html")

@system_bp.route("/forum")
@feature_unfinished
def forum():
    return render_template("forum.html")

@system_bp.route("/freebsd")
@feature_unfinished
def freebsd():
    return render_template("freebsd.html")

@system_bp.route("/smart-shield-book")
@feature_unfinished
def smart_shield_book():
    return render_template("smart_shield_book.html")

@system_bp.route("/paid-support")
@feature_unfinished
def paid_support():
    return render_template("paid_support.html")

@system_bp.route("/survey")
@feature_unfinished
def survey():
    return render_template("survey.html")

@system_bp.route("/upgrade")
@feature_unfinished
def upgrade():
    return render_template("upgrade.html")

@system_bp.route("/help")
@feature_unfinished
def help_page():
    return render_template("help.html")


# ----------------------------
# GENERAL SETUP
# ----------------------------

@system_bp.route("/general-setup", methods=["GET", "POST"])
@login_required
def general_setup():
    config_file = _general_config_path()

    def load_config():
        return _load_general_config()

    def save_config(cfg):
        config_dir = os.path.dirname(os.path.abspath(config_file))
        if config_dir:
            os.makedirs(config_dir, exist_ok=True)
        with open(config_file, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=4)

    config = load_config()

    if request.method == "POST":
        config["hostname"] = request.form.get("hostname")
        config["domain"] = request.form.get("domain")
        config["dns_servers"] = request.form.getlist("dns_server")
        config["dns_override"] = bool(request.form.get("dns_override"))
        config["dns_behavior"] = request.form.get("dns_behavior")
        config["timezone"] = request.form.get("timezone")
        config["timeservers"] = request.form.get("timeservers")
        config["language"] = request.form.get("language")
        config["theme"] = request.form.get("theme")
        config["login_color"] = request.form.get("login_color")
        config["show_hostname"] = bool(request.form.get("show_hostname"))
        config["login_message"] = request.form.get("login_message")
        config["top_navigation"] = request.form.get("top_navigation")
        config["hostname_menu"] = request.form.get("hostname_menu")

        try:
            config["dashboard_columns"] = min(max(int(request.form.get("dashboard_columns", 2)), 1), 4)
        except (TypeError, ValueError):
            config["dashboard_columns"] = 2
        config["widgets"] = bool(request.form.get("widgets"))
        config["log_filter"] = bool(request.form.get("log_filter"))
        config["manage_log"] = bool(request.form.get("manage_log"))
        config["monitoring"] = bool(request.form.get("monitoring"))

        save_config(config)
        return redirect(url_for("system.general_setup"))

    return render_template("general_setup.html", config=config)


# ----------------------------
# ADVANCED SYSTEM (submenus)
# ----------------------------

@system_bp.route("/advanced", methods=["GET", "POST"])
@login_required
def advanced():
    return redirect(url_for("system.admin_access"))

@system_bp.route("/register")
@login_required
def register():
    return render_template("register.html")

@system_bp.route("/admin-access", methods=["GET", "POST"])
@login_required
def admin_access():
    conn = get_db()
    cursor = conn.cursor()
    
    if request.method == "POST":
        _addrs = request.form.getlist('pass_list_address[]')
        _cidrs = request.form.getlist('pass_list_cidr[]')
        _pass_list = json.dumps([f"{a.strip()}/{c}" for a, c in zip(_addrs, _cidrs) if a.strip()])
        cursor.execute("""
            UPDATE advanced_admin_access SET
                protocol = ?,
                ssl_cert = ?,
                tcp_port = ?,
                max_processes = ?,
                webgui_redirect = ?,
                ocsp_stapling = ?,
                webgui_autocomplete = ?,
                gui_login_messages = ?,
                roaming = ?,
                hsts = ?,
                anti_lockout = ?,
                dns_rebind = ?,
                alternate_hostnames = ?,
                http_referer = ?,
                browser_tab_text = ?,
                enable_ssh = ?,
                ssh_key_only = ?,
                ssh_agent_forwarding = ?,
                ssh_port = ?,
                threshold = ?,
                blocktime = ?,
                detection_time = ?,
                pass_list = ?,
                serial_terminal = ?,
                serial_speed = ?,
                primary_console = ?,
                console_menu = ?
            WHERE id = 1
        """, (
            request.form.get('protocol', 'https'),
            request.form.get('ssl_cert', 'default'),
            request.form.get('tcp_port') or None,
            request.form.get('max_processes', 2),
            1 if request.form.get('webgui_redirect') else 0,
            1 if request.form.get('ocsp_stapling') else 0,
            1 if request.form.get('webgui_autocomplete') else 0,
            1 if request.form.get('gui_login_messages') else 0,
            1 if request.form.get('roaming') else 0,
            1 if request.form.get('hsts') else 0,
            1 if request.form.get('anti_lockout') else 0,
            1 if request.form.get('dns_rebind') else 0,
            request.form.get('alternate_hostnames', ''),
            1 if request.form.get('http_referer') else 0,
            1 if request.form.get('browser_tab_text') else 0,
            1 if request.form.get('enable_ssh') else 0,
            request.form.get('ssh_key_only', 'password_or_key'),
            1 if request.form.get('ssh_agent_forwarding') else 0,
            request.form.get('ssh_port', 22),
            request.form.get('threshold', 30),
            request.form.get('blocktime', 120),
            request.form.get('detection_time', 1800),
            _pass_list,
            1 if request.form.get('serial_terminal') else 0,
            request.form.get('serial_speed', '115200'),
            request.form.get('primary_console', 'video'),
            1 if request.form.get('console_menu') else 0
        ))
        conn.commit()
    
    cursor.execute("SELECT * FROM advanced_admin_access WHERE id = 1")
    config = cursor.fetchone()
    return render_template("admin_access.html", config=config)

@system_bp.route("/advanced/firewall-nat", methods=["GET", "POST"])
@login_required
def advanced_firewall_nat():
    conn = get_db()
    cursor = conn.cursor()
    
    if request.method == "POST":
        cursor.execute("""
            UPDATE advanced_firewall_nat SET
                ip_fragment = ?,
                ip_random = ?,
                firewall_optimization = ?,
                disable_scrub = ?,
                adaptive_start = ?,
                adaptive_end = ?,
                firewall_max_states = ?,
                firewall_max_table = ?,
                firewall_max_fragment = ?,
                vpn_ip_fragment = ?,
                ip_fragment_reassemble = ?,
                enable_mss = ?,
                maximum_mss = ?,
                disable_firewall = ?,
                firewall_state_policy = ?,
                disable_static_policy = ?,
                static_route_filtering = ?,
                disable_auto_added_vpn = ?,
                disable_reply_to = ?,
                disable_negate_rules = ?,
                allow_apipa = ?,
                aliases_hostnames_interval = ?,
                check_certificate_aliases_urls = ?,
                update_frequency = ?,
                nat_reflection_mode = ?,
                reflection_timeout = ?,
                enable_nat_reflection = ?,
                enable_automatic_outbound = ?,
                tftp_proxy_wan = ?,
                tftp_proxy_lan = ?,
                tcp_first = ?,
                tcp_opening = ?,
                tcp_established = ?,
                tcp_closing = ?,
                tcp_fin_wait = ?,
                tcp_closed = ?,
                tcp_tsdiff = ?,
                sctp_first = ?,
                sctp_opening = ?,
                sctp_established = ?,
                sctp_closing = ?,
                sctp_closed = ?,
                udp_first = ?,
                udp_single = ?,
                udp_multiple = ?,
                icmp_first = ?,
                icmp_error = ?,
                other_first = ?,
                other_single = ?,
                other_multiple = ?
            WHERE id = 1
        """, (
            1 if request.form.get('ip_fragment') else 0,
            1 if request.form.get('ip_random') else 0,
            request.form.get('firewall_optimization', 'normal'),
            1 if request.form.get('disable_scrub') else 0,
            request.form.get('adaptive_start') or 1134000,
            request.form.get('adaptive_end') or 2333332,
            request.form.get('firewall_max_states') or 1990000,
            request.form.get('firewall_max_table') or 400000,
            request.form.get('firewall_max_fragment') or 5000,
            1 if request.form.get('vpn_ip_fragment') else 0,
            1 if request.form.get('ip_fragment_reassemble') else 0,
            1 if request.form.get('enable_mss') else 0,
            request.form.get('maximum_mss') or 1400,
            1 if request.form.get('disable_firewall') else 0,
            request.form.get('firewall_state_policy', 'interface_bound'),
            1 if request.form.get('disable_static_policy') else 0,
            1 if request.form.get('static_route_filtering') else 0,
            1 if request.form.get('disable_auto_added_vpn') else 0,
            1 if request.form.get('disable_reply_to') else 0,
            1 if request.form.get('disable_negate_rules') else 0,
            1 if request.form.get('allow_apipa') else 0,
            request.form.get('aliases_hostnames_interval') or 300,
            1 if request.form.get('check_certificate_aliases_urls') else 0,
            request.form.get('update_frequency', 'monthly'),
            request.form.get('nat_reflection_mode', 'disabled'),
            request.form.get('reflection_timeout') or None,
            1 if request.form.get('enable_nat_reflection') else 0,
            1 if request.form.get('enable_automatic_outbound') else 0,
            1 if request.form.get('tftp_proxy_wan') else 0,
            1 if request.form.get('tftp_proxy_lan') else 0,
            request.form.get('tcp_first') or None,
            request.form.get('tcp_opening') or None,
            request.form.get('tcp_established') or None,
            request.form.get('tcp_closing') or None,
            request.form.get('tcp_fin_wait') or None,
            request.form.get('tcp_closed') or None,
            request.form.get('tcp_tsdiff') or None,
            request.form.get('sctp_first') or None,
            request.form.get('sctp_opening') or None,
            request.form.get('sctp_established') or None,
            request.form.get('sctp_closing') or None,
            request.form.get('sctp_closed') or None,
            request.form.get('udp_first') or None,
            request.form.get('udp_single') or None,
            request.form.get('udp_multiple') or None,
            request.form.get('icmp_first') or None,
            request.form.get('icmp_error') or None,
            request.form.get('other_first') or None,
            request.form.get('other_single') or None,
            request.form.get('other_multiple') or None
        ))
        conn.commit()
    
    cursor.execute("SELECT * FROM advanced_firewall_nat WHERE id = 1")
    config = cursor.fetchone()
    return render_template("advanced_firewall_nat.html", config=config)

@system_bp.route("/advanced/network", methods=["GET", "POST"])
@login_required
def advanced_network():
    conn = get_db()
    cursor = conn.cursor()
    
    if request.method == "POST":
        cursor.execute("""
            UPDATE advanced_network SET
                server_backend = ?,
                ignore_deprecation = ?,
                radvd_debug = ?,
                dhcp6_debug = ?,
                do_not_allow_release = ?,
                dhcpv6_duid = ?,
                raw_duid = ?,
                allow_ipv6 = ?,
                ipv6_over_ipv4_tunneling = ?,
                ipv4_address_tunnel_peer = ?,
                prefer_ipv4_over_ipv6 = ?,
                ipv6_dns_entry = ?,
                hardware_checksum_offloading = ?,
                hardware_tcp_segmentation = ?,
                hardware_large_receive = ?,
                hn_altq_support = ?,
                arp_handling = ?,
                reset_all_states = ?,
                if_pppoe_kernel = ?
            WHERE id = 1
        """, (
            request.form.get('server_backend', 'kea_dhcp'),
            1 if request.form.get('ignore_deprecation') else 0,
            1 if request.form.get('radvd_debug') else 0,
            1 if request.form.get('dhcp6_debug') else 0,
            1 if request.form.get('do_not_allow_release') else 0,
            request.form.get('dhcpv6_duid', 'raw_duid'),
            request.form.get('raw_duid', ''),
            1 if request.form.get('allow_ipv6') else 0,
            1 if request.form.get('ipv6_over_ipv4_tunneling') else 0,
            request.form.get('ipv4_address_tunnel_peer', ''),
            1 if request.form.get('prefer_ipv4_over_ipv6') else 0,
            1 if request.form.get('ipv6_dns_entry') else 0,
            1 if request.form.get('hardware_checksum_offloading') else 0,
            1 if request.form.get('hardware_tcp_segmentation') else 0,
            1 if request.form.get('hardware_large_receive') else 0,
            1 if request.form.get('hn_altq_support') else 0,
            1 if request.form.get('arp_handling') else 0,
            1 if request.form.get('reset_all_states') else 0,
            1 if request.form.get('if_pppoe_kernel') else 0
        ))
        conn.commit()
    
    cursor.execute("SELECT * FROM advanced_network WHERE id = 1")
    config = cursor.fetchone()
    return render_template("advanced_network.html", config=config)

@system_bp.route("/advanced/miscellaneous", methods=["GET", "POST"])
@login_required
def advanced_miscellaneous():
    conn = get_db()
    cursor = conn.cursor()
    
    if request.method == "POST":
        cursor.execute("""
            UPDATE advanced_miscellaneous SET
                proxy_url = ?,
                proxy_port = ?,
                proxy_username = ?,
                proxy_password = ?,
                load_balancing = ?,
                sticky_timeout = ?,
                powerd = ?,
                ac_power = ?,
                battery_power = ?,
                unknown_power = ?,
                cryptographic_hardware = ?,
                thermal_sensors = ?,
                kernel_pti = ?,
                mds_mode = ?,
                schedule_states = ?,
                state_killing_on_gateway_recovery = ?,
                dont_kill_policy_routing = ?,
                state_killing_on_gateway_failure = ?,
                skip_rules_gateway_down = ?,
                static_routes = ?,
                memory_limit = ?,
                use_ram_disks = ?,
                tmp_ram_disk = ?,
                var_ram_disk = ?,
                rrd_data_backup = ?,
                dhcp_leases_backup = ?,
                log_directory_backup = ?,
                captive_portal_data_backup = ?,
                hard_disk_standby_time = ?,
                smart_shield_device_id = ?
            WHERE id = 1
        """, (
            request.form.get('proxy_url', ''),
            request.form.get('proxy_port', ''),
            request.form.get('proxy_username', ''),
            request.form.get('proxy_password', ''),
            1 if request.form.get('load_balancing') else 0,
            request.form.get('sticky_timeout', 0),
            1 if request.form.get('powerd') else 0,
            request.form.get('ac_power', 'hadaptive'),
            request.form.get('battery_power', 'hadaptive'),
            request.form.get('unknown_power', 'hadaptive'),
            request.form.get('cryptographic_hardware', 'none'),
            request.form.get('thermal_sensors', 'none_acpi'),
            1 if request.form.get('kernel_pti') else 0,
            request.form.get('mds_mode', 'mitigation_disabled'),
            1 if request.form.get('schedule_states') else 0,
            request.form.get('state_killing_on_gateway_recovery', 'dont_kill'),
            1 if request.form.get('dont_kill_policy_routing') else 0,
            request.form.get('state_killing_on_gateway_failure', 'do_not_kill'),
            1 if request.form.get('skip_rules_gateway_down') else 0,
            1 if request.form.get('static_routes') else 0,
            request.form.get('memory_limit', ''),
            1 if request.form.get('use_ram_disks') else 0,
            request.form.get('tmp_ram_disk', ''),
            request.form.get('var_ram_disk', ''),
            request.form.get('rrd_data_backup', ''),
            request.form.get('dhcp_leases_backup', ''),
            request.form.get('log_directory_backup', ''),
            request.form.get('captive_portal_data_backup', ''),
            request.form.get('hard_disk_standby_time', 'always_on'),
            1 if request.form.get('smart_shield_device_id') else 0
        ))
        conn.commit()
    
    cursor.execute("SELECT * FROM advanced_miscellaneous WHERE id = 1")
    config = cursor.fetchone()
    return render_template("advanced_miscellaneous.html", config=config)


# ----------------------------
# SYSTEM TUNABLES
# ----------------------------

@system_bp.route("/advanced/system-tunables")
@login_required
def advanced_system_tunables():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM advanced_system_tunables ORDER BY id")
    tunables = cursor.fetchall()
    return render_template("advanced_system_tunables.html", tunables=tunables)


@system_bp.route("/advanced/system-tunables/edit", methods=["GET", "POST"])
@system_bp.route("/advanced/system-tunables/edit/<int:index>", methods=["GET", "POST"])
@login_required
def advanced_system_tunables_edit(index=None):
    conn = get_db()
    cursor = conn.cursor()
    
    tunable = None
    if index is not None:
        cursor.execute("SELECT * FROM advanced_system_tunables WHERE id = ?", (index,))
        tunable = cursor.fetchone()
    return render_template("advanced_system_tunables_edit.html", tunable=tunable, index=index)


@system_bp.route("/advanced/system-tunables/save", methods=["POST"])
@login_required
def advanced_system_tunables_save():
    conn = get_db()
    cursor = conn.cursor()
    
    tunable_name = request.form.get("tunable_name")
    tunable_value = request.form.get("tunable_value")
    tunable_description = request.form.get("tunable_description", "")
    index = request.form.get("index")

    if index and index.isdigit():
        cursor.execute("""
            UPDATE advanced_system_tunables SET name = ?, description = ?, value = ?
            WHERE id = ?
        """, (tunable_name, tunable_description, tunable_value, int(index)))
    else:
        cursor.execute("""
            INSERT INTO advanced_system_tunables (name, description, value)
            VALUES (?, ?, ?)
        """, (tunable_name, tunable_description, tunable_value))
    
    conn.commit()
    return redirect(url_for("system.advanced_system_tunables"))


@system_bp.route("/advanced/system-tunables/delete/<int:index>", methods=["POST"])
@login_required
def advanced_system_tunables_delete(index):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM advanced_system_tunables WHERE id = ?", (index,))
    conn.commit()
    return redirect(url_for("system.advanced_system_tunables"))


# ----------------------------
# CERTIFICATES
# ----------------------------

@system_bp.route("/certificates")
@login_required
def certificates():
    from app.services.cert_manager import list_certs, mask_cert_fields
    active_section = request.args.get("section", "certificates")
    if active_section not in ("authorities", "certificates", "revocation"):
        active_section = "certificates"
    conn = get_db()
    cur  = conn.cursor()

    # CAs from the new certificates table
    try:
        cas_raw = list_certs(conn, cert_type="ca")
        cas = [mask_cert_fields(r) for r in cas_raw]
    except Exception:
        cas = []

    # Server + client certs
    try:
        certs_raw = list_certs(conn)
        certs = [mask_cert_fields(r) for r in certs_raw if r.get("cert_type") != "ca"]
    except Exception:
        certs = []

    # Revoked certs (CRL entries)
    try:
        revoked_rows = [dict(r) for r in cur.execute(
            "SELECT id, name, common_name, revoked_at, ca_id "
            "FROM certificates WHERE revoked=1 ORDER BY revoked_at DESC"
        )]
        crls = revoked_rows
    except Exception:
        crls = []

    return render_template(
        "certificates.html",
        active_section=active_section,
        cas=cas,
        certs=certs,
        crls=crls,
    )

@system_bp.route("/add_ca", methods=["GET", "POST"])
@login_required
def add_ca():
    from app.services.cert_manager import create_ca
    if request.method == "POST":
        conn   = get_db()
        result = create_ca(
            conn,
            name=request.form.get("name", "").strip(),
            common_name=request.form.get("common_name", "").strip(),
            key_bits=int(request.form.get("key_bits", 2048) or 2048),
            lifetime_days=int(request.form.get("lifetime_days", 3650) or 3650),
            country=request.form.get("country", "").strip(),
            org=request.form.get("org", "").strip(),
            ou=request.form.get("ou", "").strip(),
            state=request.form.get("state", "").strip(),
            city=request.form.get("city", "").strip(),
        )
        if result["ok"]:
            log_event(category="system", action="ca_created",
                      username=session.get("username"), remote_addr=request.remote_addr,
                      details={"ca_id": result["id"]})
            return redirect(url_for("system.certificates", section="authorities"))
        return render_template("add_ca.html", error=result["message"])
    return render_template("add_ca.html")


@system_bp.route("/add_certificate", methods=["GET", "POST"])
@login_required
def add_certificate():
    from app.services.cert_manager import create_server_cert, create_client_cert, list_certs
    conn = get_db()
    if request.method == "POST":
        cert_type = request.form.get("cert_type", "server").strip().lower()
        ca_id     = request.form.get("ca_id", "")
        try:
            ca_id = int(ca_id)
        except (TypeError, ValueError):
            return render_template("add_certificate.html",
                                   cas=list_certs(conn, cert_type="ca"),
                                   error="A CA must be selected.")
        kwargs = dict(
            conn=conn,
            ca_id=ca_id,
            name=request.form.get("name", "").strip(),
            common_name=request.form.get("common_name", "").strip(),
            key_bits=int(request.form.get("key_bits", 2048) or 2048),
            lifetime_days=int(request.form.get("lifetime_days", 397) or 397),
            country=request.form.get("country", "").strip(),
            org=request.form.get("org", "").strip(),
            ou=request.form.get("ou", "").strip(),
        )
        if cert_type == "client":
            result = create_client_cert(**kwargs)
        else:
            san_raw = request.form.get("san_dns", "")
            san_dns = [s.strip() for s in san_raw.split(",") if s.strip()]
            san_raw_ip = request.form.get("san_ip", "")
            san_ip  = [s.strip() for s in san_raw_ip.split(",") if s.strip()]
            result  = create_server_cert(**kwargs, san_dns=san_dns, san_ip=san_ip)
        if result["ok"]:
            log_event(category="system", action="cert_created",
                      username=session.get("username"), remote_addr=request.remote_addr,
                      details={"cert_id": result["id"], "cert_type": cert_type})
            return redirect(url_for("system.certificates"))
        return render_template("add_certificate.html",
                               cas=list_certs(conn, cert_type="ca"),
                               error=result["message"])
    return render_template("add_certificate.html", cas=list_certs(conn, cert_type="ca"))


@system_bp.route("/api/certificates/<int:cert_id>/revoke", methods=["POST"])
@login_required
@superuser_required
def api_revoke_cert(cert_id):
    from app.services.cert_manager import revoke_cert
    conn   = get_db()
    result = revoke_cert(conn, cert_id)
    log_event(category="system", action="cert_revoked",
              username=session.get("username"), remote_addr=request.remote_addr,
              details={"cert_id": cert_id, "ok": result["ok"]})
    return jsonify(result)


@system_bp.route("/api/certificates/ca/<int:ca_id>/crl", methods=["POST"])
@login_required
def api_generate_crl(ca_id):
    from app.services.cert_manager import generate_crl
    conn   = get_db()
    result = generate_crl(conn, ca_id)
    if result["ok"]:
        from flask import Response
        return Response(result["pem"], mimetype="application/x-pem-file",
                        headers={"Content-Disposition": f"attachment; filename=ca{ca_id}.crl.pem"})
    return jsonify({"ok": False, "message": result["message"]}), 500


@system_bp.route("/api/certificates/<int:cert_id>/ocsp", methods=["GET"])
@login_required
def api_fetch_ocsp(cert_id):
    from app.services.cert_manager import get_cert_pem, fetch_ocsp_response, _rows as _cm_rows
    conn     = get_db()
    cert_pem = get_cert_pem(conn, cert_id)
    if not cert_pem:
        return jsonify({"ok": False, "message": "Certificate not found."}), 404
    # Load issuer cert
    rows     = _cm_rows(conn, "SELECT ca_id FROM certificates WHERE id=?", (cert_id,))
    ca_id    = rows[0]["ca_id"] if rows else None
    issuer_pem = get_cert_pem(conn, ca_id) if ca_id else ""
    if not issuer_pem:
        return jsonify({"ok": False, "message": "CA certificate not found."}), 404
    result = fetch_ocsp_response(cert_pem, issuer_pem)
    if result["ok"]:
        import base64
        return jsonify({"ok": True, "der_b64": base64.b64encode(result["der"]).decode()})
    return jsonify({"ok": False, "message": result["message"]}), 500


@system_bp.route("/api/certificates/acme/request", methods=["POST"])
@login_required
def api_acme_request():
    from app.services.cert_manager import request_acme_cert
    data   = request.get_json(force=True) or {}
    conn   = get_db()
    result = request_acme_cert(
        conn,
        domain=data.get("domain", ""),
        email=data.get("email", ""),
        staging=bool(data.get("staging", False)),
    )
    log_event(category="system", action="acme_cert_request",
              username=session.get("username"), remote_addr=request.remote_addr,
              details={"domain": data.get("domain"), "ok": result.get("ok")})
    return jsonify(result)


@system_bp.route("/api/certificates/<int:cert_id>", methods=["GET"])
@login_required
def api_get_cert(cert_id):
    from app.services.cert_manager import get_cert_pem, list_certs
    conn = get_db()
    rows = list_certs(conn)
    row  = next((r for r in rows if r.get("id") == cert_id), None)
    if not row:
        return jsonify({"ok": False, "message": "Not found"}), 404
    pem = get_cert_pem(conn, cert_id)
    return jsonify({"ok": True, "cert": {**row, "pem": pem}})


@system_bp.route("/api/certificates/<int:cert_id>", methods=["DELETE"])
@login_required
@superuser_required
def api_delete_cert(cert_id):
    from app.services.cert_manager import delete_cert
    conn   = get_db()
    result = delete_cert(conn, cert_id)
    log_event(category="system", action="cert_deleted",
              username=session.get("username"), remote_addr=request.remote_addr,
              details={"cert_id": cert_id, "ok": result["ok"]})
    return jsonify(result)


@system_bp.route("/api/certificates/ca/<int:ca_id>", methods=["DELETE"])
@login_required
def api_delete_ca(ca_id):
    from app.services.cert_manager import delete_ca
    conn   = get_db()
    result = delete_ca(conn, ca_id)
    log_event(category="system", action="ca_deleted",
              username=session.get("username"), remote_addr=request.remote_addr,
              details={"ca_id": ca_id, "ok": result["ok"]})
    return jsonify(result)


# ----------------------------
# HIGH AVAILABILITY
# ----------------------------

@system_bp.route("/high-availability", methods=["GET", "POST"])
@login_required
def high_availability():
    import json as _json
    conn = get_db()
    if request.method == "POST":
        from app.secret_store import encrypt_secret
        raw_pw = request.form.get("remote_password", "").strip()
        pw_enc = encrypt_secret(raw_pw) if raw_pw else ""
        sync_options = _json.dumps(request.form.getlist("sync_options"))
        conn.execute("""
            INSERT INTO ha_settings (id, ss_sync_enabled, sync_interface, filter_host_id,
                peer_ip, xmlrpc_ip, remote_username, remote_password_enc,
                sync_admin, sync_options, updated_at)
            VALUES (1,?,?,?,?,?,?,?,?,?, CURRENT_TIMESTAMP)
            ON CONFLICT(id) DO UPDATE SET
                ss_sync_enabled=excluded.ss_sync_enabled,
                sync_interface=excluded.sync_interface,
                filter_host_id=excluded.filter_host_id,
                peer_ip=excluded.peer_ip,
                xmlrpc_ip=excluded.xmlrpc_ip,
                remote_username=excluded.remote_username,
                remote_password_enc=CASE WHEN excluded.remote_password_enc != ''
                    THEN excluded.remote_password_enc ELSE ha_settings.remote_password_enc END,
                sync_admin=excluded.sync_admin,
                sync_options=excluded.sync_options,
                updated_at=excluded.updated_at
        """, (
            1 if request.form.get("SS-Sync_enabled") else 0,
            request.form.get("sync_interface", "WAN"),
            request.form.get("filter_host_id", ""),
            request.form.get("SS-Sync_peer_ip", ""),
            request.form.get("sync_config_ip", ""),
            request.form.get("remote_username", ""),
            pw_enc,
            1 if request.form.get("sync_admin") else 0,
            sync_options,
        ))
        conn.commit()
        log_event(category="system", action="ha_settings_saved",
                  username=session.get("username"), remote_addr=request.remote_addr)
        return redirect(url_for("system.high_availability"))

    row = conn.execute("SELECT * FROM ha_settings WHERE id=1").fetchone()
    ha  = dict(row) if row else {}
    try:
        ha["sync_options_list"] = _json.loads(ha.get("sync_options") or "[]")
    except Exception:
        ha["sync_options_list"] = []
    return render_template("high_availability.html", ha=ha)


# ----------------------------
# PACKAGE MANAGER
# ----------------------------

@system_bp.route("/package-manager")
@login_required
def package_manager():
    return render_template("package_manager.html")


@system_bp.route("/api/packages", methods=["GET"])
@login_required
def api_packages_list():
    """List installed packages via pkg info. FreeBSD only."""
    import sys, subprocess
    if not sys.platform.startswith("freebsd"):
        return jsonify({"ok": True, "packages": [], "note": "pkg not available on this platform."})
    try:
        result = subprocess.run(
            ["pkg", "info", "--raw=json-compact"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            return jsonify({"ok": False, "message": result.stderr.strip() or "pkg info failed."})
        import json as _j
        pkgs_raw = _j.loads(result.stdout)
        packages = [
            {
                "name":    name,
                "version": meta.get("version", ""),
                "comment": meta.get("comment", ""),
                "size":    meta.get("flatsize", 0),
            }
            for name, meta in pkgs_raw.items()
        ]
        packages.sort(key=lambda p: p["name"].lower())
        return jsonify({"ok": True, "packages": packages, "count": len(packages)})
    except Exception as exc:
        return jsonify({"ok": False, "message": str(exc)})


@system_bp.route("/api/packages/search", methods=["GET"])
@login_required
def api_packages_search():
    """Search available packages in the pkg repository."""
    import sys, subprocess
    query = (request.args.get("q") or "").strip()
    if not query:
        return jsonify({"ok": False, "message": "q parameter required."}), 400
    if not sys.platform.startswith("freebsd"):
        return jsonify({"ok": True, "results": [], "note": "pkg not available on this platform."})
    try:
        result = subprocess.run(
            ["pkg", "search", "--raw=json-compact", "--exact", "--", query],
            capture_output=True, text=True, timeout=30,
        )
        import json as _j
        results = []
        try:
            pkgs_raw = _j.loads(result.stdout)
            results = [
                {
                    "name":    name,
                    "version": meta.get("version", ""),
                    "comment": meta.get("comment", ""),
                }
                for name, meta in pkgs_raw.items()
            ]
        except Exception:
            # Fallback: plain-text search output
            for line in result.stdout.splitlines():
                if line.strip():
                    parts = line.split(None, 1)
                    results.append({"name": parts[0], "version": "", "comment": parts[1] if len(parts) > 1 else ""})
        return jsonify({"ok": True, "results": results, "count": len(results)})
    except Exception as exc:
        return jsonify({"ok": False, "message": str(exc)})


@system_bp.route("/api/packages/install", methods=["POST"])
@superuser_required
def api_packages_install():
    """Install a package via pkg install. FreeBSD + priv_helper only."""
    import sys, re
    if not sys.platform.startswith("freebsd"):
        return jsonify({"ok": False, "message": "pkg install is only available on FreeBSD."}), 400
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name or not re.match(r'^[A-Za-z0-9._+-]+$', name):
        return jsonify({"ok": False, "message": "Invalid package name."}), 400
    try:
        from app.services.priv_helper import run_privileged
        result = run_privileged("pkg.install", package_name=name)
        ok  = result.returncode == 0
        msg = (result.stdout or result.stderr or "").strip()
        from app.audit_log import log_event as _log_event
        _log_event(category="system", action="pkg_install",
                   username=session.get("username"), remote_addr=request.remote_addr,
                   details={"package": name, "ok": ok})
        return jsonify({"ok": ok, "message": msg or ("Installed" if ok else "Install failed")})
    except Exception as exc:
        return jsonify({"ok": False, "message": str(exc)})


# ----------------------------
# PREFLIGHT / SYSTEM HEALTH
# ----------------------------

@system_bp.route("/preflight")
@login_required
def preflight():
    from app.services.freebsd_setup import preflight_check
    report = preflight_check()
    return render_template("preflight.html", report=report)


@system_bp.route("/api/preflight", methods=["GET"])
@login_required
def preflight_api():
    from app.services.freebsd_setup import preflight_check
    return jsonify(preflight_check())


# ----------------------------
# SETUP WIZARD
# ----------------------------

@system_bp.route("/setup-wizard")
@login_required
def setup_wizard():
    return render_template("setup_wizard.html")


@system_bp.route("/setup-wizard/step/<int:step>")
@login_required
def setup_wizard_step(step):
    if step in range(2, 11):
        return render_template(f"setup_wizard_step{step}.html")
    return "Invalid wizard step", 404


@system_bp.route("/api/setup-wizard/general", methods=["POST"])
@login_required
def api_setup_wizard_general():
    import os as _os
    data = request.get_json(force=True) or {}
    cfg  = _load_general_config()
    cfg["hostname"]   = (data.get("hostname") or cfg.get("hostname", "SmartShield")).strip()
    cfg["domain"]     = (data.get("domain")   or cfg.get("domain",   "home.arpa")).strip()
    dns1 = (data.get("primary_dns")   or "").strip()
    dns2 = (data.get("secondary_dns") or "").strip()
    cfg["dns_servers"]  = [d for d in [dns1, dns2] if d]
    cfg["dns_override"] = bool(data.get("override_dns", True))
    config_file = _general_config_path()
    _os.makedirs(_os.path.dirname(_os.path.abspath(config_file)), exist_ok=True)
    with open(config_file, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=4)
    return jsonify({"ok": True, "message": "General settings saved."})


@system_bp.route("/api/setup-wizard/time", methods=["POST"])
@login_required
def api_setup_wizard_time():
    import os as _os
    data = request.get_json(force=True) or {}
    conn = get_db()

    cfg = _load_general_config()
    cfg["timezone"] = (data.get("timezone") or "Etc/UTC").strip()
    config_file = _general_config_path()
    _os.makedirs(_os.path.dirname(_os.path.abspath(config_file)), exist_ok=True)
    with open(config_file, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=4)

    ntp_row = conn.execute(
        "SELECT value_json FROM service_state WHERE key_name='ntp_settings'"
    ).fetchone()
    ntp_cfg = json.loads(ntp_row["value_json"]) if ntp_row else {}
    ntp_server = (data.get("ntp_server") or "").strip()
    if ntp_server:
        servers = ntp_cfg.get("servers", [])
        if ntp_server not in servers:
            servers = [ntp_server] + [s for s in servers if s]
        ntp_cfg["servers"] = servers[:4]
    ntp_cfg.setdefault("enabled", True)
    conn.execute(
        "INSERT INTO service_state (key_name, value_json, updated_at) VALUES ('ntp_settings',?,CURRENT_TIMESTAMP)"
        " ON CONFLICT(key_name) DO UPDATE SET value_json=excluded.value_json, updated_at=CURRENT_TIMESTAMP",
        (json.dumps(ntp_cfg),)
    )
    conn.commit()
    return jsonify({"ok": True, "message": "Time settings saved."})


# ----------------------------
# COPYRIGHT PAGE
# ----------------------------

@system_bp.route("/copyright", methods=["GET", "POST"])
@login_required
def copyright_page():
    if request.method == "POST":
        return redirect(url_for("system.dashboard"))
    return render_template("copyright.html")


# ----------------------------
# SYSTEM UPDATE PAGE
# ----------------------------

@system_bp.route("/update", methods=["GET", "POST"])
@login_required
def update_page():
    active_tab = "system"
    message = None

    if request.method == "POST":
        if "check_updates" in request.form:
            message = "Checking for updates..."
            active_tab = "system"

        elif "update_system" in request.form:
            message = "System update initiated..."
            active_tab = "system"

        elif "save_settings" in request.form:
            message = "Settings saved successfully"
            active_tab = "settings"

    return render_template("update.html", message=message, active_tab=active_tab)


# ----------------------------
# NOTIFICATIONS
# ----------------------------

_NOTIF_BOOL_FIELDS = {
    "certificate_expiration", "ignore_revoked", "disable_smtp",
    "secure_smtp_connection", "validate_ssl_tls",
    "console_bell", "startup_shutdown_sound", "enable_telegram",
}

@system_bp.route("/notifications", methods=["GET", "POST"])
@login_required
def notifications():
    conn = get_db()
    if request.method == "POST":
        data = {}
        for key, value in request.form.items():
            if key == "csrf_token":
                continue
            data[key] = value
        for field in _NOTIF_BOOL_FIELDS:
            data[field] = field in request.form
        conn.execute(
            "INSERT INTO service_state(key_name, value_json) VALUES('notification_settings', ?) "
            "ON CONFLICT(key_name) DO UPDATE SET value_json=excluded.value_json, updated_at=CURRENT_TIMESTAMP",
            (json.dumps(data),),
        )
        conn.commit()
        flash("Notification settings saved.", "success")
        return redirect(url_for("system.notifications"))

    row = conn.execute(
        "SELECT value_json FROM service_state WHERE key_name='notification_settings'"
    ).fetchone()
    settings = json.loads(row["value_json"]) if row else {}
    return render_template("notifications.html", settings=settings)
