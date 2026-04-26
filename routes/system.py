from flask import Blueprint, render_template, redirect, url_for, request, session, jsonify
from app.database import get_db
from app.auth_utils import login_required
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


def _build_dashboard_payload():
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

    conn.close()

    try:
        dashboard_columns = int(config.get("dashboard_columns", 2))
    except (TypeError, ValueError):
        dashboard_columns = 2
    dashboard_columns = min(max(dashboard_columns, 1), 4)

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

@system_bp.route("/docs")
def docs():
    return render_template("docs.html")

@system_bp.route("/about")
def about():
    return render_template("about.html")

@system_bp.route("/bug")
def bug():
    return render_template("bug.html")

@system_bp.route("/forum")
def forum():
    return render_template("forum.html")

@system_bp.route("/freebsd")
def freebsd():
    return render_template("freebsd.html")

@system_bp.route("/smart-shield-book")
def smart_shield_book():
    return render_template("smart_shield_book.html")

@system_bp.route("/paid-support")
def paid_support():
    return render_template("paid_support.html")

@system_bp.route("/survey")
def survey():
    return render_template("survey.html")

@system_bp.route("/upgrade")
def upgrade():
    return render_template("upgrade.html")

@system_bp.route("/help")
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
            1 if request.form.get('serial_terminal') else 0,
            request.form.get('serial_speed', '115200'),
            request.form.get('primary_console', 'video'),
            1 if request.form.get('console_menu') else 0
        ))
        conn.commit()
    
    cursor.execute("SELECT * FROM advanced_admin_access WHERE id = 1")
    config = cursor.fetchone()
    conn.close()
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
    conn.close()
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
    conn.close()
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
    conn.close()
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
    conn.close()
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
    
    conn.close()
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
    conn.close()
    return redirect(url_for("system.advanced_system_tunables"))


@system_bp.route("/advanced/system-tunables/delete/<int:index>", methods=["POST"])
@login_required
def advanced_system_tunables_delete(index):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM advanced_system_tunables WHERE id = ?", (index,))
    conn.commit()
    conn.close()
    return redirect(url_for("system.advanced_system_tunables"))


# ----------------------------
# CERTIFICATES
# ----------------------------

@system_bp.route("/certificates")
@login_required
def certificates():
    active_section = request.args.get("section", "certificates")
    if active_section not in ("authorities", "certificates", "revocation"):
        active_section = "certificates"
    conn = get_db()
    cur  = conn.cursor()
    cas = []
    try:
        cur.execute("SELECT * FROM certificate_authorities ORDER BY descriptive_name")
        for row in cur.fetchall():
            row = dict(row)
            dn_parts = []
            if row.get("common_name"):           dn_parts.append(f"CN={row['common_name']}")
            if row.get("organization"):          dn_parts.append(f"O={row['organization']}")
            if row.get("organizational_unit"):   dn_parts.append(f"OU={row['organizational_unit']}")
            if row.get("country_code"):          dn_parts.append(f"C={row['country_code']}")
            cas.append({
                "name":               row.get("descriptive_name", "—"),
                "internal":           True,
                "issuer":             "Self-signed",
                "certificates":       0,
                "distinguished_name": ", ".join(dn_parts) if dn_parts else "—",
                "in_use":             False,
            })
    except Exception:
        cas = []
    return render_template(
        "certificates.html",
        active_section=active_section,
        cas=cas,
        certs=[],
        crls=[],
    )

@system_bp.route("/add_ca", methods=["GET", "POST"])
@login_required
def add_ca():
    if request.method == "POST":
        # Handle form submission - currently just redirect back
        # CA data would be saved to database here when implemented
        return redirect(url_for("system.certificates"))
    return render_template("add_ca.html")

@system_bp.route("/add_certificate", methods=["GET", "POST"])
@login_required
def add_certificate():
    if request.method == "POST":
        # Handle form submission - currently just redirect back
        return redirect(url_for("system.certificates"))
    return render_template("add_certificate.html")


# ----------------------------
# HIGH AVAILABILITY
# ----------------------------

@system_bp.route("/high-availability", methods=["GET", "POST"])
@login_required
def high_availability():
    if request.method == "POST":
        return redirect(url_for("system.high_availability"))
    return render_template("high_availability.html")


# ----------------------------
# PACKAGE MANAGER
# ----------------------------

@system_bp.route("/package-manager")
@login_required
def package_manager():
    return render_template("package_manager.html")


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

@system_bp.route("/notifications", methods=["GET", "POST"])
@login_required
def notifications():
    if request.method == "POST":
        return redirect(url_for("system.notifications"))
    return render_template("notifications.html")
