from routes.system import system_bp
from routes.system._common import *  # noqa: F401,F403
from routes.system._common import _general_config_path, _config_bool, _load_general_config, _safe_count, _build_dashboard_payload  # noqa: F401


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
                console_menu = ?,
                terminal_enabled = ?
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
            1 if request.form.get('console_menu') else 0,
            1 if request.form.get('terminal_enabled') else 0
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
