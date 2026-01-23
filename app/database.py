import sqlite3

DATABASE = "data.db"

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    # USERS TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        full_name TEXT,
        status TEXT DEFAULT 'active',
        profile_picture TEXT,
        email TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # GROUPS TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS groups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        description TEXT
    )
    """)

    # USER-GROUP LINK
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS user_groups (
        user_id INTEGER,
        group_id INTEGER,
        PRIMARY KEY (user_id, group_id),
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(group_id) REFERENCES groups(id)
    )
    """)

    # ADVANCED ADMIN ACCESS TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS advanced_admin_access (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        protocol TEXT DEFAULT 'https',
        ssl_cert TEXT DEFAULT 'default',
        tcp_port INTEGER,
        max_processes INTEGER DEFAULT 2,
        webgui_redirect INTEGER DEFAULT 0,
        ocsp_stapling INTEGER DEFAULT 0,
        webgui_autocomplete INTEGER DEFAULT 1,
        gui_login_messages INTEGER DEFAULT 0,
        roaming INTEGER DEFAULT 1,
        hsts INTEGER DEFAULT 0,
        anti_lockout INTEGER DEFAULT 0,
        dns_rebind INTEGER DEFAULT 0,
        alternate_hostnames TEXT,
        http_referer INTEGER DEFAULT 0,
        browser_tab_text INTEGER DEFAULT 0,
        enable_ssh INTEGER DEFAULT 0,
        ssh_key_only TEXT DEFAULT 'password_or_key',
        ssh_agent_forwarding INTEGER DEFAULT 0,
        ssh_port INTEGER DEFAULT 22,
        threshold INTEGER DEFAULT 30,
        blocktime INTEGER DEFAULT 120,
        detection_time INTEGER DEFAULT 1800,
        pass_list TEXT,
        serial_terminal INTEGER DEFAULT 0,
        serial_speed TEXT DEFAULT '115200',
        primary_console TEXT DEFAULT 'video',
        console_menu INTEGER DEFAULT 0
    )
    """)

    # ADVANCED FIREWALL & NAT TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS advanced_firewall_nat (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_fragment INTEGER DEFAULT 0,
        ip_random INTEGER DEFAULT 0,
        firewall_optimization TEXT DEFAULT 'normal',
        disable_scrub INTEGER DEFAULT 0,
        adaptive_start INTEGER DEFAULT 1134000,
        adaptive_end INTEGER DEFAULT 2333332,
        firewall_max_states INTEGER DEFAULT 1990000,
        firewall_max_table INTEGER DEFAULT 400000,
        firewall_max_fragment INTEGER DEFAULT 5000,
        vpn_ip_fragment INTEGER DEFAULT 0,
        ip_fragment_reassemble INTEGER DEFAULT 0,
        enable_mss INTEGER DEFAULT 0,
        maximum_mss INTEGER DEFAULT 1400,
        disable_firewall INTEGER DEFAULT 0,
        firewall_state_policy TEXT DEFAULT 'interface_bound',
        disable_static_policy INTEGER DEFAULT 0,
        static_route_filtering INTEGER DEFAULT 0,
        disable_auto_added_vpn INTEGER DEFAULT 0,
        disable_reply_to INTEGER DEFAULT 0,
        disable_negate_rules INTEGER DEFAULT 0,
        allow_apipa INTEGER DEFAULT 0,
        aliases_hostnames_interval INTEGER DEFAULT 300,
        check_certificate_aliases_urls INTEGER DEFAULT 0,
        update_frequency TEXT DEFAULT 'monthly',
        nat_reflection_mode TEXT DEFAULT 'disabled',
        reflection_timeout INTEGER,
        enable_nat_reflection INTEGER DEFAULT 0,
        enable_automatic_outbound INTEGER DEFAULT 0,
        tftp_proxy_wan INTEGER DEFAULT 0,
        tftp_proxy_lan INTEGER DEFAULT 0,
        tcp_first INTEGER,
        tcp_opening INTEGER,
        tcp_established INTEGER,
        tcp_closing INTEGER,
        tcp_fin_wait INTEGER,
        tcp_closed INTEGER,
        tcp_tsdiff INTEGER,
        sctp_first INTEGER,
        sctp_opening INTEGER,
        sctp_established INTEGER,
        sctp_closing INTEGER,
        sctp_closed INTEGER,
        udp_first INTEGER,
        udp_single INTEGER,
        udp_multiple INTEGER,
        icmp_first INTEGER,
        icmp_error INTEGER,
        other_first INTEGER,
        other_single INTEGER,
        other_multiple INTEGER
    )
    """)

    # ADVANCED NETWORK TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS advanced_network (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        server_backend TEXT DEFAULT 'kea_dhcp',
        ignore_deprecation INTEGER DEFAULT 0,
        radvd_debug INTEGER DEFAULT 0,
        dhcp6_debug INTEGER DEFAULT 0,
        do_not_allow_release INTEGER DEFAULT 0,
        dhcpv6_duid TEXT DEFAULT 'raw_duid',
        raw_duid TEXT,
        allow_ipv6 INTEGER DEFAULT 1,
        ipv6_over_ipv4_tunneling INTEGER DEFAULT 0,
        ipv4_address_tunnel_peer TEXT,
        prefer_ipv4_over_ipv6 INTEGER DEFAULT 0,
        ipv6_dns_entry INTEGER DEFAULT 0,
        hardware_checksum_offloading INTEGER DEFAULT 0,
        hardware_tcp_segmentation INTEGER DEFAULT 0,
        hardware_large_receive INTEGER DEFAULT 0,
        hn_altq_support INTEGER DEFAULT 0,
        arp_handling INTEGER DEFAULT 0,
        reset_all_states INTEGER DEFAULT 0,
        if_pppoe_kernel INTEGER DEFAULT 0
    )
    """)

    # ADVANCED MISCELLANEOUS TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS advanced_miscellaneous (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        proxy_url TEXT,
        proxy_port TEXT,
        proxy_username TEXT,
        proxy_password TEXT,
        load_balancing INTEGER DEFAULT 0,
        sticky_timeout INTEGER DEFAULT 0,
        powerd INTEGER DEFAULT 0,
        ac_power TEXT DEFAULT 'hadaptive',
        battery_power TEXT DEFAULT 'hadaptive',
        unknown_power TEXT DEFAULT 'hadaptive',
        cryptographic_hardware TEXT DEFAULT 'none',
        thermal_sensors TEXT DEFAULT 'none_acpi',
        kernel_pti INTEGER DEFAULT 0,
        mds_mode TEXT DEFAULT 'mitigation_disabled',
        schedule_states INTEGER DEFAULT 0,
        state_killing_on_gateway_recovery TEXT DEFAULT 'dont_kill',
        dont_kill_policy_routing INTEGER DEFAULT 0,
        state_killing_on_gateway_failure TEXT DEFAULT 'do_not_kill',
        skip_rules_gateway_down INTEGER DEFAULT 0,
        static_routes INTEGER DEFAULT 0,
        memory_limit TEXT,
        use_ram_disks INTEGER DEFAULT 0,
        tmp_ram_disk TEXT,
        var_ram_disk TEXT,
        rrd_data_backup TEXT,
        dhcp_leases_backup TEXT,
        log_directory_backup TEXT,
        captive_portal_data_backup TEXT,
        hard_disk_standby_time TEXT DEFAULT 'always_on',
        smart_shield_device_id INTEGER DEFAULT 0
    )
    """)

    # ADVANCED SYSTEM TUNABLES TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS advanced_system_tunables (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        value TEXT NOT NULL
    )
    """)

    # Create default admin if not exists
    cursor.execute("SELECT COUNT(*) AS c FROM users")
    if cursor.fetchone()["c"] == 0:
        cursor.execute("""
            INSERT INTO users (username, password, full_name)
            VALUES ('admin', '1234', 'System Administrator')
        """)
        cursor.execute("""
            INSERT INTO groups (name, description)
            VALUES ('admins', 'System Administrators')
        """)
        cursor.execute("""
            INSERT INTO user_groups (user_id, group_id)
            VALUES (1, 1)
        """)

    # Create default advanced settings if not exists
    cursor.execute("SELECT COUNT(*) AS c FROM advanced_admin_access")
    if cursor.fetchone()["c"] == 0:
        cursor.execute("INSERT INTO advanced_admin_access DEFAULT VALUES")

    cursor.execute("SELECT COUNT(*) AS c FROM advanced_firewall_nat")
    if cursor.fetchone()["c"] == 0:
        cursor.execute("INSERT INTO advanced_firewall_nat DEFAULT VALUES")

    cursor.execute("SELECT COUNT(*) AS c FROM advanced_network")
    if cursor.fetchone()["c"] == 0:
        cursor.execute("INSERT INTO advanced_network DEFAULT VALUES")

    cursor.execute("SELECT COUNT(*) AS c FROM advanced_miscellaneous")
    if cursor.fetchone()["c"] == 0:
        cursor.execute("INSERT INTO advanced_miscellaneous DEFAULT VALUES")

    # Create default system tunable if not exists
    cursor.execute("SELECT COUNT(*) AS c FROM advanced_system_tunables")
    if cursor.fetchone()["c"] == 0:
        cursor.execute("""
            INSERT INTO advanced_system_tunables (name, description, value)
            VALUES ('net.inet.ip.portrange.first', 'First port in the ephemeral port range', '1024')
        """)

    conn.commit()


    # database.py - Add these inside init_db()

    # NAT Port Forward Rules
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS nat_pf (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        disabled INTEGER DEFAULT 0,
        interface TEXT,
        protocol TEXT,
        src_type TEXT,
        src_address TEXT,
        dst_type TEXT,
        dst_address TEXT,
        redirect_ip TEXT,
        description TEXT,
        nat_reflection TEXT
    )
    """)

    # 1:1 NAT Mappings
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS nat_1to1 (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        disabled INTEGER DEFAULT 0,
        interface TEXT,
        external_address TEXT,
        internal_address TEXT,
        destination_address TEXT,
        description TEXT
    )
    """)

    # Outbound NAT Rules
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS nat_outbound (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        disabled INTEGER DEFAULT 0,
        interface TEXT,
        src_address TEXT,
        dst_address TEXT,
        nat_address TEXT,
        static_port INTEGER DEFAULT 0,
        description TEXT
    )
    """)

    # NPt (Network Prefix Translation) IPv6
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS nat_npt (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        disabled INTEGER DEFAULT 0,
        interface TEXT,
        src_not INTEGER DEFAULT 0,
        src_prefix TEXT,
        src_prefix_length INTEGER,
        dst_not INTEGER DEFAULT 0,
        dst_type TEXT,
        dst_prefix TEXT,
        dst_prefix_length INTEGER,
        description TEXT
    )
    """)

    # Firewall Rules - Floating
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS firewall_rules_floating (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        disabled INTEGER DEFAULT 0,
        interface TEXT,
        protocol TEXT,
        source TEXT,
        source_port TEXT,
        destination TEXT,
        dest_port TEXT,
        gateway TEXT,
        queue TEXT,
        schedule TEXT,
        description TEXT,
        rule_order INTEGER DEFAULT 0
    )
    """)

    # Firewall Rules - WAN
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS firewall_rules_wan (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT DEFAULT 'pass',
        disabled INTEGER DEFAULT 0,
        protocol TEXT,
        source TEXT,
        destination TEXT,
        description TEXT,
        rule_order INTEGER DEFAULT 0
    )
    """)

    # Firewall Rules - LAN
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS firewall_rules_lan (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        disabled INTEGER DEFAULT 0,
        interface TEXT,
        protocol TEXT,
        source TEXT,
        destination TEXT,
        description TEXT,
        rule_order INTEGER DEFAULT 0
    )
    """)

    # Firewall Aliases
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS firewall_aliases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        type TEXT,
        alias_values TEXT,
        description TEXT
    )
    """)
    
    conn.commit()
    conn.close()
