import os
import sqlite3
import sys
import tempfile
from werkzeug.security import generate_password_hash

_MEMORY_ANCHOR_CONN = None
_MEMORY_ANCHOR_PATH = None


def _default_db_path():
    if sys.platform.startswith("freebsd"):
        return "/var/db/smart-shield/data.db"
    if sys.platform.startswith("win"):
        # Keep Windows dev DB out of compressed/synced workdirs and in persistent user-local storage.
        local_appdata = os.getenv("LOCALAPPDATA") or tempfile.gettempdir()
        return os.path.join(local_appdata, "SmartShield", "data.db")
    return "data.db"


def _database_path():
    # Read from env at call time so tests and runtime overrides behave deterministically.
    return os.getenv("SMARTSHIELD_DB_PATH", _default_db_path())


def _ensure_parent_dir(path: str):
    parent_dir = os.path.dirname(os.path.abspath(path))
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)


def get_db():
    global _MEMORY_ANCHOR_CONN, _MEMORY_ANCHOR_PATH
    db_path = _database_path()
    is_uri = db_path.startswith("file:")
    if not is_uri:
        _ensure_parent_dir(db_path)
    elif "mode=memory" in db_path:
        # Keep an anchor connection alive so shared-memory DBs persist across connections.
        if _MEMORY_ANCHOR_CONN is None or _MEMORY_ANCHOR_PATH != db_path:
            if _MEMORY_ANCHOR_CONN is not None:
                _MEMORY_ANCHOR_CONN.close()
            _MEMORY_ANCHOR_CONN = sqlite3.connect(db_path, uri=True)
            _MEMORY_ANCHOR_CONN.execute("PRAGMA foreign_keys = ON")
            _MEMORY_ANCHOR_PATH = db_path
    conn = sqlite3.connect(db_path, uri=is_uri)
    conn.execute("PRAGMA foreign_keys = ON")
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
        is_superuser INTEGER DEFAULT 0,
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

    # Backward-compatible migration for older DBs created before is_superuser existed.
    cursor.execute("PRAGMA table_info(users)")
    user_columns = {row["name"] for row in cursor.fetchall()}
    if "is_superuser" not in user_columns:
        cursor.execute("ALTER TABLE users ADD COLUMN is_superuser INTEGER DEFAULT 0")

    # Group-level page whitelist permissions.
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS group_page_permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id INTEGER NOT NULL,
            endpoint TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(group_id) REFERENCES groups(id) ON DELETE CASCADE
        )
        """
    )
    cursor.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_group_page_permissions_group_endpoint
        ON group_page_permissions(group_id, endpoint)
        """
    )

    # LAN INTERFACE CONFIGURATION TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS lan_config (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        enable_interface INTEGER DEFAULT 1,
        description TEXT DEFAULT 'LAN',
        ipv4_config_type TEXT DEFAULT 'static',
        ipv6_config_type TEXT DEFAULT 'none',
        mac_address TEXT DEFAULT '',
        mtu TEXT DEFAULT '',
        mss TEXT DEFAULT '',
        speed_and_duplex TEXT DEFAULT 'default',
        ipv4_address TEXT DEFAULT '192.168.1.1/24',
        ipv4_upstream_gateway TEXT DEFAULT '',
        block_private_networks INTEGER DEFAULT 0,
        block_bogon_networks INTEGER DEFAULT 0
    )
    """)

    # WAN INTERFACE CONFIGURATION TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS wan_config (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        enable_interface INTEGER DEFAULT 1,
        description TEXT DEFAULT 'WAN',
        ipv4_config_type TEXT DEFAULT 'dhcp',
        ipv6_config_type TEXT DEFAULT 'none',
        mac_address TEXT DEFAULT '',
        mtu TEXT DEFAULT '',
        mss TEXT DEFAULT '',
        speed_and_duplex TEXT DEFAULT 'default',
        ipv4_address TEXT DEFAULT '',
        ipv4_upstream_gateway TEXT DEFAULT '',
        username TEXT DEFAULT '',
        password TEXT DEFAULT '',
        dial_on_demand INTEGER DEFAULT 0,
        idle_timeout INTEGER DEFAULT 0,
        block_private_networks INTEGER DEFAULT 1,
        block_bogon_networks INTEGER DEFAULT 1
    )
    """)

    # PORT ASSIGNMENTS TABLE
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS port_assignments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            interface_label TEXT, -- e.g., 'WAN' or 'LAN'
            network_port TEXT     -- e.g., 'em0 (00:0c...)'
        )
    ''')

    # INTERFACE ASSIGNMENTS TABLE
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS interface_assignments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        interface_type TEXT NOT NULL UNIQUE,
        network_port TEXT
    )
''')
    cursor.execute("""
CREATE UNIQUE INDEX IF NOT EXISTS idx_interface_assignments_type
ON interface_assignments(interface_type)
""")

    # INTERFACE GROUPS TABLE
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS interface_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_name TEXT NOT NULL,
            description TEXT,
            members TEXT
        )
    ''')

    # WIRELESS CONFIGS TABLE
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS wireless_configs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            parent_interface TEXT,
            mode TEXT,
            description TEXT
        )
    ''')

    # VLAN CONFIGS TABLE
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vlan_configs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            parent_interface TEXT,
            vlan_tag INTEGER,
            vlan_priority INTEGER DEFAULT 0,
            description TEXT
        )
    ''')

    # QINQ CONFIGS TABLE
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS qinq_configs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            parent_interface TEXT,
            first_level_tag INTEGER,
            add_to_groups INTEGER DEFAULT 0,
            description TEXT,
            member_tags TEXT
        )
    ''')

    # PPP CONFIGS TABLE
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ppp_configs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            link_type TEXT,
            link_interfaces TEXT,
            description TEXT,
            username TEXT,
            password TEXT,
            dial_on_demand INTEGER DEFAULT 0
        )
    ''')

    # GRE CONFIGS TABLE
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS gre_configs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            parent_interface TEXT,
            gre_remote_address TEXT,
            gre_local_address TEXT,
            ipv4_tunnel_remote_address TEXT,
            ipv4_tunnel_remote_prefix INTEGER,
            ipv4_tunnel_local_address TEXT,
            ipv4_tunnel_local_prefix INTEGER,
            ipv6_tunnel_remote_address TEXT,
            ipv6_tunnel_remote_prefix INTEGER,
            ipv6_tunnel_local_address TEXT,
            ipv6_tunnel_local_prefix INTEGER,
            description TEXT
        )
    ''')

    # GIF CONFIGS TABLE
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS gif_configs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            parent_interface TEXT,
            gif_remote_address TEXT,
            gif_tunnel_local_address TEXT,
            gif_tunnel_remote_address TEXT,
            gif_tunnel_subnet INTEGER,
            ecn_friendly_behavior INTEGER DEFAULT 0,
            outer_source_filtering INTEGER DEFAULT 0,
            description TEXT
        )
    ''')

    # BRIDGE CONFIGS TABLE
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS bridge_configs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            member_interfaces TEXT,
            description TEXT,
            cache_size INTEGER DEFAULT 100,
            cache_max_age INTEGER DEFAULT 240,
            span_interfaces TEXT,
            edge_interfaces TEXT,
            auto_edge_interfaces TEXT,
            ptp_interfaces TEXT,
            sticky_ports INTEGER DEFAULT 0
        )
    ''')

    # LAGG CONFIGS TABLE
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS lagg_configs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            parent_interfaces TEXT,
            aggregation_protocol TEXT,
            description TEXT
        )
    ''')

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

    # ----------------------------
    # VPN / IPsec Mobile Clients
    # ----------------------------
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS ipsec_mobile_clients_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            ike_extensions INTEGER DEFAULT 0,
            group_auth INTEGER DEFAULT 0,
            radius_accounting INTEGER DEFAULT 0,
            virtual_address_pool INTEGER DEFAULT 1,
            virtual_ipv6_address_pool INTEGER DEFAULT 0,
            radius_ip_priority INTEGER DEFAULT 0,
            radius_advanced_parameters INTEGER DEFAULT 0,
            network_list INTEGER DEFAULT 1,
            save_xauth_password INTEGER DEFAULT 0,
            dns_default_domain INTEGER DEFAULT 0,
            split_dns INTEGER DEFAULT 0,
            dns_servers INTEGER DEFAULT 0,
            wins_servers INTEGER DEFAULT 0,
            phase2_pfs_group INTEGER DEFAULT 0,
            login_banner INTEGER DEFAULT 0,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    # ensure singleton row exists
    cursor.execute(
        """
        INSERT OR IGNORE INTO ipsec_mobile_clients_settings (id)
        VALUES (1)
        """
    )

    # ----------------------------
    # VPN / IPsec Pre-Shared Keys
    # ----------------------------
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS ipsec_pre_shared_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            identifier TEXT NOT NULL,
            secret_type TEXT NOT NULL DEFAULT 'psk',
            pre_shared_key TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    cursor.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_ipsec_psk_identifier_type
        ON ipsec_pre_shared_keys(identifier, secret_type)
        """
    )

    # ----------------------------
    # VPN / IPsec Advanced Settings
    # ----------------------------
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS ipsec_advanced_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),

            -- Logging controls (defaults: Control)
            log_daemon TEXT DEFAULT 'Control',
            log_sa_manager TEXT DEFAULT 'Control',
            log_ike_sa TEXT DEFAULT 'Control',
            log_ike_child_sa TEXT DEFAULT 'Control',
            log_job_processing TEXT DEFAULT 'Control',
            log_config_backend TEXT DEFAULT 'Control',
            log_kernel_interface TEXT DEFAULT 'Control',
            log_networking TEXT DEFAULT 'Control',
            log_asn_encoding TEXT DEFAULT 'Control',
            log_message_encoding TEXT DEFAULT 'Control',
            log_integrity_checker TEXT DEFAULT 'Control',
            log_integrity_verifier TEXT DEFAULT 'Control',
            log_platform_trust_service TEXT DEFAULT 'Control',
            log_tls_handler TEXT DEFAULT 'Control',
            log_ipsec_traffic TEXT DEFAULT 'Control',
            log_strongswan_lib TEXT DEFAULT 'Control',

            -- Advanced IPsec Settings
            unique_ids TEXT DEFAULT 'Yes (Replace)',
            ipsec_filter_mode TEXT DEFAULT 'Filter [IPsec Tunnel, Transport, and VTI] on IPsec tab (enc0)',
            ikev2_retransmission INTEGER DEFAULT 0,
            ip_compression INTEGER DEFAULT 0,
            pkcs11_support INTEGER DEFAULT 0,
            strict_interface_binding INTEGER DEFAULT 0,
            ikev1_unencrypted_payloads INTEGER DEFAULT 0,
            max_ikev1_phase2_exchanges INTEGER DEFAULT 3,
            enable_cisco_extensions INTEGER DEFAULT 0,
            strict_crl_checking INTEGER DEFAULT 0,
            fqdn_endpoints_resolve_interval INTEGER DEFAULT 60,
            make_before_break INTEGER DEFAULT 0,
            asynchronous_cryptography INTEGER DEFAULT 0,
            custom_ike_port TEXT DEFAULT '',
            custom_nat_t_port TEXT DEFAULT '',
            auto_exclude_lan_address INTEGER DEFAULT 0,
            additional_ipsec_bypass INTEGER DEFAULT 0,

            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    cursor.execute(
        """
        INSERT OR IGNORE INTO ipsec_advanced_settings (id)
        VALUES (1)
        """
    )

    # ----------------------------
    # VPN / L2TP Configuration
    # ----------------------------
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS l2tp_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            enabled INTEGER DEFAULT 1,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    cursor.execute(
        """
        INSERT OR IGNORE INTO l2tp_settings (id)
        VALUES (1)
        """
    )

    # ----------------------------
    # FIREWALL SCHEDULES
    # ----------------------------
    # A schedule is a named container; it can have multiple configured date/time ranges.
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS firewall_schedules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        description TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS firewall_schedule_ranges (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        schedule_id INTEGER NOT NULL,
        year INTEGER NOT NULL,
        month INTEGER NOT NULL,
        days_csv TEXT NOT NULL, -- comma-separated day numbers (1-31)
        start_time TEXT NOT NULL, -- HH:MM
        end_time TEXT NOT NULL,   -- HH:MM
        range_description TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(schedule_id) REFERENCES firewall_schedules(id) ON DELETE CASCADE
    )
    """)

    # Index for fast listing
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_firewall_schedule_ranges_schedule_id ON firewall_schedule_ranges(schedule_id)")

    # ----------------------------
    # VIRTUAL IPs
    # ----------------------------
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS virtual_ips_configs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT NOT NULL,
        interface TEXT NOT NULL,
        address_type TEXT DEFAULT 'single',
        address TEXT NOT NULL,
        prefix INTEGER DEFAULT 32,
        expansion INTEGER DEFAULT 0,
        description TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # ----------------------------
    # DHCP RELAY
    # ----------------------------
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS dhcp_relay_settings (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        enabled INTEGER DEFAULT 0,
        downstream_interfaces TEXT DEFAULT '',
        carp_status_vip TEXT DEFAULT 'none',
        append_circuit_id INTEGER DEFAULT 0,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS dhcp_relay_upstream_servers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        server_address TEXT NOT NULL
    )
    """)

    cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_dhcp_relay_upstream_server_address ON dhcp_relay_upstream_servers(server_address)")

    # ----------------------------
    # VPN / IPsec (Phase 1)
    # ----------------------------
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ipsec_phase1 (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        disabled INTEGER DEFAULT 0,
        ike_version TEXT DEFAULT 'ikev2',
        internet_protocol TEXT DEFAULT 'ipv4',
        interface TEXT DEFAULT 'wan',
        remote_gateway TEXT NOT NULL,
        auth_method TEXT DEFAULT 'mutual-psk',
        my_identifier TEXT DEFAULT 'my-ip',
        peer_identifier TEXT DEFAULT 'peer-ip',
        pre_shared_key TEXT DEFAULT '',
        p1_life_time INTEGER DEFAULT 28800,
        p1_rekey_time INTEGER DEFAULT 25920,
        p1_reauth_time INTEGER DEFAULT 0,
        p1_rand_time INTEGER DEFAULT 2880,
        child_sa_start_action TEXT DEFAULT 'default',
        child_sa_close_action TEXT DEFAULT 'default',
        nat_traversal TEXT DEFAULT 'auto',
        mobike TEXT DEFAULT 'disable',
        gateway_duplicates INTEGER DEFAULT 0,
        split_connections INTEGER DEFAULT 0,
        prf_selection INTEGER DEFAULT 0,
        remote_ike_port TEXT DEFAULT '',
        remote_nat_t_port TEXT DEFAULT '',
        dpd_enable INTEGER DEFAULT 1,
        dpd_delay INTEGER DEFAULT 10,
        dpd_max_failures INTEGER DEFAULT 5,
        description TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ipsec_phase1_algorithms (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        phase1_id INTEGER NOT NULL,
        encryption TEXT NOT NULL,
        key_length INTEGER,
        hash TEXT,
        dh_group TEXT,
        FOREIGN KEY(phase1_id) REFERENCES ipsec_phase1(id) ON DELETE CASCADE
    )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_ipsec_phase1_algorithms_phase1_id ON ipsec_phase1_algorithms(phase1_id)")

    # ----------------------------
    # DHCP SERVER (whole page settings)
    # ----------------------------
    # Store the whole form as JSON so we can persist every option on the page without
    # creating hundreds of columns.
    # interface: 'wan' | 'lan'
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS dhcp_server_settings (
        interface TEXT PRIMARY KEY,
        settings_json TEXT NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # ----------------------------
    # Generic service state store (JSON blobs)
    # ----------------------------
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS service_state (
            key_name TEXT PRIMARY KEY,
            value_json TEXT NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

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

    # Create bootstrap admin only if explicitly provided
    cursor.execute("SELECT COUNT(*) AS c FROM users")
    if cursor.fetchone()["c"] == 0:
        admin_user = os.getenv("BOOTSTRAP_ADMIN_USERNAME")
        admin_pass = os.getenv("BOOTSTRAP_ADMIN_PASSWORD")

        if admin_user and admin_pass:
            cursor.execute("""
            INSERT INTO users (username, password, full_name, is_superuser)
            VALUES (?, ?, ?, 1)
        """, (
             admin_user,
             generate_password_hash(admin_pass),
             "System Administrator"
        ))

    # Ensure there is always at least one superuser.
    cursor.execute("SELECT COUNT(*) AS c FROM users WHERE COALESCE(is_superuser, 0) = 1")
    if cursor.fetchone()["c"] == 0:
        cursor.execute("UPDATE users SET is_superuser = 1 WHERE username = 'admin'")
        if cursor.rowcount == 0:
            cursor.execute(
                "UPDATE users SET is_superuser = 1 WHERE id = (SELECT MIN(id) FROM users)"
            )

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

    # Create default LAN config if not exists
    cursor.execute("SELECT COUNT(*) AS c FROM lan_config")
    if cursor.fetchone()["c"] == 0:
        cursor.execute("INSERT INTO lan_config DEFAULT VALUES")

    # Create default WAN config if not exists
    cursor.execute("SELECT COUNT(*) AS c FROM wan_config")
    if cursor.fetchone()["c"] == 0:
        cursor.execute("INSERT INTO wan_config DEFAULT VALUES")

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
        nat_reflection TEXT,
        rule_order INTEGER DEFAULT 0
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
        description TEXT,
        rule_order INTEGER DEFAULT 0
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
        description TEXT,
        rule_order INTEGER DEFAULT 0
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
        description TEXT,
        rule_order INTEGER DEFAULT 0
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

    # Traffic Shaper Configs (Queues)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS traffic_shaper_configs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        interface_type TEXT NOT NULL,
        enable_disable INTEGER DEFAULT 1,
        name TEXT NOT NULL,
        scheduler_type TEXT DEFAULT 'HFSC',
        bandwidth INTEGER,
        bandwidth_unit TEXT DEFAULT 'Mbit/s',
        queue_limit INTEGER,
        tbr_size INTEGER,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Limiters Configs
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS limiters_configs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        enable_disable INTEGER DEFAULT 1,
        name TEXT NOT NULL,
        bandwidth INTEGER,
        bandwidth_unit TEXT DEFAULT 'Mbit/s',
        mask_type TEXT DEFAULT 'None',
        ipv4_mask_bits INTEGER DEFAULT 32,
        ipv6_mask_bits INTEGER DEFAULT 128,
        queue_management_algorithm TEXT DEFAULT 'Tail Drop',
        scheduler TEXT DEFAULT 'Worst-case Weighted fair Queuing (default)',
        queue_length INTEGER,
        delay_ms INTEGER,
        packet_loss_rate REAL,
        bucket_size_slots INTEGER,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)



    # OpenVPN Server Configs
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS openvpn_servers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        description TEXT,
        disabled INTEGER DEFAULT 0,
        server_mode TEXT DEFAULT 'peer2peer',
        device_mode TEXT DEFAULT 'tun',
        protocol TEXT DEFAULT 'udp4',
        interface TEXT DEFAULT 'wan',
        local_port INTEGER DEFAULT 1194,
        tls_key INTEGER DEFAULT 1,
        tls_key_auto INTEGER DEFAULT 1,
        peer_ca TEXT,
        tunnel_network TEXT,
        tunnel_network_v6 TEXT,
        redirect_gateway INTEGER DEFAULT 0,
        local_network TEXT,
        remote_network TEXT,
        max_clients INTEGER,
        compression TEXT,
        inter_client_communication INTEGER DEFAULT 0,
        duplicate_connection INTEGER DEFAULT 0,
        dynamic_ip INTEGER DEFAULT 0,
        topology TEXT DEFAULT 'subnet',
        dns_server1 TEXT,
        dns_server2 TEXT,
        dns_server3 TEXT,
        dns_server4 TEXT,
        ntp_server1 TEXT,
        ntp_server2 TEXT,
        netbios_enable INTEGER DEFAULT 0,
        netbios_node_type TEXT,
        netbios_scope TEXT,
        wins_server1 TEXT,
        wins_server2 TEXT,
        custom_options TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # OpenVPN Client Configs
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS openvpn_clients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        description TEXT,
        disabled INTEGER DEFAULT 0,
        server_mode TEXT DEFAULT 'peer2peer',
        protocol TEXT DEFAULT 'udp4',
        interface TEXT DEFAULT 'wan',
        server_hostname TEXT,
        server_port INTEGER DEFAULT 1194,
        use_tls_key INTEGER DEFAULT 0,
        tls_key TEXT,
        ca_cert TEXT,
        client_cert TEXT,
        client_key TEXT,
        encryption_algorithm TEXT DEFAULT 'AES-256-CBC',
        auth_digest_algorithm TEXT DEFAULT 'SHA256',
        inactivity_timeout INTEGER DEFAULT 300,
        ping_method TEXT DEFAULT 'keepalive',
        ping_interval INTEGER DEFAULT 10,
        ping_timeout INTEGER DEFAULT 60,
        custom_options TEXT,
        udp_fast_io INTEGER DEFAULT 0,
        send_receive_buffer TEXT DEFAULT 'default',
        verbosity_level INTEGER DEFAULT 3,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # IPsec Phase 2 (Child SA) Configs
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ipsec_phase2 (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        phase1_id INTEGER,
        description TEXT,
        disabled INTEGER DEFAULT 0,
        mode TEXT DEFAULT 'tunnel',
        local_network TEXT,
        remote_network TEXT,
        protocol TEXT DEFAULT 'esp',
        encryption_algorithms TEXT DEFAULT 'aes256',
        hash_algorithms TEXT DEFAULT 'sha256',
        pfs_key_group TEXT DEFAULT '14',
        lifetime INTEGER DEFAULT 3600,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(phase1_id) REFERENCES ipsec_phase1(id)
    )
    """)

    # L2TP Configuration
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS l2tp_config (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        enabled INTEGER DEFAULT 1,
        interface TEXT DEFAULT 'wan',
        server_address TEXT,
        remote_address_range TEXT,
        subnet_mask TEXT,
        dns_server1 TEXT,
        dns_server2 TEXT,
        wins_server TEXT,
        authentication TEXT DEFAULT 'chap',
        require_chap INTEGER DEFAULT 0,
        require_pap INTEGER DEFAULT 0,
        radius_server TEXT,
        radius_secret TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # L2TP Users
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS l2tp_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        ip_address TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # OpenVPN Client Specific Overrides
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS openvpn_cso (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        description TEXT,
        disabled INTEGER DEFAULT 0,
        common_name TEXT NOT NULL,
        connection_blocking INTEGER DEFAULT 0,
        server_list TEXT,
        reset_server_options TEXT DEFAULT 'keep',
        ipv4_tunnel_network TEXT,
        ipv6_tunnel_network TEXT,
        ipv4_gateway TEXT,
        ipv6_gateway TEXT,
        redirect_ipv4_gateway INTEGER DEFAULT 0,
        redirect_ipv6_gateway INTEGER DEFAULT 0,
        ipv4_local_networks TEXT,
        ipv6_local_networks TEXT,
        ipv4_remote_networks TEXT,
        ipv6_remote_networks TEXT,
        inactivity_timeout INTEGER DEFAULT 300,
        ping_interval INTEGER DEFAULT 10,
        ping_action TEXT DEFAULT 'none',
        dns_default_domain INTEGER DEFAULT 0,
        dns_servers INTEGER DEFAULT 0,
        block_outside_dns INTEGER DEFAULT 0,
        force_dns_cache_update INTEGER DEFAULT 0,
        ntp_servers INTEGER DEFAULT 0,
        netbios_options INTEGER DEFAULT 0,
        advanced TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Certificate Authorities (CA)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS certificate_authorities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        descriptive_name TEXT NOT NULL,
        randomize_serial INTEGER DEFAULT 1,
        key_length INTEGER DEFAULT 2048,
        lifetime INTEGER DEFAULT 3650,
        common_name TEXT,
        country_code TEXT,
        state_or_province TEXT,
        city TEXT,
        organization TEXT,
        organizational_unit TEXT,
        ca_data TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # OpenVPN Wizard Configurations
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS openvpn_wizard_configs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type_of_server TEXT DEFAULT 'local',
        ca_id INTEGER,
        server_configured INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(ca_id) REFERENCES certificate_authorities(id)
    )
    """)

    cursor.execute("""
CREATE TABLE IF NOT EXISTS dhcp_pools (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    interface_type TEXT NOT NULL UNIQUE,
    enabled INTEGER DEFAULT 0,
    start_ip TEXT NOT NULL,
    end_ip TEXT NOT NULL,
    gateway_ip TEXT,
    dns_servers TEXT DEFAULT '',
    lease_time INTEGER DEFAULT 86400,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")

    cursor.execute("SELECT COUNT(*) AS c FROM dhcp_pools")
    if cursor.fetchone()["c"] == 0:
        cursor.execute("""
            INSERT INTO dhcp_pools (interface_type, enabled, start_ip, end_ip, gateway_ip, dns_servers, lease_time)
            VALUES
            ('LAN', 0, '192.168.1.100', '192.168.1.200', '192.168.1.1', '1.1.1.1,8.8.8.8', 86400),
            ('WAN', 0, '0.0.0.0', '0.0.0.0', '', '', 86400)
        """)

    cursor.execute("""
CREATE TABLE IF NOT EXISTS static_leases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    interface_type TEXT NOT NULL,
    hostname TEXT,
    mac_address TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")

    cursor.execute("""
CREATE UNIQUE INDEX IF NOT EXISTS idx_static_leases_mac
ON static_leases(mac_address)
""")

    # Discovered host inventory (ARP + static leases) for firewall coverage tracking.
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS tracked_hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            interface_type TEXT NOT NULL DEFAULT 'UNKNOWN',
            interface_name TEXT DEFAULT '',
            ip_address TEXT NOT NULL,
            mac_address TEXT DEFAULT '',
            hostname TEXT DEFAULT '',
            discovered_via TEXT DEFAULT 'unknown',
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            policy_state TEXT DEFAULT 'unknown',
            policy_note TEXT DEFAULT ''
        )
        """
    )
    cursor.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_tracked_hosts_iface_ip
        ON tracked_hosts(interface_type, ip_address)
        """
    )
    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_tracked_hosts_last_seen
        ON tracked_hosts(last_seen)
        """
    )

    # ----------------------------
    # IDS / IPS (Suricata)
    # ----------------------------
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ids_config (
        id          INTEGER PRIMARY KEY CHECK (id = 1),
        enabled     INTEGER DEFAULT 0,
        mode        TEXT    DEFAULT 'ids',
        interface   TEXT    DEFAULT '',
        home_net    TEXT    DEFAULT '192.168.0.0/16',
        external_net TEXT   DEFAULT '!$HOME_NET',
        block_list_enabled  INTEGER DEFAULT 1,
        eve_json_enabled    INTEGER DEFAULT 1,
        fast_log_enabled    INTEGER DEFAULT 1,
        max_pending_packets INTEGER DEFAULT 1024,
        stats_interval      INTEGER DEFAULT 8,
        updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cursor.execute(
        "INSERT OR IGNORE INTO ids_config (id) VALUES (1)"
    )

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ids_rulesets (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        name        TEXT    NOT NULL UNIQUE,
        enabled     INTEGER DEFAULT 1,
        url         TEXT    DEFAULT '',
        local_path  TEXT    DEFAULT '',
        description TEXT    DEFAULT '',
        updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Seed default rulesets if none exist
    cursor.execute("SELECT COUNT(*) AS c FROM ids_rulesets")
    if cursor.fetchone()["c"] == 0:
        cursor.executemany(
            "INSERT OR IGNORE INTO ids_rulesets (name, enabled, url, description) VALUES (?,?,?,?)",
            [
                ("Emerging Threats Open", 1,
                 "https://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz",
                 "Community-maintained detection rules covering current threats"),
                ("ET Pro Telemetry Edition", 0,
                 "https://rules.emergingthreatspro.com/open-nogpl/suricata/emerging.rules.tar.gz",
                 "Enhanced ruleset with telemetry (free with registration)"),
                ("Abuse.ch SSL Blacklist", 1,
                 "https://sslbl.abuse.ch/blacklist/sslipblacklist.rules",
                 "Blocks SSL connections to known malware C2 servers"),
            ],
        )

    conn.commit()
    conn.close()
