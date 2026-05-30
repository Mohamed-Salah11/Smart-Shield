import os
import sqlite3
import sys
import tempfile
from werkzeug.security import generate_password_hash

_MEMORY_ANCHOR_CONN = None
_MEMORY_ANCHOR_PATH = None


def _default_db_path():
    if sys.platform.startswith("freebsd"):
        from app.config import _ss_dir
        return os.path.join(_ss_dir("/var/db"), "data.db")
    if sys.platform.startswith("win"):
        # Keep Windows dev DB out of compressed/synced workdirs and in persistent user-local storage.
        local_appdata = os.getenv("LOCALAPPDATA") or tempfile.gettempdir()
        return os.path.join(local_appdata, "SmartShield", "data.db")
    return "data.db"


def _database_path():
    # Treat unset AND empty-string the same — fall back to the platform default.
    val = os.getenv("SMARTSHIELD_DB_PATH", "").strip()
    return val if val else _default_db_path()


def _ensure_parent_dir(path: str):
    parent_dir = os.path.dirname(os.path.abspath(path))
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)


def _column_exists(cursor, table: str, column: str) -> bool:
    """True if ``column`` is present on ``table`` (via PRAGMA table_info).

    Used to guard index creation in init_db() for columns that older databases
    only gain via a later migration. On a fresh DB the base CREATE TABLE already
    defines the column; on a pre-migration DB the column is absent and the
    matching migration creates both the column and the index, so init_db() must
    not try to index it first."""
    return any(
        row[1] == column
        for row in cursor.execute(f"PRAGMA table_info({table})").fetchall()
    )


def get_db():
    """
    Return a SQLite connection for the current request (or call).

    When called inside a Flask application context the connection is cached on
    Flask's ``g`` object and automatically closed at the end of the request via
    ``close_db()``.  Callers that explicitly call ``conn.close()`` are still safe
    — SQLite connections are idempotent on double-close.
    """
    global _MEMORY_ANCHOR_CONN, _MEMORY_ANCHOR_PATH

    # Attempt to reuse the per-request cached connection.
    try:
        from flask import g
        if "db" in g:
            try:
                g.db.execute("SELECT 1")   # verify connection is still alive
                return g.db
            except Exception:
                g.pop("db", None)          # stale/closed — fall through to create new
    except RuntimeError:
        # No application context (e.g. CLI / background thread) — fall through.
        pass

    db_path = _database_path()
    is_uri  = db_path.startswith("file:")
    if not is_uri:
        _ensure_parent_dir(db_path)
    elif "mode=memory" in db_path:
        if _MEMORY_ANCHOR_CONN is None or _MEMORY_ANCHOR_PATH != db_path:
            if _MEMORY_ANCHOR_CONN is not None:
                _MEMORY_ANCHOR_CONN.close()
            _MEMORY_ANCHOR_CONN = sqlite3.connect(db_path, uri=True)
            _MEMORY_ANCHOR_CONN.execute("PRAGMA foreign_keys = ON")
            _MEMORY_ANCHOR_PATH = db_path

    conn = sqlite3.connect(db_path, uri=is_uri)
    conn.execute("PRAGMA foreign_keys = ON")
    # File-backed databases use WAL for better read/write concurrency and a
    # 5 s busy timeout so concurrent writers wait instead of failing with
    # "database is locked". The in-memory test DB does not support WAL.
    if "mode=memory" not in db_path:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA busy_timeout = 5000")
    conn.row_factory = sqlite3.Row

    try:
        from flask import g
        g.db = conn
    except RuntimeError:
        pass

    return conn


def close_db(error=None):
    """Close the per-request DB connection (registered as a teardown handler)."""
    try:
        from flask import g
        conn = g.pop("db", None)
        if conn is not None:
            conn.close()
    except RuntimeError:
        pass

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
        soc_tier TEXT DEFAULT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # GROUPS TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS groups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        description TEXT,
        soc_tier TEXT DEFAULT NULL
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

    # Migration: add assigned_port to lan_config / wan_config if missing.
    # Guard with `if lan_columns` so we only ALTER on existing tables — on a
    # fresh DB these tables don't exist yet and will be created with the column
    # included in the CREATE TABLE statement below.
    cursor.execute("PRAGMA table_info(lan_config)")
    lan_columns = {row["name"] for row in cursor.fetchall()}
    if lan_columns and "assigned_port" not in lan_columns:
        cursor.execute("ALTER TABLE lan_config ADD COLUMN assigned_port TEXT DEFAULT ''")

    cursor.execute("PRAGMA table_info(wan_config)")
    wan_columns = {row["name"] for row in cursor.fetchall()}
    if wan_columns and "assigned_port" not in wan_columns:
        cursor.execute("ALTER TABLE wan_config ADD COLUMN assigned_port TEXT DEFAULT ''")

    # Firewall rule table schema migrations — add missing columns to existing DBs.
    cursor.execute("PRAGMA table_info(firewall_rules_floating)")
    _fw_float_cols = {row["name"] for row in cursor.fetchall()}
    if _fw_float_cols and "action" not in _fw_float_cols:
        cursor.execute("ALTER TABLE firewall_rules_floating ADD COLUMN action TEXT DEFAULT 'pass'")

    cursor.execute("PRAGMA table_info(firewall_rules_wan)")
    _fw_wan_cols = {row["name"] for row in cursor.fetchall()}
    if _fw_wan_cols:
        if "source_port" not in _fw_wan_cols:
            cursor.execute("ALTER TABLE firewall_rules_wan ADD COLUMN source_port TEXT")
        if "dest_port" not in _fw_wan_cols:
            cursor.execute("ALTER TABLE firewall_rules_wan ADD COLUMN dest_port TEXT")

    cursor.execute("PRAGMA table_info(firewall_rules_lan)")
    _fw_lan_cols = {row["name"] for row in cursor.fetchall()}
    if _fw_lan_cols and "action" not in _fw_lan_cols:
        cursor.execute("ALTER TABLE firewall_rules_lan ADD COLUMN action TEXT DEFAULT 'pass'")

    # Keep lan_config/wan_config assigned_port in sync with interface_assignments.
    # Only run when all three tables already exist (skip on fresh install).
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='interface_assignments'"
    )
    if cursor.fetchone():
        cursor.execute(
            "SELECT interface_type, network_port FROM interface_assignments WHERE network_port IS NOT NULL"
        )
        for row in cursor.fetchall():
            itype = (row[0] or "").upper()
            port  = row[1] or ""
            if itype == "LAN" and port:
                cursor.execute("UPDATE lan_config SET assigned_port=? WHERE assigned_port=''", (port,))
            elif itype == "WAN" and port:
                cursor.execute("UPDATE wan_config SET assigned_port=? WHERE assigned_port=''", (port,))

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
        assigned_port TEXT DEFAULT '',
        ipv4_config_type TEXT DEFAULT 'static',
        ipv6_config_type TEXT DEFAULT 'none',
        mac_address TEXT DEFAULT '',
        mtu TEXT DEFAULT '',
        mss TEXT DEFAULT '',
        speed_and_duplex TEXT DEFAULT 'default',
        ipv4_address TEXT DEFAULT '',
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
        assigned_port TEXT DEFAULT '',
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

    # LOGIN BRUTE-FORCE FAILURE TRACKING
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS login_failures (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        remote_addr TEXT    NOT NULL,
        failed_at   REAL    NOT NULL
    )
    """)
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_login_failures_ip_time ON login_failures(remote_addr, failed_at)"
    )
    # Migration: add username column for per-account lockout tracking.
    cursor.execute("PRAGMA table_info(login_failures)")
    _lf_cols = {row["name"] for row in cursor.fetchall()}
    if _lf_cols and "username" not in _lf_cols:
        cursor.execute("ALTER TABLE login_failures ADD COLUMN username TEXT")

    # Migration: add soc_tier to groups if missing (column added in Phase 19).
    cursor.execute("PRAGMA table_info(groups)")
    _grp_cols = {row["name"] for row in cursor.fetchall()}
    if _grp_cols and "soc_tier" not in _grp_cols:
        cursor.execute("ALTER TABLE groups ADD COLUMN soc_tier TEXT DEFAULT NULL")

    # Migration: terminal_enabled flag on advanced_admin_access. Off by default
    # so a fresh appliance never exposes the live root shell until a superuser
    # turns it on explicitly. Read by routes/terminal.py and base.html.
    cursor.execute("PRAGMA table_info(advanced_admin_access)")
    _aaa_cols = {row["name"] for row in cursor.fetchall()}
    if _aaa_cols and "terminal_enabled" not in _aaa_cols:
        cursor.execute(
            "ALTER TABLE advanced_admin_access ADD COLUMN terminal_enabled INTEGER DEFAULT 0"
        )

    # Migration: add ssl_cert_id to soc_portal_config if the table predates that column.
    cursor.execute("PRAGMA table_info(soc_portal_config)")
    _soc_cols = {row["name"] for row in cursor.fetchall()}
    if _soc_cols and "ssl_cert_id" not in _soc_cols:
        cursor.execute("ALTER TABLE soc_portal_config ADD COLUMN ssl_cert_id INTEGER DEFAULT NULL")

    # HIGH AVAILABILITY SETTINGS
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ha_settings (
        id                  INTEGER PRIMARY KEY DEFAULT 1,
        ss_sync_enabled     INTEGER DEFAULT 1,
        sync_interface      TEXT    DEFAULT 'WAN',
        filter_host_id      TEXT    DEFAULT '',
        peer_ip             TEXT    DEFAULT '',
        xmlrpc_ip           TEXT    DEFAULT '',
        remote_username     TEXT    DEFAULT '',
        remote_password_enc TEXT    DEFAULT '',
        sync_admin          INTEGER DEFAULT 0,
        sync_options        TEXT    DEFAULT '[]',
        updated_at          TEXT    DEFAULT CURRENT_TIMESTAMP
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
        other_multiple INTEGER,
        block_bogons INTEGER DEFAULT 1,
        block_private_nets INTEGER DEFAULT 1,
        nat_reflection INTEGER DEFAULT 0,
        kill_states_on_reload INTEGER DEFAULT 0
    )
    """)

    # Bring existing advanced_firewall_nat rows up to date with new columns.
    for _afn_col, _afn_ddl in [
        ("nat_reflection",       "ALTER TABLE advanced_firewall_nat ADD COLUMN nat_reflection INTEGER DEFAULT 0"),
        ("kill_states_on_reload","ALTER TABLE advanced_firewall_nat ADD COLUMN kill_states_on_reload INTEGER DEFAULT 0"),
    ]:
        try:
            cursor.execute(_afn_ddl)
        except Exception:
            pass  # column already exists

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
        vhid INTEGER DEFAULT 1,
        carp_pass TEXT DEFAULT '',
        advskew INTEGER DEFAULT 0,
        advbase INTEGER DEFAULT 1,
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
        dst_port TEXT,
        redirect_ip TEXT,
        redirect_port TEXT,
        description TEXT,
        nat_reflection TEXT,
        rule_order INTEGER DEFAULT 0
    )
    """)
    # Migration: add dst_port and redirect_port to existing deployments
    for _col, _def in [("dst_port", "TEXT"), ("redirect_port", "TEXT")]:
        try:
            cursor.execute(f"ALTER TABLE nat_pf ADD COLUMN {_col} {_def}")
        except Exception:
            pass

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
        action TEXT DEFAULT 'pass',
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
        source_port TEXT,
        destination TEXT,
        dest_port TEXT,
        description TEXT,
        rule_order INTEGER DEFAULT 0
    )
    """)

    # Firewall Rules - LAN
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS firewall_rules_lan (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT DEFAULT 'pass',
        disabled INTEGER DEFAULT 0,
        interface TEXT,
        protocol TEXT,
        source TEXT,
        source_port TEXT,
        destination TEXT,
        dest_port TEXT,
        description TEXT,
        rule_order INTEGER DEFAULT 0
    )
    """)
    # Migrate existing LAN tables that predate source_port/dest_port columns
    for col in ("source_port", "dest_port"):
        try:
            cursor.execute(f"ALTER TABLE firewall_rules_lan ADD COLUMN {col} TEXT")
        except Exception:
            pass  # column already exists

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

    # Traffic Shaper Queue Assignments (match rules that send traffic to queues)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS traffic_shaper_queues (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        enabled INTEGER DEFAULT 1,
        queue_name TEXT NOT NULL,
        ack_queue TEXT DEFAULT '',
        protocol TEXT DEFAULT 'any',
        source TEXT DEFAULT 'any',
        source_port TEXT DEFAULT '',
        destination TEXT DEFAULT 'any',
        dest_port TEXT DEFAULT '',
        description TEXT DEFAULT '',
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
        ca_id INTEGER,
        server_cert_id INTEGER,
        inactivity_timeout INTEGER DEFAULT 300,
        ping_method TEXT DEFAULT 'keepalive',
        ping_interval INTEGER DEFAULT 10,
        ping_timeout INTEGER DEFAULT 60,
        dh_parameter_length TEXT DEFAULT '2048',
        ecdh_curve TEXT DEFAULT 'default',
        data_encryption_algorithms TEXT DEFAULT 'AES-256-GCM',
        fallback_data_encryption_algorithm TEXT DEFAULT 'AES-256-CBC',
        auth_digest_algorithm TEXT DEFAULT 'SHA256',
        verbosity_level INTEGER DEFAULT 1,
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
        pre_shared_key TEXT DEFAULT '',
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
    cursor.execute(
        "INSERT OR IGNORE INTO dhcp_pools (interface_type, start_ip, end_ip) VALUES ('LAN', '', '')"
    )

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
    cursor.execute("PRAGMA table_info(tracked_hosts)")
    _th_cols = {row["name"] for row in cursor.fetchall()}
    if _th_cols and "is_whitelisted" not in _th_cols:
        cursor.execute("ALTER TABLE tracked_hosts ADD COLUMN is_whitelisted INTEGER DEFAULT 0")
    # Phase 3.2: split the overloaded "whitelist" concept. is_whitelisted now
    # means "bypass captive portal only" (access_whitelist PF table). The new
    # is_policy_exempt column means "bypass DNS/web/app content policy"
    # (policy_exemption PF table + Unbound policy_exemption_view).
    if _th_cols and "is_policy_exempt" not in _th_cols:
        cursor.execute("ALTER TABLE tracked_hosts ADD COLUMN is_policy_exempt INTEGER DEFAULT 0")
    # P.2: records WHO set is_policy_exempt so transient grants can be cleaned
    # up without clobbering admin/manual exemptions. 'captive_session' marks an
    # exemption auto-granted on captive-auth login (captive_auth_required mode)
    # and auto-cleared on logout/expiry; '' (default) means admin/manual.
    if _th_cols and "exempt_source" not in _th_cols:
        cursor.execute("ALTER TABLE tracked_hosts ADD COLUMN exempt_source TEXT DEFAULT ''")

    # Migration: add pre_shared_key to l2tp_config (for L2TP/IPsec PSK)
    cursor.execute("PRAGMA table_info(l2tp_config)")
    _l2tp_cols = {row["name"] for row in cursor.fetchall()}
    if _l2tp_cols and "pre_shared_key" not in _l2tp_cols:
        cursor.execute("ALTER TABLE l2tp_config ADD COLUMN pre_shared_key TEXT DEFAULT ''")

    # ----------------------------
    # IDS / IPS (Suricata)
    # ----------------------------
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ids_config (
        id          INTEGER PRIMARY KEY CHECK (id = 1),
        enabled     INTEGER DEFAULT 0,
        mode        TEXT    DEFAULT 'ids',
        interface   TEXT    DEFAULT '',
        home_net    TEXT    DEFAULT '',
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

    # Seed default built-in suricata-update sources for new installs.
    # Blank URL = use "suricata-update enable-source <name>" (indexed source).
    cursor.executemany(
        "INSERT OR IGNORE INTO ids_rulesets (name, enabled, url, description) VALUES (?, 1, ?, ?)",
        [
            ("et/open", "", "Emerging Threats Open Rules (free, no registration required)"),
            ("oisf/trafficid", "", "OISF Traffic ID rules (free, protocol identification)"),
        ],
    )

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ids_threat_feeds (
        id               INTEGER PRIMARY KEY CHECK (id = 1),
        abusech_auth_key TEXT    DEFAULT '',
        abusech_dry_run  INTEGER DEFAULT 1,
        updated_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Seed dry-run ON: an unconfigured feed (no Auth-Key) must stay offline-safe
    # rather than report "live" and then fail every call. See abusech_client.py.
    cursor.execute(
        "INSERT OR IGNORE INTO ids_threat_feeds (id, abusech_dry_run) VALUES (1, 1)"
    )

    # SIEM collector offset persistence
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS siem_state (
        key        TEXT PRIMARY KEY,
        value      TEXT NOT NULL DEFAULT '',
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Indexed event store — every audit event is mirrored here for fast,
    # indexed queries; the audit.log file remains the durable forensic record.
    #
    # The full post-v34 column set is created here on fresh installs so the
    # first log_event() write at startup does not race the ALTER TABLE in
    # migration v34. Legacy DBs created before this change still rely on
    # _migration_v34 to add the same columns (it uses ADD COLUMN IF NOT
    # EXISTS semantics via a PRAGMA pre-check).
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        ts              TEXT NOT NULL,
        severity        TEXT DEFAULT 'info',
        category        TEXT,
        action          TEXT,
        username        TEXT,
        remote_addr     TEXT,
        details         TEXT,
        event_uuid      TEXT,
        source_type     TEXT,
        source_name     TEXT,
        src_ip          TEXT,
        src_port        INTEGER,
        dst_ip          TEXT,
        dst_port        INTEGER,
        protocol        TEXT,
        interface       TEXT,
        direction       TEXT,
        hostname        TEXT,
        mac             TEXT,
        domain          TEXT,
        url             TEXT,
        rule_id         TEXT,
        rule_name       TEXT,
        policy_id       TEXT,
        policy_name     TEXT,
        mitre_tactic    TEXT,
        mitre_technique TEXT,
        soc_origin      INTEGER DEFAULT 0,
        raw             TEXT
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_ts       ON events(ts)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_category ON events(category)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_action   ON events(action)")
    # event_uuid arrives via migration v34 on pre-existing DBs; index it only
    # once the column exists (the migration creates this same index after the
    # ALTER + backfill). Guards the first-upgrade-boot crash on a pre-v34 DB.
    if _column_exists(cursor, "events", "event_uuid"):
        cursor.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_events_event_uuid "
            "ON events(event_uuid)"
        )

    # Correlation rules — drive correlation_engine.py (Phase 23)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS correlation_rules (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        name            TEXT NOT NULL,
        enabled         INTEGER DEFAULT 1,
        category_filter TEXT DEFAULT '',
        action_filter   TEXT DEFAULT '',
        group_by        TEXT DEFAULT 'remote_addr',
        threshold       INTEGER DEFAULT 5,
        window_seconds  INTEGER DEFAULT 300,
        severity        TEXT DEFAULT 'high',
        mitre_technique TEXT DEFAULT '',
        created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # SIEM Case Management — incidents / case tracking with SOC assignment
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS siem_cases (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        title            TEXT    NOT NULL,
        description      TEXT    DEFAULT '',
        severity         TEXT    DEFAULT 'medium',
        status           TEXT    DEFAULT 'open',
        assigned_to      INTEGER,
        created_by       TEXT    NOT NULL DEFAULT 'system',
        source_event     TEXT    DEFAULT '',
        tags             TEXT    DEFAULT '',
        escalation_tier  TEXT    DEFAULT NULL,
        closure_type     TEXT    DEFAULT NULL,
        created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(assigned_to) REFERENCES users(id) ON DELETE SET NULL
    )
    """)
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_siem_cases_status   ON siem_cases(status)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_siem_cases_assigned ON siem_cases(assigned_to)"
    )

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS siem_case_notes (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id    INTEGER NOT NULL,
        note       TEXT    NOT NULL,
        created_by TEXT    NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(case_id) REFERENCES siem_cases(id) ON DELETE CASCADE
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS siem_case_events (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id         INTEGER NOT NULL,
        event_timestamp TEXT    NOT NULL,
        event_action    TEXT    NOT NULL DEFAULT '',
        event_category  TEXT    NOT NULL DEFAULT '',
        event_summary   TEXT    DEFAULT '',
        event_uuid      TEXT    DEFAULT '',
        event_details   TEXT    DEFAULT '',
        FOREIGN KEY(case_id) REFERENCES siem_cases(id) ON DELETE CASCADE
    )
    """)

    # SOC L1 analyst actions on individual audit-log events.
    # event_uuid is the collision-safe join key (migration v35); event_key
    # stays for backward compat with rows whose event row aged out before
    # the v35 backfill could resolve a uuid.
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS siem_alert_actions (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        event_key    TEXT    NOT NULL,
        event_uuid   TEXT,
        event_action TEXT    NOT NULL DEFAULT '',
        action       TEXT    NOT NULL,
        taken_by     TEXT    NOT NULL,
        taken_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        note         TEXT    DEFAULT '',
        case_id      INTEGER
    )
    """)
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_saa_event_key ON siem_alert_actions(event_key)"
    )
    # event_uuid added by migration v35; index only when present (see events note above).
    if _column_exists(cursor, "siem_alert_actions", "event_uuid"):
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_saa_event_uuid ON siem_alert_actions(event_uuid)"
        )

    # SOC L3-blocked IPs — source of truth for the persistent <soc_blocklist> PF table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS soc_blocked_ips (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        ip         TEXT    NOT NULL UNIQUE,
        note       TEXT    DEFAULT '',
        blocked_by TEXT    DEFAULT '',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Current analyst assignment for a live alert, keyed by event_key
    # (legacy timestamp PRIMARY KEY) with event_uuid as the collision-safe
    # join key added in migration v35.
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS siem_alert_assignments (
        event_key     TEXT    PRIMARY KEY,
        event_uuid    TEXT,
        assignee_id   INTEGER,
        assignee_name TEXT    DEFAULT '',
        assigned_by   TEXT    DEFAULT '',
        assigned_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    # event_uuid added by migration v35; index only when present (see events note above).
    if _column_exists(cursor, "siem_alert_assignments", "event_uuid"):
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_saasign_event_uuid "
            "ON siem_alert_assignments(event_uuid)"
        )

    # SOC analyst presence heartbeat — which analysts are currently logged in
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS soc_active_sessions (
        user_id   INTEGER PRIMARY KEY,
        username  TEXT    DEFAULT '',
        tier      TEXT    DEFAULT '',
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # ── Phase 19: SOC Team Portal configuration ───────────────────────────────
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS soc_portal_config (
        id          INTEGER PRIMARY KEY CHECK (id = 1),
        enabled     INTEGER DEFAULT 0,
        bind_ip     TEXT    DEFAULT '0.0.0.0',
        bind_port   INTEGER DEFAULT 8443,
        ssl_cert_id INTEGER DEFAULT NULL,
        public_url              TEXT    DEFAULT '',
        allowed_networks        TEXT    DEFAULT '',
        external_ingest_enabled INTEGER DEFAULT 0,
        retention_days          INTEGER DEFAULT 90,
        updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    cursor.execute("INSERT OR IGNORE INTO soc_portal_config (id) VALUES (1)")

    # ── SOC response recommendations ──────────────────────────────────────────
    # The SOC Portal does not change firewall state directly. Analysts file a
    # recommendation here; SmartShield Core admin reviews and approves it before
    # any firewall action is applied (separation Rule 1 + Phase 9 workflow).
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS soc_recommendations (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        source_alert_id  TEXT    DEFAULT '',
        action_type      TEXT    NOT NULL,           -- block_ip | unblock_ip | …
        target_value     TEXT    NOT NULL,           -- e.g. the IP address
        reason           TEXT    DEFAULT '',
        severity         TEXT    DEFAULT 'medium',
        status           TEXT    DEFAULT 'pending',  -- pending | approved_by_soc |
                                                     -- rejected_by_soc | sent_to_core |
                                                     -- approved_by_core | rejected_by_core |
                                                     -- applied | failed
        created_by       TEXT    DEFAULT '',
        reviewed_by      TEXT    DEFAULT '',
        reviewed_at      TIMESTAMP,
        exported_at      TIMESTAMP,
        core_approved_by TEXT    DEFAULT '',
        core_approved_at TIMESTAMP
    )
    """)
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_soc_recommendations_status "
        "ON soc_recommendations(status)"
    )

    # Seed abuse.ch key + dry-run flag from env into DB if install.sh set it and DB has no key yet
    _env_abusech_key  = os.environ.get("ABUSECH_AUTH_KEY",  "").strip()
    _env_dry_run_flag = 0 if os.environ.get("ABUSECH_DRY_RUN", "1").strip() == "0" else 1
    if _env_abusech_key:
        _existing_key = cursor.execute(
            "SELECT abusech_auth_key FROM ids_threat_feeds WHERE id=1"
        ).fetchone()
        if not (_existing_key and _existing_key["abusech_auth_key"]):
            try:
                from app.secret_store import encrypt_secret
                cursor.execute(
                    "UPDATE ids_threat_feeds SET abusech_auth_key=?, abusech_dry_run=?, updated_at=CURRENT_TIMESTAMP WHERE id=1",
                    (encrypt_secret(_env_abusech_key), _env_dry_run_flag),
                )
            except Exception:
                pass  # secret_store may be unavailable during early migration — skip

    # Seed Groq API key from env into service_state if install.sh set it and DB has no entry yet
    _env_groq_key = os.environ.get("GROQ_API_KEY", "").strip()
    if _env_groq_key:
        _existing_chatbot = cursor.execute(
            "SELECT value_json FROM service_state WHERE key_name='chatbot_settings'"
        ).fetchone()
        if not _existing_chatbot:
            try:
                import json as _json2
                from app.secret_store import encrypt_secret as _enc2
                cursor.execute(
                    "INSERT OR IGNORE INTO service_state (key_name, value_json) VALUES (?, ?)",
                    ("chatbot_settings", _json2.dumps({"groq_api_key": _enc2(_env_groq_key)})),
                )
            except Exception:
                pass

    # ── Routing: Gateways ─────────────────────────────────────────────────────
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS gateways (
        id                       INTEGER PRIMARY KEY AUTOINCREMENT,
        disabled                 INTEGER DEFAULT 0,
        name                     TEXT NOT NULL,
        interface                TEXT DEFAULT 'WAN',
        address_family           TEXT DEFAULT 'IPv4',
        gateway                  TEXT NOT NULL,
        monitor                  TEXT DEFAULT '',
        disable_monitoring       INTEGER DEFAULT 0,
        disable_monitoring_action INTEGER DEFAULT 0,
        force_state              INTEGER DEFAULT 0,
        state_killing            TEXT DEFAULT 'global',
        is_default_v4            INTEGER DEFAULT 0,
        is_default_v6            INTEGER DEFAULT 0,
        description              TEXT DEFAULT '',
        created_at               TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # ── Routing: Static Routes ────────────────────────────────────────────────
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS static_routes (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        disabled    INTEGER DEFAULT 0,
        destination TEXT NOT NULL,
        gateway_id  INTEGER,
        description TEXT DEFAULT '',
        created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(gateway_id) REFERENCES gateways(id) ON DELETE SET NULL
    )
    """)

    # ── Routing: Gateway Groups ───────────────────────────────────────────────
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS gateway_groups (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        name          TEXT NOT NULL UNIQUE,
        trigger_level TEXT DEFAULT 'down',
        description   TEXT DEFAULT '',
        members_json  TEXT DEFAULT '[]',
        created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # ── Security Profiles: DNS Filter ────────────────────────────────────────
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS filter_dns_rules (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        enabled     INTEGER DEFAULT 1,
        domain      TEXT NOT NULL,
        action      TEXT DEFAULT 'block',
        redirect_ip TEXT DEFAULT '',
        category    TEXT DEFAULT 'custom',
        description TEXT DEFAULT '',
        created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    cursor.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_filter_dns_domain ON filter_dns_rules(domain)"
    )

    # ── Security Profiles: Web Filter ─────────────────────────────────────────
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS filter_web_rules (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        enabled     INTEGER DEFAULT 1,
        url_pattern TEXT NOT NULL,
        action      TEXT DEFAULT 'block',
        category    TEXT DEFAULT 'custom',
        description TEXT DEFAULT '',
        created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    cursor.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_filter_web_pattern ON filter_web_rules(url_pattern)"
    )

    # ── Security Profiles: Application Filter ─────────────────────────────────
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS filter_app_rules (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        enabled     INTEGER DEFAULT 1,
        app_name    TEXT NOT NULL,
        action      TEXT DEFAULT 'block',
        block_dns   INTEGER DEFAULT 1,
        block_ports INTEGER DEFAULT 0,
        ports       TEXT DEFAULT '',
        protocol    TEXT DEFAULT 'tcp+udp',
        domains     TEXT DEFAULT '',
        category    TEXT DEFAULT 'custom',
        description TEXT DEFAULT '',
        created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # ── Certificates (CA, server, client) ────────────────────────────────────
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS certificates (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        name             TEXT    NOT NULL,
        cert_type        TEXT    NOT NULL DEFAULT 'client',
        common_name      TEXT    NOT NULL,
        ca_id            INTEGER,
        cert_pem         TEXT    NOT NULL DEFAULT '',
        private_key_enc  TEXT    NOT NULL DEFAULT '',
        serial           TEXT    DEFAULT '',
        not_before       TEXT    DEFAULT '',
        not_after        TEXT    DEFAULT '',
        revoked          INTEGER DEFAULT 0,
        revoked_at       TIMESTAMP,
        created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(ca_id) REFERENCES certificates(id) ON DELETE SET NULL
    )
    """)
    cursor.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_certificates_name_type "
        "ON certificates(name, cert_type)"
    )

    # ── Phase 13: Applied-state tracking (Phases 37 & 38) ────────────────────
    # config_apply_jobs: one record per apply operation with full lifecycle state
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS config_apply_jobs (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        feature_key TEXT    NOT NULL,
        state       TEXT    NOT NULL DEFAULT 'saved',
        config_hash TEXT    DEFAULT '',
        applied_by  TEXT    DEFAULT 'system',
        notes       TEXT    DEFAULT '',
        message     TEXT    DEFAULT '',
        created_at  REAL    NOT NULL DEFAULT 0,
        updated_at  REAL    NOT NULL DEFAULT 0
    )
    """)
    cursor.execute("""
    CREATE INDEX IF NOT EXISTS idx_cap_jobs_feature_created
    ON config_apply_jobs(feature_key, created_at DESC)
    """)

    # feature_applied_state: current summary state per feature (UI badge source)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS feature_applied_state (
        feature_key TEXT PRIMARY KEY,
        state       TEXT    NOT NULL DEFAULT 'saved',
        message     TEXT    DEFAULT '',
        last_job_id INTEGER,
        updated_at  REAL    NOT NULL DEFAULT 0,
        FOREIGN KEY(last_job_id) REFERENCES config_apply_jobs(id)
    )
    """)

    # ── Schema version ────────────────────────────────────────────────────────
    # Monotonically increasing integer; bumped each time the DB schema changes.
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS schema_version (
        version    INTEGER PRIMARY KEY,
        applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    cursor.execute("SELECT COALESCE(MAX(version), 0) AS v FROM schema_version")
    _current_schema_version = cursor.fetchone()["v"]
    # ── Policy-Based Routing ──────────────────────────────────────────────────
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS policy_routes (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        enabled          INTEGER DEFAULT 1,
        priority         INTEGER DEFAULT 100,
        description      TEXT    DEFAULT '',
        interface_type   TEXT    DEFAULT 'LAN',
        source           TEXT    DEFAULT 'any',
        destination      TEXT    DEFAULT 'any',
        gateway_id       INTEGER REFERENCES gateways(id),
        created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Bootstrap version records for all migrations that fresh-install skips
    for _bootstrap_ver in (2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16):
        if _current_schema_version < _bootstrap_ver:
            cursor.execute("INSERT INTO schema_version (version) VALUES (?)", (_bootstrap_ver,))

    # ── Phase 4: DHCPv6 pools ─────────────────────────────────────────────────
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS dhcpv6_pools (
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        interface_type    TEXT    NOT NULL UNIQUE,
        interface_name    TEXT    DEFAULT '',
        enabled           INTEGER DEFAULT 0,
        prefix            TEXT    DEFAULT '::/64',
        start_address     TEXT    DEFAULT '',
        end_address       TEXT    DEFAULT '',
        valid_lifetime    INTEGER DEFAULT 86400,
        preferred_lifetime INTEGER DEFAULT 3600,
        dns_servers       TEXT    DEFAULT '',
        domain_search     TEXT    DEFAULT '',
        pd_prefix         TEXT    DEFAULT '',
        pd_prefix_len     INTEGER DEFAULT 64,
        created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    cursor.execute("SELECT COUNT(*) AS c FROM dhcpv6_pools")
    if cursor.fetchone()["c"] == 0:
        cursor.execute(
            "INSERT INTO dhcpv6_pools (interface_type) VALUES ('LAN')"
        )

    # ── Phase 4: Router Advertisement per-interface settings ──────────────────
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ra_settings (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        interface_name   TEXT    NOT NULL UNIQUE,
        enabled          INTEGER DEFAULT 0,
        prefix           TEXT    DEFAULT '',
        autonomous_flag  INTEGER DEFAULT 1,
        managed_flag     INTEGER DEFAULT 0,
        other_flag       INTEGER DEFAULT 0,
        router_priority  TEXT    DEFAULT 'medium',
        min_interval     INTEGER DEFAULT 200,
        max_interval     INTEGER DEFAULT 600,
        default_lifetime INTEGER DEFAULT 1800,
        dns_servers      TEXT    DEFAULT '',
        domain_search    TEXT    DEFAULT '',
        created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    cursor.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_ra_settings_iface "
        "ON ra_settings(interface_name)"
    )

    # ── Phase 4: Wake-on-LAN saved hosts ─────────────────────────────────────
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS wol_hosts (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        name         TEXT    NOT NULL,
        mac_address  TEXT    NOT NULL,
        interface    TEXT    NOT NULL DEFAULT 'LAN',
        broadcast_ip TEXT    DEFAULT '255.255.255.255',
        description  TEXT    DEFAULT '',
        last_sent_at TIMESTAMP,
        created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    cursor.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_wol_hosts_mac "
        "ON wol_hosts(mac_address)"
    )

    # ── Phase 4: Captive portal sessions ─────────────────────────────────────
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS captive_sessions (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        mac_address  TEXT    NOT NULL UNIQUE,
        ip_address   TEXT    NOT NULL,
        username     TEXT    DEFAULT '',
        is_superuser INTEGER DEFAULT 0,
        expires_at   INTEGER NOT NULL,
        logged_out   INTEGER DEFAULT 0,
        bytes_in     INTEGER DEFAULT 0,
        bytes_out    INTEGER DEFAULT 0,
        created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    try:
        cursor.execute(
            "ALTER TABLE captive_sessions ADD COLUMN is_superuser INTEGER DEFAULT 0"
        )
    except Exception:
        pass  # column already exists
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_captive_sessions_expires "
        "ON captive_sessions(expires_at, logged_out)"
    )

    # ── Phase 4: Captive portal vouchers ─────────────────────────────────────
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS captive_vouchers (
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        code              TEXT    NOT NULL UNIQUE,
        duration_minutes  INTEGER NOT NULL DEFAULT 60,
        bandwidth_kbps    INTEGER DEFAULT 0,
        redeemed          INTEGER DEFAULT 0,
        disabled          INTEGER DEFAULT 0,
        redeemed_at       TIMESTAMP,
        created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # ── Captive portal auth attempts (rate limiting) ─────────────────────────
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS captive_auth_attempts (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT    NOT NULL,
        username   TEXT    DEFAULT '',
        auth_type  TEXT    DEFAULT '',
        success    INTEGER DEFAULT 0,
        created_at INTEGER NOT NULL
    )
    """)
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_captive_auth_attempts_ip_time "
        "ON captive_auth_attempts(ip_address, created_at)"
    )

    # ── Pending interface changes (rollback protection) ───────────────────────
    # Records a pre-apply snapshot so the UI can offer explicit rollback.
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS pending_interface_changes (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        interface_type TEXT    NOT NULL,
        snapshot_json  TEXT    NOT NULL,
        applied_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        confirmed      INTEGER DEFAULT 0,
        rollback_by    TIMESTAMP
    )
    """)
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_pending_iface_type "
        "ON pending_interface_changes(interface_type, applied_at)"
    )

    # ── Phase 5: Config version history ──────────────────────────────────────
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS config_versions (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        service      TEXT    NOT NULL,
        version_num  INTEGER NOT NULL DEFAULT 1,
        content      TEXT    NOT NULL,
        content_hash TEXT    DEFAULT '',
        applied_by   TEXT    DEFAULT 'system',
        applied_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        validation_ok INTEGER DEFAULT 1,
        apply_ok      INTEGER DEFAULT 1,
        notes        TEXT    DEFAULT '',
        file_path    TEXT    DEFAULT ''
    )
    """)
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_config_versions_service_version "
        "ON config_versions(service, version_num DESC)"
    )

    # ── Phase 5: Service health snapshots ────────────────────────────────────
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS health_snapshots (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        snapshot_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        services_json TEXT NOT NULL DEFAULT '{}',
        disk_json     TEXT NOT NULL DEFAULT '{}',
        system_json   TEXT NOT NULL DEFAULT '{}'
    )
    """)
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_health_snapshots_at "
        "ON health_snapshots(snapshot_at DESC)"
    )

    conn.commit()

    # Run formal migrations (Phase 5+).  This is a no-op when the DB is
    # already at CURRENT_SCHEMA_VERSION.
    from app.migrations import run_migrations
    run_migrations(conn)

    conn.close()
