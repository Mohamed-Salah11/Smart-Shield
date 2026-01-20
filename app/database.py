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
