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
    conn.close()
