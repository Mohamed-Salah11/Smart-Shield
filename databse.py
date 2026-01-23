import sqlite3

DATABASE = "data.db"

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    # Create the table based on your image fields
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS interface_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_name TEXT NOT NULL,
            group_description TEXT,
            group_members TEXT
        )
    ''')

    conn.commit()
    conn.close()
