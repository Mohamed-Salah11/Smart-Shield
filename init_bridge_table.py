import sqlite3
import os

# Get the database path
db_path = os.path.join(os.path.dirname(__file__), 'data.db')

# Connect to the database
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Create the bridge_configs table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS bridge_configs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        member_interfaces TEXT,
        description TEXT,
        cache_size TEXT DEFAULT '100',
        cache_max_age TEXT DEFAULT '1200',
        span_interfaces TEXT,
        edge_interfaces TEXT,
        auto_edge_interfaces TEXT,
        ptp_interfaces TEXT,
        sticky_ports BOOLEAN DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
''')

conn.commit()
conn.close()

print("Bridge configurations table created successfully!")
