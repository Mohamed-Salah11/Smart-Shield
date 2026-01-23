import sqlite3
import os

# Get the database path
db_path = os.path.join(os.path.dirname(__file__), 'data.db')

# Connect to the database
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Create the gre_configs table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS gre_configs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        parent_interface TEXT,
        gre_remote_address TEXT,
        gre_local_address TEXT,
        ipv4_tunnel_remote_address TEXT,
        ipv4_tunnel_remote_prefix TEXT DEFAULT '32',
        ipv4_tunnel_local_address TEXT,
        ipv4_tunnel_local_prefix TEXT DEFAULT '32',
        ipv6_tunnel_remote_address TEXT,
        ipv6_tunnel_remote_prefix TEXT DEFAULT '128',
        ipv6_tunnel_local_address TEXT,
        ipv6_tunnel_local_prefix TEXT DEFAULT '128',
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
''')

conn.commit()
conn.close()

print("GRE configurations table created successfully!")
