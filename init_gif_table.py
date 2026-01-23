import sqlite3
import os

# Get the database path
db_path = os.path.join(os.path.dirname(__file__), 'data.db')

# Connect to the database
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Create the gif_configs table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS gif_configs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        parent_interface TEXT,
        gif_remote_address TEXT,
        gif_tunnel_local_address TEXT,
        gif_tunnel_remote_address TEXT,
        gif_tunnel_subnet TEXT DEFAULT '32',
        ecn_friendly_behavior BOOLEAN DEFAULT 0,
        outer_source_filtering BOOLEAN DEFAULT 0,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
''')

conn.commit()
conn.close()

print("GIF configurations table created successfully!")
