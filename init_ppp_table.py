import sqlite3
import os

# Get the database path
db_path = os.path.join(os.path.dirname(__file__), 'data.db')

# Connect to the database
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Create the ppp_configs table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS ppp_configs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        link_type TEXT,
        link_interfaces TEXT,
        description TEXT,
        username TEXT,
        password TEXT,
        dial_on_demand BOOLEAN DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
''')

conn.commit()
conn.close()

print("PPP configurations table created successfully!")
