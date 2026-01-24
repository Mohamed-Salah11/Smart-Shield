import sqlite3
import os

# Get the absolute path to the database file
db_path = os.path.join(os.path.dirname(__file__), 'data.db')

# Connect to the database
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

try:
    # Create traffic shaper configuration table if it doesn't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS traffic_shaper_configs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        interface_type TEXT NOT NULL,
        enable_disable BOOLEAN DEFAULT 1,
        name TEXT NOT NULL,
        scheduler_type TEXT DEFAULT 'HFSC',
        bandwidth INTEGER,
        bandwidth_unit TEXT DEFAULT 'Mbit/s',
        queue_limit INTEGER,
        tbr_size INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    conn.commit()
    print("Traffic shaper configuration table created successfully!")
    
except Exception as e:
    print(f"Error creating traffic shaper configuration table: {e}")
    
finally:
    conn.close()
