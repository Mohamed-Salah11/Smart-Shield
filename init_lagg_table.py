import sqlite3
import os

# Get the absolute path to the database file
db_path = os.path.join(os.path.dirname(__file__), 'data.db')

# Connect to the database
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

try:
    # Create LAGG configurations table if it doesn't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS lagg_configs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        parent_interfaces TEXT NOT NULL,
        aggregation_protocol TEXT NOT NULL,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    conn.commit()
    print("LAGG configurations table created successfully!")
    
except Exception as e:
    print(f"Error creating LAGG configurations table: {e}")
    
finally:
    conn.close()
