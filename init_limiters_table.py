import sqlite3
import os

# Get the absolute path to the database file
db_path = os.path.join(os.path.dirname(__file__), 'data.db')

# Connect to the database
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

try:
    # Create limiters configuration table if it doesn't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS limiters_configs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        enable_disable BOOLEAN DEFAULT 1,
        name TEXT NOT NULL,
        bandwidth INTEGER,
        bandwidth_unit TEXT DEFAULT 'Mbit/s',
        mask_type TEXT DEFAULT 'None',
        ipv4_mask_bits INTEGER,
        ipv6_mask_bits INTEGER,
        queue_management_algorithm TEXT DEFAULT 'Tail Drop',
        scheduler TEXT DEFAULT 'Worst-case Weighted Fair Queuing',
        queue_length INTEGER,
        delay_ms INTEGER,
        packet_loss_rate REAL,
        bucket_size_slots INTEGER,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    conn.commit()
    print("Limiters configuration table created successfully!")
    
except Exception as e:
    print(f"Error creating limiters configuration table: {e}")
    
finally:
    conn.close()
