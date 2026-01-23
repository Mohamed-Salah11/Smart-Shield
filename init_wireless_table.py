import sqlite3

# Initialize wireless_configs table
conn = sqlite3.connect('data.db')
cursor = conn.cursor()

cursor.execute('''CREATE TABLE IF NOT EXISTS wireless_configs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    parent_interface TEXT NOT NULL,
    mode TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)''')

conn.commit()
conn.close()

print("Wireless configurations table created successfully!")
