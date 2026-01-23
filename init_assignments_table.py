import sqlite3

# Initialize interface_assignments table
conn = sqlite3.connect('data.db')
cursor = conn.cursor()

cursor.execute('''CREATE TABLE IF NOT EXISTS interface_assignments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    interface_type TEXT UNIQUE NOT NULL,
    network_port TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)''')

conn.commit()
conn.close()

print("Interface assignments table created successfully!")
