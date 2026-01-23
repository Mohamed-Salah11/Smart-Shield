import sqlite3

# Initialize vlan_configs table
conn = sqlite3.connect('data.db')
cursor = conn.cursor()

cursor.execute('''CREATE TABLE IF NOT EXISTS vlan_configs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    parent_interface TEXT NOT NULL,
    vlan_tag INTEGER NOT NULL,
    vlan_priority INTEGER NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)''')

conn.commit()
conn.close()

print("VLAN configurations table created successfully!")
