import sqlite3

# Initialize qinq_configs table
conn = sqlite3.connect('data.db')
cursor = conn.cursor()

cursor.execute('''CREATE TABLE IF NOT EXISTS qinq_configs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    parent_interface TEXT NOT NULL,
    first_level_tag INTEGER NOT NULL,
    add_to_groups BOOLEAN DEFAULT 0,
    description TEXT,
    member_tags TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)''')

conn.commit()
conn.close()

print("QinQ configurations table created successfully!")
