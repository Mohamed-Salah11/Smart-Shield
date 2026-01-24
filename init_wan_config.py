import sqlite3
import os

# Get the absolute path to the database file
db_path = os.path.join(os.path.dirname(__file__), 'data.db')

# Connect to the database
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

try:
    # Create WAN configuration table if it doesn't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS wan_config (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        enable_interface BOOLEAN DEFAULT 1,
        description TEXT DEFAULT 'WAN',
        ipv4_config_type TEXT DEFAULT 'dhcp',
        ipv6_config_type TEXT DEFAULT 'none',
        mac_address TEXT,
        mtu TEXT DEFAULT '1500',
        mss TEXT,
        speed_and_duplex TEXT DEFAULT 'default',
        ipv4_address TEXT,
        ipv4_upstream_gateway TEXT,
        username TEXT,
        password TEXT,
        dial_on_demand BOOLEAN DEFAULT 0,
        idle_timeout INTEGER DEFAULT 0,
        block_private_networks BOOLEAN DEFAULT 0,
        block_bogon_networks BOOLEAN DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Check if there's already a row, if not insert default
    cursor.execute('SELECT COUNT(*) FROM wan_config')
    count = cursor.fetchone()[0]
    
    if count == 0:
        cursor.execute('''INSERT INTO wan_config (enable_interface, description, ipv4_config_type, ipv6_config_type, mac_address, mtu, mss, speed_and_duplex, ipv4_address, ipv4_upstream_gateway, username, password, dial_on_demand, idle_timeout, block_private_networks, block_bogon_networks)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                       (1, 'WAN', 'dhcp', 'none', '', '1500', '', 'default', '', '', '', '', 0, 0, 0, 0))
    
    conn.commit()
    print("WAN configuration table created successfully!")
    
except Exception as e:
    print(f"Error creating WAN configuration table: {e}")
    
finally:
    conn.close()
