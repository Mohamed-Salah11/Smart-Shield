import sqlite3


DATABASE = "data.db"


def get_db():
	conn = sqlite3.connect(DATABASE)
	conn.row_factory = sqlite3.Row
	return conn


def init_csc_db():
	"""Initialize Client Specific Overrides (CSC) table."""
	conn = get_db()
	cur = conn.cursor()

	# Create CSC overrides table (persistent)
	cur.execute(
		"""
		CREATE TABLE IF NOT EXISTS openvpn_csc_overrides (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			
			-- General Information
			description TEXT,
			disable INTEGER DEFAULT 0,
			
			-- Override Configuration
			common_name TEXT NOT NULL,
			connection_blocking INTEGER DEFAULT 0,
			server_list TEXT,
			reset_server_options TEXT DEFAULT 'keep',
			
			-- Tunnel Settings
			ipv4_tunnel_network TEXT,
			ipv6_tunnel_network TEXT,
			ipv4_gateway TEXT,
			ipv6_gateway TEXT,
			redirect_ipv4_gateway INTEGER DEFAULT 0,
			redirect_ipv6_gateway INTEGER DEFAULT 0,
			ipv4_local_networks TEXT,
			ipv6_local_networks TEXT,
			ipv4_remote_networks TEXT,
			ipv6_remote_networks TEXT,
			
			-- Other Client Settings
			inactivity_timeout INTEGER,
			ping_interval INTEGER,
			ping_action TEXT DEFAULT 'none',
			dns_default_domain INTEGER DEFAULT 0,
			dns_servers INTEGER DEFAULT 0,
			block_outside_dns INTEGER DEFAULT 0,
			force_dns_cache INTEGER DEFAULT 0,
			ntp_servers INTEGER DEFAULT 0,
			netbios_options INTEGER DEFAULT 0,
			
			-- Advanced
			advanced TEXT,
			
			-- Metadata
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
		"""
	)

	# Best-effort lightweight migrations for existing DBs
	_existing_cols = {
		row[1]
		for row in cur.execute("PRAGMA table_info(openvpn_csc_overrides)").fetchall()
	}

	def _add_col_if_missing(col: str, ddl: str) -> None:
		if col in _existing_cols:
			return
		cur.execute(f"ALTER TABLE openvpn_csc_overrides ADD COLUMN {ddl}")

	_add_col_if_missing("description", "description TEXT")
	_add_col_if_missing("disable", "disable INTEGER DEFAULT 0")
	_add_col_if_missing("common_name", "common_name TEXT")
	_add_col_if_missing("connection_blocking", "connection_blocking INTEGER DEFAULT 0")
	_add_col_if_missing("server_list", "server_list TEXT")
	_add_col_if_missing("reset_server_options", "reset_server_options TEXT DEFAULT 'keep'")
	_add_col_if_missing("ipv4_tunnel_network", "ipv4_tunnel_network TEXT")
	_add_col_if_missing("ipv6_tunnel_network", "ipv6_tunnel_network TEXT")
	_add_col_if_missing("ipv4_gateway", "ipv4_gateway TEXT")
	_add_col_if_missing("ipv6_gateway", "ipv6_gateway TEXT")
	_add_col_if_missing("redirect_ipv4_gateway", "redirect_ipv4_gateway INTEGER DEFAULT 0")
	_add_col_if_missing("redirect_ipv6_gateway", "redirect_ipv6_gateway INTEGER DEFAULT 0")
	_add_col_if_missing("ipv4_local_networks", "ipv4_local_networks TEXT")
	_add_col_if_missing("ipv6_local_networks", "ipv6_local_networks TEXT")
	_add_col_if_missing("ipv4_remote_networks", "ipv4_remote_networks TEXT")
	_add_col_if_missing("ipv6_remote_networks", "ipv6_remote_networks TEXT")
	_add_col_if_missing("inactivity_timeout", "inactivity_timeout INTEGER")
	_add_col_if_missing("ping_interval", "ping_interval INTEGER")
	_add_col_if_missing("ping_action", "ping_action TEXT DEFAULT 'none'")
	_add_col_if_missing("dns_default_domain", "dns_default_domain INTEGER DEFAULT 0")
	_add_col_if_missing("dns_servers", "dns_servers INTEGER DEFAULT 0")
	_add_col_if_missing("block_outside_dns", "block_outside_dns INTEGER DEFAULT 0")
	_add_col_if_missing("force_dns_cache", "force_dns_cache INTEGER DEFAULT 0")
	_add_col_if_missing("ntp_servers", "ntp_servers INTEGER DEFAULT 0")
	_add_col_if_missing("netbios_options", "netbios_options INTEGER DEFAULT 0")
	_add_col_if_missing("advanced", "advanced TEXT")
	_add_col_if_missing(
		"created_at", "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
	)
	_add_col_if_missing(
		"updated_at", "updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
	)

	conn.commit()
	conn.close()


def list_csc_overrides():
	"""Return all CSC overrides (newest first)."""
	conn = get_db()
	try:
		init_csc_db()
		return conn.execute(
			"SELECT * FROM openvpn_csc_overrides ORDER BY id DESC"
		).fetchall()
	finally:
		conn.close()


def insert_csc_override(payload: dict) -> int:
	"""Insert a CSC override row from form payload; returns inserted id."""

	def to_int(val, default=0):
		"""Convert checkbox or string values to integer (0 or 1)."""
		if isinstance(val, str) and val.lower() == "on":
			return 1
		try:
			return int(val) if val else default
		except Exception:
			return default

	conn = get_db()
	try:
		init_csc_db()
		cur = conn.execute(
			"""
			INSERT INTO openvpn_csc_overrides (
				description, disable, common_name, connection_blocking,
				server_list, reset_server_options,
				ipv4_tunnel_network, ipv6_tunnel_network,
				ipv4_gateway, ipv6_gateway,
				redirect_ipv4_gateway, redirect_ipv6_gateway,
				ipv4_local_networks, ipv6_local_networks,
				ipv4_remote_networks, ipv6_remote_networks,
				inactivity_timeout, ping_interval, ping_action,
				dns_default_domain, dns_servers, block_outside_dns,
				force_dns_cache, ntp_servers, netbios_options,
				advanced
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			""",
			(
				payload.get("description", ""),
				to_int(payload.get("disable")),
				payload.get("common_name", "").strip(),
				to_int(payload.get("connection_blocking")),
				payload.get("server_list", ""),
				payload.get("reset_server_options", "keep"),
				payload.get("ipv4_tunnel_network", ""),
				payload.get("ipv6_tunnel_network", ""),
				payload.get("ipv4_gateway", ""),
				payload.get("ipv6_gateway", ""),
				to_int(payload.get("redirect_ipv4_gateway")),
				to_int(payload.get("redirect_ipv6_gateway")),
				payload.get("ipv4_local_networks", ""),
				payload.get("ipv6_local_networks", ""),
				payload.get("ipv4_remote_networks", ""),
				payload.get("ipv6_remote_networks", ""),
				to_int(payload.get("inactivity_timeout")),
				to_int(payload.get("ping_interval")),
				payload.get("ping_action", "none"),
				to_int(payload.get("dns_default_domain")),
				to_int(payload.get("dns_servers")),
				to_int(payload.get("block_outside_dns")),
				to_int(payload.get("force_dns_cache")),
				to_int(payload.get("ntp_servers")),
				to_int(payload.get("netbios_options")),
				payload.get("advanced", ""),
			),
		)
		conn.commit()
		return int(cur.lastrowid)
	finally:
		conn.close()


def delete_csc_override(override_id: int) -> None:
	conn = get_db()
	try:
		init_csc_db()
		conn.execute("DELETE FROM openvpn_csc_overrides WHERE id = ?", (override_id,))
		conn.commit()
	finally:
		conn.close()


def update_csc_override(override_id: int, payload: dict) -> None:
	"""Update an existing CSC override row from form payload."""

	def to_int(val, default=0):
		if isinstance(val, str) and val.lower() == "on":
			return 1
		try:
			return int(val) if val else default
		except Exception:
			return default

	conn = get_db()
	try:
		init_csc_db()
		row = conn.execute(
			"SELECT common_name FROM openvpn_csc_overrides WHERE id = ?",
			(int(override_id),),
		).fetchone()
		existing_common_name = row["common_name"] if row else ""
		new_common_name = payload.get("common_name")
		if new_common_name is None:
			new_common_name = existing_common_name
		conn.execute(
			"""
			UPDATE openvpn_csc_overrides
			SET
				description = ?,
				disable = ?,
				common_name = ?,
				connection_blocking = ?,
				server_list = ?,
				reset_server_options = ?,
				ipv4_tunnel_network = ?,
				ipv6_tunnel_network = ?,
				ipv4_gateway = ?,
				ipv6_gateway = ?,
				redirect_ipv4_gateway = ?,
				redirect_ipv6_gateway = ?,
				ipv4_local_networks = ?,
				ipv6_local_networks = ?,
				ipv4_remote_networks = ?,
				ipv6_remote_networks = ?,
				inactivity_timeout = ?,
				ping_interval = ?,
				ping_action = ?,
				dns_default_domain = ?,
				dns_servers = ?,
				block_outside_dns = ?,
				force_dns_cache = ?,
				ntp_servers = ?,
				netbios_options = ?,
				advanced = ?,
				updated_at = CURRENT_TIMESTAMP
			WHERE id = ?
			""",
			(
				payload.get("description", ""),
				to_int(payload.get("disable")),
				(str(new_common_name) if new_common_name is not None else "").strip(),
				to_int(payload.get("connection_blocking")),
				payload.get("server_list", ""),
				payload.get("reset_server_options", "keep"),
				payload.get("ipv4_tunnel_network", ""),
				payload.get("ipv6_tunnel_network", ""),
				payload.get("ipv4_gateway", ""),
				payload.get("ipv6_gateway", ""),
				to_int(payload.get("redirect_ipv4_gateway")),
				to_int(payload.get("redirect_ipv6_gateway")),
				payload.get("ipv4_local_networks", ""),
				payload.get("ipv6_local_networks", ""),
				payload.get("ipv4_remote_networks", ""),
				payload.get("ipv6_remote_networks", ""),
				to_int(payload.get("inactivity_timeout")),
				to_int(payload.get("ping_interval")),
				payload.get("ping_action", "none"),
				to_int(payload.get("dns_default_domain")),
				to_int(payload.get("dns_servers")),
				to_int(payload.get("block_outside_dns")),
				to_int(payload.get("force_dns_cache")),
				to_int(payload.get("ntp_servers")),
				to_int(payload.get("netbios_options")),
				payload.get("advanced", ""),
				int(override_id),
			),
		)
		conn.commit()
	finally:
		conn.close()

