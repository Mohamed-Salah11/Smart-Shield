import json
from typing import Any, Dict, Optional

from .database import get_db


def init_mobile_clients_table() -> None:
	"""Create the table that stores IPsec Mobile Clients settings (single-row)."""
	db = get_db()
	try:
		db.execute(
			"""
			CREATE TABLE IF NOT EXISTS ipsec_mobile_clients_settings (
				id INTEGER PRIMARY KEY CHECK (id = 1),

				enable_mobile_client_support INTEGER DEFAULT 0,
				group_authentication INTEGER DEFAULT 0,
				radius_accounting INTEGER DEFAULT 0,

				virtual_address_pool INTEGER DEFAULT 0,
				virtual_ipv6_address_pool INTEGER DEFAULT 0,
				radius_ip_priority INTEGER DEFAULT 0,
				radius_advanced INTEGER DEFAULT 0,
				network_list INTEGER DEFAULT 0,
				save_xauth_password INTEGER DEFAULT 0,

				dns_default_domain INTEGER DEFAULT 0,
				split_dns INTEGER DEFAULT 0,
				dns_servers INTEGER DEFAULT 0,
				wins_servers INTEGER DEFAULT 0,
				phase2_pfs_group INTEGER DEFAULT 0,
				login_banner INTEGER DEFAULT 0,

				-- kept for future: textarea/select based source
				user_authentication_source TEXT DEFAULT 'Local Database',
				extra_json TEXT DEFAULT '{}',

				updated_at TEXT DEFAULT CURRENT_TIMESTAMP
			)
			"""
		)
		db.commit()
	finally:
		db.close()


def _to_int_bool(val: Any) -> int:
	if isinstance(val, list):
		val = val[0] if val else ''
	if val is None:
		return 0
	if isinstance(val, bool):
		return 1 if val else 0
	s = str(val).strip().lower()
	return 1 if s in {"1", "true", "yes", "on"} else 0


def _text(val: Any, default: str = "") -> str:
	if isinstance(val, list):
		val = val[0] if val else ''
	if val is None:
		return default
	return str(val)


def get_mobile_clients_settings() -> Dict[str, Any]:
	"""Return current settings; defaults if none exist."""
	init_mobile_clients_table()
	db = get_db()
	try:
		row = db.execute(
			"SELECT * FROM ipsec_mobile_clients_settings WHERE id = 1"
		).fetchone()
		if not row:
			return {
				"enable_mobile_client_support": 0,
				"group_authentication": 0,
				"radius_accounting": 0,
				"virtual_address_pool": 0,
				"virtual_ipv6_address_pool": 0,
				"radius_ip_priority": 0,
				"radius_advanced": 0,
				"network_list": 0,
				"save_xauth_password": 0,
				"dns_default_domain": 0,
				"split_dns": 0,
				"dns_servers": 0,
				"wins_servers": 0,
				"phase2_pfs_group": 0,
				"login_banner": 0,
				"user_authentication_source": "Local Database",
				"extra": {},
			}

		d = dict(row)
		extra = {}
		try:
			extra = json.loads(d.get("extra_json") or "{}")
		except Exception:
			extra = {}
		d["extra"] = extra
		return d
	finally:
		db.close()


def save_mobile_clients_settings(form: Dict[str, Any]) -> None:
	"""Upsert the single settings row from request.form.to_dict(flat=False)."""
	init_mobile_clients_table()

	values = {
		"enable_mobile_client_support": _to_int_bool(form.get("enableMobileClientSupport")),
		"group_authentication": _to_int_bool(form.get("groupAuthentication")),
		"radius_accounting": _to_int_bool(form.get("radiusAccounting")),

		"virtual_address_pool": _to_int_bool(form.get("virtualAddressPool")),
		"virtual_ipv6_address_pool": _to_int_bool(form.get("virtualIPv6AddressPool")),
		"radius_ip_priority": _to_int_bool(form.get("radiusIPPriority")),
		"radius_advanced": _to_int_bool(form.get("radiusAdvanced")),
		"network_list": _to_int_bool(form.get("networkList")),
		"save_xauth_password": _to_int_bool(form.get("saveXauthPassword")),

		"dns_default_domain": _to_int_bool(form.get("dnsDefaultDomain")),
		"split_dns": _to_int_bool(form.get("splitDns")),
		"dns_servers": _to_int_bool(form.get("dnsServers")),
		"wins_servers": _to_int_bool(form.get("winsServers")),
		"phase2_pfs_group": _to_int_bool(form.get("phase2PFSGroup")),
		"login_banner": _to_int_bool(form.get("loginBanner")),

		"user_authentication_source": _text(form.get("userAuthentication"), "Local Database"),
	}

	db = get_db()
	try:
		db.execute(
			"""
			INSERT INTO ipsec_mobile_clients_settings (
				id,
				enable_mobile_client_support,
				group_authentication,
				radius_accounting,
				virtual_address_pool,
				virtual_ipv6_address_pool,
				radius_ip_priority,
				radius_advanced,
				network_list,
				save_xauth_password,
				dns_default_domain,
				split_dns,
				dns_servers,
				wins_servers,
				phase2_pfs_group,
				login_banner,
				user_authentication_source,
				updated_at
			) VALUES (
				1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP
			)
			ON CONFLICT(id) DO UPDATE SET
				enable_mobile_client_support = excluded.enable_mobile_client_support,
				group_authentication = excluded.group_authentication,
				radius_accounting = excluded.radius_accounting,
				virtual_address_pool = excluded.virtual_address_pool,
				virtual_ipv6_address_pool = excluded.virtual_ipv6_address_pool,
				radius_ip_priority = excluded.radius_ip_priority,
				radius_advanced = excluded.radius_advanced,
				network_list = excluded.network_list,
				save_xauth_password = excluded.save_xauth_password,
				dns_default_domain = excluded.dns_default_domain,
				split_dns = excluded.split_dns,
				dns_servers = excluded.dns_servers,
				wins_servers = excluded.wins_servers,
				phase2_pfs_group = excluded.phase2_pfs_group,
				login_banner = excluded.login_banner,
				user_authentication_source = excluded.user_authentication_source,
				updated_at = CURRENT_TIMESTAMP
			""",
			(
				values["enable_mobile_client_support"],
				values["group_authentication"],
				values["radius_accounting"],
				values["virtual_address_pool"],
				values["virtual_ipv6_address_pool"],
				values["radius_ip_priority"],
				values["radius_advanced"],
				values["network_list"],
				values["save_xauth_password"],
				values["dns_default_domain"],
				values["split_dns"],
				values["dns_servers"],
				values["wins_servers"],
				values["phase2_pfs_group"],
				values["login_banner"],
				values["user_authentication_source"],
			),
		)
		db.commit()
	finally:
		db.close()

