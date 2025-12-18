import sqlite3
from typing import Any, Dict, List, Optional


DATABASE = "data.db"


def get_db():
	conn = sqlite3.connect(DATABASE)
	conn.row_factory = sqlite3.Row
	return conn


def init_wizards_db():
	"""DB for OpenVPN Wizard tab: CA form only.

	This module intentionally creates ONE table: `openvpn_wizard_ca_form`.
	"""
	conn = get_db()
	cur = conn.cursor()

	cur.execute(
		"""
		CREATE TABLE IF NOT EXISTS openvpn_wizard_ca_form (
			id INTEGER PRIMARY KEY AUTOINCREMENT,

			descriptive_name TEXT NOT NULL,
			randomize_serial INTEGER DEFAULT 0,
			key_length INTEGER,
			lifetime_days INTEGER,
			common_name TEXT,
			country_code TEXT,
			state_or_province TEXT,
			city TEXT,
			organization TEXT,
			organizational_unit TEXT,

			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
		"""
	)

	conn.commit()
	conn.close()


def _to_int(value: Any) -> Optional[int]:
	if value is None or value == "":
		return None
	try:
		return int(value)
	except (TypeError, ValueError):
		return None


def _checkbox_to_int(value: Any) -> int:
	# Handles "on"/"true"/"1" or bool.
	if value is True:
		return 1
	if value is False or value is None:
		return 0
	return 1 if str(value).strip().lower() in {"1", "true", "on", "yes"} else 0


def insert_wizard_ca_form(payload: Dict[str, Any]) -> int:
	"""Insert one submitted CA form and return the new row id."""
	conn = get_db()
	cur = conn.cursor()

	cur.execute(
		"""
		INSERT INTO openvpn_wizard_ca_form (
			descriptive_name,
			randomize_serial,
			key_length,
			lifetime_days,
			common_name,
			country_code,
			state_or_province,
			city,
			organization,
			organizational_unit
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		""",
		(
			payload.get("descriptive_name") or payload.get("ca_name") or payload.get("name") or "",
			_checkbox_to_int(payload.get("randomize_serial")),
			_to_int(payload.get("key_length")),
			_to_int(payload.get("lifetime") or payload.get("lifetime_days")),
			payload.get("common_name"),
			payload.get("country_code"),
			payload.get("state_or_province") or payload.get("state") or payload.get("province"),
			payload.get("city"),
			payload.get("organization"),
			payload.get("organizational_unit") or payload.get("org_unit") or payload.get("ou"),
		),
	)

	new_id = int(cur.lastrowid)
	conn.commit()
	conn.close()
	return new_id


def list_wizard_ca_forms(limit: int = 50) -> List[Dict[str, Any]]:
	conn = get_db()
	cur = conn.cursor()
	cur.execute(
		"SELECT * FROM openvpn_wizard_ca_form ORDER BY id DESC LIMIT ?",
		(int(limit),),
	)
	rows = cur.fetchall()
	conn.close()
	return [dict(r) for r in rows]

