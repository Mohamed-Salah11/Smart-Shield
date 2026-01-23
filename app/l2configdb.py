"""Database helpers for L2TP configuration.

This stores the values selected in the L2TP "configuration" tab.
We keep a single-row table (id=1) similar to `ipsec_advanced_settings`.
"""

from __future__ import annotations

import json
from typing import Any, Dict

from .database import get_db


def init_l2tp_config_table() -> None:
	"""Create the L2TP config table if missing."""
	db = get_db()
	try:
		db.execute(
			"""
			CREATE TABLE IF NOT EXISTS l2tp_config (
				id INTEGER PRIMARY KEY CHECK (id = 1),
				config_json TEXT NOT NULL DEFAULT '{}',
				updated_at TEXT DEFAULT CURRENT_TIMESTAMP
			)
			"""
		)
		# Ensure single-row record exists.
		db.execute(
			"""
			INSERT OR IGNORE INTO l2tp_config (id, config_json)
			VALUES (1, '{}')
			"""
		)
		db.commit()
	finally:
		db.close()


def _first(v: Any) -> Any:
	if isinstance(v, list):
		return v[0] if v else None
	return v


def _text(v: Any, default: str = "") -> str:
	v = _first(v)
	if v is None:
		return default
	return str(v).strip()


def _bool(form: Dict[str, Any], key: str) -> bool:
	# HTML checkboxes submit as 'on' when checked; absent when unchecked.
	v = _first(form.get(key))
	if v is None:
		return False
	if isinstance(v, bool):
		return v
	return str(v).lower() in {"1", "true", "yes", "on"}


def get_l2tp_config() -> dict:
	"""Return the persisted L2TP config dict (may be empty)."""
	init_l2tp_config_table()
	db = get_db()
	try:
		row = db.execute(
			"SELECT config_json FROM l2tp_config WHERE id = 1"
		).fetchone()
		if not row:
			return {}
		try:
			return json.loads(row["config_json"] or "{}")
		except Exception:
			return {}
	finally:
		db.close()


def save_l2tp_config(form: Dict[str, Any]) -> dict:
	"""Persist L2TP configuration tab values.

	Contract:
	- form: request.form converted with `to_dict(flat=False)` or a plain dict.
	- returns: the dict that was saved.

	Note: since you didn't specify the exact fields yet, we store:
	- known_common: a few common L2TP options if present
	- extras: everything else (so you don't lose any new fields)
	"""
	init_l2tp_config_table()

	# A small set of common L2TP/PPP fields. If your template names differ,
	# these will just stay default, and the values will still be captured in extras.
	saved = {
		"enabled": _bool(form, "enabled") or _bool(form, "l2tp_enabled"),
		"interface": _text(form.get("interface"), ""),
		"local_ip": _text(form.get("local_ip"), ""),
		"remote_ip_range": _text(form.get("remote_ip_range"), ""),
		"dns_servers": _text(form.get("dns_servers"), ""),
		"auth_method": _text(form.get("auth_method"), ""),
		"username": _text(form.get("username"), ""),
		"password": _text(form.get("password"), ""),
	}

	# Capture all incoming fields too, to avoid blocking on exact schema.
	extras: Dict[str, Any] = {}
	for k, v in form.items():
		if k in saved:
			continue
		extras[k] = _first(v)
	if extras:
		saved["extras"] = extras

	payload = json.dumps(saved, ensure_ascii=False)

	db = get_db()
	try:
		db.execute(
			"""
			UPDATE l2tp_config
			SET config_json = ?, updated_at = CURRENT_TIMESTAMP
			WHERE id = 1
			""",
			(payload,),
		)
		db.commit()
	finally:
		db.close()

	return saved

