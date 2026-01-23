from __future__ import annotations

import json
from typing import Any, Dict, Optional

from .database import get_db


def init_advanced_settings_table() -> None:
	"""Create tables for IPsec Advanced Settings (Advanced Settings tab)."""
	db = get_db()
	try:
		db.execute(
			"""
			CREATE TABLE IF NOT EXISTS ipsec_advanced_settings (
				id INTEGER PRIMARY KEY CHECK (id = 1),
				logging_json TEXT NOT NULL DEFAULT '{}',
				settings_json TEXT NOT NULL DEFAULT '{}',
				updated_at TEXT DEFAULT CURRENT_TIMESTAMP
			)
			"""
		)
		# Ensure single-row record exists.
		db.execute(
			"""
			INSERT OR IGNORE INTO ipsec_advanced_settings (id, logging_json, settings_json)
			VALUES (1, '{}', '{}')
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
	# HTML checkboxes submit as 'on' (or custom value) when checked; absent when unchecked.
	v = _first(form.get(key))
	if v is None:
		return False
	if isinstance(v, bool):
		return v
	return str(v).lower() in {"1", "true", "yes", "on"}


def get_ipsec_advanced_settings() -> dict:
	"""Return a dict with two nested dicts: logging + settings."""
	init_advanced_settings_table()
	db = get_db()
	try:
		row = db.execute(
			"SELECT logging_json, settings_json FROM ipsec_advanced_settings WHERE id = 1"
		).fetchone()
		if not row:
			return {"logging": {}, "settings": {}}
		try:
			logging = json.loads(row["logging_json"] or "{}")
		except Exception:
			logging = {}
		try:
			settings = json.loads(row["settings_json"] or "{}")
		except Exception:
			settings = {}
		return {"logging": logging, "settings": settings}
	finally:
		db.close()


def save_ipsec_advanced_settings(form: Dict[str, Any]) -> None:
	"""Persist Advanced Settings tab values from a request.form dict (flat=False)."""
	init_advanced_settings_table()

	logging = {
		"daemon": _text(form.get("log_daemon"), "control"),
		"sa_manager": _text(form.get("log_sa_manager"), "control"),
		"ike_sa": _text(form.get("log_ike_sa"), "diag"),
		"ike_child_sa": _text(form.get("log_ike_child_sa"), "diag"),
		"job_processing": _text(form.get("log_job_processing"), "control"),
		"config_backend": _text(form.get("log_config_backend"), "diag"),
		"kernel_interface": _text(form.get("log_kernel_interface"), "control"),
		"networking": _text(form.get("log_networking"), "control"),
		"asn_encoding": _text(form.get("log_asn_encoding"), "control"),
		"message_encoding": _text(form.get("log_message_encoding"), "control"),
		"integrity_checker": _text(form.get("log_integrity_checker"), "control"),
		"integrity_verifier": _text(form.get("log_integrity_verifier"), "control"),
		"pts": _text(form.get("log_pts"), "control"),
		"tls": _text(form.get("log_tls"), "control"),
		"ipsec_traffic": _text(form.get("log_ipsec_traffic"), "control"),
		"strongswan_lib": _text(form.get("log_strongswan_lib"), "control"),
	}

	settings = {
		"configure_unique_ids": _text(form.get("configure_unique_ids"), "yes"),
		"ipsec_filter_mode": _text(form.get("ipsec_filter_mode"), "tunnel"),
		"ikev2_retransmission": _bool(form, "ikev2_retransmission"),
		"ip_compression": _bool(form, "ip_compression"),
		"pkcs11_support": _bool(form, "pkcs11_support"),
		"strict_interface_binding": _bool(form, "strict_interface_binding"),
		"unencrypted_payloads": _bool(form, "unencrypted_payloads"),
		"max_ikev1_phase2": _text(form.get("max_ikev1_phase2"), "3"),
		"cisco_extensions": _bool(form, "cisco_extensions"),
		"strict_crl_checking": _bool(form, "strict_crl_checking"),
		"fqdn_resolve_interval": _text(form.get("fqdn_resolve_interval"), "60"),
		"make_before_break": _bool(form, "make_before_break"),
		"async_crypto": _bool(form, "async_crypto"),
		"ike_port": _text(form.get("ike_port"), "500"),
		"natt_port": _text(form.get("natt_port"), "4500"),
		"auto_exclude_lan": _bool(form, "auto_exclude_lan"),
		"additional_bypass": _bool(form, "additional_bypass"),
	}

	db = get_db()
	try:
		db.execute(
			"""
			UPDATE ipsec_advanced_settings
			SET logging_json = ?, settings_json = ?, updated_at = CURRENT_TIMESTAMP
			WHERE id = 1
			"""
			,
			(json.dumps(logging), json.dumps(settings)),
		)
		db.commit()
	finally:
		db.close()
