"""Database helpers for IPsec Phase 1 tunnels.

This table is intended to store *all* fields from the "Add P1" modal.
Complex/dynamic fields (like multiple algorithms rows) are stored as JSON.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from app.database import get_db


def init_tunnels_table() -> None:
	"""Create the IPsec Phase 1 tunnels table if missing."""
	db = get_db()
	try:
		db.execute(
			"""
			CREATE TABLE IF NOT EXISTS ipsec_tunnels (
				id INTEGER PRIMARY KEY AUTOINCREMENT,

				-- General
				description TEXT DEFAULT '',
				disabled INTEGER DEFAULT 0,

				-- IKE endpoint configuration
				key_exchange TEXT DEFAULT 'ikev2',
				internet_protocol TEXT DEFAULT 'ipv4',
				interface TEXT DEFAULT 'wan',
				remote_gateway TEXT NOT NULL,

				-- Authentication
				auth_method TEXT DEFAULT 'mutual-psk',
				my_identifier TEXT DEFAULT 'my-ip',
				peer_identifier TEXT DEFAULT 'peer-ip',
				pre_shared_key TEXT DEFAULT '',

				-- Phase 1 proposal (encryption algorithm)
				algorithms_json TEXT DEFAULT '[]',

				-- Expiration and replacement
				life_time INTEGER DEFAULT 28800,
				rekey_time INTEGER DEFAULT 25920,
				reauth_time INTEGER DEFAULT 0,
				rand_time INTEGER DEFAULT 2880,

				-- Advanced options
				child_sa_start_action TEXT DEFAULT 'default',
				child_sa_close_action TEXT DEFAULT 'default',
				nat_traversal TEXT DEFAULT 'auto',
				mobike TEXT DEFAULT 'disable',

				gateway_duplicates INTEGER DEFAULT 0,
				split_connections INTEGER DEFAULT 0,
				prf_selection INTEGER DEFAULT 0,

				remote_ike_port INTEGER,
				remote_natt_port INTEGER,

				enable_dpd INTEGER DEFAULT 1,
				dpd_delay INTEGER DEFAULT 10,
				max_failures INTEGER DEFAULT 5,

				created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
			)
			"""
		)
		db.commit()
	finally:
		db.close()


def _to_int(val: Any, default: Optional[int] = 0) -> Optional[int]:
	if val is None or val == "":
		return default
	if isinstance(val, str) and val.lower() in {"on", "true", "yes"}:
		return 1
	try:
		return int(val)
	except Exception:
		return default


def _first(val: Any) -> Any:
	"""Unwrap Flask MultiDict values when using to_dict(flat=False)."""
	if isinstance(val, list):
		return val[0] if val else None
	return val


def _text(form: Dict[str, Any], *keys: str, default: str = "") -> str:
	for k in keys:
		if k in form and form.get(k) is not None:
			v = _first(form.get(k))
			if v is None:
				continue
			return str(v).strip()
	return default


def _parse_algorithms(form: Dict[str, Any]) -> List[Dict[str, Any]]:
	"""Accept either JSON string field or array-style multi fields."""
	raw = form.get("algorithms_json") or form.get("algorithms")
	if raw:
		if isinstance(raw, str):
			try:
				parsed = json.loads(raw)
				if isinstance(parsed, list):
					return parsed
			except Exception:
				pass

	# Fallback: handle repeated fields from HTML like algorithms_encryption[]
	enc = form.get("algorithms_encryption[]")
	if enc is None:
		# Flask MultiDict with to_dict(flat=False) will produce lists under keys.
		enc = form.get("algorithms_encryption")
	keylen = form.get("algorithms_keylength[]") or form.get("algorithms_keylength")
	hsh = form.get("algorithms_hash[]") or form.get("algorithms_hash")
	dh = form.get("algorithms_dhgroup[]") or form.get("algorithms_dhgroup")

	# Normalize to lists
	def as_list(v: Any) -> List[Any]:
		if v is None:
			return []
		return v if isinstance(v, list) else [v]

	enc_l, keylen_l, hsh_l, dh_l = map(as_list, (enc, keylen, hsh, dh))
	n = max(len(enc_l), len(keylen_l), len(hsh_l), len(dh_l))
	out: List[Dict[str, Any]] = []
	for i in range(n):
		out.append(
			{
				"encryption": enc_l[i] if i < len(enc_l) else "",
				"keylength": keylen_l[i] if i < len(keylen_l) else "",
				"hash": hsh_l[i] if i < len(hsh_l) else "",
				"dhgroup": dh_l[i] if i < len(dh_l) else "",
			}
		)
	return out


def list_ipsec_tunnels():
	db = get_db()
	try:
		return db.execute(
			"""
			SELECT *
			FROM ipsec_tunnels
			ORDER BY id DESC
			"""
		).fetchall()
	finally:
		db.close()


def get_ipsec_tunnel(tunnel_id: int):
	db = get_db()
	try:
		return db.execute(
			"SELECT * FROM ipsec_tunnels WHERE id = ?",
			(tunnel_id,),
		).fetchone()
	finally:
		db.close()


def insert_ipsec_tunnel(form: Dict[str, Any]) -> int:
	algorithms = _parse_algorithms(form)
	db = get_db()
	try:
		cur = db.execute(
			"""
			INSERT INTO ipsec_tunnels (
				description, disabled,
				key_exchange, internet_protocol, interface, remote_gateway,
				auth_method, my_identifier, peer_identifier, pre_shared_key,
				algorithms_json,
				life_time, rekey_time, reauth_time, rand_time,
				child_sa_start_action, child_sa_close_action,
				nat_traversal, mobike,
				gateway_duplicates, split_connections, prf_selection,
				remote_ike_port, remote_natt_port,
				enable_dpd, dpd_delay, max_failures
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			""",
			(
				_text(form, "description"),
				_to_int(_first(form.get("disabled")), 0),
				_text(form, "key_exchange", "keyExchange", default="ikev2"),
				_text(form, "internet_protocol", "protocol", default="ipv4"),
				_text(form, "interface", default="wan"),
				_text(form, "remote_gateway", "remoteGateway"),
				_text(form, "auth_method", "authMethod", default="mutual-psk"),
				_text(form, "my_identifier", "myIdentifier", default="my-ip"),
				_text(form, "peer_identifier", "peerIdentifier", default="peer-ip"),
				_text(form, "pre_shared_key", "preSharedKey"),
				json.dumps(algorithms),
				_to_int(_first(form.get("life_time") or form.get("lifeTime")), 28800),
				_to_int(_first(form.get("rekey_time") or form.get("rekeyTime")), 25920),
				_to_int(_first(form.get("reauth_time") or form.get("reAuthTime")), 0),
				_to_int(_first(form.get("rand_time") or form.get("randTime")), 2880),
				_text(form, "child_sa_start_action", "childSAStartAction", default="default"),
				_text(form, "child_sa_close_action", "childSACloseAction", default="default"),
				_text(form, "nat_traversal", "natTraversal", default="auto"),
				_text(form, "mobike", default="disable"),
				_to_int(_first(form.get("gateway_duplicates") or form.get("gatewayDuplicates")), 0),
				_to_int(_first(form.get("split_connections") or form.get("splitConnections")), 0),
				_to_int(_first(form.get("prf_selection") or form.get("prfSelection")), 0),
				_to_int(_first(form.get("remote_ike_port") or form.get("remoteIKEPort")), None),
				_to_int(_first(form.get("remote_natt_port") or form.get("remoteNATTPort")), None),
				_to_int(_first(form.get("enable_dpd") or form.get("enableDPD")), 0),
				_to_int(_first(form.get("dpd_delay") or form.get("dpdDelay")), 10),
				_to_int(_first(form.get("max_failures") or form.get("maxFailures")), 5),
			),
		)
		db.commit()
		return int(cur.lastrowid)
	finally:
		db.close()


def update_ipsec_tunnel(tunnel_id: int, form: Dict[str, Any]) -> None:
	algorithms = _parse_algorithms(form)
	db = get_db()
	try:
		db.execute(
			"""
			UPDATE ipsec_tunnels SET
				description = ?, disabled = ?,
				key_exchange = ?, internet_protocol = ?, interface = ?, remote_gateway = ?,
				auth_method = ?, my_identifier = ?, peer_identifier = ?, pre_shared_key = ?,
				algorithms_json = ?,
				life_time = ?, rekey_time = ?, reauth_time = ?, rand_time = ?,
				child_sa_start_action = ?, child_sa_close_action = ?,
				nat_traversal = ?, mobike = ?,
				gateway_duplicates = ?, split_connections = ?, prf_selection = ?,
				remote_ike_port = ?, remote_natt_port = ?,
				enable_dpd = ?, dpd_delay = ?, max_failures = ?
			WHERE id = ?
			""",
			(
				_text(form, "description"),
				_to_int(_first(form.get("disabled")), 0),
				_text(form, "key_exchange", "keyExchange", default="ikev2"),
				_text(form, "internet_protocol", "protocol", default="ipv4"),
				_text(form, "interface", default="wan"),
				_text(form, "remote_gateway", "remoteGateway"),
				_text(form, "auth_method", "authMethod", default="mutual-psk"),
				_text(form, "my_identifier", "myIdentifier", default="my-ip"),
				_text(form, "peer_identifier", "peerIdentifier", default="peer-ip"),
				_text(form, "pre_shared_key", "preSharedKey"),
				json.dumps(algorithms),
				_to_int(_first(form.get("life_time") or form.get("lifeTime")), 28800),
				_to_int(_first(form.get("rekey_time") or form.get("rekeyTime")), 25920),
				_to_int(_first(form.get("reauth_time") or form.get("reAuthTime")), 0),
				_to_int(_first(form.get("rand_time") or form.get("randTime")), 2880),
				_text(form, "child_sa_start_action", "childSAStartAction", default="default"),
				_text(form, "child_sa_close_action", "childSACloseAction", default="default"),
				_text(form, "nat_traversal", "natTraversal", default="auto"),
				_text(form, "mobike", default="disable"),
				_to_int(_first(form.get("gateway_duplicates") or form.get("gatewayDuplicates")), 0),
				_to_int(_first(form.get("split_connections") or form.get("splitConnections")), 0),
				_to_int(_first(form.get("prf_selection") or form.get("prfSelection")), 0),
				_to_int(_first(form.get("remote_ike_port") or form.get("remoteIKEPort")), None),
				_to_int(_first(form.get("remote_natt_port") or form.get("remoteNATTPort")), None),
				_to_int(_first(form.get("enable_dpd") or form.get("enableDPD")), 0),
				_to_int(_first(form.get("dpd_delay") or form.get("dpdDelay")), 10),
				_to_int(_first(form.get("max_failures") or form.get("maxFailures")), 5),
				tunnel_id,
			),
		)
		db.commit()
	finally:
		db.close()


def delete_ipsec_tunnel(tunnel_id: int) -> None:
	db = get_db()
	try:
		db.execute("DELETE FROM ipsec_tunnels WHERE id = ?", (tunnel_id,))
		db.commit()
	finally:
		db.close()
