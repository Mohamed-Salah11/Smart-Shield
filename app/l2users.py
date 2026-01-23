"""Database helpers for L2TP users.

Stores user entries created from the L2TP Users tab (Add modal).
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from .database import get_db


def init_l2tp_users_table() -> None:
	"""Create the L2TP users table if missing."""
	db = get_db()
	try:
		db.execute(
			"""
			CREATE TABLE IF NOT EXISTS l2tp_users (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				username TEXT NOT NULL UNIQUE,
				password TEXT NOT NULL,
				ip_address TEXT DEFAULT '',
				created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
			)
			"""
		)
		db.commit()
	finally:
		db.close()


def _first(v: Any) -> Any:
	if isinstance(v, list):
		return v[0] if v else None
	return v


def _text(form: Dict[str, Any], key: str, default: str = "") -> str:
	v = _first(form.get(key))
	if v is None:
		return default
	return str(v).strip()


def list_l2tp_users():
	"""Return all L2TP users (newest first)."""
	init_l2tp_users_table()
	db = get_db()
	try:
		return db.execute(
			"SELECT * FROM l2tp_users ORDER BY id DESC"
		).fetchall()
	finally:
		db.close()


def get_l2tp_user(user_id: int):
	init_l2tp_users_table()
	db = get_db()
	try:
		return db.execute(
			"SELECT * FROM l2tp_users WHERE id = ?",
			(user_id,),
		).fetchone()
	finally:
		db.close()


def insert_l2tp_user(form: Dict[str, Any]) -> int:
	"""Insert a user from request.form (flat=False). Returns inserted id."""
	init_l2tp_users_table()
	username = _text(form, "username")
	password = _text(form, "password")
	ip_address = _text(form, "ip_address")

	if not username:
		raise ValueError("username is required")
	if not password:
		raise ValueError("password is required")

	db = get_db()
	try:
		cur = db.execute(
			"""
			INSERT INTO l2tp_users (username, password, ip_address)
			VALUES (?, ?, ?)
			""",
			(username, password, ip_address),
		)
		db.commit()
		return int(cur.lastrowid)
	finally:
		db.close()


def update_l2tp_user(user_id: int, form: Dict[str, Any]) -> None:
	"""Update an existing user. Empty password means 'keep existing'."""
	init_l2tp_users_table()
	username = _text(form, "username")
	password = _text(form, "password", default="")
	ip_address = _text(form, "ip_address")

	if not username:
		raise ValueError("username is required")

	db = get_db()
	try:
		if password:
			db.execute(
				"""
				UPDATE l2tp_users
				SET username = ?, password = ?, ip_address = ?, updated_at = CURRENT_TIMESTAMP
				WHERE id = ?
				""",
				(username, password, ip_address, user_id),
			)
		else:
			db.execute(
				"""
				UPDATE l2tp_users
				SET username = ?, ip_address = ?, updated_at = CURRENT_TIMESTAMP
				WHERE id = ?
				""",
				(username, ip_address, user_id),
			)
		db.commit()
	finally:
		db.close()


def delete_l2tp_user(user_id: int) -> None:
	init_l2tp_users_table()
	db = get_db()
	try:
		db.execute("DELETE FROM l2tp_users WHERE id = ?", (user_id,))
		db.commit()
	finally:
		db.close()

