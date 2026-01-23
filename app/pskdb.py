from typing import Any, Dict, List, Optional

from .database import get_db


def init_psk_table() -> None:
	db = get_db()
	try:
		db.execute(
			"""
			CREATE TABLE IF NOT EXISTS ipsec_psks (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				identifier TEXT NOT NULL,
				secret_type TEXT NOT NULL DEFAULT 'psk',
				secret TEXT NOT NULL,
				created_at TEXT DEFAULT CURRENT_TIMESTAMP
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


def _text(v: Any, default: str = "") -> str:
	v = _first(v)
	if v is None:
		return default
	return str(v).strip()


def list_psks() -> List[dict]:
	init_psk_table()
	db = get_db()
	try:
		rows = db.execute(
			"SELECT id, identifier, secret_type, secret, created_at FROM ipsec_psks ORDER BY id DESC"
		).fetchall()
		return [dict(r) for r in rows]
	finally:
		db.close()


def get_psk(psk_id: int) -> Optional[dict]:
	init_psk_table()
	db = get_db()
	try:
		row = db.execute(
			"SELECT id, identifier, secret_type, secret, created_at FROM ipsec_psks WHERE id = ?",
			(psk_id,),
		).fetchone()
		return dict(row) if row else None
	finally:
		db.close()


def insert_psk(form: Dict[str, Any]) -> None:
	init_psk_table()
	identifier = _text(form.get("identifier"), "any")
	secret_type = _text(form.get("secret_type"), "psk") or "psk"
	secret = _text(form.get("secret"), "")

	db = get_db()
	try:
		db.execute(
			"INSERT INTO ipsec_psks (identifier, secret_type, secret) VALUES (?, ?, ?)",
			(identifier, secret_type, secret),
		)
		db.commit()
	finally:
		db.close()


def update_psk(psk_id: int, form: Dict[str, Any]) -> None:
	init_psk_table()
	identifier = _text(form.get("identifier"), "any")
	secret_type = _text(form.get("secret_type"), "psk") or "psk"
	secret = _text(form.get("secret"), "")

	db = get_db()
	try:
		db.execute(
			"UPDATE ipsec_psks SET identifier = ?, secret_type = ?, secret = ? WHERE id = ?",
			(identifier, secret_type, secret, psk_id),
		)
		db.commit()
	finally:
		db.close()


def delete_psk(psk_id: int) -> None:
	init_psk_table()
	db = get_db()
	try:
		db.execute("DELETE FROM ipsec_psks WHERE id = ?", (psk_id,))
		db.commit()
	finally:
		db.close()

