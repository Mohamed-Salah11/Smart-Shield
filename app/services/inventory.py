"""
app/services/inventory.py
-------------------------
Admin-managed asset & identity catalog.

Assets    — physical/virtual hosts identified by IP. Track criticality,
            owner, business unit and free-text tags so SOC analysts and
            reports know whether an event hit a crown-jewel.
Identities — usernames mapped to a person/role/manager/sensitivity.

Both are intentionally simple lookup tables; they're populated from the
admin UI and consumed by the TI enrichment pipeline (so each event picks
up ``details.asset`` / ``details.identity`` when a match exists) and by
the report generator.
"""

from __future__ import annotations

import threading
import time


_CACHE_LOCK = threading.Lock()
_CACHE_ASSETS: dict     = {}     # ip -> dict
_CACHE_IDENTITIES: dict = {}     # username -> dict
_CACHE_LOADED:    float = 0.0
_CACHE_TTL              = 60     # seconds — keep enrichment fast

_VALID_CRIT      = {"low", "medium", "high", "crown_jewel"}
_VALID_SENSIT    = {"standard", "privileged", "crown_jewel"}


def _now() -> float:
    return time.time()


def _refresh(force: bool = False) -> None:
    """Reload the in-memory cache from the inventory tables."""
    global _CACHE_ASSETS, _CACHE_IDENTITIES, _CACHE_LOADED
    if not force and (_now() - _CACHE_LOADED) < _CACHE_TTL:
        return
    from app.audit_log import _events_db
    conn = _events_db()
    if conn is None:
        return
    try:
        try:
            assets = {
                r["ip"]: dict(r)
                for r in conn.execute(
                    "SELECT ip, hostname, owner, business_unit, criticality, tags FROM assets"
                ).fetchall()
            }
        except Exception:
            assets = {}
        try:
            idents = {
                r["username"]: dict(r)
                for r in conn.execute(
                    "SELECT username, full_name, role, manager, business_unit, sensitivity "
                    "FROM identities"
                ).fetchall()
            }
        except Exception:
            idents = {}
    finally:
        try: conn.close()
        except Exception: pass
    with _CACHE_LOCK:
        _CACHE_ASSETS     = assets
        _CACHE_IDENTITIES = idents
        _CACHE_LOADED     = _now()


def lookup_asset(ip: str) -> dict:
    """Return the asset record for *ip* (empty dict if unknown)."""
    if not ip:
        return {}
    _refresh()
    return _CACHE_ASSETS.get(ip.strip(), {})


def lookup_identity(username: str) -> dict:
    if not username:
        return {}
    _refresh()
    return _CACHE_IDENTITIES.get(username.strip(), {})


def annotate_details(details: dict, *, ip_field: str = None, username: str = None) -> dict:
    """
    Return *details* with ``asset`` / ``identity`` keys added when a match
    exists in the inventory. Never raises. Caller already has a copy
    semantics-wise (we always return the same dict object).
    """
    if not isinstance(details, dict):
        return details
    if ip_field:
        a = lookup_asset(details.get(ip_field, ""))
        if a and "asset" not in details:
            details["asset"] = {
                "ip":            a.get("ip"),
                "hostname":      a.get("hostname"),
                "owner":         a.get("owner"),
                "business_unit": a.get("business_unit"),
                "criticality":   a.get("criticality"),
            }
    if username:
        i = lookup_identity(username)
        if i and "identity" not in details:
            details["identity"] = {
                "username":      i.get("username"),
                "full_name":     i.get("full_name"),
                "role":          i.get("role"),
                "manager":       i.get("manager"),
                "business_unit": i.get("business_unit"),
                "sensitivity":   i.get("sensitivity"),
            }
    return details


def refresh_cache() -> tuple:
    """Force-refresh the cache; returns (asset_count, identity_count)."""
    _refresh(force=True)
    return len(_CACHE_ASSETS), len(_CACHE_IDENTITIES)


# ---------------------------------------------------------------------------
# CRUD helpers — used by the admin route
# ---------------------------------------------------------------------------

def list_assets(conn) -> list:
    return [dict(r) for r in conn.execute(
        "SELECT * FROM assets ORDER BY criticality DESC, ip"
    ).fetchall()]


def list_identities(conn) -> list:
    return [dict(r) for r in conn.execute(
        "SELECT * FROM identities ORDER BY sensitivity DESC, username"
    ).fetchall()]


def upsert_asset(conn, payload: dict) -> dict:
    ip = (payload.get("ip") or "").strip()
    if not ip:
        return {"ok": False, "message": "ip is required"}
    crit = (payload.get("criticality") or "medium").strip().lower()
    if crit not in _VALID_CRIT:
        crit = "medium"
    aid = payload.get("id")
    if aid:
        conn.execute(
            "UPDATE assets SET ip=?, hostname=?, mac=?, owner=?, business_unit=?, "
            "criticality=?, tags=?, notes=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (ip, (payload.get("hostname") or "").strip(),
             (payload.get("mac") or "").strip(),
             (payload.get("owner") or "").strip(),
             (payload.get("business_unit") or "").strip(),
             crit,
             (payload.get("tags") or "").strip(),
             (payload.get("notes") or "").strip(),
             int(aid)),
        )
    else:
        conn.execute(
            "INSERT INTO assets (ip, hostname, mac, owner, business_unit, "
            "criticality, tags, notes) VALUES (?,?,?,?,?,?,?,?)",
            (ip, (payload.get("hostname") or "").strip(),
             (payload.get("mac") or "").strip(),
             (payload.get("owner") or "").strip(),
             (payload.get("business_unit") or "").strip(),
             crit,
             (payload.get("tags") or "").strip(),
             (payload.get("notes") or "").strip()),
        )
    conn.commit()
    refresh_cache()
    return {"ok": True}


def upsert_identity(conn, payload: dict) -> dict:
    username = (payload.get("username") or "").strip()
    if not username:
        return {"ok": False, "message": "username is required"}
    sens = (payload.get("sensitivity") or "standard").strip().lower()
    if sens not in _VALID_SENSIT:
        sens = "standard"
    iid = payload.get("id")
    if iid:
        conn.execute(
            "UPDATE identities SET username=?, full_name=?, email=?, role=?, "
            "manager=?, business_unit=?, sensitivity=?, notes=?, "
            "updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (username, (payload.get("full_name") or "").strip(),
             (payload.get("email") or "").strip(),
             (payload.get("role") or "").strip(),
             (payload.get("manager") or "").strip(),
             (payload.get("business_unit") or "").strip(),
             sens,
             (payload.get("notes") or "").strip(),
             int(iid)),
        )
    else:
        conn.execute(
            "INSERT INTO identities (username, full_name, email, role, manager, "
            "business_unit, sensitivity, notes) VALUES (?,?,?,?,?,?,?,?)",
            (username, (payload.get("full_name") or "").strip(),
             (payload.get("email") or "").strip(),
             (payload.get("role") or "").strip(),
             (payload.get("manager") or "").strip(),
             (payload.get("business_unit") or "").strip(),
             sens,
             (payload.get("notes") or "").strip()),
        )
    conn.commit()
    refresh_cache()
    return {"ok": True}


def delete_asset(conn, asset_id: int) -> None:
    conn.execute("DELETE FROM assets WHERE id=?", (int(asset_id),))
    conn.commit()
    refresh_cache()


def delete_identity(conn, identity_id: int) -> None:
    conn.execute("DELETE FROM identities WHERE id=?", (int(identity_id),))
    conn.commit()
    refresh_cache()
