"""
config_history.py
-----------------
Configuration version history and rollback.

Every time a service config is generated and applied (pf.conf, dhcpd.conf,
unbound.conf, openvpn configs, etc.) a versioned copy is stored in the
``config_versions`` table.

Public API
----------
save_config_version(conn, service, content, *, applied_by, file_path,
                    validation_ok, apply_ok, notes)  -> int   version_id
list_config_versions(conn, service, limit)            -> list
get_config_version(conn, version_id)                  -> dict | None
rollback_to_config_version(conn, version_id)          -> dict
prune_config_versions(conn, service, keep)            -> int  rows deleted
"""

import hashlib
import json
import sys
from datetime import datetime, timezone
from typing import Optional


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Write
# ---------------------------------------------------------------------------

def save_config_version(
    conn,
    service: str,
    content: str,
    *,
    applied_by: str = "system",
    file_path: str = "",
    validation_ok: bool = True,
    apply_ok: bool = True,
    notes: str = "",
) -> int:
    """
    Persist a config snapshot.

    Parameters
    ----------
    service        : Logical service name, e.g. ``"pf"``, ``"dhcpd"``,
                     ``"unbound"``, ``"openvpn"``.
    content        : Full text of the generated config file.
    applied_by     : Username (or ``"system"``) who triggered the apply.
    file_path      : Absolute path of the config file on disk.
    validation_ok  : True if pre-apply validation succeeded.
    apply_ok       : True if the service was successfully reloaded.
    notes          : Free-form text (e.g. validation errors, rollback reason).

    Returns
    -------
    The new ``version_id`` (INTEGER PRIMARY KEY).
    """
    service = (service or "unknown").strip()[:64]
    content_hash = _sha256(content)

    # Compute the next sequential version number for this service
    row = conn.execute(
        "SELECT COALESCE(MAX(version_num), 0) AS v FROM config_versions WHERE service=?",
        (service,),
    ).fetchone()
    next_version = (row["v"] if row else 0) + 1

    cursor = conn.execute(
        """
        INSERT INTO config_versions
            (service, version_num, content, content_hash, applied_by, applied_at,
             validation_ok, apply_ok, notes, file_path)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            service,
            next_version,
            content,
            content_hash,
            applied_by,
            _now_iso(),
            1 if validation_ok else 0,
            1 if apply_ok else 0,
            notes[:1024],
            file_path,
        ),
    )
    conn.commit()
    return cursor.lastrowid


# ---------------------------------------------------------------------------
# Read
# ---------------------------------------------------------------------------

def list_config_versions(conn, service: str, limit: int = 20) -> list:
    """
    Return the most-recent versions for a service (newest first).
    Content is EXCLUDED from the listing to keep response sizes small.
    """
    service = (service or "").strip()
    limit   = max(1, min(int(limit), 200))

    rows = conn.execute(
        """
        SELECT id, service, version_num, content_hash, applied_by, applied_at,
               validation_ok, apply_ok, notes, file_path
        FROM config_versions
        WHERE service=?
        ORDER BY version_num DESC
        LIMIT ?
        """,
        (service, limit),
    ).fetchall()
    return [dict(r) for r in rows]


def list_all_services_with_history(conn) -> list:
    """Return distinct services that have at least one version saved."""
    rows = conn.execute(
        """
        SELECT service,
               COUNT(*)         AS version_count,
               MAX(applied_at)  AS last_applied,
               MAX(version_num) AS latest_version
        FROM config_versions
        GROUP BY service
        ORDER BY last_applied DESC
        """
    ).fetchall()
    return [dict(r) for r in rows]


def get_config_version(conn, version_id: int) -> Optional[dict]:
    """Return a single version record (including full content), or None."""
    row = conn.execute(
        "SELECT * FROM config_versions WHERE id=?", (version_id,)
    ).fetchone()
    return dict(row) if row else None


# ---------------------------------------------------------------------------
# Rollback
# ---------------------------------------------------------------------------

def rollback_to_config_version(conn, version_id: int, rolled_back_by: str = "system") -> dict:
    """
    Re-apply a previously saved config version.

    The function writes the stored config to the original ``file_path`` and
    reloads the relevant service.  If the service writer module for this
    service cannot be found, the file is written but the service reload is
    skipped (the caller should restart the service manually).

    Returns
    -------
    dict with keys: ok, message, version_id, service, version_num
    """
    row = get_config_version(conn, version_id)
    if not row:
        return {"ok": False, "message": f"Version {version_id} not found.", "version_id": version_id}

    service     = row["service"]
    content     = row["content"]
    file_path   = row.get("file_path", "")
    version_num = row["version_num"]

    # 1. Write config file (FreeBSD only)
    write_ok  = False
    write_msg = "Non-FreeBSD — file not written."
    if sys.platform.startswith("freebsd") and file_path:
        try:
            import os
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, "w", encoding="utf-8") as fh:
                fh.write(content)
            write_ok  = True
            write_msg = f"Wrote {file_path}"
        except OSError as exc:
            return {
                "ok": False,
                "message": f"Failed to write {file_path}: {exc}",
                "version_id": version_id,
                "service": service,
                "version_num": version_num,
            }
    else:
        write_ok = True  # non-FreeBSD is always a no-op success

    # 2. Reload service
    reload_ok  = False
    reload_msg = "Service reload skipped (non-FreeBSD or no file path)."
    if sys.platform.startswith("freebsd") and file_path:
        reload_ok, reload_msg = _reload_service_for(service, file_path, conn)
    else:
        reload_ok = True

    # 3. Record this as a new version (marked as rollback)
    save_config_version(
        conn, service, content,
        applied_by=rolled_back_by,
        file_path=file_path,
        validation_ok=True,
        apply_ok=reload_ok,
        notes=f"Rollback to version {version_num}. {reload_msg}",
    )

    # 4. Audit
    try:
        from app.audit_log import log_event
        log_event(
            category="system",
            action="config_rollback",
            username=rolled_back_by,
            remote_addr="",
            details={
                "service": service,
                "rolled_back_to_version": version_num,
                "version_id": version_id,
                "reload_ok": reload_ok,
            },
        )
    except Exception:
        pass

    ok  = write_ok and reload_ok
    msg = f"{write_msg}. {reload_msg}"
    return {
        "ok": ok,
        "message": msg.strip(),
        "version_id": version_id,
        "service": service,
        "version_num": version_num,
    }


def _reload_service_for(service: str, file_path: str, conn) -> tuple:
    """
    Best-effort service reload after writing a rollback file.
    Returns (ok: bool, message: str).
    """
    try:
        if service == "pf":
            from app.services.pf_generator import reload_pf_rules
            r = reload_pf_rules(conn)
            return r["ok"], r.get("message", "")

        if service == "dhcpd":
            from app.services.service_manager import service_action
            r = service_action("isc-dhcpd", "restart")
            return r["ok"], r.get("message", "")

        if service == "unbound":
            from app.services.service_manager import service_action
            r = service_action("unbound", "reload")
            return r["ok"], r.get("message", "")

        if service == "openvpn":
            from app.services.service_manager import service_action
            r = service_action("openvpn", "restart")
            return r["ok"], r.get("message", "")

        if service == "strongswan":
            from app.services.service_manager import service_action
            r = service_action("strongswan", "restart")
            return r["ok"], r.get("message", "")

        if service == "suricata":
            from app.services.service_manager import service_action
            r = service_action("suricata", "restart")
            return r["ok"], r.get("message", "")

        return True, f"No reload handler for service {service!r} — file written, restart manually."
    except Exception as exc:
        return False, f"Reload failed: {exc}"


# ---------------------------------------------------------------------------
# Pruning
# ---------------------------------------------------------------------------

def prune_config_versions(conn, service: str, keep: int = 20) -> int:
    """
    Delete old versions beyond the most-recent ``keep`` for a service.

    Returns the number of rows deleted.
    """
    service = (service or "").strip()
    keep    = max(1, int(keep))

    ids_to_keep = conn.execute(
        """
        SELECT id FROM config_versions
        WHERE service=?
        ORDER BY version_num DESC
        LIMIT ?
        """,
        (service, keep),
    ).fetchall()

    if not ids_to_keep:
        return 0

    keep_ids    = tuple(r["id"] for r in ids_to_keep)
    placeholders = ",".join("?" * len(keep_ids))
    cursor = conn.execute(
        f"DELETE FROM config_versions WHERE service=? AND id NOT IN ({placeholders})",
        (service, *keep_ids),
    )
    conn.commit()
    return cursor.rowcount
