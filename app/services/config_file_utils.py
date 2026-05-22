"""
config_file_utils.py
--------------------
Common atomic file write + rollback helpers for Smart Shield config writers.

Public API
----------
atomic_write(path, content, mode=0o644)               -> None
backup_config(path)                                    -> str | None
rollback_config(path)                                  -> dict
apply_with_rollback(path, content, restart_fn,
                    *, validate_fn=None, mode=0o644)   -> dict

Non-FreeBSD behaviour
---------------------
- atomic_write:          always works (temp-file + rename).
- backup_config:         returns None ("non-FreeBSD" path skipped).
- rollback_config:       returns {"ok": False, "message": "non-FreeBSD"}.
- apply_with_rollback:   callers are expected to guard with _on_freebsd()
                         before calling, but the function is safe to call
                         on non-FreeBSD — it will still write atomically and
                         run restart_fn (the caller can pass a no-op).

Wave I additions
----------------
- Optional ``validate_fn(tmp_path)`` runs against the temp file *before*
  it replaces the real config — syntax errors are caught without touching
  the live file.
- Every step (write / validate / backup / swap / restart / rollback) is
  emitted through the module logger so transaction history is visible in
  the audit log and the admin UI's apply-job rows.
"""

import os
import sys
import shutil
import tempfile
import logging

_log = logging.getLogger(__name__)

_BACKUP_SUFFIX = ".known_good"


def _on_freebsd() -> bool:
    return sys.platform.startswith("freebsd")


# ---------------------------------------------------------------------------
# atomic_write
# ---------------------------------------------------------------------------

def atomic_write(path: str, content: str, mode: int = 0o644) -> None:
    """
    Write *content* to *path* atomically using a temp file + os.replace.

    Steps:
      1. Write content to a temporary file in the same directory as *path*.
      2. chmod the temp file to *mode*.
      3. os.replace(tmp, path) — atomic on POSIX; best-effort on Windows.

    Raises OSError on any I/O failure.
    """
    dir_name = os.path.dirname(os.path.abspath(path))
    os.makedirs(dir_name, exist_ok=True)

    fd, tmp_path = tempfile.mkstemp(dir=dir_name, prefix=".ss_tmp_")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(content)
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# backup_config
# ---------------------------------------------------------------------------

def backup_config(path: str):
    """
    Copy *path* → *path*.known_good if *path* exists on FreeBSD.

    Returns the backup path on success, or None if the original does not
    exist or we are not on FreeBSD.
    """
    if not _on_freebsd():
        return None
    if not os.path.exists(path):
        return None
    backup = path + _BACKUP_SUFFIX
    try:
        shutil.copy2(path, backup)
        return backup
    except OSError:
        return None


# ---------------------------------------------------------------------------
# rollback_config
# ---------------------------------------------------------------------------

def rollback_config(path: str) -> dict:
    """
    Copy *path*.known_good → *path* if the backup exists.

    Returns {"ok": bool, "message": str}.
    On non-FreeBSD always returns {"ok": False, "message": "non-FreeBSD"}.
    """
    if not _on_freebsd():
        return {"ok": False, "message": "non-FreeBSD — rollback skipped"}
    backup = path + _BACKUP_SUFFIX
    if not os.path.exists(backup):
        return {"ok": False, "message": f"No backup found at {backup}"}
    try:
        shutil.copy2(backup, path)
        return {"ok": True, "message": f"Rolled back {path} from {backup}"}
    except OSError as exc:
        return {"ok": False, "message": f"Rollback failed: {exc}"}


# ---------------------------------------------------------------------------
# apply_with_rollback
# ---------------------------------------------------------------------------

def apply_with_rollback(
    path: str,
    content: str,
    restart_fn,
    *,
    validate_fn=None,
    mode: int = 0o644,
    rollback_on_restart_failure: bool = True,
) -> dict:
    """
    Tmp-file → optionally validate → backup → swap → reload, with rollback
    on failure.

    Sequence
    --------
    1. Write *content* to a temp file in the same directory as *path*.
    2. If *validate_fn* is given, call it with the temp path. It must return
       ``{"ok": bool, "message": str, "output": str}`` (or raise). On failure
       the temp file is unlinked and the live config is **left untouched**.
    3. backup_config(path)         — save .known_good (FreeBSD only).
    4. os.replace(tmp, path)       — atomic swap.
    5. result = restart_fn()       — must return ``{"ok": bool, "message": str}``.
    6. If restart fails AND ``rollback_on_restart_failure`` is true,
       rollback_config(path) and report rolled_back flag. When false, the new
       file is left in place so the operator can diagnose without losing the
       intended change (used by nginx, where reverting to an older LAN-IP-
       bound config produces a strictly worse stuck state).

    Returns a dict with: ok, message, rolled_back, and (when set) validation
    metadata.
    """
    # Step 1 — write to temp file in the same directory
    dir_name = os.path.dirname(os.path.abspath(path))
    os.makedirs(dir_name, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=dir_name, prefix=".ss_tmp_")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(content)
        os.chmod(tmp_path, mode)
        _log.debug("config_file_utils: staged %s -> %s (%d bytes)",
                   path, tmp_path, len(content))
    except OSError as exc:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        _log.error("config_file_utils: write failed for %s: %s", path, exc)
        return {
            "ok": False,
            "rolled_back": False,
            "message": f"Failed to write {path}: {exc}",
        }

    # Step 2 — validate the temp file before touching the live one
    if validate_fn is not None:
        try:
            v = validate_fn(tmp_path)
        except Exception as exc:
            v = {"ok": False, "message": str(exc), "output": ""}
        if not isinstance(v, dict):
            v = {"ok": bool(v), "message": "", "output": ""}
        if not v.get("ok"):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            _log.warning("config_file_utils: validation rejected %s: %s",
                         path, v.get("message", "")[:200])
            return {
                "ok": False,
                "rolled_back": False,   # live config still untouched
                "validated": False,
                "validation_output": v.get("output", ""),
                "message": v.get("message") or f"Validation failed for {path}",
            }
        _log.info("config_file_utils: validation OK for %s", path)

    # Step 3 — backup live config
    backup_path = backup_config(path)
    if backup_path:
        _log.debug("config_file_utils: backed up %s -> %s", path, backup_path)

    # Step 4 — atomic swap
    try:
        os.replace(tmp_path, path)
    except OSError as exc:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        _log.error("config_file_utils: swap failed for %s: %s", path, exc)
        return {
            "ok": False,
            "rolled_back": False,
            "message": f"Failed to install {path}: {exc}",
        }

    # Step 5 — restart / reload
    try:
        result = restart_fn()
    except Exception as exc:
        result = {"ok": False, "message": str(exc)}

    # Step 6 — rollback on restart failure (skippable; see docstring)
    if not result.get("ok"):
        if rollback_on_restart_failure:
            rb = rollback_config(path)
            _log.warning("config_file_utils: restart failed for %s; rollback ok=%s",
                         path, rb.get("ok"))
            return {
                "ok": False,
                "rolled_back": rb.get("ok", False),
                "message": result.get("message", "restart failed"),
                "rollback_message": rb.get("message", ""),
            }
        _log.warning("config_file_utils: restart failed for %s; new file kept "
                     "(rollback_on_restart_failure=False)", path)
        return {
            "ok": False,
            "rolled_back": False,
            "message": result.get("message", "restart failed"),
        }

    _log.info("config_file_utils: apply OK for %s", path)
    return {
        "ok": True,
        "rolled_back": False,
        "message": result.get("message", ""),
    }
