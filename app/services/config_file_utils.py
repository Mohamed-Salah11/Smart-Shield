"""
config_file_utils.py
--------------------
Common atomic file write + rollback helpers for Smart Shield config writers.

Public API
----------
atomic_write(path, content, mode=0o644)   -> None
backup_config(path)                        -> str | None
rollback_config(path)                      -> dict
apply_with_rollback(path, content, restart_fn, mode=0o644) -> dict

Non-FreeBSD behaviour
---------------------
- atomic_write:          always works (temp-file + rename).
- backup_config:         returns None ("non-FreeBSD" path skipped).
- rollback_config:       returns {"ok": False, "message": "non-FreeBSD"}.
- apply_with_rollback:   callers are expected to guard with _on_freebsd()
                         before calling, but the function is safe to call
                         on non-FreeBSD — it will still write atomically and
                         run restart_fn (the caller can pass a no-op).
"""

import os
import sys
import shutil
import tempfile

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
    mode: int = 0o644,
) -> dict:
    """
    Atomically write *content* to *path*, run *restart_fn*, and roll back
    on failure.

    Sequence
    --------
    1. backup_config(path)         — save .known_good (FreeBSD only)
    2. atomic_write(path, content, mode)
    3. result = restart_fn()       — must return {"ok": bool, "message": str}
    4. If not result["ok"]:
         rollback_config(path)
         return {"ok": False, "rolled_back": True/False, ...}
    5. Return {"ok": True, "rolled_back": False, ...}

    *restart_fn* must return a dict with at least {"ok": bool, "message": str}.

    Returns dict with keys: ok, message, rolled_back.
    """
    # Step 1 – backup
    backup_config(path)

    # Step 2 – write
    try:
        atomic_write(path, content, mode)
    except OSError as exc:
        return {
            "ok": False,
            "rolled_back": False,
            "message": f"Failed to write {path}: {exc}",
        }

    # Step 3 – restart
    try:
        result = restart_fn()
    except Exception as exc:
        result = {"ok": False, "message": str(exc)}

    # Step 4 – rollback if restart failed
    if not result.get("ok"):
        rb = rollback_config(path)
        return {
            "ok": False,
            "rolled_back": rb.get("ok", False),
            "message": result.get("message", "restart failed"),
            "rollback_message": rb.get("message", ""),
        }

    # Step 5 – success
    return {
        "ok": True,
        "rolled_back": False,
        "message": result.get("message", ""),
    }
