"""
worker_lock.py
--------------
Ensures only one Gunicorn worker process runs background daemon threads.
Uses an exclusive fcntl.flock on a lock file under the SmartShield runtime
state dir (/var/run/smartshield by default; legacy /var/run/smart-shield is
honored when present).
On non-FreeBSD (dev/Windows): always returns True (single process assumed).
"""
import os
import sys

from app.config import _ss_dir

_LOCK_FILE = os.path.join(_ss_dir("/var/run"), "worker.lock")
_lock_fd = None  # module-level file descriptor; held for process lifetime


def _remove_stale_lock() -> None:
    """Remove the lock file if it was left by a process that no longer exists."""
    if not os.path.exists(_LOCK_FILE):
        return
    try:
        with open(_LOCK_FILE) as fh:
            pid_str = fh.read().strip()
        if pid_str and pid_str.isdigit():
            try:
                os.kill(int(pid_str), 0)  # raises OSError if process is gone
            except OSError:
                os.unlink(_LOCK_FILE)
    except OSError:
        pass


def acquire_worker_lock() -> bool:
    """
    Try to acquire an exclusive non-blocking flock.
    Returns True if this process becomes the leader (should start daemons).
    Returns False if another process already holds the lock.
    On non-FreeBSD: always returns True.
    """
    global _lock_fd
    if not sys.platform.startswith(("freebsd", "linux", "darwin")):
        return True
    try:
        import fcntl
        lock_dir = os.path.dirname(_LOCK_FILE)
        os.makedirs(lock_dir, exist_ok=True)
        _remove_stale_lock()
        _lock_fd = open(_LOCK_FILE, "w")
        fcntl.flock(_lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _lock_fd.write(str(os.getpid()))
        _lock_fd.flush()
        return True
    except OSError:
        # Another worker holds the lock
        if _lock_fd:
            _lock_fd.close()
            _lock_fd = None
        return False


def is_worker_leader() -> bool:
    """Return True if this process currently holds the worker lock."""
    return _lock_fd is not None
