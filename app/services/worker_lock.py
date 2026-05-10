"""
worker_lock.py
--------------
Ensures only one Gunicorn worker process runs background daemon threads.
Uses an exclusive fcntl.flock on a lock file under /var/run/smart-shield/.
On non-FreeBSD (dev/Windows): always returns True (single process assumed).
"""
import os
import sys

_LOCK_FILE = "/var/run/smart-shield/worker.lock"
_lock_fd = None  # module-level file descriptor; held for process lifetime


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
        os.makedirs(os.path.dirname(_LOCK_FILE), exist_ok=True)
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
