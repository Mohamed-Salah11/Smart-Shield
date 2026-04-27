"""
health_monitor.py
-----------------
Comprehensive service and system health monitoring.

Checks every subsystem Smart Shield manages and returns a structured
snapshot.  The snapshot is also stored in ``health_snapshots`` for
trend display on the dashboard.

Platform notes
--------------
* On non-FreeBSD the OS-level checks (disk, memory, CPU) use Python's
  cross-platform APIs so they work in development/CI environments.
* Service-level checks (pf, dhcpd, etc.) return ``state: "dry-run"``
  on non-FreeBSD or when SMARTSHIELD_NETWORK_DRY_RUN=1.

Public API
----------
check_all_services(conn)              -> dict
check_disk_usage()                    -> dict
check_memory_cpu()                    -> dict
full_health_check(conn)               -> dict
store_health_snapshot(conn, snapshot) -> int   (snapshot id)
get_health_history(conn, limit)       -> list
get_latest_health(conn)               -> dict | None
prune_health_history(conn, keep)      -> int   (rows deleted)
"""

import json
import os
import sys
import time
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _state(running: bool) -> str:
    return "running" if running else "stopped"


# ---------------------------------------------------------------------------
# Disk usage
# ---------------------------------------------------------------------------

_PATHS_TO_MONITOR = [
    ("/",                    "root"),
    ("/var",                 "var"),
    ("/var/db/smart-shield", "data"),
    ("/var/log/smart-shield","logs"),
    ("/tmp",                 "tmp"),
]


def check_disk_usage() -> dict:
    """
    Return disk usage for key filesystem paths.

    Each entry: {path, label, total_gb, used_gb, free_gb, used_pct, ok}
    ``ok`` is False when used_pct > 90.
    """
    results = []
    for path, label in _PATHS_TO_MONITOR:
        try:
            stat = os.statvfs(path) if hasattr(os, "statvfs") else None
            if stat:
                total = stat.f_blocks * stat.f_frsize
                free  = stat.f_bavail * stat.f_frsize
                used  = total - stat.f_bfree * stat.f_frsize
            else:
                # Windows fallback (development only)
                import shutil
                total, used, free = shutil.disk_usage(path)

            total_gb = round(total / 1024**3, 2)
            used_gb  = round(used  / 1024**3, 2)
            free_gb  = round(free  / 1024**3, 2)
            used_pct = round((used / total * 100) if total else 0, 1)

            results.append({
                "path":     path,
                "label":    label,
                "total_gb": total_gb,
                "used_gb":  used_gb,
                "free_gb":  free_gb,
                "used_pct": used_pct,
                "ok":       used_pct <= 90,
            })
        except OSError:
            pass

    # Deduplicate by device (same mount can appear twice with different paths)
    seen_devs = set()
    unique = []
    for entry in results:
        try:
            dev = os.stat(entry["path"]).st_dev
            if dev not in seen_devs:
                seen_devs.add(dev)
                unique.append(entry)
        except OSError:
            unique.append(entry)
    return {"disks": unique}


# ---------------------------------------------------------------------------
# Memory & CPU
# ---------------------------------------------------------------------------

def check_memory_cpu() -> dict:
    """
    Return memory and CPU load averages.

    Memory keys: total_mb, used_mb, free_mb, used_pct, ok (>90% is not-ok).
    CPU keys:    load_1, load_5, load_15.
    """
    mem  = _check_memory()
    cpu  = _check_cpu_load()
    return {**mem, **cpu}


def _check_memory() -> dict:
    try:
        if sys.platform.startswith("freebsd"):
            # Use sysctl on FreeBSD for accurate active/inactive split
            from app.services.network_service import run_command
            r = run_command(["sysctl", "-n",
                "hw.physmem",
                "vm.stats.vm.v_free_count",
                "vm.stats.vm.v_page_size"],
                check=False, timeout_seconds=3)
            lines = [ln.strip() for ln in (r.stdout or "").splitlines() if ln.strip()]
            if len(lines) >= 3:
                phys_bytes = int(lines[0])
                free_pages = int(lines[1])
                page_size  = int(lines[2])
                free_bytes = free_pages * page_size
                used_bytes = phys_bytes - free_bytes
                total_mb   = round(phys_bytes / 1024**2, 1)
                used_mb    = round(used_bytes  / 1024**2, 1)
                free_mb    = round(free_bytes  / 1024**2, 1)
                used_pct   = round(used_bytes / phys_bytes * 100, 1) if phys_bytes else 0
                return {
                    "memory_total_mb": total_mb,
                    "memory_used_mb":  used_mb,
                    "memory_free_mb":  free_mb,
                    "memory_used_pct": used_pct,
                    "memory_ok":       used_pct <= 90,
                }

        # Fallback: /proc/meminfo (Linux) or Windows
        if os.path.exists("/proc/meminfo"):
            info = {}
            with open("/proc/meminfo") as f:
                for line in f:
                    k, v = line.split(":", 1)
                    info[k.strip()] = int(v.strip().split()[0])  # kB
            total  = info.get("MemTotal", 0)
            avail  = info.get("MemAvailable", info.get("MemFree", 0))
            used   = total - avail
            used_p = round(used / total * 100, 1) if total else 0
            return {
                "memory_total_mb": round(total / 1024, 1),
                "memory_used_mb":  round(used  / 1024, 1),
                "memory_free_mb":  round(avail / 1024, 1),
                "memory_used_pct": used_p,
                "memory_ok":       used_p <= 90,
            }
    except Exception:
        pass

    return {
        "memory_total_mb": 0,
        "memory_used_mb":  0,
        "memory_free_mb":  0,
        "memory_used_pct": 0,
        "memory_ok":       True,
    }


def _check_cpu_load() -> dict:
    try:
        load = os.getloadavg()
        return {
            "cpu_load_1":  round(load[0], 2),
            "cpu_load_5":  round(load[1], 2),
            "cpu_load_15": round(load[2], 2),
        }
    except (OSError, AttributeError):
        return {"cpu_load_1": 0.0, "cpu_load_5": 0.0, "cpu_load_15": 0.0}


# ---------------------------------------------------------------------------
# Service health
# ---------------------------------------------------------------------------

def check_all_services(conn) -> dict:
    """
    Return a health snapshot for all Smart Shield services.

    Builds on the existing ``service_manager.get_all_service_health()`` and
    extends it with Phase 4 services and config-drift detection.
    """
    from app.services.service_manager import get_all_service_health, service_status

    health = get_all_service_health(conn)

    # Phase 4 services (best-effort)
    _p4_services = [
        ("ntpd",       "ntpd"),
        ("kea_dhcp6",  "kea-dhcp6"),
        ("rtadvd",     "rtadvd"),
        ("ddclient",   "ddclient"),
        ("bsnmpd",     "bsnmpd"),
        ("miniupnpd",  "miniupnpd"),
        ("igmpproxy",  "igmpproxy"),
    ]
    for key, svc_name in _p4_services:
        if key not in health:
            s = service_status(svc_name)
            health[key] = {
                "running": s.get("running", False),
                "state":   _state(s.get("running", False)),
                "message": s.get("message", ""),
            }

    # Captive portal enabled flag
    try:
        from app.services.captive_portal import get_captive_status
        cp = get_captive_status(conn)
        health["captive_portal"] = {
            "running":         cp.get("enabled", False),
            "state":           cp.get("state", "stopped"),
            "active_sessions": cp.get("active_sessions", 0),
            "message":         "",
        }
    except Exception as exc:
        health["captive_portal"] = {"running": False, "state": "unknown", "message": str(exc)}

    # Config drift: compare last applied config hash to what would be generated now
    health["config_drift"] = _check_config_drift(conn)

    return health


def _check_config_drift(conn) -> dict:
    """
    Compare the most-recently-applied config hash to the currently generated one.
    Returns {service: {drifted: bool, message: str}, ...}.
    """
    import hashlib
    drift = {}

    def _sha(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()

    checks = [
        ("pf",     _gen_pf_conf),
        ("dhcpd",  _gen_dhcpd_conf),
        ("unbound", _gen_unbound_conf),
    ]

    for service, gen_fn in checks:
        try:
            current_hash = conn.execute(
                "SELECT content_hash FROM config_versions WHERE service=? ORDER BY version_num DESC LIMIT 1",
                (service,),
            ).fetchone()
            if not current_hash:
                drift[service] = {"drifted": False, "message": "No saved version yet."}
                continue

            current_content = gen_fn(conn)
            new_hash = _sha(current_content)
            drifted  = current_hash["content_hash"] != new_hash
            drift[service] = {
                "drifted": drifted,
                "message": "Config has unsaved changes." if drifted else "In sync.",
            }
        except Exception as exc:
            drift[service] = {"drifted": False, "message": f"Check skipped: {exc}"}

    return drift


def _gen_pf_conf(conn) -> str:
    try:
        from app.services.pf_generator import generate_pf_conf
        return generate_pf_conf(conn)
    except Exception:
        return ""


def _gen_dhcpd_conf(conn) -> str:
    try:
        from app.services.dhcp_writer import generate_dhcpd_conf
        return generate_dhcpd_conf(conn)
    except Exception:
        return ""


def _gen_unbound_conf(conn) -> str:
    try:
        from app.services.dns_writer import generate_unbound_conf
        return generate_unbound_conf(conn)
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Full health check
# ---------------------------------------------------------------------------

def full_health_check(conn) -> dict:
    """
    Run all health checks and return a combined snapshot dict.

    Keys: timestamp, services, disk, system (memory+cpu)
    """
    snapshot = {
        "timestamp": _now_iso(),
        "services":  check_all_services(conn),
        "disk":      check_disk_usage(),
        "system":    check_memory_cpu(),
    }

    # Overall health flag
    svc_healthy = all(
        v.get("running", True) is not False or v.get("state") in ("dry-run", "unknown")
        for k, v in snapshot["services"].items()
        if k not in ("interfaces", "config_drift")
        and isinstance(v, dict)
    )
    disk_healthy = all(d.get("ok", True) for d in snapshot["disk"].get("disks", []))
    mem_healthy  = snapshot["system"].get("memory_ok", True)

    snapshot["overall_ok"] = svc_healthy and disk_healthy and mem_healthy
    return snapshot


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def store_health_snapshot(conn, snapshot: dict) -> int:
    """
    Persist a health snapshot to the DB.  Returns the new row id.
    """
    cursor = conn.execute(
        """
        INSERT INTO health_snapshots (snapshot_at, services_json, disk_json, system_json)
        VALUES (?, ?, ?, ?)
        """,
        (
            snapshot.get("timestamp", _now_iso()),
            json.dumps(snapshot.get("services", {})),
            json.dumps(snapshot.get("disk", {})),
            json.dumps(snapshot.get("system", {})),
        ),
    )
    conn.commit()
    return cursor.lastrowid


def get_health_history(conn, limit: int = 24) -> list:
    """Return the most-recent ``limit`` health snapshots (newest first)."""
    limit = max(1, min(int(limit), 168))
    rows  = conn.execute(
        """
        SELECT id, snapshot_at, services_json, disk_json, system_json
        FROM health_snapshots
        ORDER BY snapshot_at DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    result = []
    for r in rows:
        entry = {
            "id":          r["id"],
            "snapshot_at": r["snapshot_at"],
        }
        for key, col in [("services", "services_json"), ("disk", "disk_json"), ("system", "system_json")]:
            try:
                entry[key] = json.loads(r[col] or "{}")
            except (json.JSONDecodeError, TypeError):
                entry[key] = {}
        result.append(entry)
    return result


def get_latest_health(conn) -> dict:
    """Return the most-recent stored health snapshot, or an empty dict."""
    history = get_health_history(conn, limit=1)
    return history[0] if history else {}


def prune_health_history(conn, keep: int = 168) -> int:
    """Delete old health snapshots beyond the most-recent ``keep`` rows."""
    keep   = max(1, int(keep))
    cursor = conn.execute(
        """
        DELETE FROM health_snapshots
        WHERE id NOT IN (
            SELECT id FROM health_snapshots
            ORDER BY snapshot_at DESC
            LIMIT ?
        )
        """,
        (keep,),
    )
    conn.commit()
    return cursor.rowcount
