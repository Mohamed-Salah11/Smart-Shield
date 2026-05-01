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


# ---------------------------------------------------------------------------
# Health alerting
# ---------------------------------------------------------------------------

_ALERT_THRESHOLDS = {
    "disk_pct":   90.0,   # % used
    "memory_pct": 90.0,   # % used
    "cpu_load":   8.0,    # 1-min load average (absolute, not per-core)
}


def _load_alert_settings(conn) -> dict:
    """Read alert settings from service_state. Returns {} if not configured."""
    try:
        row = conn.execute(
            "SELECT value_json FROM service_state WHERE key_name='health_alert_settings'"
        ).fetchone()
        if row:
            import json as _json
            return _json.loads(row["value_json"] or "{}")
    except Exception:
        pass
    return {}


def check_thresholds(snapshot: dict) -> list:
    """
    Compare a full_health_check snapshot against thresholds.
    Returns a list of human-readable alert strings; empty = all healthy.
    """
    alerts = []

    # Disk
    for disk in snapshot.get("disk", {}).get("disks", []):
        pct = disk.get("used_pct", 0)
        if pct > _ALERT_THRESHOLDS["disk_pct"]:
            alerts.append(
                f"Disk {disk.get('path','?')} is {pct:.1f}% full "
                f"({disk.get('used_gb','?')} GB / {disk.get('total_gb','?')} GB)"
            )

    # Memory
    mem_pct = snapshot.get("system", {}).get("memory_used_pct", 0)
    if mem_pct > _ALERT_THRESHOLDS["memory_pct"]:
        alerts.append(f"Memory usage is {mem_pct:.1f}% (threshold {_ALERT_THRESHOLDS['memory_pct']}%)")

    # CPU load
    cpu_load = snapshot.get("system", {}).get("cpu_load_1", 0)
    if cpu_load > _ALERT_THRESHOLDS["cpu_load"]:
        alerts.append(f"CPU 1-min load average is {cpu_load:.2f} (threshold {_ALERT_THRESHOLDS['cpu_load']})")

    # Stopped services (skip dry-run / unknown states)
    for svc_name, svc_data in snapshot.get("services", {}).items():
        if svc_name in ("interfaces", "config_drift"):
            continue
        if not isinstance(svc_data, dict):
            continue
        state = svc_data.get("state", "")
        if state in ("stopped",) and svc_data.get("running") is False:
            alerts.append(f"Service '{svc_name}' is stopped.")

    return alerts


def send_alerts(conn, snapshot: dict) -> list:
    """
    Check thresholds and dispatch alerts via every configured channel.
    Returns a list of dispatched alert strings (empty if nothing triggered).
    """
    alerts = check_thresholds(snapshot)
    if not alerts:
        return []

    settings  = _load_alert_settings(conn)
    channels  = settings.get("channels", [])
    subject   = "Smart Shield Health Alert"
    body      = "\n".join(f"• {a}" for a in alerts)
    body      = f"Smart Shield detected the following issues at {snapshot.get('timestamp','?')}:\n\n{body}"

    for ch in channels:
        ch_type = (ch.get("type") or "").lower()
        try:
            if ch_type == "email":
                _send_email_alert(ch, subject, body)
            elif ch_type == "webhook":
                _send_webhook_alert(ch, subject, body, alerts)
        except Exception as exc:
            import logging
            logging.getLogger(__name__).warning("Alert dispatch failed (%s): %s", ch_type, exc)

    return alerts


def _send_email_alert(cfg: dict, subject: str, body: str):
    import smtplib
    from email.mime.text import MIMEText

    host    = cfg.get("smtp_host", "localhost")
    port    = int(cfg.get("smtp_port", 25))
    use_tls = bool(cfg.get("use_tls", False))
    user    = cfg.get("smtp_user", "")
    passwd  = cfg.get("smtp_password", "")
    frm     = cfg.get("from_address", "smartshield@localhost")
    to_list = cfg.get("to_addresses", [])
    if not to_list:
        return

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"]    = frm
    msg["To"]      = ", ".join(to_list)

    if use_tls:
        smtp = smtplib.SMTP_SSL(host, port)
    else:
        smtp = smtplib.SMTP(host, port)
    try:
        if user and passwd:
            smtp.login(user, passwd)
        smtp.sendmail(frm, to_list, msg.as_string())
    finally:
        smtp.quit()


def _send_webhook_alert(cfg: dict, subject: str, body: str, alerts: list):
    import json as _json
    import urllib.request

    url     = cfg.get("url", "")
    method  = (cfg.get("method") or "POST").upper()
    headers = cfg.get("headers") or {"Content-Type": "application/json"}
    if not url:
        return

    payload = _json.dumps({
        "subject":   subject,
        "message":   body,
        "alerts":    alerts,
        "timestamp": _now_iso(),
    }).encode()

    req = urllib.request.Request(url, data=payload, method=method)
    for k, v in headers.items():
        req.add_header(k, v)
    with urllib.request.urlopen(req, timeout=10):
        pass
