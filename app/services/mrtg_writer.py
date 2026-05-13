"""
mrtg_writer.py
--------------
Generate and apply the MRTG configuration for Smart Shield network interfaces.

MRTG is driven by cron every 5 minutes. When SNMP is enabled it polls bsnmpd
on localhost via SNMP (ifInOctets/ifOutOctets, interface-by-name lookup).
Falls back to mrtg-probe.sh (netstat -ibn) when SNMP is not configured.

Public API
----------
generate_mrtg_conf(conn)  -> str    # mrtg.cfg content
apply_mrtg(conn)          -> dict   # {"ok": bool, "message": str}
get_mrtg_status()         -> dict   # availability + diagnostics
"""

import os
import sys
import time

_MRTG_CONF_PATH  = "/usr/local/etc/mrtg/mrtg.cfg"
_MRTG_WORK_DIR   = "/var/db/smart-shield/mrtg"
_PROBE_SCRIPT    = "/usr/local/sbin/mrtg-probe.sh"
_MRTG_LOCK_FILE  = "/var/run/smart-shield/mrtg.lock"
_CRON_FILE       = "/etc/cron.d/smart-shield-mrtg"
_CRON_LINE       = (
    "*/5 * * * * root env LANG=C "
    "/usr/local/bin/mrtg /usr/local/etc/mrtg/mrtg.cfg "
    f"--lock-file {_MRTG_LOCK_FILE} 2>/dev/null\n"
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _iface_name(row: dict, key: str = "assigned_port") -> str:
    return (row.get(key) or "").strip()


def _get_snmp_settings(conn) -> dict:
    """Read SNMP settings from service_state. Returns {} if not configured."""
    try:
        import json
        row = conn.execute(
            "SELECT value_json FROM service_state WHERE key_name='snmp_settings'"
        ).fetchone()
        return json.loads(row["value_json"]) if row else {}
    except Exception:
        return {}


def _discover_interfaces(conn) -> list:
    """
    Return list of active interface port names from wan_config / lan_config,
    falling back to ['em0', 'em1'] if no interfaces are configured.
    """
    ifaces, seen = [], set()
    try:
        for table in ("wan_config", "lan_config"):
            row = conn.execute(
                f"SELECT assigned_port FROM {table} LIMIT 1"
            ).fetchone()
            if row:
                port = (row["assigned_port"] or "").strip()
                if port and port not in seen:
                    seen.add(port)
                    ifaces.append(port)
    except Exception:
        pass
    return ifaces or ["em0", "em1"]


def _ensure_run_dir() -> None:
    """/var/run is tmpfs on FreeBSD — cleared on every reboot. Create on demand."""
    run_dir = os.path.dirname(_MRTG_LOCK_FILE)
    os.makedirs(run_dir, exist_ok=True)


def _is_stale_lock() -> bool:
    """True when lock file is older than 10 minutes (process that held it is gone)."""
    if not os.path.exists(_MRTG_LOCK_FILE):
        return False
    return (time.time() - os.path.getmtime(_MRTG_LOCK_FILE)) > 600


def _clear_stale_lock() -> bool:
    """Remove lock file if stale. Returns True when a stale lock was removed."""
    if not _is_stale_lock():
        return False
    try:
        os.remove(_MRTG_LOCK_FILE)
        return True
    except OSError:
        return False


def _workdir_writable() -> bool:
    return os.access(_MRTG_WORK_DIR, os.W_OK)


def _ensure_cron_job() -> bool:
    """Write /etc/cron.d/smart-shield-mrtg if missing. Returns True when installed."""
    if os.path.exists(_CRON_FILE):
        return False
    try:
        with open(_CRON_FILE, "w") as fh:
            fh.write(_CRON_LINE)
        os.chmod(_CRON_FILE, 0o644)
        return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Config generation
# ---------------------------------------------------------------------------

def generate_mrtg_conf(conn) -> str:
    """Build a complete mrtg.cfg from dynamically discovered interfaces.

    Interfaces are discovered from the DB (interfaces table) with fallback
    to WAN/LAN config tables, then ['em0', 'em1'].
    Uses SNMP (bsnmpd on localhost) when SNMP is enabled and a community
    string is set. Falls back to the mrtg-probe.sh shell script otherwise.
    """
    # Prefer DB-discovered interfaces; fall back to WAN/LAN config table lookup
    db_ifaces = _discover_interfaces(conn)

    # Try to enrich with descriptions from wan_config / lan_config
    try:
        wan_row = conn.execute("SELECT assigned_port, description FROM wan_config LIMIT 1").fetchone()
        lan_row = conn.execute("SELECT assigned_port, description FROM lan_config LIMIT 1").fetchone()
    except Exception:
        wan_row = lan_row = None

    wan = dict(wan_row) if wan_row else {}
    lan = dict(lan_row) if lan_row else {}
    wan_iface_cfg = _iface_name(wan) or ""
    lan_iface_cfg = _iface_name(lan) or ""

    def _label_for(iface):
        if iface == wan_iface_cfg:
            return (wan.get("description") or "WAN").strip() or "WAN"
        if iface == lan_iface_cfg:
            return (lan.get("description") or "LAN").strip() or "LAN"
        return iface.upper()

    # Deduplicate
    seen = set()
    unique_ifaces = []
    for iface in db_ifaces:
        if iface and iface not in seen:
            seen.add(iface)
            unique_ifaces.append((iface, _label_for(iface), _label_for(iface)))

    # Resolve data source: SNMP (native) or shell script (fallback)
    snmp           = _get_snmp_settings(conn)
    snmp_enabled   = bool(snmp.get("enabled")) and bool((snmp.get("community") or "").strip())
    snmp_community = (snmp.get("community") or "smartshield").strip()
    snmp_port      = int(snmp.get("port") or 161)

    lines = [
        "# =================================================================",
        "# Smart Shield MRTG Configuration",
        "# Generated by app/services/mrtg_writer.py — do not edit manually",
        "# Interfaces discovered dynamically from DB (interfaces table)",
        "# =================================================================",
        "",
        f"WorkDir: {_MRTG_WORK_DIR}",
        "Refresh: 300",
        "Interval: 5",
        "Language: English",
        "Options[_]: growright, bits",
        "PathAdd: /usr/local/bin",
        "# Log rotation: newsyslog(8) rotates /var/log/mrtg.log weekly.",
        "# Add to /etc/newsyslog.conf:  /var/log/mrtg.log  644 7 * @T00 Z",
        "",
    ]

    for iface, desc, label in unique_ifaces:
        if snmp_enabled:
            # Native SNMP: \ifname resolves interface by ifDescr (= name on FreeBSD)
            target = f"\\{iface}:{snmp_community}@localhost:{snmp_port}"
        else:
            # Fallback: shell script reads netstat -ibn directly
            target = f"`{_PROBE_SCRIPT} {iface}`"

        lines += [
            f"# ── {label} interface: {iface} ──────────────────────────────",
            f"Target[{iface}]: {target}",
            f"MaxBytes[{iface}]: 125000000",
            f"Title[{iface}]: {label} Traffic — {iface} ({desc})",
            f"PageTop[{iface}]: <h1>{label} — {iface}</h1>",
            f"Options[{iface}]: bits, growright, noinfo",
            "",
        ]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------

def apply_mrtg(conn) -> dict:
    """Write mrtg.cfg, initialise log files, generate first PNG graphs, and
    ensure the cron job is in place so graphs keep updating every 5 minutes."""
    conf = generate_mrtg_conf(conn)

    snmp = _get_snmp_settings(conn)
    snmp_active = bool(snmp.get("enabled")) and bool((snmp.get("community") or "").strip())

    if not sys.platform.startswith("freebsd"):
        result = {
            "ok": True,
            "rolled_back": False,
            "message": "Non-FreeBSD — mrtg.cfg generated but not written.",
            "conf": conf,
        }
        if not snmp_active:
            result["snmp_note"] = (
                "SNMP not enabled — using mrtg-probe.sh fallback. "
                "Enable SNMP for native polling."
            )
        return result

    try:
        os.makedirs(os.path.dirname(_MRTG_CONF_PATH), exist_ok=True)
        os.makedirs(_MRTG_WORK_DIR, exist_ok=True)
    except Exception as exc:
        return {"ok": False, "rolled_back": False,
                "message": f"Cannot create MRTG directories: {exc}"}

    from app.services.config_file_utils import atomic_write, backup_config, rollback_config
    backup_config(_MRTG_CONF_PATH)
    try:
        atomic_write(_MRTG_CONF_PATH, conf, mode=0o644)
    except Exception as exc:
        return {"ok": False, "rolled_back": False,
                "message": f"Cannot write {_MRTG_CONF_PATH}: {exc}"}

    # Guarantee the lock-file directory exists (/var/run is tmpfs, cleared on reboot)
    try:
        _ensure_run_dir()
    except Exception as exc:
        return {"ok": False, "rolled_back": False,
                "message": f"Cannot create lock-file directory: {exc}"}

    # Remove any stale lock left by a crashed MRTG process before the two-pass init
    stale_removed = _clear_stale_lock()

    # Run MRTG twice:
    #   Pass 1: creates .log RRD files (exits non-zero because files are new — that is normal)
    #   Pass 2: reads the .log files and generates initial PNG graph images
    try:
        import subprocess
        _cmd = ["/usr/local/bin/mrtg", _MRTG_CONF_PATH,
                "--lock-file", _MRTG_LOCK_FILE, "--log-level", "0"]
        for i in range(2):
            subprocess.run(_cmd, capture_output=True, text=True, timeout=30)
            if i == 0:
                time.sleep(5)  # MRTG needs a time delta between runs to compute rates
    except FileNotFoundError:
        rb = rollback_config(_MRTG_CONF_PATH)
        return {"ok": False, "rolled_back": rb.get("ok", False),
                "message": "mrtg binary not found — is net-mgmt/mrtg installed?"}
    except Exception as exc:
        rb = rollback_config(_MRTG_CONF_PATH)
        return {"ok": False, "rolled_back": rb.get("ok", False),
                "message": f"MRTG first-run failed: {exc}"}

    # Ensure the cron job exists so graphs keep updating every 5 minutes.
    # This repairs the common case where install.sh ran before the MRTG package
    # was installed and the cron file was therefore never created.
    cron_installed = _ensure_cron_job()

    result = {
        "ok": True,
        "rolled_back": False,
        "message": f"MRTG config written to {_MRTG_CONF_PATH} and initialised.",
        "stale_lock_removed": stale_removed,
        "cron_installed": cron_installed,
    }
    if not snmp_active:
        result["snmp_note"] = (
            "SNMP not enabled — using mrtg-probe.sh fallback. "
            "Enable SNMP for native polling."
        )
    return result


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

def get_mrtg_status() -> dict:
    """
    Return MRTG availability status and diagnostics.

    MRTG is cron-driven (not a persistent daemon), so we report whether the
    binary is installed and provide specific diagnostic flags so the UI can
    show actionable guidance instead of a generic "no graphs yet" message.

    Returns {
        "available": bool,
        "state": str,
        "last_run": str|None,
        "graphs_ok": bool,
        "graph_count": int,
        "cron_installed": bool,
        "stale_lock": bool,
        "workdir_ok": bool,
        "message": str,
    }
    """
    import shutil

    mrtg_bin = "/usr/local/bin/mrtg"
    if not os.path.exists(mrtg_bin) and not shutil.which("mrtg"):
        return {
            "available":      False,
            "state":          "unavailable",
            "last_run":       None,
            "graphs_ok":      False,
            "graph_count":    0,
            "cron_installed": os.path.exists(_CRON_FILE),
            "stale_lock":     _is_stale_lock(),
            "workdir_ok":     False,
            "message":        "mrtg binary not found — install net-mgmt/mrtg.",
        }

    # Check when the mrtg.cfg was last written (proxy for last successful apply)
    last_run = None
    if os.path.exists(_MRTG_CONF_PATH):
        try:
            import datetime as _dt
            mtime = os.path.getmtime(_MRTG_CONF_PATH)
            last_run = _dt.datetime.fromtimestamp(mtime).isoformat()
        except Exception:
            pass

    # Count PNG graph files (proxy for successful cron execution)
    graph_files = []
    if os.path.isdir(_MRTG_WORK_DIR):
        try:
            graph_files = [f for f in os.listdir(_MRTG_WORK_DIR) if f.endswith(".png")]
        except OSError:
            pass

    workdir_ok = os.path.isdir(_MRTG_WORK_DIR) and _workdir_writable()

    return {
        "available":      True,
        "state":          "cron",
        "last_run":       last_run,
        "graphs_ok":      len(graph_files) > 0,
        "graph_count":    len(graph_files),
        "cron_installed": os.path.exists(_CRON_FILE),
        "stale_lock":     _is_stale_lock(),
        "workdir_ok":     workdir_ok,
        "message":        "MRTG runs via cron — not a persistent service.",
    }
