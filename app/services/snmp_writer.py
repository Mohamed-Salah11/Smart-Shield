"""
snmp_writer.py
--------------
Generates bsnmpd.conf for FreeBSD base-system SNMP daemon.
bsnmpd ships in FreeBSD base; no extra package is needed.

Config: /etc/snmpd.config   (bsnmpd uses .config not .conf)
Service: bsnmpd

IMPORTANT: SNMP community strings are credentials. This module
masks them in all API responses and never logs them.

Public API
----------
generate_snmpd_config(settings)   -> str
validate_snmp(settings)           -> list[str]
apply_snmp(conn)                  -> dict
get_snmp_status()                 -> dict
mask_snmp_settings(settings)      -> dict
"""

import ipaddress
import sys

_SNMPD_CONF_PATH = "/etc/snmpd.config"
_SNMPD_PID_PATH  = "/var/run/bsnmpd.pid"


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_snmp(settings: dict) -> list:
    errors = []

    community = (settings.get("community") or "").strip()
    if not community:
        errors.append("SNMP community string is required.")
    if community.lower() in ("public", "private"):
        errors.append(
            f"Community string {community!r} is a well-known default — use a unique value."
        )

    port = settings.get("port") or 161
    try:
        p = int(port)
        if not (1 <= p <= 65535):
            errors.append(f"SNMP port must be 1–65535, got {port}.")
    except (TypeError, ValueError):
        errors.append(f"SNMP port must be an integer, got {port!r}.")

    allowed = settings.get("allowed_networks") or []
    for net in allowed:
        n = (net or "").strip()
        if not n:
            continue
        try:
            ipaddress.ip_network(n, strict=False)
        except ValueError:
            errors.append(f"Invalid network in allowed_networks: {n!r}.")

    return errors


# ---------------------------------------------------------------------------
# Config generator
# ---------------------------------------------------------------------------

def generate_snmpd_config(settings: dict) -> str:
    community   = (settings.get("community") or "smartshield").strip()
    location    = (settings.get("location") or "Unknown").strip()
    contact     = (settings.get("contact") or "admin@example.com").strip()
    interfaces  = settings.get("interfaces") or []
    port        = settings.get("port") or 161
    allowed     = settings.get("allowed_networks") or []
    read_write  = bool(settings.get("read_write", False))

    lines = [
        "#",
        "# Smart Shield — auto-generated snmpd.config",
        "# Backend: bsnmpd (FreeBSD base system)",
        "# COMMUNITY STRING IS A CREDENTIAL — permissions 0600",
        "# DO NOT EDIT MANUALLY",
        "#",
        "",
        'location := "%s"' % location,
        'contact  := "%s"' % contact,
        "",
        "# Enable MIB modules",
        "%include \"/usr/share/snmp/defs/tree.def\"",
        "%include \"/usr/share/snmp/defs/mibII.def\"",
        "",
    ]

    # Community access
    perm = "readwrite" if read_write else "read"
    if allowed:
        for net in allowed:
            n = (net or "").strip()
            if n:
                lines.append(f"community := \"{community}\" {perm} {n}")
    else:
        lines.append(f"community := \"{community}\" {perm}")

    lines += ["", "# Listen interfaces"]
    if interfaces:
        for iface in interfaces:
            i = (iface or "").strip()
            if i:
                lines.append(f"listen = udpport(\"{i}\", {port})")
    else:
        lines.append(f"listen = udpport(\"0.0.0.0\", {port})")

    lines += [
        "",
        "# System info",
        "sysDescr    := \"Smart Shield Firewall\"",
        "begemotSnmpdDebugDumpPdus    := 2",
        "begemotSnmpdDebugSyslogPrio  := 7",
        "",
    ]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Security validation (DB-level)
# ---------------------------------------------------------------------------

def validate_snmp_config(conn) -> list:
    """
    Validate SNMP security posture from DB.
    Returns list of warning strings (empty = no issues).
    Does NOT block apply — callers should treat these as warnings.
    """
    warnings = []
    row = None
    try:
        row = conn.execute("SELECT * FROM snmp_config WHERE id=1").fetchone()
    except Exception:
        pass

    if row is not None:
        row = dict(row)
        community = (row.get("community") or "public").strip()
        listen_addr = (row.get("listen_address") or "").strip()
    else:
        # Fall back to service_state
        try:
            import json as _json
            srow = conn.execute(
                "SELECT value_json FROM service_state WHERE key_name='snmp_settings'"
            ).fetchone()
            if not srow:
                return []
            settings = _json.loads(srow["value_json"])
            community = (settings.get("community") or "public").strip()
            listen_addr = (settings.get("listen_address") or "").strip()
        except Exception:
            return []

    if community.lower() in {"public", "private", "community", "snmp", "default"}:
        warnings.append(
            f"SNMP community string '{community}' is insecure — use a random string."
        )
    if listen_addr in {"0.0.0.0", ""}:
        warnings.append(
            "SNMP listens on all interfaces — restrict to LAN IP for security."
        )
    return warnings


# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------

def apply_snmp(conn) -> dict:
    import json
    rows = conn.execute(
        "SELECT value_json FROM service_state WHERE key_name='snmp_settings'"
    ).fetchone()
    settings = json.loads(rows["value_json"]) if rows else {}

    errors = validate_snmp(settings)
    conf   = generate_snmpd_config(settings)

    if errors:
        return {"ok": False, "message": "Validation failed: " + " | ".join(errors), "conf": conf}

    # Non-blocking security warnings
    sec_warnings = validate_snmp_config(conn)

    if not sys.platform.startswith("freebsd"):
        result = {"ok": True, "rolled_back": False,
                  "message": "Non-FreeBSD — snmpd.config generated but not written.", "conf": conf}
        result["warnings"] = sec_warnings
        return result

    from app.services.config_file_utils import apply_with_rollback
    from app.services.service_manager import service_action, sysrc_set
    enabled = bool(settings.get("enabled", True))

    def _restart():
        if enabled:
            sysrc_set("bsnmpd_enable", "YES")
            return service_action("bsnmpd", "restart")
        else:
            sysrc_set("bsnmpd_enable", "NO")
            return service_action("bsnmpd", "stop")

    result = apply_with_rollback(_SNMPD_CONF_PATH, conf, _restart, mode=0o600)
    result["warnings"] = sec_warnings
    return {**result, "conf": conf}


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

def get_snmp_status() -> dict:
    if not sys.platform.startswith("freebsd"):
        return {"running": False, "state": "dry-run", "message": "Non-FreeBSD host."}
    import os
    running = os.path.exists(_SNMPD_PID_PATH)
    if not running:
        from app.services.service_manager import service_action
        r = service_action("bsnmpd", "status")
        running = r["ok"] and "running" in r.get("message", "").lower()
    return {"running": running, "state": "running" if running else "stopped", "message": ""}


# ---------------------------------------------------------------------------
# Mask secrets for UI / API
# ---------------------------------------------------------------------------

def mask_snmp_settings(settings: dict) -> dict:
    """Return a copy of settings with the community string masked."""
    safe = dict(settings)
    if "community" in safe and safe["community"]:
        safe["community"] = "••••••••"
    return safe
