"""
upnp_writer.py
--------------
Generates miniupnpd.conf for FreeBSD.
Backend: miniupnpd (pkg install miniupnpd)
Config:  /usr/local/etc/miniupnpd/miniupnpd.conf
Service: miniupnpd

Security warning: UPnP/NAT-PMP allows LAN hosts to punch holes in the
firewall WITHOUT administrator approval.  Restrict to trusted subnets and
disable in high-security environments.

Public API
----------
generate_miniupnpd_conf(settings)  -> str
validate_upnp(settings)            -> list[str]
apply_upnp(conn)                   -> dict
get_upnp_status()                  -> dict
get_active_mappings()              -> list[dict]
"""

import ipaddress
import sys

_UPNP_CONF_DIR  = "/usr/local/etc/miniupnpd"
_UPNP_CONF_PATH = "/usr/local/etc/miniupnpd/miniupnpd.conf"
_UPNP_LEASE_FILE = "/var/db/miniupnpd/upnp.leases"


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_upnp(settings: dict) -> list:
    errors = []

    wan_iface = (settings.get("wan_interface") or "").strip()
    if not wan_iface:
        errors.append("WAN interface is required.")

    lan_iface = (settings.get("lan_interface") or "").strip()
    if not lan_iface:
        errors.append("LAN interface is required.")

    listening = settings.get("listening_ip") or []
    for ip in listening:
        s = (ip or "").strip()
        if not s:
            continue
        try:
            ipaddress.ip_address(s)
        except ValueError:
            errors.append(f"Listening IP {s!r} is invalid.")

    allowed = settings.get("allowed_subnets") or []
    for net in allowed:
        n = (net or "").strip()
        if not n:
            continue
        try:
            ipaddress.ip_network(n, strict=False)
        except ValueError:
            errors.append(f"Allowed subnet {n!r} is invalid.")

    ext_port_start = settings.get("ext_port_start")
    ext_port_end   = settings.get("ext_port_end")
    if ext_port_start is not None or ext_port_end is not None:
        try:
            ps = int(ext_port_start or 1024)
            pe = int(ext_port_end or 65535)
            if not (1 <= ps <= 65535):
                errors.append(f"External port start {ps} out of range 1–65535.")
            if not (1 <= pe <= 65535):
                errors.append(f"External port end {pe} out of range 1–65535.")
            if pe < ps:
                errors.append(f"External port end {pe} must be >= start {ps}.")
        except (TypeError, ValueError):
            errors.append("External port range values must be integers.")

    return errors


# ---------------------------------------------------------------------------
# Config generator
# ---------------------------------------------------------------------------

def generate_miniupnpd_conf(settings: dict) -> str:
    wan_iface   = (settings.get("wan_interface") or "em0").strip()
    lan_iface   = (settings.get("lan_interface") or "em1").strip()
    listening   = settings.get("listening_ip") or []
    secure_mode = bool(settings.get("secure_mode", True))
    enable_pcp  = bool(settings.get("enable_pcp", False))
    enable_natpmp = bool(settings.get("enable_natpmp", True))
    allowed_subs = settings.get("allowed_subnets") or []
    ext_port_start = settings.get("ext_port_start") or 1024
    ext_port_end   = settings.get("ext_port_end") or 65535
    uuid = settings.get("uuid") or "00000000-0000-0000-0000-000000000000"

    lines = [
        "# ============================================================",
        "# Smart Shield — auto-generated miniupnpd.conf",
        "# Backend: miniupnpd (pkg install miniupnpd)",
        "# WARNING: UPnP allows hosts to open firewall ports without",
        "#          administrator approval. Use with caution.",
        "# DO NOT EDIT MANUALLY",
        "# ============================================================",
        "",
        f"ext_ifname={wan_iface}",
        f"listening_ip={lan_iface}",
    ]

    for ip in listening:
        s = (ip or "").strip()
        if s:
            lines.append(f"listening_ip={s}")

    lines += [
        f"port=1900",
        f"enable_upnp=yes",
        f"enable_natpmp={'yes' if enable_natpmp else 'no'}",
        f"enable_pcp={'yes' if enable_pcp else 'no'}",
        f"secure_mode={'yes' if secure_mode else 'no'}",
        f"ext_perform_stun=yes",
        "",
        f"uuid={uuid}",
        "",
        f"# Port range for external mappings",
        f"ext_port_range={ext_port_start}-{ext_port_end}",
        "",
        "# Lease file",
        f"lease_file={_UPNP_LEASE_FILE}",
        "",
    ]

    # Allowed subnets
    if allowed_subs:
        lines.append("# Allowed subnets for UPnP requests")
        for net in allowed_subs:
            n = (net or "").strip()
            if n:
                lines.append(f"allow 1024-65535 {n} 1024-65535")
        lines.append("# Deny everything else")
        lines.append("deny 0-65535 0.0.0.0/0 0-65535")
    else:
        lines.append("allow 1024-65535 0.0.0.0/0 1024-65535")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------

def apply_upnp(conn) -> dict:
    import json, os
    rows = conn.execute(
        "SELECT value_json FROM service_state WHERE key_name='upnp_settings'"
    ).fetchone()
    settings = json.loads(rows["value_json"]) if rows else {}

    errors = validate_upnp(settings)
    conf   = generate_miniupnpd_conf(settings)

    if errors:
        return {"ok": False, "message": "Validation failed: " + " | ".join(errors), "conf": conf}

    if not sys.platform.startswith("freebsd"):
        return {"ok": True, "rolled_back": False,
                "message": "Non-FreeBSD — miniupnpd.conf generated but not written.", "conf": conf}

    os.makedirs(_UPNP_CONF_DIR, exist_ok=True)
    os.makedirs("/var/db/miniupnpd", exist_ok=True)

    from app.services.config_file_utils import apply_with_rollback
    from app.services.service_manager import service_action, sysrc_set
    enabled = bool(settings.get("enabled", True))

    def _restart():
        if enabled:
            sysrc_set("miniupnpd_enable", "YES")
            return service_action("miniupnpd", "restart")
        else:
            sysrc_set("miniupnpd_enable", "NO")
            return service_action("miniupnpd", "stop")

    result = apply_with_rollback(_UPNP_CONF_PATH, conf, _restart)
    return {**result, "conf": conf}


# ---------------------------------------------------------------------------
# Status + active mappings
# ---------------------------------------------------------------------------

def get_upnp_status() -> dict:
    if not sys.platform.startswith("freebsd"):
        return {"running": False, "state": "dry-run", "message": "Non-FreeBSD host."}
    from app.services.service_manager import service_action
    r = service_action("miniupnpd", "status")
    running = r["ok"] and "running" in r.get("message", "").lower()
    return {"running": running, "state": "running" if running else "stopped",
            "message": r.get("message", "")}


def get_active_mappings() -> list:
    """Parse the miniupnpd lease file for active port mappings."""
    if not sys.platform.startswith("freebsd"):
        return []
    try:
        mappings = []
        with open(_UPNP_LEASE_FILE) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Format: proto:ext_port:int_client:int_port:timestamp:description
                parts = line.split(":")
                if len(parts) >= 5:
                    mappings.append({
                        "protocol":     parts[0],
                        "ext_port":     parts[1],
                        "int_client":   parts[2],
                        "int_port":     parts[3],
                        "expires":      parts[4],
                        "description":  parts[5] if len(parts) > 5 else "",
                    })
        return mappings
    except (OSError, FileNotFoundError):
        return []
