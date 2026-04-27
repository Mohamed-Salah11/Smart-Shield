"""
igmp_writer.py
--------------
Generates igmpproxy.conf for FreeBSD multicast routing.
Backend: igmpproxy (pkg install igmpproxy)
Config:  /usr/local/etc/igmpproxy.conf
Service: igmpproxy

One upstream interface (Internet-facing) and one or more downstream
interfaces (LAN-facing) are required.

Public API
----------
generate_igmpproxy_conf(settings)  -> str
validate_igmp(settings)            -> list[str]
apply_igmp(conn)                   -> dict
get_igmp_status()                  -> dict
"""

import sys

_IGMPPROXY_CONF = "/usr/local/etc/igmpproxy.conf"


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_igmp(settings: dict) -> list:
    errors = []
    upstream = settings.get("upstream_interfaces") or []
    downstream = settings.get("downstream_interfaces") or []

    if not upstream:
        errors.append("At least one upstream (WAN) interface is required.")
    if not downstream:
        errors.append("At least one downstream (LAN) interface is required.")

    for iface_list, label in [(upstream, "upstream"), (downstream, "downstream")]:
        for iface in iface_list:
            name = (iface.get("interface") or "").strip()
            if not name:
                errors.append(f"An {label} interface has no name.")
            alt_subnet = iface.get("alt_subnet") or []
            for net in alt_subnet:
                import ipaddress
                n = (net or "").strip()
                if not n:
                    continue
                try:
                    ipaddress.ip_network(n, strict=False)
                except ValueError:
                    errors.append(f"[{name}] Alt subnet {n!r} is invalid.")

    return errors


# ---------------------------------------------------------------------------
# Config generator
# ---------------------------------------------------------------------------

def generate_igmpproxy_conf(settings: dict) -> str:
    upstream   = settings.get("upstream_interfaces") or []
    downstream = settings.get("downstream_interfaces") or []
    quick_leave = bool(settings.get("quick_leave", False))

    lines = [
        "#",
        "# Smart Shield — auto-generated igmpproxy.conf",
        "# Backend: igmpproxy (pkg install igmpproxy)",
        "# DO NOT EDIT MANUALLY",
        "#",
        "",
    ]

    if quick_leave:
        lines.append("quickleave")
        lines.append("")

    for iface in upstream:
        name    = (iface.get("interface") or "").strip()
        thresh  = iface.get("threshold") or 1
        altnets = iface.get("alt_subnet") or []
        if not name:
            continue
        lines.append(f"phyint {name} upstream  ratelimit 0  threshold {thresh}")
        for net in altnets:
            n = (net or "").strip()
            if n:
                lines.append(f"    altnet {n}")
        lines.append("")

    for iface in downstream:
        name    = (iface.get("interface") or "").strip()
        thresh  = iface.get("threshold") or 1
        altnets = iface.get("alt_subnet") or []
        if not name:
            continue
        lines.append(f"phyint {name} downstream  ratelimit 0  threshold {thresh}")
        for net in altnets:
            n = (net or "").strip()
            if n:
                lines.append(f"    altnet {n}")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------

def apply_igmp(conn) -> dict:
    import json
    rows = conn.execute(
        "SELECT value_json FROM service_state WHERE key_name='igmp_settings'"
    ).fetchone()
    settings = json.loads(rows["value_json"]) if rows else {}

    errors = validate_igmp(settings)
    conf   = generate_igmpproxy_conf(settings)

    if errors:
        return {"ok": False, "message": "Validation failed: " + " | ".join(errors), "conf": conf}

    if not sys.platform.startswith("freebsd"):
        return {"ok": True, "message": "Non-FreeBSD — igmpproxy.conf generated but not written.", "conf": conf}

    try:
        with open(_IGMPPROXY_CONF, "w") as fh:
            fh.write(conf)
    except OSError as exc:
        return {"ok": False, "message": str(exc), "conf": conf}

    from app.services.service_manager import service_action, sysrc_set
    enabled = bool(settings.get("enabled", True))
    if enabled:
        sysrc_set("igmpproxy_enable", "YES")
        r = service_action("igmpproxy", "restart")
    else:
        sysrc_set("igmpproxy_enable", "NO")
        r = service_action("igmpproxy", "stop")
    return {"ok": r["ok"], "message": r["message"], "conf": conf}


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

def get_igmp_status() -> dict:
    if not sys.platform.startswith("freebsd"):
        return {"running": False, "state": "dry-run", "message": "Non-FreeBSD host."}
    from app.services.service_manager import service_action
    r = service_action("igmpproxy", "status")
    running = r["ok"] and "running" in r.get("message", "").lower()
    return {"running": running, "state": "running" if running else "stopped",
            "message": r.get("message", "")}
