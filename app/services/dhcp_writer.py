"""
dhcp_writer.py
--------------
Generates /usr/local/etc/dhcpd.conf from Smart Shield's SQLite DHCP tables
and optionally reloads isc-dhcpd.

Public API
----------
validate_dhcp_config(conn)  -> list[str]           validation errors (empty = ok)
generate_dhcpd_conf(conn)   -> str
write_dhcpd_conf(conn)      -> {"ok", "message", "conf"}
apply_dhcpd(conn)           -> {"ok", "message", "conf"}
get_dhcp_status()           -> {"running", "state", "message"}
get_live_leases()           -> list[dict]
"""

import ipaddress
import re
import sys
import textwrap

from app.services.network_service import FreeBSDNetworkError

_DHCPD_CONF_PATH  = "/usr/local/etc/dhcpd.conf"
_DHCPD_LEASE_PATH = "/var/db/dhcpd/dhcpd.leases"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rows(conn, sql, params=()):
    cur = conn.cursor()
    cur.execute(sql, params)
    return [dict(r) for r in cur.fetchall()]


def _dns_list(raw: str) -> list:
    return [s.strip() for s in (raw or "").replace(";", ",").split(",") if s.strip()]


def _parse_cidr(cidr: str):
    """Return (network, netmask) strings or (None, None) on failure."""
    try:
        net = ipaddress.ip_interface(cidr).network
        return str(net.network_address), str(net.netmask)
    except Exception:
        return None, None


def _ip(s: str):
    """Return IPv4Address or None."""
    try:
        return ipaddress.IPv4Address((s or "").strip())
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_dhcp_config(conn) -> list:
    """
    Check the DHCP configuration for semantic errors.
    Returns a list of human-readable error strings; empty list means valid.
    """
    errors = []

    pools = _rows(conn, "SELECT * FROM dhcp_pools ORDER BY interface_type")
    all_static = _rows(conn, "SELECT * FROM static_leases")

    seen_macs = {}
    seen_ips  = {}

    for pool in pools:
        itype   = (pool.get("interface_type") or "?").upper()
        enabled = bool(pool.get("enabled"))
        if not enabled:
            continue

        start_raw  = (pool.get("start_ip")  or "").strip()
        end_raw    = (pool.get("end_ip")    or "").strip()
        gw_raw     = (pool.get("gateway_ip") or "").strip()
        dns_raw    = (pool.get("dns_servers") or "").strip()
        lease_time = pool.get("lease_time") or 0

        start = _ip(start_raw)
        end   = _ip(end_raw)

        if not start:
            errors.append(f"[{itype}] Pool start IP '{start_raw}' is invalid.")
        if not end:
            errors.append(f"[{itype}] Pool end IP '{end_raw}' is invalid.")
        if start and end and start > end:
            errors.append(f"[{itype}] Pool start {start_raw} > end {end_raw}.")

        # Verify pool IPs are within the interface subnet
        if itype == "LAN":
            iface_rows = _rows(conn, "SELECT ipv4_address FROM lan_config LIMIT 1")
        else:
            iface_rows = _rows(conn, "SELECT ipv4_address FROM wan_config LIMIT 1")

        if iface_rows:
            cidr = (iface_rows[0].get("ipv4_address") or "").strip()
            try:
                net = ipaddress.ip_interface(cidr).network
                if start and start not in net:
                    errors.append(f"[{itype}] Pool start {start_raw} not in interface subnet {cidr}.")
                if end and end not in net:
                    errors.append(f"[{itype}] Pool end {end_raw} not in interface subnet {cidr}.")
            except Exception:
                pass

        if gw_raw and not _ip(gw_raw):
            errors.append(f"[{itype}] Gateway '{gw_raw}' is not a valid IP.")

        for dns in _dns_list(dns_raw):
            if not _ip(dns):
                errors.append(f"[{itype}] DNS server '{dns}' is not a valid IP.")

        if lease_time < 60:
            errors.append(f"[{itype}] Lease time {lease_time}s is too short (minimum 60s).")

    # Check static leases
    for sl in all_static:
        mac = (sl.get("mac_address") or "").strip().lower()
        ip  = (sl.get("ip_address")  or "").strip()
        hostname = (sl.get("hostname") or "").strip()

        if not mac:
            errors.append(f"Static lease (hostname={hostname!r}) has no MAC address.")
            continue
        if not _ip(ip):
            errors.append(f"Static lease MAC={mac} has invalid IP '{ip}'.")

        # Duplicate MAC
        if mac in seen_macs:
            errors.append(f"Duplicate static lease MAC={mac} (also used by {seen_macs[mac]}).")
        else:
            seen_macs[mac] = ip

        # Duplicate IP
        if ip in seen_ips:
            errors.append(f"Duplicate static lease IP={ip} (also assigned to MAC {seen_ips[ip]}).")
        else:
            seen_ips[ip] = mac

        # Check static IP doesn't fall inside any enabled dynamic pool
        ip_obj = _ip(ip)
        if ip_obj:
            for pool in pools:
                if not pool.get("enabled"):
                    continue
                s = _ip(pool.get("start_ip") or "")
                e = _ip(pool.get("end_ip") or "")
                if s and e and s <= ip_obj <= e:
                    itype = pool.get("interface_type", "?")
                    errors.append(
                        f"Static lease IP={ip} (MAC={mac}) falls inside {itype} pool "
                        f"{pool['start_ip']}–{pool['end_ip']}."
                    )

    return errors


# ---------------------------------------------------------------------------
# Config generator
# ---------------------------------------------------------------------------

def generate_dhcpd_conf(conn) -> str:
    lines = [
        "# ============================================================",
        "# Smart Shield — auto-generated dhcpd.conf",
        "# Generated by app/services/dhcp_writer.py",
        "# DO NOT EDIT MANUALLY",
        "# ============================================================",
        "",
        "default-lease-time 86400;",
        "max-lease-time 86400;",
        "authoritative;",
        "",
    ]

    pools = _rows(conn, "SELECT * FROM dhcp_pools WHERE enabled=1 ORDER BY interface_type")
    for pool in pools:
        itype = (pool.get("interface_type") or "LAN").upper()

        if itype == "LAN":
            iface_rows = _rows(conn, "SELECT ipv4_address, assigned_port FROM lan_config LIMIT 1")
        else:
            iface_rows = _rows(conn, "SELECT ipv4_address, assigned_port FROM wan_config LIMIT 1")

        iface_row  = iface_rows[0] if iface_rows else {}
        iface_cidr = iface_row.get("ipv4_address") or ""
        iface_port = iface_row.get("assigned_port") or ""

        subnet, netmask = _parse_cidr(iface_cidr)
        if not subnet:
            continue

        start_ip = (pool.get("start_ip") or "").strip()
        end_ip   = (pool.get("end_ip")   or "").strip()
        if not start_ip or not end_ip:
            continue

        gateway  = (pool.get("gateway_ip")  or "").strip()
        dns_raw  = (pool.get("dns_servers") or "").strip()
        lease    = pool.get("lease_time") or 86400
        dns_list = _dns_list(dns_raw)

        lines.append(f"# {itype} pool ({iface_port or itype})")
        lines.append(f"subnet {subnet} netmask {netmask} {{")
        lines.append(f"    range {start_ip} {end_ip};")
        if gateway:
            lines.append(f"    option routers {gateway};")
        if dns_list:
            lines.append(f"    option domain-name-servers {', '.join(dns_list)};")
        lines.append(f"    default-lease-time {lease};")
        lines.append(f"    max-lease-time {lease};")
        lines.append("}")
        lines.append("")

    # Static leases
    leases = _rows(conn, "SELECT * FROM static_leases ORDER BY interface_type, hostname")
    if leases:
        lines.append("# ── Static leases ──")
        for lease in leases:
            hostname = (lease.get("hostname") or "").strip()
            mac      = (lease.get("mac_address") or "").strip().lower()
            ip       = (lease.get("ip_address")  or "").strip()
            if not mac or not ip:
                continue
            host_id = hostname.replace(" ", "_") if hostname else mac.replace(":", "")
            lines.append(f"host {host_id} {{")
            lines.append(f"    hardware ethernet {mac};")
            lines.append(f"    fixed-address {ip};")
            if hostname:
                lines.append(f'    option host-name "{hostname}";')
            lines.append("}")
            lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Write
# ---------------------------------------------------------------------------

def write_dhcpd_conf(conn) -> dict:
    conf = generate_dhcpd_conf(conn)
    if not sys.platform.startswith("freebsd"):
        return {"ok": True, "message": "Non-FreeBSD — dhcpd.conf generated but not written.", "conf": conf}
    try:
        with open(_DHCPD_CONF_PATH, "w") as fh:
            fh.write(conf)
        return {"ok": True, "message": f"Written to {_DHCPD_CONF_PATH}", "conf": conf}
    except OSError as exc:
        return {"ok": False, "message": str(exc), "conf": conf}


# ---------------------------------------------------------------------------
# Apply (write + service restart)
# ---------------------------------------------------------------------------

def apply_dhcpd(conn) -> dict:
    """
    Validate config, write dhcpd.conf, and restart isc-dhcpd.
    On non-FreeBSD: validate + generate only (no filesystem writes, no restart).
    Returns ``{"ok": bool, "message": str, "conf": str, "errors": list}``.
    """
    # 1. Validate
    errors = validate_dhcp_config(conn)
    conf   = generate_dhcpd_conf(conn)

    if errors:
        return {
            "ok": False,
            "message": f"DHCP config has {len(errors)} error(s); not applied.",
            "conf": conf,
            "errors": errors,
        }

    # 2. Non-FreeBSD dry-run
    if not sys.platform.startswith("freebsd"):
        return {
            "ok": True,
            "message": "Non-FreeBSD — dhcpd.conf generated but not applied.",
            "conf": conf,
            "errors": [],
        }

    # 3. Write
    try:
        with open(_DHCPD_CONF_PATH, "w") as fh:
            fh.write(conf)
    except OSError as exc:
        return {"ok": False, "message": str(exc), "conf": conf, "errors": []}

    # 4. Restart service
    from app.services.service_manager import service_action
    result = service_action("isc-dhcpd", "restart")
    return {
        "ok": result["ok"],
        "message": result["message"],
        "conf": conf,
        "errors": [],
    }


# ---------------------------------------------------------------------------
# Service status
# ---------------------------------------------------------------------------

def get_dhcp_status() -> dict:
    """Return the live isc-dhcpd running state."""
    if not sys.platform.startswith("freebsd"):
        return {"running": False, "state": "dry-run", "message": "Non-FreeBSD host."}
    from app.services.service_manager import service_action
    result = service_action("isc-dhcpd", "status")
    msg    = result.get("message", "")
    running = result.get("ok", False) and "running" in msg.lower()
    return {
        "running": running,
        "state":   "running" if running else "stopped",
        "message": msg,
    }


# ---------------------------------------------------------------------------
# Live lease file parser
# ---------------------------------------------------------------------------

_LEASE_IP_RE    = re.compile(r"^lease\s+(\S+)\s*\{", re.M)
_LEASE_FIELD_RE = re.compile(r"^\s+(\S+.*?)\s*;", re.M)


def get_live_leases() -> list:
    """
    Parse /var/db/dhcpd/dhcpd.leases and return active leases as a list of dicts.
    On non-FreeBSD or if the file doesn't exist, returns [].
    """
    if not sys.platform.startswith("freebsd"):
        return []

    try:
        with open(_DHCPD_LEASE_PATH) as fh:
            text = fh.read()
    except (OSError, FileNotFoundError):
        return []

    leases = []
    # Split into lease blocks
    blocks = re.split(r"^lease\s+", text, flags=re.M)[1:]
    for block in blocks:
        lines = block.strip().splitlines()
        if not lines:
            continue
        ip = lines[0].split()[0].rstrip("{").strip()
        entry = {"ip_address": ip}
        for line in lines[1:]:
            line = line.strip().rstrip(";").rstrip("}")
            if not line or line == "}":
                continue
            if line.startswith("hardware ethernet"):
                entry["mac_address"] = line.split()[-1]
            elif line.startswith("client-hostname"):
                entry["hostname"] = line.split(None, 1)[-1].strip('"')
            elif line.startswith("starts"):
                parts = line.split(None, 2)
                if len(parts) >= 3:
                    entry["starts"] = parts[2]
            elif line.startswith("ends"):
                parts = line.split(None, 2)
                if len(parts) >= 3:
                    entry["ends"] = parts[2]
            elif line.startswith("binding state"):
                entry["state"] = line.split(None, 2)[-1]
        leases.append(entry)

    # Return only active leases
    return [l for l in leases if l.get("state", "active") == "active"]
