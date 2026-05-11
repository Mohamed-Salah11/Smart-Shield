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
import os
import re
import sys
import tempfile
import textwrap

from app.services.network_service import FreeBSDNetworkError

_DHCPD_CONF_PATH       = "/etc/dhcpd.conf"
_DHCPD_KNOWN_GOOD_PATH = "/etc/dhcpd.conf.known_good"
_DHCPD_LEASE_PATH      = "/var/db/dhcpd/dhcpd.leases"


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


def _auto_pool_from_cidr(cidr: str) -> dict:
    """
    Derive sensible DHCP pool defaults from an interface CIDR.

    Reserves the first 99 host addresses for static assignments (gateway,
    servers, printers, etc.) and gives the remainder to the dynamic pool.
    For small subnets (< 10 hosts) splits at the midpoint instead.

    Returns a dict with: gateway_ip, start_ip, end_ip, dns_servers.
    Returns {} on parse failure.
    """
    try:
        iface  = ipaddress.ip_interface(cidr)
        gw     = str(iface.ip)
        hosts  = list(iface.network.hosts())
        if not hosts:
            return {}
        # Reserve first 99 addresses (or 1/4 of the range, whichever is smaller)
        offset = min(99, max(1, len(hosts) // 4))
        start  = str(hosts[min(offset, len(hosts) - 1)])
        end    = str(hosts[-1])
        return {
            "gateway_ip":  gw,
            "start_ip":    start,
            "end_ip":      end,
            "dns_servers": gw,   # Smart Shield / Unbound is the LAN DNS resolver
        }
    except Exception:
        return {}


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

        # Auto-derive missing fields from the interface CIDR so the pool works
        # out of the box even when the admin only toggled "enabled".
        auto = _auto_pool_from_cidr(iface_cidr)

        start_ip = (pool.get("start_ip") or "").strip() or auto.get("start_ip", "")
        end_ip   = (pool.get("end_ip")   or "").strip() or auto.get("end_ip",   "")
        if not start_ip or not end_ip:
            continue

        gateway  = (pool.get("gateway_ip")  or "").strip() or auto.get("gateway_ip",  "")
        dns_raw  = (pool.get("dns_servers") or "").strip()
        lease    = pool.get("lease_time") or 86400
        dns_list = _dns_list(dns_raw) or _dns_list(auto.get("dns_servers", ""))

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
# Syntax check + rollback helpers
# ---------------------------------------------------------------------------

def _validate_dhcpd_conf_syntax(conf: str) -> tuple:
    """
    Write conf to a temp file and run ``dhcpd -t -cf <tempfile>``.
    Returns ``(True, "")`` on success, ``(False, error_output)`` on failure.
    Skipped on non-FreeBSD or when dhcpd is not installed.
    """
    if not sys.platform.startswith("freebsd"):
        return (True, "skipped-non-freebsd")

    import shutil
    if not shutil.which("dhcpd"):
        return (True, "skipped-dhcpd-not-found")

    tmp_path = None
    try:
        from app.services.network_service import run_command
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".conf", delete=False, prefix="ss_dhcpd_"
        ) as f:
            f.write(conf)
            tmp_path = f.name

        result = run_command(["dhcpd", "-t", "-cf", tmp_path], check=False)
        ok  = result.returncode == 0
        msg = (result.stderr or result.stdout or "").strip()
        return (ok, msg)
    except Exception as exc:
        return (False, str(exc))
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass


def _save_known_good_dhcpd() -> bool:
    """Copy current dhcpd.conf to the known-good backup. Returns True on success."""
    try:
        if os.path.exists(_DHCPD_CONF_PATH):
            with open(_DHCPD_CONF_PATH) as fh:
                current = fh.read()
            with open(_DHCPD_KNOWN_GOOD_PATH, "w") as fh:
                fh.write(current)
        return True
    except OSError:
        return False


def _rollback_dhcpd() -> dict:
    """Restore the known-good dhcpd.conf and restart isc-dhcpd."""
    if not os.path.exists(_DHCPD_KNOWN_GOOD_PATH):
        return {"ok": False, "message": "No known-good dhcpd.conf backup found."}
    try:
        with open(_DHCPD_KNOWN_GOOD_PATH) as fh:
            old_conf = fh.read()
        with open(_DHCPD_CONF_PATH, "w") as fh:
            fh.write(old_conf)
        from app.services.service_manager import service_action
        result = service_action("isc-dhcpd", "restart")
        if result["ok"]:
            return {"ok": True, "message": "Rolled back to last known-good dhcpd.conf."}
        return {"ok": False, "message": f"Rollback file restored but restart failed: {result['message']}"}
    except OSError as exc:
        return {"ok": False, "message": f"Rollback failed: {exc}"}


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

    # 3. Syntax check via dhcpd -t
    syn_ok, syn_err = _validate_dhcpd_conf_syntax(conf)
    if not syn_ok:
        return {
            "ok": False,
            "message": f"dhcpd syntax check failed: {syn_err}",
            "conf": conf,
            "errors": [syn_err],
        }

    # 4. Backup current config as known-good
    _save_known_good_dhcpd()

    # 5. Write new config
    try:
        with open(_DHCPD_CONF_PATH, "w") as fh:
            fh.write(conf)
    except OSError as exc:
        return {"ok": False, "message": str(exc), "conf": conf, "errors": []}

    # 6. Enable service in rc.conf so it starts on reboot, then restart it
    from app.services.service_manager import service_action, sysrc_set
    sysrc_set("isc_dhcpd_enable", "YES")
    result = service_action("isc-dhcpd", "restart")
    if not result["ok"]:
        rb = _rollback_dhcpd()
        rb_msg = rb.get("message", "rollback status unknown")
        return {
            "ok": False,
            "message": f"isc-dhcpd restart failed ({result['message']}). {rb_msg}",
            "conf": conf,
            "errors": [],
            "rolled_back": rb["ok"],
        }
    return {
        "ok": True,
        "message": result["message"],
        "conf": conf,
        "errors": [],
        "rolled_back": False,
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


# ---------------------------------------------------------------------------
# Auto-configure pool from LAN interface + ARP discovery
# ---------------------------------------------------------------------------

def auto_configure_pool(conn, interface_type: str = "LAN") -> dict:
    """
    Derive DHCP pool settings from the interface CIDR and persist them to the
    dhcp_pools table.  Also runs an ARP scan so any already-online devices are
    registered in tracked_hosts (and can be promoted to static leases by the
    admin if desired).

    Returns {"ok": bool, "message": str, "pool": dict, "discovered": list}.
    """
    itype = interface_type.upper()

    # 1. Read interface CIDR
    if itype == "LAN":
        row = conn.execute(
            "SELECT ipv4_address, assigned_port FROM lan_config WHERE id=1"
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT ipv4_address, assigned_port FROM wan_config WHERE id=1"
        ).fetchone()

    cidr = (row["ipv4_address"] if row else "") or ""
    if not cidr:
        return {"ok": False, "message": f"{itype} interface has no IP configured.", "pool": {}, "discovered": []}

    pool = _auto_pool_from_cidr(cidr)
    if not pool:
        return {"ok": False, "message": f"Could not derive pool from CIDR '{cidr}'.", "pool": {}, "discovered": []}

    # 2. Persist to dhcp_pools (enable the pool, keep any existing lease_time)
    existing = conn.execute(
        "SELECT lease_time FROM dhcp_pools WHERE interface_type=?", (itype,)
    ).fetchone()
    lease_time = (existing["lease_time"] if existing else None) or 86400

    conn.execute(
        """
        INSERT INTO dhcp_pools (interface_type, enabled, start_ip, end_ip, gateway_ip, dns_servers, lease_time)
        VALUES (?, 1, ?, ?, ?, ?, ?)
        ON CONFLICT(interface_type) DO UPDATE SET
            enabled    = 1,
            start_ip   = excluded.start_ip,
            end_ip     = excluded.end_ip,
            gateway_ip = excluded.gateway_ip,
            dns_servers = excluded.dns_servers,
            updated_at = CURRENT_TIMESTAMP
        """,
        (itype, pool["start_ip"], pool["end_ip"], pool["gateway_ip"], pool["dns_servers"], lease_time),
    )
    conn.commit()

    # 3. ARP scan to discover currently-online devices on this interface
    discovered = []
    try:
        from app.services.network_service import list_arp_neighbors
        neighbors = list_arp_neighbors()
        iface_port = (row["assigned_port"] if row else "") or ""
        iface_net  = ipaddress.ip_interface(cidr).network

        for nb in neighbors:
            ip_str = nb.get("ip_address", "")
            try:
                ip_obj = ipaddress.ip_address(ip_str)
            except ValueError:
                continue
            if ip_obj not in iface_net:
                continue
            # Upsert into tracked_hosts
            conn.execute(
                """
                INSERT INTO tracked_hosts
                    (interface_type, interface_name, ip_address, mac_address, hostname, discovered_via, last_seen)
                VALUES (?, ?, ?, ?, ?, 'arp', CURRENT_TIMESTAMP)
                ON CONFLICT(interface_type, ip_address) DO UPDATE SET
                    mac_address   = excluded.mac_address,
                    hostname      = excluded.hostname,
                    interface_name = excluded.interface_name,
                    discovered_via = 'arp',
                    last_seen      = CURRENT_TIMESTAMP
                """,
                (itype, iface_port, ip_str,
                 nb.get("mac_address", ""), nb.get("hostname", "")),
            )
            discovered.append(nb)
        conn.commit()
    except Exception:
        pass

    pool["lease_time"] = lease_time
    pool["interface_type"] = itype
    return {
        "ok": True,
        "message": (
            f"{itype} pool auto-configured from {cidr}: "
            f"{pool['start_ip']} – {pool['end_ip']}, "
            f"gateway {pool['gateway_ip']}. "
            f"{len(discovered)} device(s) discovered on LAN."
        ),
        "pool": pool,
        "discovered": discovered,
    }
