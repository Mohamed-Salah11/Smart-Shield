"""
dhcpv6_writer.py
----------------
Generates Kea DHCPv6 configuration for FreeBSD.
Backend: Kea DHCP (pkg install kea)
Service: kea-dhcp6

Kea stores its config as JSON; this module generates kea-dhcp6.conf.

Public API
----------
generate_kea_dhcp6_conf(conn)  -> str   (JSON text)
validate_dhcpv6(conn)          -> list[str]
apply_dhcpv6(conn)             -> dict
get_dhcpv6_status()            -> dict
get_dhcpv6_leases()            -> list[dict]
"""

import ipaddress
import json
import sys

_KEA_DHCP6_CONF = "/usr/local/etc/kea/kea-dhcp6.conf"
_KEA_LEASE_FILE = "/var/db/kea/kea-leases6.csv"


def _rows(conn, sql, params=()):
    cur = conn.cursor()
    cur.execute(sql, params)
    return [dict(r) for r in cur.fetchall()]


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_dhcpv6(conn) -> list:
    errors = []
    pools = _rows(conn, "SELECT * FROM dhcpv6_pools WHERE enabled=1")
    if not pools:
        return []  # nothing configured, no errors

    for pool in pools:
        itype = (pool.get("interface_type") or "?").upper()
        start = (pool.get("start_address") or "").strip()
        end   = (pool.get("end_address") or "").strip()
        prefix = (pool.get("prefix") or "").strip()

        if start:
            try:
                addr = ipaddress.ip_address(start)
                if addr.version != 6:
                    errors.append(f"[{itype}] Start address {start!r} is not an IPv6 address.")
            except ValueError:
                errors.append(f"[{itype}] Start address {start!r} is invalid.")

        if end:
            try:
                addr = ipaddress.ip_address(end)
                if addr.version != 6:
                    errors.append(f"[{itype}] End address {end!r} is not an IPv6 address.")
            except ValueError:
                errors.append(f"[{itype}] End address {end!r} is invalid.")

        if prefix:
            try:
                net = ipaddress.ip_network(prefix, strict=False)
                if net.version != 6:
                    errors.append(f"[{itype}] Prefix {prefix!r} is not an IPv6 network.")
            except ValueError:
                errors.append(f"[{itype}] Prefix {prefix!r} is invalid.")

        lease_time = pool.get("valid_lifetime") or 0
        try:
            lt = int(lease_time)
            if lt < 60:
                errors.append(f"[{itype}] Valid lifetime {lt}s is too short (minimum 60s).")
        except (TypeError, ValueError):
            errors.append(f"[{itype}] Valid lifetime {lease_time!r} must be an integer.")

        dns_raw = (pool.get("dns_servers") or "").strip()
        for dns in (s.strip() for s in dns_raw.split(",") if s.strip()):
            try:
                a = ipaddress.ip_address(dns)
                if a.version != 6:
                    errors.append(f"[{itype}] DNS server {dns!r} is not an IPv6 address.")
            except ValueError:
                errors.append(f"[{itype}] DNS server {dns!r} is invalid.")

    return errors


# ---------------------------------------------------------------------------
# Config generator
# ---------------------------------------------------------------------------

def generate_kea_dhcp6_conf(conn) -> str:
    """Generate Kea DHCPv6 JSON configuration from the DB."""
    pools = _rows(conn, "SELECT * FROM dhcpv6_pools WHERE enabled=1 ORDER BY interface_type")

    subnets = []
    for pool in pools:
        itype   = (pool.get("interface_type") or "LAN").upper()
        prefix  = (pool.get("prefix") or "::/0").strip()
        start   = (pool.get("start_address") or "").strip()
        end     = (pool.get("end_address") or "").strip()
        valid   = pool.get("valid_lifetime") or 86400
        pref    = pool.get("preferred_lifetime") or 3600
        dns_raw = (pool.get("dns_servers") or "").strip()
        dns     = [s.strip() for s in dns_raw.split(",") if s.strip()]
        domain  = (pool.get("domain_search") or "").strip()
        iface   = (pool.get("interface_name") or "").strip()
        pd_pre  = (pool.get("pd_prefix") or "").strip()
        pd_len  = pool.get("pd_prefix_len") or 64

        subnet_obj: dict = {
            "id": pool.get("id", 1),
            "subnet": prefix,
            "valid-lifetime": valid,
            "preferred-lifetime": pref,
        }
        if iface:
            subnet_obj["interface"] = iface

        if start and end:
            subnet_obj["pools"] = [{"pool": f"{start} - {end}"}]

        # Prefix delegation pool
        if pd_pre:
            subnet_obj["pd-pools"] = [{
                "prefix": pd_pre,
                "prefix-len": pd_len,
                "delegated-len": pd_len,
            }]

        # Option data
        options = []
        if dns:
            options.append({
                "name": "dns-servers",
                "data": ", ".join(dns),
            })
        if domain:
            options.append({
                "name": "domain-search",
                "data": domain,
            })
        if options:
            subnet_obj["option-data"] = options

        subnets.append(subnet_obj)

    config = {
        "Dhcp6": {
            "interfaces-config": {
                "interfaces": ["*"],
                "dhcp-socket-type": "raw",
            },
            "lease-database": {
                "type": "memfile",
                "lfc-interval": 3600,
                "name": _KEA_LEASE_FILE,
            },
            "valid-lifetime": 86400,
            "preferred-lifetime": 3600,
            "renew-timer": 21600,
            "rebind-timer": 43200,
            "subnet6": subnets,
            "loggers": [{
                "name": "kea-dhcp6",
                "output_options": [{"output": "/var/log/kea/kea-dhcp6.log"}],
                "severity": "INFO",
            }],
        }
    }

    header = (
        "// ============================================================\n"
        "// Smart Shield — auto-generated kea-dhcp6.conf\n"
        "// Generated by app/services/dhcpv6_writer.py\n"
        "// Backend: Kea DHCP6 (pkg install kea)\n"
        "// DO NOT EDIT MANUALLY\n"
        "// ============================================================\n"
    )
    return header + json.dumps(config, indent=2)


# ---------------------------------------------------------------------------
# Write + apply
# ---------------------------------------------------------------------------

def apply_dhcpv6(conn) -> dict:
    errors = validate_dhcpv6(conn)
    conf   = generate_kea_dhcp6_conf(conn)

    if errors:
        return {"ok": False, "message": "Validation failed: " + " | ".join(errors),
                "conf": conf, "errors": errors}

    if not sys.platform.startswith("freebsd"):
        return {"ok": True, "message": "Non-FreeBSD — kea-dhcp6.conf generated but not written.",
                "conf": conf, "errors": []}

    import os
    os.makedirs("/usr/local/etc/kea", exist_ok=True)
    os.makedirs("/var/db/kea", exist_ok=True)
    os.makedirs("/var/log/kea", exist_ok=True)

    try:
        with open(_KEA_DHCP6_CONF, "w") as fh:
            fh.write(conf)
    except OSError as exc:
        return {"ok": False, "message": str(exc), "conf": conf, "errors": []}

    from app.services.service_manager import service_action
    r = service_action("kea-dhcp6", "restart")
    return {"ok": r["ok"], "message": r["message"], "conf": conf, "errors": []}


# ---------------------------------------------------------------------------
# Status + leases
# ---------------------------------------------------------------------------

def get_dhcpv6_status() -> dict:
    if not sys.platform.startswith("freebsd"):
        return {"running": False, "state": "dry-run", "message": "Non-FreeBSD host."}
    from app.services.service_manager import service_action
    r = service_action("kea-dhcp6", "status")
    running = r["ok"] and "running" in r.get("message", "").lower()
    return {"running": running, "state": "running" if running else "stopped",
            "message": r.get("message", "")}


def get_dhcpv6_leases() -> list:
    """Parse Kea lease CSV for active IPv6 leases."""
    if not sys.platform.startswith("freebsd"):
        return []
    try:
        import csv, io
        with open(_KEA_LEASE_FILE) as fh:
            reader = csv.DictReader(fh)
            leases = []
            for row in reader:
                if row.get("state", "0") == "0":  # 0 = active
                    leases.append({
                        "address":    row.get("address", ""),
                        "duid":       row.get("duid", ""),
                        "valid_lifetime": row.get("valid_lifetime", ""),
                        "expire":     row.get("expire", ""),
                        "hostname":   row.get("hostname", ""),
                    })
            return leases
    except (OSError, FileNotFoundError):
        return []
