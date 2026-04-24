"""
service_manager.py
------------------
FreeBSD service and rc.conf wrappers used by Smart Shield.

All calls go through run_command so SMARTSHIELD_NETWORK_DRY_RUN=1 is respected.

Public API
----------
service_action(name, action)       -> dict   {"ok", "message"}
sysrc_set(key, value)              -> dict
sysrc_get(key)                     -> str | None
service_is_enabled(name)           -> bool
service_status(name)               -> dict   {"ok", "running", "message"}
reload_all_services(conn)          -> dict   {"ok", "results": [...]}
"""

import sys
from app.services.network_service import run_command, FreeBSDNetworkError

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _on_freebsd() -> bool:
    return sys.platform.startswith("freebsd")


def _ok(msg: str) -> dict:
    return {"ok": True, "message": msg}


def _err(msg: str) -> dict:
    return {"ok": False, "message": msg}


# ---------------------------------------------------------------------------
# sysrc wrappers
# ---------------------------------------------------------------------------

def sysrc_get(key: str):
    """Read an rc.conf value. Returns string value or None."""
    if not _on_freebsd():
        return None
    try:
        result = run_command(["sysrc", "-n", key], check=False)
        if result.returncode == 0:
            return result.stdout.strip() or None
        return None
    except FreeBSDNetworkError:
        return None


def sysrc_set(key: str, value: str) -> dict:
    """Set a persistent rc.conf value via sysrc."""
    if not _on_freebsd():
        return _ok(f"Non-FreeBSD — skipped sysrc {key}={value}")
    try:
        run_command(["sysrc", f"{key}={value}"], check=True)
        return _ok(f"sysrc: {key}={value}")
    except FreeBSDNetworkError as exc:
        return _err(str(exc))


# ---------------------------------------------------------------------------
# service wrapper
# ---------------------------------------------------------------------------

VALID_ACTIONS = {"start", "stop", "restart", "reload", "status", "enable", "disable"}


def service_action(name: str, action: str) -> dict:
    """
    Run `service <name> <action>` on FreeBSD.
    For enable/disable, uses sysrc to set <name>_enable=YES/NO.
    """
    if not _on_freebsd():
        return _ok(f"Non-FreeBSD — skipped: service {name} {action}")

    action = action.lower().strip()
    if action not in VALID_ACTIONS:
        return _err(f"Unknown service action: {action}")

    if action == "enable":
        return sysrc_set(f"{name}_enable", "YES")
    if action == "disable":
        return sysrc_set(f"{name}_enable", "NO")

    try:
        result = run_command(["service", name, action], check=False)
        ok = result.returncode == 0
        msg = (result.stdout or result.stderr or "").strip()
        return {"ok": ok, "message": msg or f"service {name} {action} completed"}
    except FreeBSDNetworkError as exc:
        return _err(str(exc))


def service_is_enabled(name: str) -> bool:
    val = sysrc_get(f"{name}_enable")
    return (val or "").strip().upper() == "YES"


def service_status(name: str) -> dict:
    if not _on_freebsd():
        return {"ok": True, "running": False, "message": "Non-FreeBSD host"}
    result = service_action(name, "status")
    running = result.get("ok", False) and "running" in result.get("message", "").lower()
    return {"ok": result["ok"], "running": running, "message": result.get("message", "")}


# ---------------------------------------------------------------------------
# Known Smart Shield service names on FreeBSD
# ---------------------------------------------------------------------------

SERVICES = {
    "pf":       "pf",
    "pflog":    "pflog",
    "dhcpd":    "isc-dhcpd",
    "unbound":  "unbound",
    "openvpn":  "openvpn",
    "strongswan": "strongswan",
    "ntpd":     "ntpd",
    "nginx":    "nginx",
}


def reload_all_services(conn) -> dict:
    """
    Inspect the DB for enabled services and reload/start each one.
    Returns a summary dict with per-service results.
    """
    from app.database import get_db

    results = []

    # Always reload PF first
    from app.services.pf_generator import reload_pf_rules
    pf_result = reload_pf_rules(conn)
    results.append({"service": "pf", "ok": pf_result["ok"], "message": pf_result["message"]})

    # DHCP
    try:
        from app.services.dhcp_writer import write_dhcpd_conf
        dhcp_result = write_dhcpd_conf(conn)
        results.append({"service": "dhcpd", "ok": dhcp_result["ok"], "message": dhcp_result["message"]})
        if dhcp_result["ok"]:
            r = service_action(SERVICES["dhcpd"], "restart")
            results.append({"service": "dhcpd-restart", "ok": r["ok"], "message": r["message"]})
    except Exception as exc:
        results.append({"service": "dhcpd", "ok": False, "message": str(exc)})

    # DNS (unbound)
    try:
        from app.services.dns_writer import write_unbound_conf
        dns_result = write_unbound_conf(conn)
        results.append({"service": "unbound", "ok": dns_result["ok"], "message": dns_result["message"]})
        if dns_result["ok"]:
            r = service_action(SERVICES["unbound"], "restart")
            results.append({"service": "unbound-restart", "ok": r["ok"], "message": r["message"]})
    except Exception as exc:
        results.append({"service": "unbound", "ok": False, "message": str(exc)})

    # OpenVPN
    try:
        from app.services.openvpn_writer import write_openvpn_configs
        ovpn_result = write_openvpn_configs(conn)
        results.append({"service": "openvpn", "ok": ovpn_result["ok"], "message": ovpn_result["message"]})
        if ovpn_result["ok"]:
            r = service_action(SERVICES["openvpn"], "restart")
            results.append({"service": "openvpn-restart", "ok": r["ok"], "message": r["message"]})
    except Exception as exc:
        results.append({"service": "openvpn", "ok": False, "message": str(exc)})

    # IPsec
    try:
        from app.services.ipsec_writer import write_ipsec_conf
        ipsec_result = write_ipsec_conf(conn)
        results.append({"service": "strongswan", "ok": ipsec_result["ok"], "message": ipsec_result["message"]})
        if ipsec_result["ok"]:
            r = service_action(SERVICES["strongswan"], "restart")
            results.append({"service": "strongswan-restart", "ok": r["ok"], "message": r["message"]})
    except Exception as exc:
        results.append({"service": "strongswan", "ok": False, "message": str(exc)})

    overall_ok = all(r["ok"] for r in results)
    return {"ok": overall_ok, "results": results}
