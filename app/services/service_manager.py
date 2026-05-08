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
from app.services.priv_helper import run_privileged, PrivilegedActionError

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
        result = run_privileged("sysrc.get", key=key)
        if result.returncode == 0:
            return result.stdout.strip() or None
        return None

    except (FreeBSDNetworkError, PrivilegedActionError):
        return None


def sysrc_set(key: str, value: str) -> dict:
    """Set a persistent rc.conf value via sysrc."""
    if not _on_freebsd():
        return _ok(f"Non-FreeBSD — skipped sysrc {key}={value}")

    try:
        result = run_privileged("sysrc.set", key=key, value=value)
        ok = result.returncode == 0
        msg = (result.stdout or result.stderr or "").strip()
        return {"ok": ok, "message": msg or f"sysrc: {key}={value}"}

    except (FreeBSDNetworkError, PrivilegedActionError) as exc:
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
        result = run_privileged("service.action", service_name=name, action=action)
        ok = result.returncode == 0
        msg = (result.stdout or result.stderr or "").strip()
        return {"ok": ok, "message": msg or f"service {name} {action} completed"}
    except (FreeBSDNetworkError, PrivilegedActionError) as exc:
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


def get_all_service_health(conn) -> dict:
    """
    Return a lightweight health snapshot of all Smart Shield services.
    Safe to call on non-FreeBSD — returns ``state: "dry-run"`` for all.

    Result shape::

        {
          "pf":      {"running": bool, "state": str, "message": str},
          "dhcpd":   {...},
          "unbound": {...},
          "openvpn": {...},
          "ipsec":   {...},
          "ids":     {...},
          "interfaces": [{"name": str, "state": str, "ip": str}, ...],
        }
    """
    health: dict = {}

    # PF
    try:
        from app.services.pf_generator import get_pf_status
        health["pf"] = get_pf_status()
    except Exception as exc:
        health["pf"] = {"running": False, "state": "error", "message": str(exc)}

    # DHCP
    try:
        from app.services.dhcp_writer import get_dhcp_status
        health["dhcpd"] = get_dhcp_status()
    except Exception as exc:
        health["dhcpd"] = {"running": False, "state": "error", "message": str(exc)}

    # Unbound
    try:
        from app.services.dns_writer import get_unbound_status
        health["unbound"] = get_unbound_status()
    except Exception as exc:
        health["unbound"] = {"running": False, "state": "error", "message": str(exc)}

    # OpenVPN (best-effort)
    try:
        from app.services.openvpn_writer import get_openvpn_status
        ovpn = get_openvpn_status()
        health["openvpn"] = {
            "running": ovpn.get("running", False),
            "state":   "running" if ovpn.get("running") else "stopped",
            "message": ovpn.get("status", ""),
        }
    except Exception:
        health["openvpn"] = service_status("openvpn")

    # IPsec / strongSwan (best-effort)
    try:
        from app.services.ipsec_writer import get_ipsec_status
        ipsec = get_ipsec_status()
        health["ipsec"] = {
            "running": ipsec.get("running", False),
            "state":   "running" if ipsec.get("running") else "stopped",
            "message": ipsec.get("status", ""),
        }
    except Exception:
        health["ipsec"] = service_status("strongswan")

    # IDS / Suricata (best-effort)
    try:
        from app.services.ids_writer import get_ids_status
        ids = get_ids_status()
        health["ids"] = {
            "running": ids.get("running", False),
            "state":   "running" if ids.get("running") else "stopped",
            "message": ids.get("status", ""),
        }
    except Exception:
        health["ids"] = {"running": False, "state": "unknown", "message": "IDS status unavailable"}

    # PPPoE (best-effort)
    try:
        from app.services.pppoe_writer import get_pppoe_status
        pppoe = get_pppoe_status()
        health["pppoe"] = {
            "running":    pppoe.get("running", False),
            "state":      "running" if pppoe.get("running") else "stopped",
            "ip_address": pppoe.get("ip_address", ""),
            "message":    pppoe.get("message", ""),
        }
    except Exception:
        health["pppoe"] = {"running": False, "state": "unknown", "message": "PPPoE status unavailable"}

    # Interface state (LAN/WAN from DB + live on FreeBSD)
    interfaces = []
    try:
        cur = conn.cursor()
        for table, label in [("lan_config", "LAN"), ("wan_config", "WAN")]:
            cur.execute(f"SELECT assigned_port, ipv4_address FROM {table} LIMIT 1")
            row = cur.fetchone()
            if row:
                port = (row["assigned_port"] or "").strip()
                ip   = (row["ipv4_address"]  or "").strip()
                iface_info = {"name": label, "port": port, "ip": ip, "state": "unknown"}
                if _on_freebsd() and port:
                    try:
                        r = run_command(["ifconfig", port.split()[0]], check=False, timeout_seconds=3)
                        if r.returncode == 0:
                            iface_info["state"] = "up" if "status: active" in r.stdout else "down"
                    except Exception:
                        pass
                else:
                    iface_info["state"] = "dry-run"
                interfaces.append(iface_info)
    except Exception:
        pass
    health["interfaces"] = interfaces

    return health


def reload_all_services(conn) -> dict:
    """
    Inspect the DB for enabled services and reload/start each one.
    Returns a summary dict with per-service results.
    """
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

    # L2TP (mpd5)
    try:
        from app.services.l2tp_writer import write_l2tp_conf
        l2tp_result = write_l2tp_conf(conn)
        results.append({"service": "l2tp", "ok": l2tp_result["ok"], "message": l2tp_result["message"]})
        if l2tp_result["ok"]:
            r = service_action("mpd5", "restart")
            results.append({"service": "l2tp-restart", "ok": r["ok"], "message": r["message"]})
    except Exception as exc:
        results.append({"service": "l2tp", "ok": False, "message": str(exc)})

    # NTP — only apply when explicitly enabled
    try:
        import json as _j
        _row = conn.execute("SELECT value_json FROM service_state WHERE key_name='ntp_settings'").fetchone()
        _ntp = _j.loads(_row["value_json"]) if _row else {}
        if _ntp.get("enabled", True):
            from app.services.ntp_writer import apply_ntp
            ntp_result = apply_ntp(conn)
            results.append({"service": "ntpd", "ok": ntp_result["ok"], "message": ntp_result["message"]})
    except Exception as exc:
        results.append({"service": "ntpd", "ok": False, "message": str(exc)})

    # IDS / Suricata
    try:
        from app.services.ids_writer import write_suricata_config, _cfg as _ids_cfg
        ids_cfg = _ids_cfg(conn)
        if ids_cfg.get("enabled"):
            ids_result = write_suricata_config(conn)
            results.append({"service": "suricata", "ok": ids_result["ok"], "message": ids_result["message"]})
            if ids_result["ok"]:
                r = service_action("suricata", "restart")
                results.append({"service": "suricata-restart", "ok": r["ok"], "message": r["message"]})
    except Exception as exc:
        results.append({"service": "suricata", "ok": False, "message": str(exc)})

    # DDNS (ddclient) — only apply when at least one active client is configured
    try:
        import json as _j
        _row = conn.execute("SELECT value_json FROM service_state WHERE key_name='dynamic_dns_clients'").fetchone()
        _clients = _j.loads(_row["value_json"]) if _row else []
        if any(not c.get("disabled") for c in _clients):
            from app.services.ddns_writer import apply_ddns
            ddns_result = apply_ddns(conn)
            results.append({"service": "ddns", "ok": ddns_result["ok"], "message": ddns_result["message"]})
    except Exception as exc:
        results.append({"service": "ddns", "ok": False, "message": str(exc)})

    # SNMP (bsnmpd) — only apply when explicitly enabled
    try:
        import json as _j
        _row = conn.execute("SELECT value_json FROM service_state WHERE key_name='snmp_settings'").fetchone()
        _snmp = _j.loads(_row["value_json"]) if _row else {}
        if _snmp.get("enabled"):
            from app.services.snmp_writer import apply_snmp
            snmp_result = apply_snmp(conn)
            results.append({"service": "bsnmpd", "ok": snmp_result["ok"], "message": snmp_result["message"]})
    except Exception as exc:
        results.append({"service": "bsnmpd", "ok": False, "message": str(exc)})

    # UPnP (miniupnpd) — only apply when explicitly enabled
    try:
        import json as _j
        _row = conn.execute("SELECT value_json FROM service_state WHERE key_name='upnp_settings'").fetchone()
        _upnp = _j.loads(_row["value_json"]) if _row else {}
        if _upnp.get("enabled"):
            from app.services.upnp_writer import apply_upnp
            upnp_result = apply_upnp(conn)
            results.append({"service": "miniupnpd", "ok": upnp_result["ok"], "message": upnp_result["message"]})
    except Exception as exc:
        results.append({"service": "miniupnpd", "ok": False, "message": str(exc)})

    # IGMP proxy — only apply when explicitly enabled
    try:
        import json as _j
        _row = conn.execute("SELECT value_json FROM service_state WHERE key_name='igmp_settings'").fetchone()
        _igmp = _j.loads(_row["value_json"]) if _row else {}
        if _igmp.get("enabled"):
            from app.services.igmp_writer import apply_igmp
            igmp_result = apply_igmp(conn)
            results.append({"service": "igmpproxy", "ok": igmp_result["ok"], "message": igmp_result["message"]})
    except Exception as exc:
        results.append({"service": "igmpproxy", "ok": False, "message": str(exc)})

    # Captive portal PF anchor
    try:
        from app.services.captive_portal import apply_captive_portal, get_captive_status
        cp_status = get_captive_status(conn)
        if cp_status.get("enabled"):
            cp_result = apply_captive_portal(conn)
            results.append({"service": "captive_portal", "ok": cp_result["ok"], "message": cp_result["message"]})
    except Exception as exc:
        results.append({"service": "captive_portal", "ok": False, "message": str(exc)})

    overall_ok = all(r["ok"] for r in results)
    return {"ok": overall_ok, "results": results}
