"""
pf_generator.py
---------------
Generates /etc/pf.conf from Smart Shield's SQLite database and applies it
via pfctl.  All OS calls go through network_service.run_command so
SMARTSHIELD_NETWORK_DRY_RUN=1 is respected everywhere.

Public API
----------
generate_pf_conf(conn)          -> str          full pf.conf text from DB
validate_pf_conf(text)          -> (bool, str)  (ok, error_message)
reload_pf_rules(conn)           -> dict         {"ok", "message", "conf"}
get_pf_status()                 -> dict         {"running", "state", "message"}
rollback_pf()                   -> dict         {"ok", "message"}
"""

import os
import sys
import tempfile
import textwrap
from typing import Optional

from app.services.network_service import run_command, FreeBSDNetworkError

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_PF_CONF_PATH      = "/etc/pf.conf"
_PF_KNOWN_GOOD_PATH = "/etc/pf.conf.known_good"

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _rows(conn, sql, params=()):
    cur = conn.cursor()
    cur.execute(sql, params)
    return [dict(r) for r in cur.fetchall()]


def _addr(addr: Optional[str]) -> str:
    a = (addr or "").strip()
    return "any" if (not a or a.lower() == "any") else a


def _proto_line(proto: Optional[str]) -> str:
    p = (proto or "").strip().lower()
    return f"proto {p} " if p and p not in {"any", "all", ""} else ""


def _port_line(port: Optional[str], prefix="port ") -> str:
    p = (port or "").strip()
    return f"{prefix}{p} " if p and p not in {"any", ""} else ""


# ---------------------------------------------------------------------------
# 1. Alias tables
# ---------------------------------------------------------------------------

def _build_alias_tables(conn) -> str:
    rows = _rows(conn, "SELECT name, type, alias_values FROM firewall_aliases ORDER BY name")
    if not rows:
        return ""
    lines = ["# ── Aliases / Tables ──"]
    import json as _json
    for row in rows:
        name = (row.get("name") or "").strip()
        atype = (row.get("type") or "host").lower()
        raw = (row.get("alias_values") or "").strip()
        if not name or not raw:
            continue
        # alias_values may be JSON array or comma-separated
        try:
            vals = _json.loads(raw)
            if isinstance(vals, list):
                values = [str(v).strip() for v in vals if str(v).strip()]
            else:
                values = [str(vals).strip()]
        except Exception:
            values = [v.strip() for v in raw.replace("\n", ",").split(",") if v.strip()]
        if not values:
            continue
        if atype in ("host", "network", "urltable"):
            lines.append(f"table <{name}> persist {{ {' '.join(values)} }}")
        else:
            # port list → macro
            lines.append(f'{name} = "{{ {", ".join(values)} }}"')
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 2. NAT rules  (outbound → 1:1 → port-forwards → NPt)
# ---------------------------------------------------------------------------

def _build_nat_rules(conn, wan_iface: str) -> str:
    lines = ["# ── NAT Rules ──"]

    # Outbound NAT
    for r in _rows(conn, "SELECT * FROM nat_outbound WHERE disabled=0 ORDER BY rule_order, id"):
        iface   = (r.get("interface") or wan_iface).strip() or wan_iface
        src     = _addr(r.get("src_address"))
        dst     = _addr(r.get("dst_address"))
        nat_addr = (r.get("nat_address") or "").strip()
        static   = " static-port" if r.get("static_port") else ""
        target   = f"({iface})" if not nat_addr else nat_addr
        desc     = (r.get("description") or "").strip()
        if desc:
            lines.append(f"# {desc}")
        lines.append(f"nat on {iface} from {src} to {dst} -> {target}{static}")

    # 1:1 NAT
    for r in _rows(conn, "SELECT * FROM nat_1to1 WHERE disabled=0 ORDER BY rule_order, id"):
        iface    = (r.get("interface") or wan_iface).strip() or wan_iface
        ext      = _addr(r.get("external_address"))
        internal = _addr(r.get("internal_address"))
        desc     = (r.get("description") or "").strip()
        if desc:
            lines.append(f"# {desc}")
        lines.append(f"binat on {iface} from {internal} to any -> {ext}")

    # Port forwards (rdr)
    for r in _rows(conn, "SELECT * FROM nat_pf WHERE disabled=0 ORDER BY rule_order, id"):
        iface    = (r.get("interface") or wan_iface).strip() or wan_iface
        proto    = (r.get("protocol") or "tcp").lower()
        src      = _addr(r.get("src_address"))
        dst      = _addr(r.get("dst_address"))
        redirect = _addr(r.get("redirect_ip"))
        desc     = (r.get("description") or "").strip()
        if not redirect or redirect == "any":
            continue  # skip rules with no redirect target
        if desc:
            lines.append(f"# {desc}")
        lines.append(f"rdr on {iface} proto {proto} from {src} to {dst} -> {redirect}")

    # NPt — Network Prefix Translation (IPv6)
    for r in _rows(conn, "SELECT * FROM nat_npt WHERE disabled=0 ORDER BY rule_order, id"):
        iface    = (r.get("interface") or wan_iface).strip() or wan_iface
        src_not  = "!" if r.get("src_not") else ""
        src_pfx  = (r.get("src_prefix") or "").strip()
        dst_not  = "!" if r.get("dst_not") else ""
        dst_pfx  = (r.get("dst_prefix") or "").strip()
        desc     = (r.get("description") or "").strip()
        if not src_pfx or not dst_pfx:
            continue
        if desc:
            lines.append(f"# {desc}")
        lines.append(f"binat6 on {iface} from {src_not}{src_pfx} to {dst_not}{dst_pfx}")

    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 3. Firewall rules  (floating → WAN → LAN)
# ---------------------------------------------------------------------------

def _build_firewall_rules(conn, wan_iface: str, lan_iface: str) -> str:
    lines = ["# ── Firewall Rules ──"]

    # Floating
    for r in _rows(conn, "SELECT * FROM firewall_rules_floating WHERE disabled=0 ORDER BY rule_order, id"):
        iface  = (r.get("interface") or "").strip()
        proto  = _proto_line(r.get("protocol"))
        src    = _addr(r.get("source"))
        sport  = _port_line(r.get("source_port"))
        dst    = _addr(r.get("destination"))
        dport  = _port_line(r.get("dest_port"))
        action = (r.get("action") or "pass").lower()
        ipart  = f"on {iface} " if iface else ""
        desc   = (r.get("description") or "").strip()
        if desc:
            lines.append(f"# {desc}")
        lines.append(f"{action} quick {ipart}{proto}from {src} {sport}to {dst} {dport}keep state")

    # WAN
    for r in _rows(conn, "SELECT * FROM firewall_rules_wan WHERE disabled=0 ORDER BY rule_order, id"):
        proto  = _proto_line(r.get("protocol"))
        src    = _addr(r.get("source"))
        dst    = _addr(r.get("destination"))
        action = (r.get("action") or "pass").lower()
        desc   = (r.get("description") or "").strip()
        if desc:
            lines.append(f"# {desc}")
        lines.append(f"{action} in on {wan_iface} {proto}from {src} to {dst} keep state")

    # LAN
    for r in _rows(conn, "SELECT * FROM firewall_rules_lan WHERE disabled=0 ORDER BY rule_order, id"):
        proto  = _proto_line(r.get("protocol"))
        src    = _addr(r.get("source"))
        dst    = _addr(r.get("destination"))
        desc   = (r.get("description") or "").strip()
        if desc:
            lines.append(f"# {desc}")
        lines.append(f"pass in on {lan_iface} {proto}from {src} to {dst} keep state")

    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 4. Application filter PF rules
# ---------------------------------------------------------------------------

def _build_app_filter_rules(conn) -> str:
    try:
        from app.services.app_filter import generate_app_filter_pf_rules
        return generate_app_filter_pf_rules(conn)
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# 5. Canonical PF config generator
# ---------------------------------------------------------------------------

def generate_pf_conf(conn) -> str:
    """
    Build the complete pf.conf from the Smart Shield database.
    Pipeline: header → aliases → default NAT → NAT rules → default policy
              → app filter → firewall rules
    """
    lan_rows = _rows(conn, "SELECT assigned_port, ipv4_address FROM lan_config LIMIT 1")
    wan_rows = _rows(conn, "SELECT assigned_port, ipv4_config_type, ipv4_address FROM wan_config LIMIT 1")

    lan_iface = (lan_rows[0].get("assigned_port") or "em1") if lan_rows else "em1"
    wan_iface = (wan_rows[0].get("assigned_port") or "em0") if wan_rows else "em0"
    lan_net   = (lan_rows[0].get("ipv4_address") or "192.168.1.0/24") if lan_rows else "192.168.1.0/24"

    wan_type  = (wan_rows[0].get("ipv4_config_type") or "dhcp") if wan_rows else "dhcp"
    if wan_type == "pppoe":
        wan_iface = "tun0"  # PPPoE sessions appear on tun0

    try:
        import ipaddress as _ipaddress
        lan_net = str(_ipaddress.ip_interface(lan_net).network)
    except Exception:
        pass

    header = textwrap.dedent(f"""\
        # ============================================================
        # Smart Shield — auto-generated pf.conf
        # Generated by app/services/pf_generator.py
        # DO NOT EDIT MANUALLY — changes will be overwritten
        # ============================================================

        WAN     = "{wan_iface}"
        LAN     = "{lan_iface}"
        LAN_NET = "{lan_net}"

        set block-policy drop
        set skip on lo0

        scrub in all

    """)

    # Default outbound masquerade only when no explicit outbound rules
    out_count = _rows(conn, "SELECT COUNT(*) AS c FROM nat_outbound WHERE disabled=0")[0]["c"]
    default_nat = (
        f"# Default masquerade — LAN to WAN\n"
        f"nat on $WAN from $LAN_NET to any -> ($WAN)\n\n"
    ) if out_count == 0 else ""

    default_policy = textwrap.dedent("""\
        # ── Default policy ──
        block all
        pass out quick keep state
        pass in on $LAN keep state

    """)

    return (
        header
        + _build_alias_tables(conn)
        + default_nat
        + _build_nat_rules(conn, wan_iface)
        + default_policy
        + _build_app_filter_rules(conn)
        + _build_firewall_rules(conn, wan_iface, lan_iface)
    )


# ---------------------------------------------------------------------------
# 6. pfctl validation (syntax check)
# ---------------------------------------------------------------------------

def validate_pf_conf(text: str) -> tuple:
    """
    Validate pf.conf syntax via ``pfctl -nf``.
    Returns ``(True, "")`` on success, ``(False, error_message)`` on failure.
    On non-FreeBSD returns ``(True, "skipped-non-freebsd")``.
    """
    if not sys.platform.startswith("freebsd"):
        return (True, "skipped-non-freebsd")

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".conf", delete=False, prefix="ss_pf_"
        ) as f:
            f.write(text)
            tmp_path = f.name

        result = run_command(["pfctl", "-nf", tmp_path], check=False)
        ok  = result.returncode == 0
        msg = (result.stderr or result.stdout or "").strip()
        return (ok, msg)
    except FreeBSDNetworkError as exc:
        return (False, str(exc))
    finally:
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# 7. Rollback support
# ---------------------------------------------------------------------------

def _save_known_good() -> bool:
    """Copy current pf.conf to the known-good backup. Returns True on success."""
    try:
        if os.path.exists(_PF_CONF_PATH):
            with open(_PF_CONF_PATH) as fh:
                current = fh.read()
            with open(_PF_KNOWN_GOOD_PATH, "w") as fh:
                fh.write(current)
        return True
    except OSError:
        return False


def rollback_pf() -> dict:
    """
    Restore the known-good pf.conf and reload PF.
    Returns ``{"ok": bool, "message": str}``.
    """
    if not sys.platform.startswith("freebsd"):
        return {"ok": False, "message": "Rollback only runs on FreeBSD."}

    if not os.path.exists(_PF_KNOWN_GOOD_PATH):
        return {"ok": False, "message": "No known-good backup found."}

    try:
        with open(_PF_KNOWN_GOOD_PATH) as fh:
            old_conf = fh.read()
        with open(_PF_CONF_PATH, "w") as fh:
            fh.write(old_conf)
        run_command(["pfctl", "-f", _PF_CONF_PATH], check=True)
        return {"ok": True, "message": "Rolled back to last known-good pf.conf."}
    except (OSError, FreeBSDNetworkError) as exc:
        return {"ok": False, "message": f"Rollback failed: {exc}"}


# ---------------------------------------------------------------------------
# 8. PF running status
# ---------------------------------------------------------------------------

def get_pf_status() -> dict:
    """
    Return the live PF running state.
    On non-FreeBSD returns state='dry-run'.
    """
    if not sys.platform.startswith("freebsd"):
        return {
            "running": False,
            "state":   "dry-run",
            "message": "Non-FreeBSD host — PF not available.",
            "enabled": False,
        }
    try:
        result = run_command(["pfctl", "-s", "info"], check=False)
        enabled = result.returncode == 0
        running = enabled and "Enabled" in (result.stdout or "")
        return {
            "running": running,
            "state":   "running" if running else ("stopped" if enabled else "error"),
            "message": (result.stdout or "").splitlines()[0] if result.stdout else "",
            "enabled": enabled,
        }
    except FreeBSDNetworkError as exc:
        return {"running": False, "state": "error", "message": str(exc), "enabled": False}


# ---------------------------------------------------------------------------
# 9. Write + reload (with rollback on failure)
# ---------------------------------------------------------------------------

def reload_pf_rules(conn) -> dict:
    """
    Generate pf.conf from DB, validate, write, and reload PF.
    Saves a known-good backup before overwriting; rolls back automatically
    if the reload fails.

    Returns ``{"ok": bool, "message": str, "conf": str}``.
    On non-FreeBSD generates the conf but does not touch the filesystem.
    """
    conf_text = generate_pf_conf(conn)

    if not sys.platform.startswith("freebsd"):
        return {
            "ok": True,
            "message": "Non-FreeBSD host — rules generated but not applied.",
            "conf": conf_text,
        }

    # Step 1 — syntax validation
    ok, err = validate_pf_conf(conf_text)
    if not ok:
        return {
            "ok": False,
            "message": f"pfctl syntax error: {err}",
            "conf": conf_text,
        }

    # Step 2 — save current config as known-good backup
    _save_known_good()

    # Step 3 — write new config
    try:
        with open(_PF_CONF_PATH, "w") as fh:
            fh.write(conf_text)
    except OSError as exc:
        return {"ok": False, "message": f"Failed to write {_PF_CONF_PATH}: {exc}", "conf": conf_text}

    # Step 4 — reload PF
    try:
        run_command(["pfctl", "-f", _PF_CONF_PATH], check=True)
        run_command(["pfctl", "-e"], check=False)   # enable PF if not running
    except FreeBSDNetworkError as exc:
        # Step 5 — rollback on reload failure
        rb = rollback_pf()
        rb_msg = rb.get("message", "rollback status unknown")
        return {
            "ok": False,
            "message": f"pfctl reload failed ({exc}). {rb_msg}",
            "conf": conf_text,
        }

    return {"ok": True, "message": "PF rules reloaded successfully.", "conf": conf_text}
