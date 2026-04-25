"""
pf_generator.py
---------------
Generates /etc/pf.conf anchor content from Smart Shield's SQLite database
and applies it via pfctl.  All OS calls are routed through network_service.run_command
so dry-run mode (SMARTSHIELD_NETWORK_DRY_RUN=1) is respected everywhere.

Public API
----------
generate_pf_conf(conn)         -> str          # full pf.conf text from DB
validate_pf_conf(text)         -> (bool, str)  # (ok, error_message)
reload_pf_rules(conn)          -> dict          # {"ok": bool, "message": str}
"""

import os
import sys
import tempfile
import textwrap
from typing import Optional

from app.services.network_service import run_command, FreeBSDNetworkError

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rows(conn, sql, params=()):
    cur = conn.cursor()
    cur.execute(sql, params)
    return [dict(r) for r in cur.fetchall()]


def _quote(value: Optional[str]) -> str:
    """Wrap a pf value that contains spaces in braces."""
    v = (value or "").strip()
    return f"{{ {v} }}" if " " in v else v


def _proto_line(proto: Optional[str]) -> str:
    p = (proto or "").strip().lower()
    return f"proto {p} " if p and p != "any" else ""


def _port_line(port: Optional[str], prefix="port ") -> str:
    p = (port or "").strip()
    return f"{prefix}{p} " if p and p not in {"any", ""} else ""


def _addr(addr: Optional[str]) -> str:
    a = (addr or "").strip()
    if not a or a.lower() == "any":
        return "any"
    return a


# ---------------------------------------------------------------------------
# Alias table → pf tables
# ---------------------------------------------------------------------------

def _build_alias_tables(conn) -> str:
    rows = _rows(conn, "SELECT name, type, alias_values FROM firewall_aliases ORDER BY name")
    if not rows:
        return ""
    lines = ["# ── Aliases ──"]
    for row in rows:
        name = (row.get("name") or "").strip()
        atype = (row.get("type") or "host").lower()
        values_raw = (row.get("alias_values") or "").strip()
        if not name or not values_raw:
            continue
        # alias_values may be comma- or newline-separated
        values = [v.strip() for v in values_raw.replace("\n", ",").split(",") if v.strip()]
        if not values:
            continue
        # pf table for host/network aliases; macro for port aliases
        if atype in ("host", "network", "urltable"):
            entries = " ".join(values)
            lines.append(f"table <{name}> persist {{ {entries} }}")
        else:
            # port list → pf macro
            entries = ", ".join(values)
            lines.append(f"{name} = \"{{ {entries} }}\"")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# NAT rules
# ---------------------------------------------------------------------------

def _build_nat_rules(conn, wan_iface: str) -> str:
    lines = ["# ── NAT Rules ──"]

    # Outbound NAT (highest priority — defines masquerade)
    out_rows = _rows(conn, """
        SELECT * FROM nat_outbound WHERE disabled=0 ORDER BY rule_order, id
    """)
    for r in out_rows:
        iface = (r.get("interface") or wan_iface).strip() or wan_iface
        src = _addr(r.get("src_address"))
        dst = _addr(r.get("dst_address"))
        nat_addr = (r.get("nat_address") or "").strip()
        static = " static-port" if r.get("static_port") else ""
        nat_target = f"({iface})" if not nat_addr else nat_addr
        desc = r.get("description") or ""
        if desc:
            lines.append(f"# {desc}")
        lines.append(
            f"nat on {iface} from {src} to {dst} -> {nat_target}{static}"
        )

    # 1:1 NAT
    one_rows = _rows(conn, """
        SELECT * FROM nat_1to1 WHERE disabled=0 ORDER BY rule_order, id
    """)
    for r in one_rows:
        iface = (r.get("interface") or wan_iface).strip() or wan_iface
        ext = _addr(r.get("external_address"))
        internal = _addr(r.get("internal_address"))
        desc = r.get("description") or ""
        if desc:
            lines.append(f"# {desc}")
        lines.append(f"binat on {iface} from {internal} to any -> {ext}")

    # Port forwards (rdr)
    pf_rows = _rows(conn, """
        SELECT * FROM nat_pf WHERE disabled=0 ORDER BY rule_order, id
    """)
    for r in pf_rows:
        iface = (r.get("interface") or wan_iface).strip() or wan_iface
        proto = (r.get("protocol") or "tcp").lower()
        src = _addr(r.get("src_address"))
        dst = _addr(r.get("dst_address"))
        redirect = _addr(r.get("redirect_ip"))
        desc = r.get("description") or ""
        if desc:
            lines.append(f"# {desc}")
        lines.append(
            f"rdr on {iface} proto {proto} from {src} to {dst} -> {redirect}"
        )

    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Firewall rules
# ---------------------------------------------------------------------------

def _action(row: dict, default: str = "pass") -> str:
    return (row.get("action") or default).lower()


def _build_firewall_rules(conn, wan_iface: str, lan_iface: str) -> str:
    lines = ["# ── Firewall Rules ──"]

    # Floating rules (apply on any interface, quick)
    float_rows = _rows(conn, """
        SELECT * FROM firewall_rules_floating WHERE disabled=0 ORDER BY rule_order, id
    """)
    for r in float_rows:
        iface = (r.get("interface") or "").strip()
        proto  = _proto_line(r.get("protocol"))
        src    = _addr(r.get("source"))
        sport  = _port_line(r.get("source_port"), "port ")
        dst    = _addr(r.get("destination"))
        dport  = _port_line(r.get("dest_port"), "port ")
        action = _action(r, "pass")
        iface_part = f"on {iface} " if iface else ""
        desc = r.get("description") or ""
        if desc:
            lines.append(f"# {desc}")
        lines.append(
            f"{action} quick {iface_part}{proto}from {src} {sport}to {dst} {dport}keep state"
        )

    # WAN rules
    wan_rows = _rows(conn, """
        SELECT * FROM firewall_rules_wan WHERE disabled=0 ORDER BY rule_order, id
    """)
    for r in wan_rows:
        proto  = _proto_line(r.get("protocol"))
        src    = _addr(r.get("source"))
        dst    = _addr(r.get("destination"))
        action = _action(r, "pass")
        desc = r.get("description") or ""
        if desc:
            lines.append(f"# {desc}")
        lines.append(
            f"{action} in on {wan_iface} {proto}from {src} to {dst} keep state"
        )

    # LAN rules
    lan_rows = _rows(conn, """
        SELECT * FROM firewall_rules_lan WHERE disabled=0 ORDER BY rule_order, id
    """)
    for r in lan_rows:
        proto  = _proto_line(r.get("protocol"))
        src    = _addr(r.get("source"))
        dst    = _addr(r.get("destination"))
        desc = r.get("description") or ""
        if desc:
            lines.append(f"# {desc}")
        lines.append(
            f"pass in on {lan_iface} {proto}from {src} to {dst} keep state"
        )

    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Full pf.conf generator
# ---------------------------------------------------------------------------

def generate_pf_conf(conn) -> str:
    """
    Build the full pf.conf text from the Smart Shield database.
    Returns a string suitable for writing to /etc/pf.conf or an anchor file.
    """
    # Pull interface assignments
    lan_rows = _rows(conn, "SELECT assigned_port, ipv4_address FROM lan_config LIMIT 1")
    wan_rows = _rows(conn, "SELECT assigned_port, ipv4_config_type, ipv4_address FROM wan_config LIMIT 1")

    lan_iface = (lan_rows[0].get("assigned_port") or "em1") if lan_rows else "em1"
    wan_iface = (wan_rows[0].get("assigned_port") or "em0") if wan_rows else "em0"
    lan_net   = (lan_rows[0].get("ipv4_address") or "192.168.1.0/24") if lan_rows else "192.168.1.0/24"

    # Normalise lan_net to network address if it's a host address
    try:
        import ipaddress
        lan_net = str(ipaddress.ip_interface(lan_net).network)
    except Exception:
        pass

    header = textwrap.dedent(f"""\
        # ============================================================
        # Smart Shield — auto-generated pf.conf
        # Generated by app/services/pf_generator.py
        # DO NOT EDIT MANUALLY — changes will be overwritten
        # ============================================================

        WAN = "{wan_iface}"
        LAN = "{lan_iface}"
        LAN_NET = "{lan_net}"

        set block-policy drop
        set skip on lo0

        scrub in all

    """)

    aliases = _build_alias_tables(conn)
    nat     = _build_nat_rules(conn, wan_iface)
    fw      = _build_firewall_rules(conn, wan_iface, lan_iface)

    # Default outbound NAT when no explicit outbound rules exist
    nat_rows = _rows(conn, "SELECT COUNT(*) AS c FROM nat_outbound WHERE disabled=0")
    default_nat = ""
    if nat_rows[0]["c"] == 0:
        default_nat = (
            f"# Default masquerade — LAN to WAN\n"
            f"nat on $WAN from $LAN_NET to any -> ($WAN)\n\n"
        )

    # Default allow rules so traffic passes before specific rules
    default_rules = textwrap.dedent("""\
        # ── Default policy ──
        block all
        pass out quick keep state
        pass in on $LAN keep state

    """)

    return header + aliases + default_nat + nat + default_rules + fw


# ---------------------------------------------------------------------------
# Validate via pfctl dry-run
# ---------------------------------------------------------------------------

def validate_pf_conf(text: str) -> tuple:
    """
    Write text to a temp file and run `pfctl -nf <file>` to validate syntax.
    Returns (True, "") on success, (False, error_string) on failure.
    Works on FreeBSD only; on other platforms returns (True, "skipped-non-freebsd").
    """
    if not sys.platform.startswith("freebsd"):
        return (True, "skipped-non-freebsd")

    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".conf", delete=False, prefix="ss_pf_"
        ) as f:
            f.write(text)
            tmp_path = f.name

        result = run_command(["pfctl", "-nf", tmp_path], check=False)
        ok = result.returncode == 0
        msg = (result.stderr or result.stdout or "").strip()
        return (ok, msg)
    except FreeBSDNetworkError as exc:
        return (False, str(exc))
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Write + reload
# ---------------------------------------------------------------------------

_PF_CONF_PATH = "/etc/pf.conf"
_PF_ANCHOR    = "smart_shield"


def reload_pf_rules(conn) -> dict:
    """
    Generate pf.conf from DB, validate it, write it, and reload PF.
    Returns {"ok": bool, "message": str, "conf": str}.

    On non-FreeBSD (dev/Windows) this is a no-op that still returns the
    generated conf text so callers can review it.
    """
    conf_text = generate_pf_conf(conn)

    if not sys.platform.startswith("freebsd"):
        return {
            "ok": True,
            "message": "Non-FreeBSD host — rules generated but not applied.",
            "conf": conf_text,
        }

    # 1. Validate
    ok, err = validate_pf_conf(conf_text)
    if not ok:
        return {
            "ok": False,
            "message": f"pfctl syntax error: {err}",
            "conf": conf_text,
        }

    # 2. Write
    try:
        with open(_PF_CONF_PATH, "w") as fh:
            fh.write(conf_text)
    except OSError as exc:
        return {"ok": False, "message": f"Failed to write {_PF_CONF_PATH}: {exc}", "conf": conf_text}

    # 3. Reload
    try:
        run_command(["pfctl", "-f", _PF_CONF_PATH], check=True)
        run_command(["pfctl", "-e"], check=False)  # enable PF if not yet running
    except FreeBSDNetworkError as exc:
        return {"ok": False, "message": f"pfctl reload failed: {exc}", "conf": conf_text}

    return {"ok": True, "message": "PF rules reloaded successfully.", "conf": conf_text}
