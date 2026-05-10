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
from unittest import result

from app.services.network_service import run_command, FreeBSDNetworkError
from app.services.priv_helper import run_privileged

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
        iface       = (r.get("interface") or wan_iface).strip() or wan_iface
        proto       = (r.get("protocol") or "tcp").lower()
        src         = _addr(r.get("src_address"))
        dst         = _addr(r.get("dst_address"))
        redirect    = _addr(r.get("redirect_ip"))
        redir_port  = (r.get("redirect_port") or r.get("local_port") or "").strip()
        dst_port    = _port_line(r.get("dst_port") or r.get("destination_port"))
        desc        = (r.get("description") or "").strip()
        if not redirect or redirect == "any":
            continue  # skip rules with no redirect target
        redir_target = f"{redirect} port {redir_port}" if redir_port else redirect
        if desc:
            lines.append(f"# {desc}")
        lines.append(f"rdr on {iface} proto {proto} from {src} to {dst} {dst_port}-> {redir_target}")

    # NAT Reflection (hairpin NAT) — LAN clients connecting to WAN IP for port-forwards
    try:
        _afn = conn.execute(
            "SELECT nat_reflection FROM advanced_firewall_nat WHERE id=1"
        ).fetchone()
        _nat_reflection = bool(_afn["nat_reflection"]) if _afn and _afn["nat_reflection"] is not None else False
    except Exception:
        _nat_reflection = False

    if _nat_reflection:
        lines.append("# Hairpin NAT: LAN clients connecting to WAN IP for port-forwards")
        lan_rows_nr = conn.execute(
            "SELECT assigned_port, ipv4_address FROM lan_config LIMIT 1"
        ).fetchone()
        _lan_iface_nr = (lan_rows_nr["assigned_port"] or "em1") if lan_rows_nr else "em1"
        _lan_net_nr   = (lan_rows_nr["ipv4_address"]  or "192.168.1.0/24") if lan_rows_nr else "192.168.1.0/24"
        try:
            import ipaddress as _ipaddress
            _lan_net_nr = str(_ipaddress.ip_interface(_lan_net_nr).network)
        except Exception:
            pass
        lines.append(f"nat on {_lan_iface_nr} from {_lan_net_nr} to any -> ({_lan_iface_nr})")

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
#    Rules with a non-empty schedule field are only included when the
#    schedule is currently active (evaluated by schedule_service).
# ---------------------------------------------------------------------------

def _build_firewall_rules(conn, wan_iface: str, lan_iface: str) -> str:
    from app.services.schedule_service import filter_rules_by_schedule

    lines = ["# ── Firewall Rules ──"]

    def _label(rule_id, desc):
        """Return a PF label string for rule tracking via pfctl -s labels."""
        safe = (desc or "").replace('"', "'")[:60]
        return f'label "ss-{rule_id} {safe}"' if safe else f'label "ss-{rule_id}"'

    # Floating
    raw_floating = _rows(
        conn,
        "SELECT * FROM firewall_rules_floating WHERE disabled=0 ORDER BY rule_order, id",
    )
    for r in filter_rules_by_schedule(conn, raw_floating):
        iface  = (r.get("interface") or "").strip()
        proto  = _proto_line(r.get("protocol"))
        src    = _addr(r.get("source"))
        sport  = _port_line(r.get("source_port"))
        dst    = _addr(r.get("destination"))
        dport  = _port_line(r.get("dest_port"))
        action = (r.get("action") or "pass").lower()
        ipart  = f"on {iface} " if iface else ""
        desc   = (r.get("description") or "").strip()
        sched  = (r.get("schedule") or "").strip()
        lbl    = _label(r.get("id", 0), desc)
        if desc:
            lines.append(f"# {desc}" + (f" [schedule: {sched}]" if sched else ""))
        lines.append(f"{action} quick {ipart}{proto}from {src} {sport}to {dst} {dport}{lbl} keep state")

    # WAN
    raw_wan = _rows(
        conn,
        "SELECT * FROM firewall_rules_wan WHERE disabled=0 ORDER BY rule_order, id",
    )
    for r in filter_rules_by_schedule(conn, raw_wan):
        proto  = _proto_line(r.get("protocol"))
        src    = _addr(r.get("source"))
        sport  = _port_line(r.get("source_port"))
        dst    = _addr(r.get("destination"))
        dport  = _port_line(r.get("dest_port"))
        action = (r.get("action") or "pass").lower()
        desc   = (r.get("description") or "").strip()
        sched  = (r.get("schedule") or "").strip()
        lbl    = _label(r.get("id", 0), desc)
        if desc:
            lines.append(f"# {desc}" + (f" [schedule: {sched}]" if sched else ""))
        lines.append(f"{action} in on {wan_iface} {proto}from {src} {sport}to {dst} {dport}{lbl} keep state")

    # LAN
    raw_lan = _rows(
        conn,
        "SELECT * FROM firewall_rules_lan WHERE disabled=0 ORDER BY rule_order, id",
    )
    for r in filter_rules_by_schedule(conn, raw_lan):
        proto  = _proto_line(r.get("protocol"))
        src    = _addr(r.get("source"))
        sport  = _port_line(r.get("source_port"))
        dst    = _addr(r.get("destination"))
        dport  = _port_line(r.get("dest_port"))
        action = (r.get("action") or "pass").lower()
        desc   = (r.get("description") or "").strip()
        sched  = (r.get("schedule") or "").strip()
        lbl    = _label(r.get("id", 0), desc)
        if desc:
            lines.append(f"# {desc}" + (f" [schedule: {sched}]" if sched else ""))
        lines.append(f"{action} in on {lan_iface} {proto}from {src} {sport}to {dst} {dport}{lbl} keep state")

    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 4. Traffic shaper — altq queue declarations
# ---------------------------------------------------------------------------

_SCHED_MAP = {
    "hfsc":  "hfsc",
    "cbq":   "cbq",
    "priq":  "priq",
    "fairq": "fairq",
}


def _build_shaper_queues(conn, wan_iface: str, lan_iface: str) -> str:
    """
    Read traffic_shaper_configs from the DB and emit altq queue declarations.
    One altq line per enabled interface entry, plus child queue lines.
    Returns an empty string when no shaper configs are present.
    """
    try:
        configs = _rows(
            conn,
            "SELECT * FROM traffic_shaper_configs WHERE enable_disable=1 ORDER BY interface_type, id",
        )
    except Exception:
        return ""

    if not configs:
        return ""

    lines = ["# ── Traffic Shaper (altq) ──"]
    for cfg in configs:
        itype    = (cfg.get("interface_type") or "WAN").upper()
        iface    = wan_iface if itype == "WAN" else lan_iface
        sched    = _SCHED_MAP.get((cfg.get("scheduler_type") or "hfsc").lower(), "hfsc")
        bw       = cfg.get("bandwidth") or 100
        bw_unit  = (cfg.get("bandwidth_unit") or "Mb").rstrip("b").rstrip("B")
        qlimit   = cfg.get("queue_limit") or 50
        tbr      = cfg.get("tbr_size") or 0
        name     = (cfg.get("name") or f"root_{iface}").replace(" ", "_")

        tbr_part = f" tbrsize {tbr}" if tbr else ""
        lines.append(
            f"altq on {iface} {sched} bandwidth {bw}{bw_unit}b"
            f" qlimit {qlimit}{tbr_part} queue {{ {name} }}"
        )
        lines.append(f"queue {name} on {iface} {sched} bandwidth 100%")

    # Assignment: match rules that assign traffic to queues
    try:
        assigns = _rows(
            conn,
            "SELECT * FROM traffic_shaper_queues WHERE enabled=1 ORDER BY id",
        )
        if assigns:
            lines.append("")
            for q in assigns:
                proto   = _proto_line(q.get("protocol"))
                src     = _addr(q.get("source"))
                dst     = _addr(q.get("destination"))
                sport   = _port_line(q.get("source_port"))
                dport   = _port_line(q.get("dest_port"))
                qname   = (q.get("queue_name") or "").strip()
                ackq    = q.get("ack_queue") or ""
                ack_part = f" ackqueue {ackq}" if ackq else ""
                if qname:
                    lines.append(
                        f"match {proto}from {src} {sport}to {dst} {dport}queue {qname}{ack_part}"
                    )
    except Exception:
        pass

    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 4b. Virtual IP rules
# ---------------------------------------------------------------------------

def _build_virtual_ip_rules(conn) -> str:
    """
    Read virtual_ips_configs and emit:
    - CARP pass rule when any CARP VIPs are configured
    - VIRTUAL_IPS macro listing all VIP addresses (for use in filter rules)
    - Comment lines documenting each VIP
    """
    try:
        rows = _rows(
            conn,
            "SELECT type, interface, address, prefix FROM virtual_ips_configs ORDER BY id",
        )
    except Exception:
        return ""

    if not rows:
        return ""

    lines = ["# ── Virtual IPs ──"]
    has_carp = False
    vip_addrs = []

    for vip in rows:
        vtype  = (vip.get("type") or "").strip().lower()
        addr   = (vip.get("address") or "").strip()
        prefix = vip.get("prefix") or 32
        iface  = (vip.get("interface") or "").strip()
        if not addr:
            continue
        vip_addrs.append(addr)
        if vtype == "carp":
            has_carp = True
        lines.append(f"# {vtype.title()} VIP: {addr}/{prefix} on {iface}")

    if has_carp:
        lines.append("pass quick proto carp keep state")
    if vip_addrs:
        lines.append(f'VIRTUAL_IPS = "{{ {" ".join(vip_addrs)} }}"')
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 4c. Dummynet limiter comment block (pipes applied in reload_pf_rules)
# ---------------------------------------------------------------------------

def _build_dummynet_pipes(conn) -> str:
    """
    Emit a comment block documenting the dummynet pipes that will be created
    by _run_dnctl_setup() before pfctl loads this conf.  The pipe IDs (1-based,
    ordered by limiters_configs.id) can be referenced in future match rules via
    dnpipe N.
    """
    try:
        rows = _rows(
            conn,
            "SELECT id, name, bandwidth, bandwidth_unit FROM limiters_configs "
            "WHERE enable_disable=1 ORDER BY id",
        )
    except Exception:
        return ""

    if not rows:
        return ""

    lines = ["# ── Dummynet Limiter Pipes ──"]
    for i, row in enumerate(rows, start=1):
        bw      = row.get("bandwidth") or 0
        bw_unit = (row.get("bandwidth_unit") or "Mbit/s").rstrip("/s").lower()
        name    = (row.get("name") or f"limiter_{i}").strip()
        lines.append(f"# Pipe {i}: {name}  ({bw}{bw_unit})")
    lines.append("")
    return "\n".join(lines)


def _run_dnctl_setup(conn) -> None:
    """
    Create dummynet pipes from limiters_configs via dnctl before applying
    PF rules.  Pipe IDs are 1-based, ordered by row id.
    No-op on non-FreeBSD or when no limiters are configured.
    """
    if not sys.platform.startswith("freebsd"):
        return
    try:
        rows = _rows(
            conn,
            "SELECT bandwidth, bandwidth_unit, delay_ms, queue_length "
            "FROM limiters_configs WHERE enable_disable=1 ORDER BY id",
        )
    except Exception:
        return
    if not rows:
        return

    try:
        run_command(["/sbin/dnctl", "-q", "flush"], check=False)
    except Exception:
        pass

    for i, row in enumerate(rows, start=1):
        bw      = row.get("bandwidth") or 0
        bw_unit = (row.get("bandwidth_unit") or "Mbit/s").rstrip("/s")
        delay   = row.get("delay_ms") or 0
        qlimit  = row.get("queue_length") or 50
        cmd = ["/sbin/dnctl", "pipe", str(i), "config",
               "bw", f"{bw}{bw_unit}",
               "queue", str(qlimit)]
        if delay:
            cmd += ["delay", str(delay)]
        try:
            run_command(cmd, check=False)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# 4d. Hardening rules (anti-spoof, bogons, private-net block, ICMP, admin UI)
# ---------------------------------------------------------------------------

# Standard bogon / unroutable prefixes that should never appear as WAN sources.
_BOGON_PREFIXES = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
    "224.0.0.0/3", "240.0.0.0/4",
]

# RFC-1918 private address blocks.
_PRIVATE_NET_PREFIXES = [
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
]

# ICMPv6 types always needed for neighbor discovery (must never be blocked).
_ND_ICMPV6_TYPES = "133 134 135 136 137"

# Default admin GUI port if not configured in the DB.
_DEFAULT_ADMIN_PORT = 5000


def _build_hardening_rules(conn, wan_iface: str, lan_iface: str) -> str:
    """
    Emit sane default firewall hardening rules:
      - Bogon table (unroutable addresses) and block rule on WAN (configurable)
      - Private-net block on WAN (configurable)
      - anti-spoof rules on WAN and LAN
      - Sane ICMP pass rules
      - ICMPv6 Neighbor Discovery always-pass rules
      - Admin GUI protection rule (always pass from LAN)
    """
    # Read hardening settings; fall back to safe defaults if table/columns missing.
    block_bogons       = True
    block_private_nets = True
    admin_port         = _DEFAULT_ADMIN_PORT

    try:
        row = conn.execute(
            "SELECT block_bogons, block_private_nets FROM advanced_firewall_nat LIMIT 1"
        ).fetchone()
        if row:
            block_bogons       = bool(row[0]) if row[0] is not None else True
            block_private_nets = bool(row[1]) if row[1] is not None else True
    except Exception:
        pass

    try:
        arow = conn.execute(
            "SELECT tcp_port FROM advanced_admin_access LIMIT 1"
        ).fetchone()
        if arow and arow[0]:
            admin_port = int(arow[0])
    except Exception:
        pass

    lines = ["# ── Firewall Hardening ──"]

    # IDS block table — populated by push_blocked_ips_to_pf() in ids_writer
    lines.append("table <ss_ids_blocks> persist")
    lines.append("block in quick from <ss_ids_blocks>")
    lines.append("")

    # Bogon table
    if block_bogons:
        bogon_list = " ".join(_BOGON_PREFIXES)
        lines.append(f"table <bogons> const {{ {bogon_list} }}")

    # Private nets table
    if block_private_nets:
        priv_list = " ".join(_PRIVATE_NET_PREFIXES)
        lines.append(f"table <private_nets> const {{ {priv_list} }}")

    lines.append("")

    # anti-spoof — prevents spoofed source packets from the wrong interface
    lines.append(f"antispoof quick for {wan_iface}")
    lines.append(f"antispoof quick for {lan_iface}")
    lines.append("")

    # Block bogon sources arriving on WAN
    if block_bogons:
        lines.append(f"block in quick on {wan_iface} from <bogons> to any")

    # Block private-net sources arriving on WAN (prevent RFC-1918 spoofing from internet)
    if block_private_nets:
        lines.append(f"block in quick on {wan_iface} from <private_nets> to any")

    if block_bogons or block_private_nets:
        lines.append("")

    # Sane ICMP pass rules (types safe to pass; covers ping + path MTU discovery)
    lines.append("# ICMP: allow essential types, drop the rest")
    lines.append(
        "pass in  quick proto icmp  icmp-type  { echoreq unreach timex paramprob squench } keep state"
    )
    lines.append(
        "pass out quick proto icmp  icmp-type  { echoreq unreach timex paramprob squench } keep state"
    )
    lines.append("")

    # ICMPv6 — Neighbor Discovery types must always be allowed
    lines.append("# ICMPv6: Neighbor Discovery (must not be blocked)")
    lines.append(
        f"pass quick proto icmp6 icmp6-type {{ {_ND_ICMPV6_TYPES} }} keep state"
    )
    lines.append("")

    # Admin GUI protection — always allow from LAN so admins can't be locked out
    lines.append(f"# Admin GUI: always reachable from LAN on port {admin_port}")
    lines.append(
        f"pass in quick on {lan_iface} proto tcp "
        f"from any to any port {admin_port} keep state"
    )
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 4e. Policy-Based Routing (route-to)
# ---------------------------------------------------------------------------

def _build_policy_routes(conn, wan_iface: str, lan_iface: str) -> str:
    """
    Emit PF route-to rules for policy-based routing entries.
    Queries policy_routes joined with gateways to get the gateway IP and interface.
    Returns an empty string if the table doesn't exist or has no enabled rows.
    """
    try:
        rows = _rows(
            conn,
            """
            SELECT pr.id, pr.interface_type, pr.source, pr.destination,
                   pr.description, g.gateway AS gw_ip, g.interface AS gw_iface
            FROM policy_routes pr
            LEFT JOIN gateways g ON g.id = pr.gateway_id
            WHERE pr.enabled=1
            ORDER BY pr.priority, pr.id
            """,
        )
    except Exception:
        return ""  # table doesn't exist yet — skip gracefully

    if not rows:
        return ""

    lines = ["# ── Policy-Based Routing (route-to) ──"]
    for r in rows:
        itype    = (r.get("interface_type") or "LAN").upper()
        iface    = wan_iface if itype == "WAN" else lan_iface
        src      = _addr(r.get("source"))
        dst      = _addr(r.get("destination"))
        gw_ip    = (r.get("gw_ip") or "").strip()
        gw_iface = (r.get("gw_iface") or wan_iface).strip() or wan_iface
        desc     = (r.get("description") or "").strip()
        if not gw_ip:
            continue  # no gateway resolved — skip
        if desc:
            lines.append(f"# {desc}")
        lines.append(
            f"pass in quick on {iface} from {src} to {dst} "
            f"route-to ({gw_iface} {gw_ip}) keep state"
        )

    if len(lines) == 1:
        return ""  # only the header was added, nothing useful

    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 5. Application filter PF rules
# ---------------------------------------------------------------------------

def _build_app_filter_rules(conn) -> str:
    try:
        from app.services.app_filter import generate_app_filter_pf_rules
        return generate_app_filter_pf_rules(conn)
    except Exception as exc:
        try:
            from app.app_log import log_error
            log_error("pf_generator", "_build_app_filter_rules", {"error": str(exc)})
        except Exception:
            pass
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

    macros = textwrap.dedent(f"""\
        # ============================================================
        # Smart Shield — auto-generated pf.conf
        # Generated by app/services/pf_generator.py
        # DO NOT EDIT MANUALLY — changes will be overwritten
        # ============================================================

        WAN     = "{wan_iface}"
        LAN     = "{lan_iface}"
        LAN_NET = "{lan_net}"

    """)

    base_tables = (
        "table <authenticated_clients> persist\n"
        "table <admin_bypass_clients> persist\n\n"
    )

    options = textwrap.dedent("""\
        set block-policy drop
        set skip on lo0

    """)

    scrub = textwrap.dedent("""\
        scrub in all

    """)

    # Default outbound masquerade only when no explicit outbound rules
    out_count = _rows(conn, "SELECT COUNT(*) AS c FROM nat_outbound WHERE disabled=0")[0]["c"]
    default_nat = (
        f"# Default masquerade — LAN to WAN\n"
        f"nat on $WAN from $LAN_NET to any -> ($WAN)\n\n"
    ) if out_count == 0 else ""

    import json as _json
    _cp_row = conn.execute(
        "SELECT value_json FROM service_state WHERE key_name='captive_portal_settings'"
    ).fetchone()
    _cp_settings = _json.loads(_cp_row["value_json"]) if _cp_row else {}
    _cp_enabled = bool(_cp_settings.get("enabled", False))

    translation_hooks = textwrap.dedent("""\
    # Captive portal translation hook
    rdr-anchor "captive_portal"

    """)
    cp_anchor_line = (
        "# Captive portal filter hook must run before generic LAN allow.\n"
        "anchor \"captive_portal\"\n\n"
    )

    default_policy = (
        textwrap.dedent("""\
    # Default policy
    block all
    pass out quick keep state

    # Admin accounts bypass all content policy filtering
    pass in quick from <admin_bypass_clients> to any keep state

    """)
        + cp_anchor_line
        + textwrap.dedent("""\
    # Generic LAN allow after portal pass/block decisions.
    pass in on $LAN keep state

    """)
    )

    # Check if L2TP is configured and add its required firewall rules
    _l2tp_rules_block = ""
    try:
        _l2tp_rows = _rows(conn, "SELECT COUNT(*) as n FROM l2tp_users LIMIT 1")
        if _l2tp_rows and _l2tp_rows[0].get("n", 0) > 0:
            from app.services.l2tp_writer import get_l2tp_pf_rules
            _l2tp_lines = get_l2tp_pf_rules(conn)
            if _l2tp_lines:
                _l2tp_rules_block = (
                    "# ── L2TP/IPsec auto-rules ──\n"
                    + "\n".join(_l2tp_lines)
                    + "\n\n"
                )
    except Exception:
        pass

    return (
        macros
        + base_tables
        + _build_alias_tables(conn)
        + _build_virtual_ip_rules(conn)
        + _build_dummynet_pipes(conn)
        + options
        + scrub
        + _build_hardening_rules(conn, wan_iface, lan_iface)
        + _build_shaper_queues(conn, wan_iface, lan_iface)
        + default_nat
        + _build_nat_rules(conn, wan_iface)
        + translation_hooks
        + default_policy
        + _build_policy_routes(conn, wan_iface, lan_iface)
        + _l2tp_rules_block
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
        from app.services.priv_helper import run_privileged

        result = run_privileged("pf.reload", config_path=_PF_CONF_PATH)
        if result.returncode != 0:
            raise FreeBSDNetworkError(
                (result.stderr or result.stdout or "pf.reload failed").strip()
            )
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

    # Step 3b — apply dummynet limiter pipes before PF loads
    try:
        _run_dnctl_setup(conn)
    except Exception:
        pass

    # Step 4 — reload PF
    try:
        from app.services.priv_helper import run_privileged

        result = run_privileged("pf.reload", config_path=_PF_CONF_PATH)
        if result.returncode != 0:
            raise FreeBSDNetworkError(
            (result.stderr or result.stdout or "pf.reload failed").strip()
            )

        run_privileged("pf.enable")   # enable PF if not running
    except FreeBSDNetworkError as exc:
        # Step 5 — rollback on reload failure
        rb = rollback_pf()
        rb_msg = rb.get("message", "rollback status unknown")
        return {
            "ok": False,
            "message": f"pfctl reload failed ({exc}). {rb_msg}",
            "conf": conf_text,
        }

    # Step 5b — kill all states if configured
    try:
        _ks_row = conn.execute(
            "SELECT kill_states_on_reload FROM advanced_firewall_nat WHERE id=1"
        ).fetchone()
        _kill_states = bool(_ks_row["kill_states_on_reload"]) if _ks_row and _ks_row["kill_states_on_reload"] is not None else False
    except Exception:
        _kill_states = False

    if _kill_states:
        import warnings
        warnings.warn("All PF states flushed (kill_states_on_reload=1)", RuntimeWarning, stacklevel=1)
        try:
            run_command(["pfctl", "-k", "0.0.0.0/0"], check=False)
        except Exception:
            pass

    return {"ok": True, "message": "PF rules reloaded successfully.", "conf": conf_text}
