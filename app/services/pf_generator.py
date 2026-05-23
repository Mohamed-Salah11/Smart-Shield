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

import logging
import os
import sys
import tempfile
import textwrap
from typing import Optional

from app.services.network_service import run_command, FreeBSDNetworkError
from app.services.priv_helper import run_privileged

logger = logging.getLogger(__name__)

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
    if not p or p in {"any", "all", ""}:
        return ""
    if p in {"tcp+udp", "tcp/udp"}:
        return "proto { tcp udp } "
    if p in {"icmpv6", "ipv6-icmp"}:
        return "proto icmp6 "
    return f"proto {p} "


def _pf_action(action: str) -> str:
    """Translate a DB action value to the correct PF keyword.
    'reject' maps to 'block return' (drop + ICMP unreachable / TCP RST).
    """
    a = (action or "pass").lower()
    if a == "reject":
        return "block return"
    return a if a in {"pass", "block"} else "pass"


# Protocols that carry no L4 ports — port filtering is invalid for these.
_PORTLESS_PROTOS = frozenset({"icmp", "icmpv6", "ipv6-icmp", "esp", "ah", "gre"})


def _port_line(port: Optional[str], prefix="port ") -> str:
    import re as _re
    p = (port or "").strip()
    if not p or p.lower() in {"any", ""}:
        return ""
    # Split on commas or whitespace, normalize each range separator - → :
    parts = [x.strip() for x in _re.split(r"[,\s]+", p) if x.strip()]
    normalized = [_re.sub(r"^(\d+)-(\d+)$", r"\1:\2", part) for part in parts]
    if len(normalized) == 1:
        return f"{prefix}{normalized[0]} "
    return f"{prefix}{{ {' '.join(normalized)} }} "


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
    # The NAT UI stores `interface` as the symbolic "WAN"/"LAN". PF needs the
    # real interface name (em0/em1/…) — mirrors the translation in
    # _build_firewall_rules. Without this, pfctl rejects the ruleset.
    lan_rows = _rows(conn, "SELECT assigned_port FROM lan_config LIMIT 1")
    lan_iface = (lan_rows[0].get("assigned_port") or "em1") if lan_rows else "em1"

    def _resolve_iface(raw) -> str:
        v = (raw or "").strip()
        if v.upper() == "WAN":
            return wan_iface
        if v.upper() == "LAN":
            return lan_iface
        return v or wan_iface

    lines = ["# ── NAT Rules ──"]

    # Outbound NAT
    for r in _rows(conn, "SELECT * FROM nat_outbound WHERE disabled=0 ORDER BY rule_order, id"):
        iface   = _resolve_iface(r.get("interface"))
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
        iface    = _resolve_iface(r.get("interface"))
        ext      = _addr(r.get("external_address"))
        internal = _addr(r.get("internal_address"))
        desc     = (r.get("description") or "").strip()
        if desc:
            lines.append(f"# {desc}")
        lines.append(f"binat on {iface} from {internal} to any -> {ext}")

    # Port forwards (rdr)
    for r in _rows(conn, "SELECT * FROM nat_pf WHERE disabled=0 ORDER BY rule_order, id"):
        iface       = _resolve_iface(r.get("interface"))
        proto       = (r.get("protocol") or "tcp").lower()
        src         = _addr(r.get("src_address"))
        redirect    = _addr(r.get("redirect_ip"))
        redir_port  = (r.get("redirect_port") or r.get("local_port") or "").strip()
        dst_port    = _port_line(r.get("dst_port") or r.get("destination_port"))
        desc        = (r.get("description") or "").strip()
        if not redirect or redirect == "any":
            continue  # skip rules with no redirect target
        # Resolve destination: dst_type=wan_address → (iface); otherwise use dst_address
        dst_type = (r.get("dst_type") or "").strip().lower()
        dst_raw  = _addr(r.get("dst_address"))
        if dst_type == "wan_address":
            dst = f"({iface})"
        elif dst_raw and dst_raw != "any":
            dst = dst_raw
        else:
            dst = "any"
        redir_target = f"{redirect} port {redir_port}" if redir_port else redirect
        if desc:
            lines.append(f"# {desc}")
        lines.append(f"rdr on {iface} proto {proto} from {src} to {dst} {dst_port}-> {redir_target}")

    # NAT Reflection (hairpin NAT) — LAN clients connecting to WAN IP for port-forwards
    try:
        _afn_nr = conn.execute(
            "SELECT nat_reflection_mode FROM advanced_firewall_nat WHERE id=1"
        ).fetchone()
        _mode = (_afn_nr["nat_reflection_mode"] or "disabled") if _afn_nr else "disabled"
        _nat_reflection = _mode.lower() not in ("disabled", "", "none")
    except Exception:
        logger.warning("Failed to load NAT reflection mode; defaulting to disabled", exc_info=True)
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
            logger.warning("Failed to normalize LAN network %r for NAT reflection", _lan_net_nr, exc_info=True)
        lines.append(f"nat on {_lan_iface_nr} from {_lan_net_nr} to any -> ({_lan_iface_nr})")

    # NPt — Network Prefix Translation (IPv6)
    for r in _rows(conn, "SELECT * FROM nat_npt WHERE disabled=0 ORDER BY rule_order, id"):
        iface    = _resolve_iface(r.get("interface"))
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

    # ── Content-policy DNS interception ───────────────────────────────────
    # When ANY content/DNS/web/app block rule is enabled, force all LAN DNS
    # through Unbound so policy can't be sidestepped by setting 8.8.8.8 on
    # the client. The captive-portal anchor adds the same rule when enabled;
    # this rule is the always-on baseline for DNS-only filtering with no portal.
    try:
        from app.services.content_policy import has_active_content_policy
        _policy_active = bool(has_active_content_policy(conn))
    except Exception:
        _policy_active = False

    if _policy_active:
        try:
            import ipaddress as _ipaddress
            _lan_row = conn.execute(
                "SELECT assigned_port, ipv4_address FROM lan_config WHERE id=1"
            ).fetchone()
            if _lan_row and _lan_row["ipv4_address"] and _lan_row["assigned_port"]:
                _iface = _ipaddress.ip_interface(_lan_row["ipv4_address"])
                _lan_iface_dns = _lan_row["assigned_port"]
                _lan_ip_dns    = str(_iface.ip)
                _lan_net_dns   = str(_iface.network)
                lines.append("")
                lines.append("# Force LAN DNS to Smart Shield when content filtering is active.")
                lines.append("# Per-client policy is then applied by Unbound (views: whitelist_view /")
                lines.append("# policy_exemption_view) — see app/services/dns_writer.py.")
                lines.append(
                    f"rdr on {_lan_iface_dns} proto udp from {_lan_net_dns} to ! {_lan_ip_dns} "
                    f"port 53 -> {_lan_ip_dns} port 53"
                )
                lines.append(
                    f"rdr on {_lan_iface_dns} proto tcp from {_lan_net_dns} to ! {_lan_ip_dns} "
                    f"port 53 -> {_lan_ip_dns} port 53"
                )
        except Exception:
            pass

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

    def _label(rule_id, _desc=None):
        """Return a PF label in the canonical ``smartshield:<source>:<detail>``
        format. The label is what pflog/tcpdump prints back to the collector
        (with ``-v``), and what :func:`_policy_source_from_label` decodes into
        ``firewall_events.policy_source``. Rule descriptions are emitted as a
        ``# comment`` above the rule rather than packed into the label, so
        the label stays short and parseable.
        """
        return f'label "smartshield:user_rule:{rule_id}"'

    def _log_kw(rule: dict, pf_action: str) -> str:
        """Decide whether this rule emits the PF ``log`` keyword.

        Logs go to pflog0 and become rows in ``firewall_events``. We always
        log blocked/rejected traffic (security signal). For pass rules we
        opt in via the per-rule ``log_enabled`` column added in v36 — this
        lets operators turn on packet logging for a single high-value
        allow rule without flooding the event store with every passed
        packet on the box.
        """
        if pf_action.startswith("block") or pf_action.startswith("reject"):
            return "log "
        try:
            if int(rule.get("log_enabled") or 0):
                return "log "
        except (TypeError, ValueError):
            pass
        return ""

    # Floating
    raw_floating = _rows(
        conn,
        "SELECT * FROM firewall_rules_floating WHERE disabled=0 ORDER BY rule_order, id",
    )
    for r in filter_rules_by_schedule(conn, raw_floating):
        iface  = (r.get("interface") or "").strip()
        # Normalize symbolic labels stored by the UI to real interface names
        if iface.upper() == "WAN":
            iface = wan_iface
        elif iface.upper() == "LAN":
            iface = lan_iface
        proto  = _proto_line(r.get("protocol"))
        src    = _addr(r.get("source"))
        sport  = _port_line(r.get("source_port"))
        dst    = _addr(r.get("destination"))
        dport  = _port_line(r.get("dest_port"))
        pf_act = _pf_action(r.get("action"))
        ipart  = f"on {iface} " if iface else ""
        desc   = (r.get("description") or "").strip()
        sched  = (r.get("schedule") or "").strip()
        lbl    = _label(r.get("id", 0), desc)
        # Protocols with no L4 ports — strip any port that slipped through
        if (r.get("protocol") or "").strip().lower() in _PORTLESS_PROTOS:
            sport = ""
            dport = ""
        # PF: port filtering requires an explicit protocol (not "any")
        if (dport or sport) and not proto:
            proto = "proto tcp "
        # PF: keep state is only valid for pass rules
        state_part = " keep state" if pf_act == "pass" else ""
        # PF ``log`` keyword — always for block/reject, opt-in for pass.
        log_kw     = _log_kw(r, pf_act)
        if desc:
            lines.append(f"# {desc}" + (f" [schedule: {sched}]" if sched else ""))
        lines.append(f"{pf_act} {log_kw}quick {ipart}{proto}from {src} {sport}to {dst} {dport}{lbl}{state_part}")

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
        pf_act = _pf_action(r.get("action"))
        desc   = (r.get("description") or "").strip()
        sched  = (r.get("schedule") or "").strip()
        lbl    = _label(r.get("id", 0), desc)
        if (r.get("protocol") or "").strip().lower() in _PORTLESS_PROTOS:
            sport = ""
            dport = ""
        if (dport or sport) and not proto:
            proto = "proto tcp "
        state_part = " keep state" if pf_act == "pass" else ""
        # PF ``log`` keyword — always for block/reject, opt-in for pass.
        log_kw     = _log_kw(r, pf_act)
        if desc:
            lines.append(f"# {desc}" + (f" [schedule: {sched}]" if sched else ""))
        lines.append(f"{pf_act} in {log_kw}on {wan_iface} {proto}from {src} {sport}to {dst} {dport}{lbl}{state_part}")

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
        pf_act = _pf_action(r.get("action"))
        desc   = (r.get("description") or "").strip()
        sched  = (r.get("schedule") or "").strip()
        lbl    = _label(r.get("id", 0), desc)
        if (r.get("protocol") or "").strip().lower() in _PORTLESS_PROTOS:
            sport = ""
            dport = ""
        if (dport or sport) and not proto:
            proto = "proto tcp "
        state_part = " keep state" if pf_act == "pass" else ""
        # PF ``log`` keyword — always for block/reject, opt-in for pass.
        log_kw     = _log_kw(r, pf_act)
        if desc:
            lines.append(f"# {desc}" + (f" [schedule: {sched}]" if sched else ""))
        lines.append(f"{pf_act} in {log_kw}on {lan_iface} {proto}from {src} {sport}to {dst} {dport}{lbl}{state_part}")

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
        logger.warning("Failed to load traffic_shaper_configs; emitting no altq block", exc_info=True)
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
        logger.warning("Failed to load traffic_shaper_queues; skipping queue assignments", exc_info=True)

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
        logger.warning("Failed to load virtual_ips_configs; emitting no VIP block", exc_info=True)
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
        logger.warning("Failed to load limiters_configs; emitting no limiter block", exc_info=True)
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
        logger.exception("Failed to load limiters_configs for dnctl setup; skipping dummynet")
        return
    if not rows:
        return

    try:
        run_command(["/sbin/dnctl", "-q", "flush"], check=False)
    except Exception:
        logger.exception("dnctl flush failed; dummynet pipes may be stale")

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
            logger.exception("dnctl pipe %d config failed: %s", i, cmd)


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
        logger.warning("Failed to load bogons/private-nets settings; defaulting to enabled", exc_info=True)

    try:
        arow = conn.execute(
            "SELECT tcp_port FROM advanced_admin_access LIMIT 1"
        ).fetchone()
        if arow and arow[0]:
            admin_port = int(arow[0])
    except Exception:
        logger.warning("Failed to load admin tcp_port; defaulting to %d", admin_port, exc_info=True)

    # Resolve the firewall's own LAN IP and network so the admin-GUI HTTPS
    # rule can be scoped (the broad `to any port 443` is a P0 enforcement bug:
    # it lets unauthenticated LAN clients reach arbitrary external HTTPS hosts
    # before captive portal / content-policy rules can block them).
    lan_ip = ""
    lan_net = ""
    try:
        import ipaddress as _ipaddress
        _lan_row = conn.execute(
            "SELECT ipv4_address FROM lan_config WHERE id=1"
        ).fetchone()
        if _lan_row and _lan_row["ipv4_address"]:
            _iface = _ipaddress.ip_interface(_lan_row["ipv4_address"])
            lan_ip  = str(_iface.ip)
            lan_net = str(_iface.network)
    except Exception:
        pass

    lines = ["# ── Firewall Hardening ──"]

    # IDS block table — populated by push_blocked_ips_to_pf() in ids_writer
    lines.append("table <ss_ids_blocks> persist")
    lines.append(
        'block in log quick from <ss_ids_blocks> label "smartshield:ids:block_table"'
    )
    lines.append("")

    # SOC block table — populated by push_soc_blocklist_to_pf() from the SOC
    # portal (L3 quick action). Deliberately NOT logged: SOC-blocked traffic
    # must stay out of the admin firewall logs.
    lines.append("table <soc_blocklist> persist")
    lines.append("block quick from <soc_blocklist> to any")
    lines.append("block quick from any to <soc_blocklist>")
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
        lines.append(
            f"block in log quick on {wan_iface} from <bogons> to any "
            f'label "smartshield:hardening:bogon_wan"'
        )

    # Block private-net sources arriving on WAN (prevent RFC-1918 spoofing from internet)
    if block_private_nets:
        lines.append(
            f"block in log quick on {wan_iface} from <private_nets> to any "
            f'label "smartshield:hardening:private_net_wan"'
        )

    if block_bogons or block_private_nets:
        lines.append("")

    # Sane ICMP pass rules.
    # pass in does NOT include echoreq so that user firewall rules can block ping.
    # pass out keeps echoreq so the firewall itself can ping outbound.
    lines.append("# ICMP: allow essential error types inbound; echoreq handled by user rules")
    lines.append(
        "pass in  inet proto icmp  icmp-type  { unreach timex paramprob } keep state"
    )
    lines.append(
        "pass out quick inet proto icmp  icmp-type  { echoreq unreach timex paramprob squench } keep state"
    )
    lines.append("")

    # ICMPv6 — Neighbor Discovery types must always be allowed
    lines.append("# ICMPv6: Neighbor Discovery (must not be blocked)")
    lines.append(
        f"pass quick inet6 proto icmp6 icmp6-type {{ {_ND_ICMPV6_TYPES} }} keep state"
    )
    lines.append("")

    # Admin GUI: nginx HTTPS is reachable from LAN ONLY on the firewall's own
    # LAN IP. The previous `to any port 443` form allowed unauthenticated LAN
    # clients to reach arbitrary external HTTPS hosts, bypassing captive portal
    # and content-policy rules.
    lines.append(f"# Admin GUI: nginx HTTPS reachable from LAN to firewall LAN IP only")
    if lan_ip and lan_net:
        lines.append(
            f"pass in quick on {lan_iface} proto tcp from {lan_net} to {lan_ip} port 443 "
            f'label "smartshield:admin:allow_admin_https" keep state'
        )
    elif lan_ip:
        lines.append(
            f"pass in quick on {lan_iface} proto tcp from any to {lan_ip} port 443 "
            f'label "smartshield:admin:allow_admin_https" keep state'
        )
    else:
        # No LAN IP discoverable — fall back to the (broad) original form rather
        # than locking the admin out. Log a warning so this is visible.
        lines.append(
            f"# WARNING: lan_config.ipv4_address missing; admin HTTPS rule remains broad."
        )
        lines.append(
            f"pass in quick on {lan_iface} proto tcp from any to any port 443 "
            f'label "smartshield:admin:allow_admin_https_broad" keep state'
        )
    lines.append(f"# Admin GUI: restrict direct gunicorn access to loopback only")
    lines.append(
        f"pass in quick on lo0 proto tcp from 127.0.0.1 to 127.0.0.1 port {admin_port} "
        f'label "smartshield:admin:allow_local_gunicorn" keep state'
    )
    lines.append(
        f"block in log quick on {lan_iface} proto tcp from any to any port {admin_port} "
        f'label "smartshield:admin:block_lan_to_gunicorn"'
    )

    # When content filtering is active, block LAN→WAN DNS so clients can't
    # bypass Unbound by sending queries directly upstream. The companion rdr
    # in _build_nat_rules redirects LAN→non-firewall DNS to Smart Shield;
    # this block catches anything the rdr missed (e.g., via VPN, IPv6).
    try:
        from app.services.content_policy import has_active_content_policy
        _policy_active_dns_block = bool(has_active_content_policy(conn))
    except Exception:
        _policy_active_dns_block = False
    if _policy_active_dns_block and lan_net:
        lines.append("")
        lines.append("# Block LAN→WAN DNS when content filtering is active (Phase 3.1).")
        lines.append(
            f"block out log quick on {wan_iface} proto udp from {lan_net} to any port 53 "
            f'label "smartshield:content_policy:dns_egress_udp"'
        )
        lines.append(
            f"block out log quick on {wan_iface} proto tcp from {lan_net} to any port 53 "
            f'label "smartshield:content_policy:dns_egress_tcp"'
        )

    # Phase 4.1 — opt-in QUIC block (UDP/443).
    # YouTube/Google services prefer HTTP/3 over QUIC and can stream video over
    # UDP/443, sidestepping DNS-based block pages because the browser already
    # cached the IP. Enabling block_quic forces them back to TCP/443 where
    # DNS redirection + TLS-SNI cuts the connection. Side effect: ALL HTTP/3
    # is disabled for LAN clients, which is why this is opt-in.
    try:
        import json as _json_qb
        _af_row = conn.execute(
            "SELECT value_json FROM service_state WHERE key_name='app_filter_settings'"
        ).fetchone()
        _af_settings = _json_qb.loads(_af_row["value_json"]) if _af_row else {}
    except Exception:
        _af_settings = {}
    if bool(_af_settings.get("block_quic", False)) and lan_net:
        lines.append("")
        lines.append("# Block QUIC (UDP/443) for LAN clients so blocked HTTPS sites can't")
        lines.append("# stream over HTTP/3 and bypass DNS-based filtering. Policy-exempt")
        lines.append("# clients are excluded so legitimate HTTP/3 still works for them.")
        # Order matters: 'quick' rules are terminal on match, so the pass for
        # policy_exemption MUST come before the catch-all block.
        lines.append(
            f"pass  in quick on {lan_iface} proto udp from <policy_exemption> to any port 443 "
            f'label "smartshield:content_policy:quic_exempt" keep state'
        )
        lines.append(
            f"block in log quick on {lan_iface} proto udp from {lan_net} to any port 443 "
            f'label "smartshield:content_policy:quic_block"'
        )
    lines.append("")

    # SOC Team Portal: reachable from LAN on its dedicated VIP only.
    try:
        soc = conn.execute(
            "SELECT enabled, bind_ip, bind_port FROM soc_portal_config WHERE id=1"
        ).fetchone()
    except Exception:
        soc = None
    if soc and soc["enabled"] and soc["bind_ip"] and soc["bind_ip"] != "0.0.0.0":
        soc_ip   = str(soc["bind_ip"]).strip()
        soc_port = int(soc["bind_port"] or 8443)
        lines.append("# SOC Team Portal: reachable from LAN on its dedicated VIP")
        lines.append(
            f"pass in quick on {lan_iface} proto tcp from any to {soc_ip} port {soc_port} "
            f'label "smartshield:admin:soc_portal" keep state'
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
        logger.warning("Failed to load policy_routes; emitting no PBR block", exc_info=True)
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

def _build_app_filter_rules(conn, lan_iface: str = "") -> str:
    try:
        from app.services.app_filter import generate_app_filter_pf_rules
        return generate_app_filter_pf_rules(conn, lan_iface=lan_iface)
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

    # Read advanced firewall/NAT settings once; fall back to safe defaults if missing
    _afn = {}
    try:
        _afn_row = conn.execute("SELECT * FROM advanced_firewall_nat WHERE id=1").fetchone()
        if _afn_row:
            _afn = dict(_afn_row)
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
        "table <admin_bypass_clients> persist\n"
        "table <device_whitelist> persist\n"
        # Phase 3.2: split whitelist semantics.
        # <access_whitelist>   — captive-portal bypass only (alias for device_whitelist
        #                        in the current release; populated from tracked_hosts.is_whitelisted)
        # <policy_exemption>   — bypass content/DNS/app policy via Unbound's
        #                        policy_exemption_view (populated from tracked_hosts.is_policy_exempt)
        "table <access_whitelist> persist\n"
        "table <policy_exemption> persist\n\n"
    )

    opt_value = (_afn.get("firewall_optimization") or "normal").strip().lower()
    options = (
        f"set block-policy drop\n"
        f"set skip on lo0\n"
        f"set optimization {opt_value}\n\n"
    )

    _max_states = int(_afn.get("firewall_max_states") or 1990000)
    _max_frags  = int(_afn.get("firewall_max_fragment") or 5000)
    _max_table  = int(_afn.get("firewall_max_table") or 400000)
    limits = (
        f"set limit {{ states {_max_states}, frags {_max_frags} }}\n"
        f"set limit table-entries {_max_table}\n\n"
    )

    _adp_start = int(_afn.get("adaptive_start") or 1134000)
    _adp_end   = int(_afn.get("adaptive_end") or 2333332)
    _timeout_keys = [
        ("tcp_first", "tcp.first"), ("tcp_opening", "tcp.opening"),
        ("tcp_established", "tcp.established"), ("tcp_closing", "tcp.closing"),
        ("tcp_fin_wait", "tcp.fin_wait"), ("tcp_closed", "tcp.closed"),
        ("tcp_tsdiff", "tcp.tsdiff"),
        ("udp_first", "udp.first"), ("udp_single", "udp.single"),
        ("udp_multiple", "udp.multiple"),
        ("icmp_first", "icmp.first"), ("icmp_error", "icmp.error"),
        ("other_first", "other.first"), ("other_single", "other.single"),
        ("other_multiple", "other.multiple"),
    ]
    _tv = [f"{pf_key} {int(_afn[db_key])}" for db_key, pf_key in _timeout_keys if _afn.get(db_key)]
    _tv += [f"adaptive.start {_adp_start}", f"adaptive.end {_adp_end}"]
    timeouts = f"set timeout {{ {', '.join(_tv)} }}\n\n"

    if _afn.get("disable_scrub"):
        scrub = ""
    elif _afn.get("enable_mss") and _afn.get("maximum_mss"):
        scrub = f"scrub in all max-mss {int(_afn['maximum_mss'])}\n\n"
    else:
        scrub = "scrub in all\n\n"

    # Routing-only mode: disable all filtering when admin requests it
    if _afn.get("disable_firewall"):
        return macros + base_tables + "# Firewall disabled — pass all traffic\npass all\n"

    # Default LAN→WAN masquerade is always emitted. PF NAT uses last-match
    # semantics and explicit outbound rules from nat_outbound are emitted by
    # _build_nat_rules below this line, so they still override the default
    # for any traffic they match. The default acts as the safety net so LAN
    # clients never lose internet just because an admin added a NAT rule.
    default_nat = (
        "# Default masquerade — LAN to WAN\n"
        "nat on $WAN from $LAN_NET to any -> ($WAN)\n\n"
    )

    import json as _json
    _cp_row = conn.execute(
        "SELECT value_json FROM service_state WHERE key_name='captive_portal_settings'"
    ).fetchone()
    _cp_settings = _json.loads(_cp_row["value_json"]) if _cp_row else {}
    _cp_enabled = bool(_cp_settings.get("enabled", False))

    translation_hooks = textwrap.dedent("""\
    # Captive portal translation hook (rdr-only anchor)
    rdr-anchor "captive_portal_rdr"

    """)
    cp_anchor_line = (
        "# Captive portal filter hook must run before generic LAN allow (filter-only anchor).\n"
        "anchor \"captive_portal_filter\"\n\n"
    )

    default_policy = (
        textwrap.dedent("""\
    # Default policy
    block log all
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
        logger.warning("Failed to emit L2TP/IPsec auto-rules; skipping block", exc_info=True)

    # Auto-emit WAN pass rules for any enabled VPN service so the daemon
    # is actually reachable from the internet without the admin needing
    # to hand-write rules in the firewall UI.
    _vpn_rules_block = _emit_vpn_pass_rules(conn, wan_iface)

    return (
        macros
        + base_tables
        + _build_alias_tables(conn)
        + _build_dummynet_pipes(conn)
        + options
        + limits
        + timeouts
        + scrub
        + _build_shaper_queues(conn, wan_iface, lan_iface)
        + default_nat
        + _build_nat_rules(conn, wan_iface)
        + translation_hooks
        + _build_virtual_ip_rules(conn)
        + _build_hardening_rules(conn, wan_iface, lan_iface)
        + default_policy
        + _build_policy_routes(conn, wan_iface, lan_iface)
        + _l2tp_rules_block
        + _vpn_rules_block
        + _build_app_filter_rules(conn, lan_iface)
        + _build_firewall_rules(conn, wan_iface, lan_iface)
    )


# ---------------------------------------------------------------------------
# VPN auto pass-rule emitter
# ---------------------------------------------------------------------------

def _emit_vpn_pass_rules(conn, wan_iface: str) -> str:
    """Emit PF pass rules for every enabled VPN service.

    Reads ``openvpn_servers``, ``ipsec_phase1``, and ``l2tp_config`` and
    returns a block of ``pass in quick`` rules so remote clients can
    reach the daemons without the admin manually adding firewall rules.

    Each emitted line carries the comment ``# smart-shield: vpn`` so it's
    identifiable in ``pfctl -sr``.
    """
    lines = ["# ── VPN auto pass-rules (smart-shield: vpn) ──"]

    # OpenVPN — one rule per non-disabled server, anchored on the server's
    # configured interface (defaults to WAN).
    try:
        ovpn = _rows(
            conn,
            "SELECT id, protocol, interface, local_port FROM openvpn_servers "
            "WHERE COALESCE(disabled, 0) = 0",
        )
        for row in ovpn:
            proto = (row.get("protocol") or "udp4").lower()
            # OpenVPN config uses udp/udp4/udp6/tcp/tcp4/tcp6 — PF only knows
            # udp/tcp, so collapse to the L4 family.
            pf_proto = "tcp" if proto.startswith("tcp") else "udp"
            iface = (row.get("interface") or "wan").lower()
            iface_macro = "$WAN" if iface == "wan" else iface
            port = int(row.get("local_port") or 1194)
            lines.append(
                f"pass in quick on {iface_macro} proto {pf_proto} "
                f"from any to ({iface_macro}) port {port} keep state "
                f"# smart-shield: vpn openvpn srv={row.get('id')}"
            )
    except Exception:
        pass  # table may not exist yet on a partially-migrated DB

    # IPsec — IKE (500/udp), NAT-T (4500/udp), ESP (proto 50). Aggregate
    # by interface so multiple Phase 1 rows on the same iface share rules.
    try:
        ipsec_ifaces = set()
        rows = _rows(
            conn,
            "SELECT DISTINCT interface FROM ipsec_phase1 "
            "WHERE COALESCE(disabled, 0) = 0",
        )
        for row in rows:
            iface = (row.get("interface") or "wan").lower()
            ipsec_ifaces.add(iface)
        for iface in sorted(ipsec_ifaces):
            iface_macro = "$WAN" if iface == "wan" else iface
            lines.append(
                f"pass in quick on {iface_macro} proto udp "
                f"from any to ({iface_macro}) port {{ 500 4500 }} keep state "
                f"# smart-shield: vpn ipsec-ike"
            )
            lines.append(
                f"pass in quick on {iface_macro} proto esp "
                f"from any to ({iface_macro}) keep state "
                f"# smart-shield: vpn ipsec-esp"
            )
    except Exception:
        pass

    # L2TP — 1701/udp, plus the IPsec ports when an L2TP/IPsec PSK is set.
    try:
        row = conn.execute(
            "SELECT enabled, COALESCE(pre_shared_key,'') AS psk "
            "FROM l2tp_config WHERE id=1"
        ).fetchone()
        if row and int(row["enabled"] or 0):
            lines.append(
                f"pass in quick on $WAN proto udp "
                f"from any to ($WAN) port 1701 keep state "
                f"# smart-shield: vpn l2tp"
            )
            if (row["psk"] or "").strip():
                lines.append(
                    f"pass in quick on $WAN proto udp "
                    f"from any to ($WAN) port {{ 500 4500 }} keep state "
                    f"# smart-shield: vpn l2tp-ipsec-ike"
                )
                lines.append(
                    f"pass in quick on $WAN proto esp "
                    f"from any to ($WAN) keep state "
                    f"# smart-shield: vpn l2tp-ipsec-esp"
                )
    except Exception:
        pass

    if len(lines) == 1:
        return ""
    return "\n".join(lines) + "\n\n"


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

def _validate_pf_macros(conn) -> tuple:
    """
    Verify WAN/LAN/LAN_NET resolve to non-empty, valid values BEFORE we generate
    a pf.conf. Without this, generate_pf_conf silently falls back to em0/em1/
    192.168.1.0/24 placeholders and we end up loading NAT rules against
    interfaces that don't exist on this appliance.
    """
    lan_rows = _rows(conn, "SELECT assigned_port, ipv4_address FROM lan_config LIMIT 1")
    wan_rows = _rows(conn, "SELECT assigned_port FROM wan_config LIMIT 1")

    lan_iface = (lan_rows[0].get("assigned_port") or "").strip() if lan_rows else ""
    wan_iface = (wan_rows[0].get("assigned_port") or "").strip() if wan_rows else ""
    lan_cidr  = (lan_rows[0].get("ipv4_address")  or "").strip() if lan_rows else ""

    if not wan_iface:
        return False, "PF macros: WAN interface is unassigned. Set it in Interfaces → WAN."
    if not lan_iface:
        return False, "PF macros: LAN interface is unassigned. Set it in Interfaces → LAN."
    if not lan_cidr:
        return False, "PF macros: LAN network is unset. Configure a LAN IPv4 address (CIDR)."
    try:
        import ipaddress as _ip
        _ip.ip_interface(lan_cidr).network  # parse — raises if malformed
    except Exception as exc:
        return False, f"PF macros: LAN network {lan_cidr!r} is not a valid CIDR: {exc}"
    return True, ""


def reload_pf_rules(conn) -> dict:
    """
    Generate pf.conf from DB, validate, write, and reload PF.
    Saves a known-good backup before overwriting; rolls back automatically
    if the reload fails.

    Returns ``{"ok": bool, "message": str, "conf": str}``.
    On non-FreeBSD generates the conf but does not touch the filesystem.
    """
    # The router-mode macro check (B9) fires only when we're about to apply to
    # a live FreeBSD kernel — on non-FreeBSD (dev/CI) we still generate the
    # conf for testing/preview using the existing default fallbacks.
    if sys.platform.startswith("freebsd"):
        macros_ok, macros_err = _validate_pf_macros(conn)
        if not macros_ok:
            return {"ok": False, "message": macros_err, "conf": ""}

    conf_text = generate_pf_conf(conn)

    # Step 0 — static section-order check (runs on all platforms; catches
    # rdr-after-pass / nat-after-block bugs that pfctl would otherwise reject
    # only at runtime on FreeBSD).
    try:
        from app.services.pf_static_validator import (
            validate_section_order, PfRuleOrderError,
        )
        validate_section_order(conf_text)
    except PfRuleOrderError as exc:
        return {"ok": False, "message": f"PF rule-order error: {exc}", "conf": conf_text}

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

    # Step 3 — write new config atomically (Phase 5.4). atomic_write writes to
    # a temp file in the same directory and os.replace()s it into place, so a
    # crash mid-write leaves the previous valid pf.conf intact rather than a
    # half-flushed file that pfctl would later refuse to parse.
    try:
        from app.services.config_file_utils import atomic_write
        atomic_write(_PF_CONF_PATH, conf_text)
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
