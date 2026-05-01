"""
rc_conf_writer.py
-----------------
Generates and applies the network section of /etc/rc.conf so that interface
assignments, IP addresses, default gateway, and enabled services survive a
reboot.

FreeBSD uses /etc/rc.conf (or /etc/rc.conf.local) for persistent startup
configuration.  This module writes a clearly delimited Smart Shield block
inside /etc/rc.conf.local so the system-managed /etc/rc.conf is never
touched.

Block format
------------
    # >>> Smart Shield managed block — do not edit manually <<<
    ifconfig_em0="DHCP"
    ifconfig_em1="inet 192.168.1.1 netmask 255.255.255.0"
    defaultrouter="10.0.0.1"
    pf_enable="YES"
    pflog_enable="YES"
    isc_dhcpd_enable="YES"
    unbound_enable="YES"
    # <<< end Smart Shield managed block >>>

Public API
----------
generate_rc_conf_block(conn)     -> str   the managed block text
apply_rc_conf(conn)              -> dict  {"ok": bool, "message": str}
get_current_rc_conf_block()      -> str   current written block or ""
"""

import ipaddress
import os
import re
import sys

_RC_CONF_LOCAL = "/etc/rc.conf.local"
_BLOCK_START   = "# >>> Smart Shield managed block — do not edit manually <<<"
_BLOCK_END     = "# <<< end Smart Shield managed block >>>"


def _rows(conn, sql, params=()):
    cur = conn.cursor()
    cur.execute(sql, params)
    return [dict(r) for r in cur.fetchall()]


def _on_freebsd() -> bool:
    return sys.platform.startswith("freebsd")


# ---------------------------------------------------------------------------
# Block generator
# ---------------------------------------------------------------------------

def generate_rc_conf_block(conn) -> str:
    """
    Build the complete Smart Shield rc.conf block from the database.
    Returns just the block text (without the delimiters — those are added
    by the writer so the block can be safely replaced in place).
    """
    lines = []

    # ── PF (always enabled on a firewall appliance) ──────────────────────────
    lines += [
        'pf_enable="YES"',
        'pflog_enable="YES"',
    ]

    # ── WAN interface ────────────────────────────────────────────────────────
    wan_rows = _rows(conn, "SELECT * FROM wan_config WHERE id=1")
    if wan_rows:
        wan = wan_rows[0]
        wan_iface   = (wan.get("assigned_port") or "em0").strip()
        wan_type    = (wan.get("ipv4_config_type") or "dhcp").lower()
        wan_ip_cidr = (wan.get("ipv4_address") or "").strip()
        wan_gw      = (wan.get("ipv4_gateway") or "").strip()
        wan_mtu     = (wan.get("mtu") or "").strip()

        if wan_type == "dhcp":
            lines.append(f'ifconfig_{_rc_iface(wan_iface)}="DHCP"')
        elif wan_type == "pppoe":
            # PPPoE creates tun0; the physical NIC stays un-numbered
            lines.append(f'ifconfig_{_rc_iface(wan_iface)}="up"')
            lines.append('ppp_enable="YES"')
            lines.append(f'ppp_profile="smartshield_wan"')
            lines.append('ppp_mode="ddial"')
        elif wan_type == "static" and wan_ip_cidr:
            try:
                iface_obj = ipaddress.ip_interface(wan_ip_cidr)
                ip      = str(iface_obj.ip)
                netmask = str(iface_obj.network.netmask)
                cfg = f"inet {ip} netmask {netmask}"
                if wan_mtu:
                    cfg += f" mtu {wan_mtu}"
                lines.append(f'ifconfig_{_rc_iface(wan_iface)}="{cfg}"')
            except ValueError:
                pass

        if wan_gw:
            lines.append(f'defaultrouter="{wan_gw}"')

    # ── LAN interface ────────────────────────────────────────────────────────
    lan_rows = _rows(conn, "SELECT * FROM lan_config WHERE id=1")
    if lan_rows:
        lan = lan_rows[0]
        lan_iface   = (lan.get("assigned_port") or "em1").strip()
        lan_ip_cidr = (lan.get("ipv4_address") or "").strip()
        if lan_ip_cidr:
            try:
                iface_obj = ipaddress.ip_interface(lan_ip_cidr)
                ip      = str(iface_obj.ip)
                netmask = str(iface_obj.network.netmask)
                lines.append(f'ifconfig_{_rc_iface(lan_iface)}="inet {ip} netmask {netmask}"')
            except ValueError:
                pass

    # ── VLANs ────────────────────────────────────────────────────────────────
    vlan_list = []
    for vlan in _rows(conn, "SELECT * FROM vlan_configs ORDER BY id"):
        parent = (vlan.get("parent_interface") or "").strip()
        tag    = vlan.get("vlan_tag") or 0
        ip_raw = (vlan.get("ip_address") or "").strip()
        if not parent or not tag:
            continue
        vname = f"{parent}.{tag}"
        vlan_list.append(vname)
        if ip_raw:
            try:
                iface_obj = ipaddress.ip_interface(ip_raw)
                ip      = str(iface_obj.ip)
                netmask = str(iface_obj.network.netmask)
                lines.append(f'ifconfig_{_rc_iface(vname)}="inet {ip} netmask {netmask} vlan {tag} vlandev {parent}"')
            except ValueError:
                lines.append(f'ifconfig_{_rc_iface(vname)}="vlan {tag} vlandev {parent}"')
    if vlan_list:
        lines.append(f'vlans_{"_".join(vlan_list[:1])}="{" ".join(vlan_list)}"')

    # ── LAGG (bonding) ───────────────────────────────────────────────────────
    for lagg in _rows(conn, "SELECT * FROM lagg_configs ORDER BY id"):
        name     = (lagg.get("lagg_interface") or f"lagg{lagg.get('id',0)}").strip()
        members  = (lagg.get("member_interfaces") or "").strip()
        protocol = (lagg.get("lagg_protocol") or "lacp").lower()
        ip_raw   = (lagg.get("ip_address") or "").strip()
        if not members:
            continue
        for m in members.split(","):
            m = m.strip()
            if m:
                lines.append(f'ifconfig_{_rc_iface(m)}="up"')
        cfg_parts = [f"laggproto {protocol}"]
        for m in members.split(","):
            m = m.strip()
            if m:
                cfg_parts.append(f"laggport {m}")
        if ip_raw:
            try:
                iface_obj = ipaddress.ip_interface(ip_raw)
                cfg_parts.append(f"inet {iface_obj.ip} netmask {iface_obj.network.netmask}")
            except ValueError:
                pass
        lines.append(f'ifconfig_{_rc_iface(name)}="{" ".join(cfg_parts)}"')
        lines.append(f'cloned_interfaces="${{cloned_interfaces}} {name}"')

    # ── Bridge ───────────────────────────────────────────────────────────────
    for bridge in _rows(conn, "SELECT * FROM bridge_configs ORDER BY id"):
        name    = (bridge.get("bridge_interface") or f"bridge{bridge.get('id',0)}").strip()
        members = (bridge.get("member_interfaces") or "").strip()
        ip_raw  = (bridge.get("ip_address") or "").strip()
        if not members:
            continue
        cfg_parts = []
        for m in members.split(","):
            m = m.strip()
            if m:
                cfg_parts.append(f"addm {m}")
        if ip_raw:
            try:
                iface_obj = ipaddress.ip_interface(ip_raw)
                cfg_parts.append(f"inet {iface_obj.ip} netmask {iface_obj.network.netmask}")
            except ValueError:
                pass
        lines.append(f'ifconfig_{_rc_iface(name)}="{" ".join(cfg_parts)}"')
        lines.append(f'cloned_interfaces="${{cloned_interfaces}} {name}"')

    # ── GRE tunnels ──────────────────────────────────────────────────────────
    for gre in _rows(conn, "SELECT * FROM gre_configs ORDER BY id"):
        name    = (gre.get("tunnel_interface") or f"gre{gre.get('id',0)}").strip()
        local   = (gre.get("local_address") or "").strip()
        remote  = (gre.get("remote_address") or "").strip()
        tunnel_ip = (gre.get("tunnel_ip") or "").strip()
        if not local or not remote:
            continue
        cfg = f"tunnel {local} {remote}"
        if tunnel_ip:
            try:
                iface_obj = ipaddress.ip_interface(tunnel_ip)
                cfg += f" inet {iface_obj.ip} {iface_obj.network.network_address}"
            except ValueError:
                pass
        lines.append(f'ifconfig_{_rc_iface(name)}="{cfg}"')
        lines.append(f'cloned_interfaces="${{cloned_interfaces}} {name}"')

    # ── Services enabled in rc.conf ──────────────────────────────────────────
    # DHCP
    dhcp_on = _rows(conn, "SELECT COUNT(*) AS c FROM dhcp_pools WHERE enabled=1")
    if dhcp_on and dhcp_on[0]["c"] > 0:
        lines.append('isc_dhcpd_enable="YES"')

    # Unbound (DNS)
    try:
        dns_row = _rows(conn, "SELECT value_json FROM service_state WHERE key_name='dns_resolver'")
        if dns_row:
            import json
            cfg = json.loads(dns_row[0]["value_json"] or "{}")
            if cfg.get("enabled", True):
                lines.append('unbound_enable="YES"')
    except Exception:
        lines.append('unbound_enable="YES"')

    # NTP
    ntp_row = _rows(conn, "SELECT value_json FROM service_state WHERE key_name='ntp_settings'")
    if ntp_row:
        try:
            import json
            ntp = json.loads(ntp_row[0]["value_json"] or "{}")
            if ntp.get("enabled", False):
                lines.append('ntpd_enable="YES"')
        except Exception:
            pass

    # OpenVPN
    ovpn_count = _rows(conn, "SELECT COUNT(*) AS c FROM openvpn_servers WHERE disabled=0")
    if ovpn_count and ovpn_count[0]["c"] > 0:
        lines.append('openvpn_enable="YES"')

    # IPsec
    ipsec_count = _rows(conn, "SELECT COUNT(*) AS c FROM ipsec_phase1 WHERE disabled=0")
    if ipsec_count and ipsec_count[0]["c"] > 0:
        lines.append('strongswan_enable="YES"')

    # IDS/Suricata
    ids_row = _rows(conn, "SELECT enabled FROM ids_config WHERE id=1")
    if ids_row and ids_row[0].get("enabled"):
        lines.append('suricata_enable="YES"')

    return "\n".join(lines)


def _rc_iface(name: str) -> str:
    """Convert interface name to rc.conf-safe form (dots → underscores)."""
    return re.sub(r"[^A-Za-z0-9_]", "_", name)


# ---------------------------------------------------------------------------
# Writer
# ---------------------------------------------------------------------------

def get_current_rc_conf_block() -> str:
    """Return the current Smart Shield block from rc.conf.local, or ''."""
    if not os.path.exists(_RC_CONF_LOCAL):
        return ""
    try:
        with open(_RC_CONF_LOCAL) as fh:
            content = fh.read()
        m = re.search(
            re.escape(_BLOCK_START) + r"(.*?)" + re.escape(_BLOCK_END),
            content,
            re.DOTALL,
        )
        return m.group(1).strip() if m else ""
    except OSError:
        return ""


def apply_rc_conf(conn) -> dict:
    """
    Write/replace the Smart Shield block in /etc/rc.conf.local.
    Non-FreeBSD: generates the block but does not write.
    Returns {"ok": bool, "message": str, "block": str}.
    """
    block_body = generate_rc_conf_block(conn)
    full_block = f"{_BLOCK_START}\n{block_body}\n{_BLOCK_END}\n"

    if not _on_freebsd():
        return {
            "ok": True,
            "message": "Non-FreeBSD — rc.conf block generated but not written.",
            "block": full_block,
        }

    # Read existing rc.conf.local
    existing = ""
    if os.path.exists(_RC_CONF_LOCAL):
        try:
            with open(_RC_CONF_LOCAL) as fh:
                existing = fh.read()
        except OSError as exc:
            return {"ok": False, "message": f"Cannot read {_RC_CONF_LOCAL}: {exc}", "block": full_block}

    # Replace or append our block
    pattern = re.escape(_BLOCK_START) + r".*?" + re.escape(_BLOCK_END)
    if re.search(pattern, existing, re.DOTALL):
        new_content = re.sub(pattern, full_block.rstrip("\n"), existing, flags=re.DOTALL)
    else:
        new_content = existing.rstrip("\n") + "\n\n" + full_block

    try:
        with open(_RC_CONF_LOCAL, "w") as fh:
            fh.write(new_content)
        return {
            "ok": True,
            "message": f"Network config written to {_RC_CONF_LOCAL}",
            "block": full_block,
        }
    except OSError as exc:
        return {"ok": False, "message": f"Cannot write {_RC_CONF_LOCAL}: {exc}", "block": full_block}


def apply_static_routes(conn) -> dict:
    """
    Push all enabled static routes from DB to the live OS routing table and
    write them to rc.conf.local for reboot persistence.
    """
    from app.services.network_service import run_command

    routes = _rows(conn, """
        SELECT sr.destination, sr.disabled, g.gateway
        FROM static_routes sr
        LEFT JOIN gateways g ON sr.gateway_id = g.id
        WHERE sr.disabled = 0 AND g.gateway IS NOT NULL
    """)

    if not routes:
        return {"ok": True, "message": "No enabled static routes.", "applied": 0}

    if not _on_freebsd():
        return {"ok": True, "message": "Non-FreeBSD — static routes not applied.", "applied": 0}

    errors = []
    applied = 0
    for r in routes:
        dst = r["destination"]
        gw  = r["gateway"]
        try:
            # Try delete first (ignore failure), then add
            run_command(["route", "-n", "delete", "-net", dst, gw], check=False)
            result = run_command(["route", "-n", "add", "-net", dst, gw], check=False)
            if result.returncode == 0:
                applied += 1
            else:
                errors.append(f"{dst} via {gw}: {(result.stderr or result.stdout or '').strip()}")
        except Exception as exc:
            errors.append(f"{dst} via {gw}: {exc}")

    # Also persist to rc.conf.local as static_routes entries
    try:
        route_lines = " ".join(
            f'"-net {r["destination"]} {r["gateway"]}"' for r in routes
        )
        existing = ""
        if os.path.exists(_RC_CONF_LOCAL):
            with open(_RC_CONF_LOCAL) as fh:
                existing = fh.read()
        # Replace or append static_routes line
        if 'static_routes=' in existing:
            existing = re.sub(r'^static_routes=.*$', f'static_routes="{route_lines}"', existing, flags=re.MULTILINE)
        else:
            existing += f'\nstatic_routes="{route_lines}"\n'
        with open(_RC_CONF_LOCAL, "w") as fh:
            fh.write(existing)
    except OSError:
        pass

    if errors:
        return {"ok": False, "message": "Some routes failed: " + "; ".join(errors), "applied": applied}
    return {"ok": True, "message": f"{applied} static route(s) applied.", "applied": applied}
