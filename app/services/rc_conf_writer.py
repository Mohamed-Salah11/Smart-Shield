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
    dhcpd_enable="YES"
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

    # ── PF + IP forwarding (always enabled on a firewall appliance) ─────────
    lines += [
        'pf_enable="YES"',
        'pflog_enable="YES"',
        'gateway_enable="YES"',        # IPv4 packet forwarding — required for router/NAT operation
        'ipv6_gateway_enable="YES"',   # IPv6 packet forwarding — IPv6 routing / DHCPv6 / RA features
    ]

    # ── WAN interface ────────────────────────────────────────────────────────
    wan_rows = _rows(conn, "SELECT * FROM wan_config WHERE id=1")
    if wan_rows:
        wan = wan_rows[0]
        wan_iface   = (wan.get("assigned_port") or "em0").strip()
        wan_type    = (wan.get("ipv4_config_type") or "dhcp").lower()
        wan_ip_cidr = (wan.get("ipv4_address") or "").strip()
        wan_gw = (wan.get("ipv4_upstream_gateway") or "").strip()
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
                lines.append('smart_shield_bind="127.0.0.1:5000"')
            except ValueError:
                pass

    # ── VLANs ────────────────────────────────────────────────────────────────
    vlan_list = []
    for vlan in _rows(conn, "SELECT * FROM vlan_configs ORDER BY id"):
        parent = (vlan.get("parent_interface") or "").strip()
        tag    = vlan.get("vlan_tag") or 0
        if not parent or not tag:
            continue
        vname = f"{parent}.{tag}"
        vlan_list.append(vname)
        lines.append(f'ifconfig_{_rc_iface(vname)}="vlan {tag} vlandev {parent}"')
    if vlan_list:
        lines.append(f'vlans_{"_".join(vlan_list[:1])}="{" ".join(vlan_list)}"')

    # ── LAGG (bonding) ───────────────────────────────────────────────────────
    for lagg in _rows(conn, "SELECT * FROM lagg_configs ORDER BY id"):
        name     = f"lagg{lagg.get('id', 0)}"
        members  = (lagg.get("parent_interfaces") or "").strip()
        protocol = (lagg.get("aggregation_protocol") or "lacp").lower()
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
        lines.append(f'ifconfig_{_rc_iface(name)}="{" ".join(cfg_parts)}"')
        lines.append(f'cloned_interfaces="${{cloned_interfaces}} {name}"')

    # ── Bridge ───────────────────────────────────────────────────────────────
    for bridge in _rows(conn, "SELECT * FROM bridge_configs ORDER BY id"):
        name    = (bridge.get("bridge_interface") or f"bridge{bridge.get('id',0)}").strip()
        members = (bridge.get("member_interfaces") or "").strip()
        if not members:
            continue
        cfg_parts = []
        for m in members.split(","):
            m = m.strip()
            if m:
                cfg_parts.append(f"addm {m}")
        lines.append(f'ifconfig_{_rc_iface(name)}="{" ".join(cfg_parts)}"')
        lines.append(f'cloned_interfaces="${{cloned_interfaces}} {name}"')

    # ── GRE tunnels ──────────────────────────────────────────────────────────
    for gre in _rows(conn, "SELECT * FROM gre_configs ORDER BY id"):
        name      = (gre.get("parent_interface") or f"gre{gre.get('id',0)}").strip()
        local     = (gre.get("gre_local_address") or "").strip()
        remote    = (gre.get("gre_remote_address") or "").strip()
        tunnel_ip = (gre.get("ipv4_tunnel_local_address") or "").strip()
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
    # DHCP — the pkg rc script reads `dhcpd_enable`, NOT `isc_dhcpd_enable`.
    # Get this wrong and `service isc-dhcpd restart` silently no-ops with
    # "Cannot 'restart' dhcpd. Set dhcpd_enable to YES in /etc/rc.conf".
    dhcp_on = _rows(conn, "SELECT COUNT(*) AS c FROM dhcp_pools WHERE enabled=1")
    if dhcp_on and dhcp_on[0]["c"] > 0:
        lines.append('dhcpd_enable="YES"')
        lines.append('dhcpd_flags="-q"')
        # Bind dhcpd only to the LAN interface(s) that have an enabled pool.
        # Without this, ISC dhcpd binds every broadcast interface (incl. the WAN)
        # and logs "No subnet declaration for <wan>" / "Ignoring requests on
        # <wan>" on every boot. Derived from the same pool→assigned_port mapping
        # dhcp_writer uses; see app/services/dhcp_writer.py:_dhcp_ifaces.
        dhcpd_ifaces = _dhcpd_ifaces(conn)
        if dhcpd_ifaces:
            lines.append(f'dhcpd_ifaces="{dhcpd_ifaces}"')

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

    # L2TP / mpd5 — separate row, separate daemon. Without this entry the
    # admin enables L2TP through the UI, mpd5 runs once, then dies on the
    # first reboot.
    try:
        l2tp_row = _rows(conn, "SELECT enabled FROM l2tp_config WHERE id=1")
        if l2tp_row and l2tp_row[0].get("enabled"):
            lines.append('mpd_enable="YES"')
    except Exception:
        pass

    # IDS/Suricata — enable PLUS the launch vars the FreeBSD rc script needs so
    # the daemon survives a reboot the same way the live enable keeps it up.
    # Without suricata_interface the service starts then exits. Mirrors
    # ids_writer._apply_suricata_rcvars (single resolver, so YAML + rc agree).
    ids_row = _rows(conn, "SELECT enabled, mode FROM ids_config WHERE id=1")
    if ids_row and ids_row[0].get("enabled"):
        lines.append('suricata_enable="YES"')
        try:
            from app.services.ids_writer import _resolve_capture_iface, _SURICATA_CONF_PATH
            lines.append(f'suricata_conf="{_SURICATA_CONF_PATH}"')
            if (ids_row[0].get("mode") or "ids").lower() == "ips":
                # IPS: capture is YAML-driven netmap across two ifaces — no rc -i.
                lines.append('suricata_interface=""')
            else:
                lines.append(f'suricata_interface="{_resolve_capture_iface(conn)}"')
        except Exception:
            pass

    return "\n".join(lines)


def _rc_iface(name: str) -> str:
    """Convert interface name to rc.conf-safe form (dots → underscores)."""
    return re.sub(r"[^A-Za-z0-9_]", "_", name)


def _dhcpd_ifaces(conn) -> str:
    """Space-joined LAN interface list for the ``dhcpd_ifaces`` rcvar.

    Delegates to ``dhcp_writer._dhcp_ifaces`` so the value persisted to rc.conf
    for the next boot is identical to the one ``apply_dhcpd`` sets live — a
    single source of truth. Best-effort: returns "" on any failure so a writer
    hiccup never blocks rc.conf generation."""
    try:
        from app.services.dhcp_writer import _dhcp_ifaces
        return _dhcp_ifaces(conn)
    except Exception:
        return ""


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


def _validate_rc_conf_local(text: str) -> list:
    """Static checks on the generated /etc/rc.conf.local before we install it.

    Returns a list of error strings; an empty list means valid.
    """
    errors = []
    starts = text.count(_BLOCK_START)
    ends   = text.count(_BLOCK_END)
    if starts != 1 or ends != 1:
        errors.append(
            f"managed-block markers must appear exactly once "
            f"(found {starts} start / {ends} end)"
        )
    if text.count('"') % 2 != 0:
        errors.append("unbalanced double-quote in generated rc.conf.local")
    # Reject display labels like `em0 (08:00:27:aa:bb:cc)` slipping into ifconfig_*
    for m in re.finditer(r'^(ifconfig_[A-Za-z0-9_.]+)\s*=\s*"([^"]*)"', text, re.MULTILINE):
        val = m.group(2).strip()
        if not val:
            continue
        if "(" in val or ")" in val:
            errors.append(f"{m.group(1)} contains display-label characters: {val!r}")
        # Must look like a DHCP / SYNCDHCP keyword OR start with "inet "
        head = val.split()[0].upper() if val else ""
        if head not in {"DHCP", "SYNCDHCP", "INET", "INET6"} and not val.startswith("inet "):
            errors.append(f"{m.group(1)} has unexpected form: {val!r}")
    return errors


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

    # Strip any stale `isc_dhcpd_enable=...` line sitting OUTSIDE the managed
    # block from an older install — the FreeBSD pkg rc script wants
    # `dhcpd_enable`, and leaving both around just confuses readers.
    new_content = re.sub(r"^isc_dhcpd_enable=.*\n?", "", new_content, flags=re.MULTILINE)

    # Static-validate the generated content before installing it.
    val_errors = _validate_rc_conf_local(new_content)
    if val_errors:
        return {
            "ok": False,
            "message": f"rc.conf.local validation failed: {'; '.join(val_errors)}",
            "block": full_block,
            "errors": val_errors,
        }

    try:
        from app.services.config_file_utils import atomic_write, backup_config
        backup_config(_RC_CONF_LOCAL)
        atomic_write(_RC_CONF_LOCAL, new_content, mode=0o644)
    except OSError as exc:
        return {"ok": False, "message": f"Cannot write {_RC_CONF_LOCAL}: {exc}", "block": full_block}

    if _on_freebsd():
        from app.services.network_service import run_command
        # Activate IP forwarding immediately so LAN clients can route without a reboot
        run_command(["sysctl", "net.inet.ip.forwarding=1"], check=False)
        run_command(["sysctl", "net.inet6.ip6.forwarding=1"], check=False)
        # NOTE: nginx regeneration intentionally NOT done here. Callers must
        # invoke apply_nginx() AFTER apply_interface_config() has plumbed the
        # new LAN IP onto the interface — otherwise `service nginx reload`
        # tries to bind to an IP that is not yet live and fails with
        # EADDRNOTAVAIL. See routes/setup.py api_step4_apply for the wizard
        # path (reload_all_services runs after apply_interface_config) and
        # routes/interfaces.py save_lan_config for the UI path.
    return {
        "ok": True,
        "message": f"Network config written to {_RC_CONF_LOCAL}",
        "block": full_block,
    }


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

    # Persist to rc.conf.local using valid FreeBSD syntax. FreeBSD requires named
    # routes in `static_routes` plus a `route_<name>` variable per entry:
    #
    #   static_routes="ssroute0 ssroute1"
    #   route_ssroute0="-net 10.10.0.0/24 192.168.1.254"
    #   route_ssroute1="-net 172.16.0.0/16 192.168.1.254"
    #
    # Entries are wrapped in BEGIN/END markers so admin-managed routes that live
    # outside our block are never clobbered on update.
    _STATIC_BEGIN = "# SMARTSHIELD_STATIC_ROUTES_BEGIN"
    _STATIC_END   = "# SMARTSHIELD_STATIC_ROUTES_END"
    try:
        names: list[str] = []
        defs:  list[str] = []
        for idx, r in enumerate(routes):
            name = f"ssroute{idx}"
            names.append(name)
            defs.append(f'route_{name}="-net {r["destination"]} {r["gateway"]}"')
        new_block = (
            _STATIC_BEGIN + "\n"
            + f'static_routes="{" ".join(names)}"\n'
            + ("\n".join(defs) + "\n" if defs else "")
            + _STATIC_END + "\n"
        )

        existing = ""
        if os.path.exists(_RC_CONF_LOCAL):
            with open(_RC_CONF_LOCAL) as fh:
                existing = fh.read()
        marker_re = re.compile(
            re.escape(_STATIC_BEGIN) + r".*?" + re.escape(_STATIC_END) + r"\n?",
            re.DOTALL,
        )
        if marker_re.search(existing):
            existing = marker_re.sub(new_block, existing)
        else:
            if existing and not existing.endswith("\n"):
                existing += "\n"
            existing += new_block
        with open(_RC_CONF_LOCAL, "w") as fh:
            fh.write(existing)
    except OSError:
        pass

    if errors:
        return {"ok": False, "message": "Some routes failed: " + "; ".join(errors), "applied": applied}
    return {"ok": True, "message": f"{applied} static route(s) applied.", "applied": applied}
