from flask import Blueprint, current_app, jsonify, render_template, request, session
from app.audit_log import log_event
from app.database import get_db
from app.auth_utils import login_required
from app.api_auth import api_permission_required
from app.secret_store import encrypt_secret, mask_secret
from app.services.network_service import (
    capture_dns_activity,
    capture_http_activity,
    FreeBSDNetworkError,
    apply_interface_ipv4,
    ensure_freebsd,
    list_arp_neighbors,
    list_live_connections,
    normalize_interface_payload,
    set_default_gateway,
)
import ipaddress
import os
import re
import sys
from typing import Dict, List




def validate_interface_type(interface_type: str):
    if interface_type not in ("LAN", "WAN"):
        raise ValueError("interface_type must be LAN or WAN")


def validate_interface_name(name: str):
    if not name or not all(c.isalnum() or c in ("_", "-", ".") for c in name):
        raise ValueError("invalid interface name")


def validate_cidr(value: str):
    if value:
        ipaddress.ip_interface(value)


def validate_ip(value: str):
    if value:
        ipaddress.ip_address(value)


def validate_mac(value: str):
    if not re.fullmatch(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$", value):
        raise ValueError("invalid MAC address")


def row_to_bool(row, key, default=False):
    return bool(row[key]) if row and key in row.keys() else default


def _network_apply_enabled():
    return os.getenv("SMARTSHIELD_ENABLE_NETWORK_APPLY", "0").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _as_bool(value, default=False):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _normalize_interface_name(port_value: str):
    text = (port_value or "").strip()
    if not text:
        return ""
    token = text.split()[0]
    return re.sub(r"[^A-Za-z0-9_.:-]", "", token)


def _parse_ipv4_network(cidr: str):
    value = (cidr or "").strip()
    if not value:
        return None
    try:
        iface = ipaddress.ip_interface(value)
    except ValueError:
        return None
    if iface.version != 4:
        return None
    return iface.network


def _safe_ip_address(value: str):
    text = (value or "").strip()
    if not text:
        return None
    try:
        ip_obj = ipaddress.ip_address(text)
    except ValueError:
        return None
    return ip_obj


def _split_selector_values(selector: str):
    value = (selector or "").strip()
    if not value:
        return []
    return [p.strip() for p in re.split(r"[,\n;]+", value) if p.strip()]


def _source_selector_matches(ip_obj, selector: str, interface_type: str):
    tokens = _split_selector_values(selector)
    if not tokens:
        return False, False

    matched = False
    used_any = False
    iface_lower = (interface_type or "").strip().lower()

    for token in tokens:
        t = token.strip().lower()
        if t in {"any", "*", "all"}:
            matched = True
            used_any = True
            continue

        if t in {f"{iface_lower} net", f"{iface_lower} address", f"{iface_lower} ip"}:
            matched = True
            continue

        if t.startswith("host "):
            t = t[5:].strip()

        try:
            if "/" in t:
                network = ipaddress.ip_network(t, strict=False)
                if ip_obj in network:
                    matched = True
                    continue
            else:
                parsed = ipaddress.ip_address(t)
                if parsed == ip_obj:
                    matched = True
                    continue
        except ValueError:
            # Skip alias-like selectors we cannot resolve in this lightweight engine.
            continue

    return matched, used_any


def _load_interface_context(cur):
    cur.execute("SELECT interface_type, network_port FROM interface_assignments")
    assignments = {}
    for row in cur.fetchall():
        iface_type = (row["interface_type"] or "").upper()
        assignments[iface_type] = {
            "raw": row["network_port"] or "",
            "name": _normalize_interface_name(row["network_port"] or ""),
        }

    cur.execute("SELECT ipv4_address FROM lan_config WHERE id = 1")
    lan = cur.fetchone()
    cur.execute("SELECT ipv4_address FROM wan_config WHERE id = 1")
    wan = cur.fetchone()

    return {
        "assignments": assignments,
        "LAN_network": _parse_ipv4_network(lan["ipv4_address"] if lan else ""),
        "WAN_network": _parse_ipv4_network(wan["ipv4_address"] if wan else ""),
    }


def _classify_host_interface(ip_address: str, interface_name: str, context):
    iface_name = (interface_name or "").strip().lower()

    for iface_type, assignment in context["assignments"].items():
        assigned_name = (assignment.get("name") or "").strip().lower()
        if assigned_name and iface_name and assigned_name == iface_name:
            return iface_type

    ip_obj = _safe_ip_address(ip_address)
    if ip_obj and isinstance(ip_obj, ipaddress.IPv4Address):
        lan_net = context.get("LAN_network")
        wan_net = context.get("WAN_network")
        if lan_net and ip_obj in lan_net:
            return "LAN"
        if wan_net and ip_obj in wan_net:
            return "WAN"

    return "UNKNOWN"


def _fetch_active_firewall_rules(cur, interface_type: str):
    if interface_type == "WAN":
        cur.execute(
            """
            SELECT id, rule_order, action, source, destination, protocol, description
            FROM firewall_rules_wan
            WHERE COALESCE(disabled, 0) = 0
            ORDER BY rule_order, id
            """
        )
        return [dict(r) for r in cur.fetchall()]

    if interface_type == "LAN":
        cur.execute(
            """
            SELECT id, rule_order, source, destination, protocol, description
            FROM firewall_rules_lan
            WHERE COALESCE(disabled, 0) = 0
            ORDER BY rule_order, id
            """
        )
        return [dict(r) for r in cur.fetchall()]

    return []


def _evaluate_host_policy(host: dict, wan_rules: List[dict], lan_rules: List[dict]):
    interface_type = (host.get("interface_type") or "UNKNOWN").upper()
    ip_obj = _safe_ip_address(host.get("ip_address", ""))
    if ip_obj is None:
        return {
            "policy_state": "invalid_ip",
            "policy_note": "Host has an invalid IP address.",
            "suggestion": "Fix host IP data before firewall evaluation.",
        }

    if interface_type == "WAN":
        if not wan_rules:
            return {
                "policy_state": "no_rules",
                "policy_note": "No enabled WAN firewall rules were found.",
                "suggestion": "Add explicit WAN rules before exposing this host.",
            }

        for rule in wan_rules:
            matched, broad = _source_selector_matches(ip_obj, rule.get("source", ""), "WAN")
            if not matched:
                continue

            action = (rule.get("action") or "pass").lower()
            description = (rule.get("description") or "").strip() or f"rule #{rule.get('id')}"

            if action in {"block", "reject"}:
                return {
                    "policy_state": "blocked",
                    "policy_note": f"Matched WAN {action} rule ({description}).",
                    "suggestion": "Host traffic is blocked by current WAN policy.",
                }

            if broad:
                return {
                    "policy_state": "allowed_broad",
                    "policy_note": f"Allowed by broad WAN rule ({description}).",
                    "suggestion": "Restrict source to host/subnet instead of 'any'.",
                }

            return {
                "policy_state": "allowed_specific",
                "policy_note": f"Allowed by specific WAN rule ({description}).",
                "suggestion": "Policy coverage is explicit for this host.",
            }

        return {
            "policy_state": "default_policy",
            "policy_note": "No WAN rule matched this host source.",
            "suggestion": "Add explicit WAN source rule if this host needs access.",
        }

    if interface_type == "LAN":
        if not lan_rules:
            return {
                "policy_state": "no_rules",
                "policy_note": "No enabled LAN firewall rules were found.",
                "suggestion": "Create LAN rules so local hosts are governed explicitly.",
            }

        matched_rules = []
        broad_matches = 0
        for rule in lan_rules:
            matched, broad = _source_selector_matches(ip_obj, rule.get("source", ""), "LAN")
            if matched:
                matched_rules.append(rule)
                if broad:
                    broad_matches += 1

        if not matched_rules:
            return {
                "policy_state": "no_match",
                "policy_note": "No LAN rule matched this host source.",
                "suggestion": "Add a LAN rule for this host/subnet.",
            }

        if broad_matches > 0:
            return {
                "policy_state": "allowed_broad",
                "policy_note": "Matched LAN rule(s) with broad source selector.",
                "suggestion": "Tighten LAN source selectors for stronger segmentation.",
            }

        return {
            "policy_state": "covered_specific",
            "policy_note": "Matched specific LAN source rule(s).",
            "suggestion": "Policy coverage is explicit for this host.",
        }

    return {
        "policy_state": "unclassified",
        "policy_note": "Host could not be mapped to LAN or WAN.",
        "suggestion": "Assign interface ports and set valid interface IPv4 networks.",
    }


def _merge_host_record(store: Dict[str, dict], record: dict):
    iface_type = (record.get("interface_type") or "UNKNOWN").upper()
    ip_address = (record.get("ip_address") or "").strip()
    if not ip_address:
        return

    key = f"{iface_type}|{ip_address}"
    existing = store.get(key)
    if not existing:
        store[key] = record
        return

    # ARP and explicit values should override weaker static data.
    if record.get("discovered_via") == "arp":
        existing["discovered_via"] = "arp"
    if record.get("interface_name"):
        existing["interface_name"] = record["interface_name"]
    if record.get("mac_address"):
        existing["mac_address"] = record["mac_address"]
    if record.get("hostname"):
        existing["hostname"] = record["hostname"]


def _refresh_tracked_hosts(cur):
    context = _load_interface_context(cur)
    hosts: Dict[str, dict] = {}

    # Seed from static lease definitions so known hosts are tracked even before ARP hits.
    cur.execute(
        """
        SELECT interface_type, hostname, mac_address, ip_address
        FROM static_leases
        """
    )
    for row in cur.fetchall():
        _merge_host_record(
            hosts,
            {
                "interface_type": (row["interface_type"] or "UNKNOWN").upper(),
                "interface_name": "",
                "ip_address": (row["ip_address"] or "").strip(),
                "mac_address": (row["mac_address"] or "").strip().lower(),
                "hostname": (row["hostname"] or "").strip(),
                "discovered_via": "static_lease",
            },
        )

    # ARP discovery is available only on FreeBSD.
    if sys.platform.startswith("freebsd"):
        try:
            arp_hosts = list_arp_neighbors()
        except FreeBSDNetworkError:
            arp_hosts = []

        for item in arp_hosts:
            iface_name = (item.get("interface_name") or "").strip()
            ip_addr = (item.get("ip_address") or "").strip()
            iface_type = _classify_host_interface(ip_addr, iface_name, context)
            _merge_host_record(
                hosts,
                {
                    "interface_type": iface_type,
                    "interface_name": iface_name,
                    "ip_address": ip_addr,
                    "mac_address": (item.get("mac_address") or "").strip().lower(),
                    "hostname": (item.get("hostname") or "").strip(),
                    "discovered_via": "arp",
                },
            )

    # Enrich hostnames from active DHCP leases (client-announced hostnames).
    # get_live_leases() reads /var/db/dhcpd/dhcpd.leases and returns [] on non-FreeBSD.
    try:
        from app.services.dhcp_writer import get_live_leases
        _lease_map = {
            l["ip_address"]: l["hostname"]
            for l in get_live_leases()
            if l.get("hostname") and l.get("ip_address")
        }
        for host in hosts.values():
            if not host.get("hostname") and host.get("ip_address") in _lease_map:
                host["hostname"] = _lease_map[host["ip_address"]]
    except Exception:
        pass

    # Last resort: actively probe still-nameless same-network devices via
    # NetBIOS / mDNS. Runs after ARP/DHCP/static so announced names always win.
    # WAN hosts are never probed. Results are cached, so repeated refreshes
    # (the /devices page refreshes on every load) stay fast.
    try:
        from app.services.hostname_resolver import resolve_hostnames
        unresolved = [
            host["ip_address"]
            for host in hosts.values()
            if not host.get("hostname")
            and host.get("ip_address")
            and host.get("interface_type") != "WAN"
        ]
        if unresolved:
            probed = resolve_hostnames(unresolved)
            for host in hosts.values():
                if not host.get("hostname"):
                    name = probed.get(host.get("ip_address"))
                    if name:
                        host["hostname"] = name
    except Exception:
        pass

    wan_rules = _fetch_active_firewall_rules(cur, "WAN")
    lan_rules = _fetch_active_firewall_rules(cur, "LAN")

    for host in hosts.values():
        policy = _evaluate_host_policy(host, wan_rules=wan_rules, lan_rules=lan_rules)
        host.update(policy)
        cur.execute(
            """
            INSERT INTO tracked_hosts (
                interface_type, interface_name, ip_address, mac_address, hostname,
                discovered_via, first_seen, last_seen, policy_state, policy_note
            )
            VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?, ?)
            ON CONFLICT(interface_type, ip_address) DO UPDATE SET
                interface_name = CASE
                    WHEN excluded.interface_name <> '' THEN excluded.interface_name
                    ELSE tracked_hosts.interface_name
                END,
                mac_address = CASE
                    WHEN excluded.mac_address <> '' THEN excluded.mac_address
                    ELSE tracked_hosts.mac_address
                END,
                hostname = CASE
                    WHEN excluded.hostname <> '' THEN excluded.hostname
                    ELSE tracked_hosts.hostname
                END,
                discovered_via = excluded.discovered_via,
                last_seen = CURRENT_TIMESTAMP,
                policy_state = excluded.policy_state,
                policy_note = excluded.policy_note
            """,
            (
                host.get("interface_type", "UNKNOWN"),
                host.get("interface_name", ""),
                host.get("ip_address", ""),
                host.get("mac_address", ""),
                host.get("hostname", ""),
                host.get("discovered_via", "unknown"),
                host.get("policy_state", "unknown"),
                host.get("policy_note", ""),
            ),
        )

    return len(hosts)


def _list_tracked_hosts(cur, interface_type_filter=None):
    wan_rules = _fetch_active_firewall_rules(cur, "WAN")
    lan_rules = _fetch_active_firewall_rules(cur, "LAN")

    if interface_type_filter:
        cur.execute(
            """
            SELECT id, interface_type, interface_name, ip_address, mac_address, hostname,
                   discovered_via, first_seen, last_seen, is_whitelisted
            FROM tracked_hosts
            WHERE interface_type = ?
            ORDER BY interface_type, ip_address
            """,
            (interface_type_filter,),
        )
    else:
        cur.execute(
            """
            SELECT id, interface_type, interface_name, ip_address, mac_address, hostname,
                   discovered_via, first_seen, last_seen, is_whitelisted
            FROM tracked_hosts
            ORDER BY interface_type, ip_address
            """
        )

    rows = []
    for row in cur.fetchall():
        host = dict(row)
        policy = _evaluate_host_policy(host, wan_rules=wan_rules, lan_rules=lan_rules)
        host.update(policy)
        rows.append(host)
    return rows


def _capture_interfaces(cur, interface_type_filter: str):
    cur.execute("SELECT interface_type, network_port FROM interface_assignments")
    rows = cur.fetchall()
    interfaces = []
    for row in rows:
        iface_type = (row["interface_type"] or "").upper()
        iface_name = _normalize_interface_name(row["network_port"] or "")
        if not iface_name:
            continue
        if interface_type_filter and iface_type != interface_type_filter:
            continue
        interfaces.append((iface_type, iface_name))

    # Deduplicate by interface name.
    seen = set()
    unique = []
    for iface_type, iface_name in interfaces:
        if iface_name in seen:
            continue
        seen.add(iface_name)
        unique.append((iface_type, iface_name))
    return unique


def _aggregate_web_activity(dns_rows: List[dict], http_rows: List[dict], host_lookup: Dict[str, dict]):
    entries: Dict[str, dict] = {}

    def ensure(source_ip: str, interface_name: str):
        key = (source_ip or "").strip()
        if not key:
            return None
        if key not in entries:
            host_meta = host_lookup.get(key, {})
            entries[key] = {
                "source_ip": key,
                "interface_type": host_meta.get("interface_type", "UNKNOWN"),
                "interface_name": interface_name or host_meta.get("interface_name", ""),
                "hostname": host_meta.get("hostname", ""),
                "mac_address": host_meta.get("mac_address", ""),
                "policy_state": host_meta.get("policy_state", "unknown"),
                "policy_note": host_meta.get("policy_note", ""),
                "dns_queries": [],
                "websites": [],
                "http_links": [],
                "http_requests": [],
            }
        return entries[key]

    for row in dns_rows:
        item = ensure(row.get("source_ip", ""), row.get("interface_name", ""))
        if not item:
            continue

        query = (row.get("query_name") or "").strip().lower()
        if query and query not in item["dns_queries"]:
            item["dns_queries"].append(query)

            # Keep website-level summary (domain only) separate from full DNS query value.
            website = query.lstrip(".")
            if website.startswith("www."):
                website = website[4:]
            if website and website not in item["websites"]:
                item["websites"].append(website)

    for row in http_rows:
        item = ensure(row.get("source_ip", ""), row.get("interface_name", ""))
        if not item:
            continue

        link = (row.get("link") or "").strip()
        host = (row.get("host") or "").strip().lower()
        method = (row.get("method") or "GET").upper()
        path = (row.get("path") or "").strip() or "/"

        if host and host not in item["websites"]:
            normalized_host = host[4:] if host.startswith("www.") else host
            if normalized_host and normalized_host not in item["websites"]:
                item["websites"].append(normalized_host)

        if link and link not in item["http_links"]:
            item["http_links"].append(link)

        req = f"{method} {path}"
        if host:
            req = f"{method} {host}{path}"
        if req not in item["http_requests"]:
            item["http_requests"].append(req)

    # Keep output concise.
    output = []
    for item in entries.values():
        item["dns_queries"] = item["dns_queries"][:20]
        item["websites"] = item["websites"][:20]
        item["http_links"] = item["http_links"][:20]
        item["http_requests"] = item["http_requests"][:20]
        output.append(item)

    output.sort(key=lambda x: x.get("source_ip", ""))
    return output
