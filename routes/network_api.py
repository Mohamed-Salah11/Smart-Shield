from flask import Blueprint, jsonify, request, session
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


network_api_bp = Blueprint("network_api", __name__, url_prefix="/api/network")


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
                   discovered_via, first_seen, last_seen
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
                   discovered_via, first_seen, last_seen
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


@network_api_bp.route("/interfaces", methods=["GET"])
@login_required
def get_interfaces():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT interface_type, network_port FROM interface_assignments")
    assignments = {row["interface_type"]: row["network_port"] for row in cur.fetchall()}

    cur.execute(
        """
        SELECT enable_interface, description, ipv4_config_type, ipv6_config_type,
               mac_address, mtu, mss, speed_and_duplex, ipv4_address,
               ipv4_upstream_gateway, block_private_networks, block_bogon_networks
        FROM lan_config WHERE id = 1
        """
    )
    lan = cur.fetchone()

    cur.execute(
        """
        SELECT enable_interface, description, ipv4_config_type, ipv6_config_type,
               mac_address, mtu, mss, speed_and_duplex, ipv4_address,
               ipv4_upstream_gateway, username, password, dial_on_demand,
               idle_timeout, block_private_networks, block_bogon_networks
        FROM wan_config WHERE id = 1
        """
    )
    wan = cur.fetchone()

    return jsonify(
        {
            "status": "success",
            "data": {
                "LAN": {
                    "assigned_port": assignments.get("LAN"),
                    "enable_interface": row_to_bool(lan, "enable_interface", True),
                    "description": lan["description"] if lan else "LAN",
                    "ipv4_config_type": lan["ipv4_config_type"] if lan else "static",
                    "ipv6_config_type": lan["ipv6_config_type"] if lan else "none",
                    "mac_address": lan["mac_address"] if lan else "",
                    "mtu": lan["mtu"] if lan else "",
                    "mss": lan["mss"] if lan else "",
                    "speed_and_duplex": lan["speed_and_duplex"] if lan else "default",
                    "ipv4_address": lan["ipv4_address"] if lan else "192.168.1.1/24",
                    "ipv4_upstream_gateway": lan["ipv4_upstream_gateway"] if lan else "",
                    "block_private_networks": row_to_bool(lan, "block_private_networks"),
                    "block_bogon_networks": row_to_bool(lan, "block_bogon_networks"),
                },
                "WAN": {
                    "assigned_port": assignments.get("WAN"),
                    "enable_interface": row_to_bool(wan, "enable_interface", True),
                    "description": wan["description"] if wan else "WAN",
                    "ipv4_config_type": wan["ipv4_config_type"] if wan else "dhcp",
                    "ipv6_config_type": wan["ipv6_config_type"] if wan else "none",
                    "mac_address": wan["mac_address"] if wan else "",
                    "mtu": wan["mtu"] if wan else "",
                    "mss": wan["mss"] if wan else "",
                    "speed_and_duplex": wan["speed_and_duplex"] if wan else "default",
                    "ipv4_address": wan["ipv4_address"] if wan else "",
                    "ipv4_upstream_gateway": wan["ipv4_upstream_gateway"] if wan else "",
                    "username": wan["username"] if wan else "",
                    "has_password": bool(wan and wan["password"]),
                    "password_placeholder": mask_secret(wan["password"] if wan else ""),
                    "dial_on_demand": row_to_bool(wan, "dial_on_demand"),
                    "idle_timeout": wan["idle_timeout"] if wan else 0,
                    "block_private_networks": row_to_bool(wan, "block_private_networks", True),
                    "block_bogon_networks": row_to_bool(wan, "block_bogon_networks", True),
                },
            },
        }
    )


@network_api_bp.route("/interfaces/<interface_type>", methods=["PUT"])
@api_permission_required("api.network.edit")
def update_interface(interface_type):
    try:
        validate_interface_type(interface_type)
        data = request.get_json(force=True) or {}
        payload = normalize_interface_payload(data, interface_type)

        ipv4_address = (payload["ipv4_address"] or "").strip()
        gateway = (payload["ipv4_upstream_gateway"] or "").strip()
        validate_cidr(ipv4_address)
        validate_ip(gateway)

        conn = get_db()
        cur  = conn.cursor()

        # Save pre-apply snapshot for rollback support
        import json as _json
        _snap_table = "lan_config" if interface_type == "LAN" else "wan_config"
        cur.execute(f"SELECT * FROM {_snap_table} WHERE id=1")
        _snap_row = cur.fetchone()
        if _snap_row:
            cur.execute(
                """
                INSERT INTO pending_interface_changes
                    (interface_type, snapshot_json, confirmed)
                VALUES (?, ?, 0)
                """,
                (interface_type, _json.dumps(dict(_snap_row))),
            )

        if interface_type == "LAN":
            cur.execute(
                """
                UPDATE lan_config
                SET enable_interface = ?,
                    description = ?,
                    ipv4_config_type = ?,
                    ipv6_config_type = ?,
                    mac_address = ?,
                    mtu = ?,
                    mss = ?,
                    speed_and_duplex = ?,
                    ipv4_address = ?,
                    ipv4_upstream_gateway = ?,
                    block_private_networks = ?,
                    block_bogon_networks = ?
                WHERE id = 1
                """,
                (
                    int(payload["enable_interface"]),
                    payload["description"],
                    payload["ipv4_config_type"],
                    payload["ipv6_config_type"],
                    payload["mac_address"],
                    payload["mtu"],
                    payload["mss"],
                    payload["speed_and_duplex"],
                    ipv4_address,
                    gateway,
                    int(payload["block_private_networks"]),
                    int(payload["block_bogon_networks"]),
                ),
            )
        else:
            cur.execute(
                """
                UPDATE wan_config
                SET enable_interface = ?,
                    description = ?,
                    ipv4_config_type = ?,
                    ipv6_config_type = ?,
                    mac_address = ?,
                    mtu = ?,
                    mss = ?,
                    speed_and_duplex = ?,
                    ipv4_address = ?,
                    ipv4_upstream_gateway = ?,
                    username = ?,
                    password = COALESCE(NULLIF(?, ''), password),
                    dial_on_demand = ?,
                    idle_timeout = ?,
                    block_private_networks = ?,
                    block_bogon_networks = ?
                WHERE id = 1
                """,
                (
                    int(payload["enable_interface"]),
                    payload["description"],
                    payload["ipv4_config_type"],
                    payload["ipv6_config_type"],
                    payload["mac_address"],
                    payload["mtu"],
                    payload["mss"],
                    payload["speed_and_duplex"],
                    ipv4_address,
                    gateway,
                    payload["username"],
                    # Encrypt on save; pass None so COALESCE keeps existing value when empty.
                    encrypt_secret(payload["password"]) if payload.get("password") else None,
                    int(payload["dial_on_demand"]),
                    payload["idle_timeout"],
                    int(payload["block_private_networks"]),
                    int(payload["block_bogon_networks"]),
                ),
            )

        assigned_port = payload["assigned_port"]
        if assigned_port:
            cur.execute(
                """
                INSERT INTO interface_assignments (interface_type, network_port)
                VALUES (?, ?)
                ON CONFLICT(interface_type) DO UPDATE SET network_port = excluded.network_port
                """,
                (interface_type, assigned_port),
            )

        conn.commit()
        return jsonify({"status": "success", "message": f"{interface_type} updated"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


@network_api_bp.route("/dhcp", methods=["GET"])
@login_required
def get_dhcp():
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT interface_type, enabled, start_ip, end_ip, gateway_ip, dns_servers, lease_time FROM dhcp_pools"
    )
    rows = cur.fetchall()

    data = {}
    for row in rows:
        data[row["interface_type"]] = {
            "enabled": bool(row["enabled"]),
            "start_ip": row["start_ip"],
            "end_ip": row["end_ip"],
            "gateway_ip": row["gateway_ip"],
            "dns_servers": [x for x in (row["dns_servers"] or "").split(",") if x],
            "lease_time": row["lease_time"],
        }

    return jsonify({"status": "success", "data": data})


@network_api_bp.route("/dhcp/<interface_type>", methods=["PUT"])
@api_permission_required("api.network.edit")
def update_dhcp(interface_type):
    try:
        validate_interface_type(interface_type)
        data = request.get_json(force=True) or {}

        validate_ip(data.get("start_ip", ""))
        validate_ip(data.get("end_ip", ""))
        validate_ip(data.get("gateway_ip", ""))

        dns_servers = data.get("dns_servers", [])
        for dns in dns_servers:
            validate_ip(dns)

        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO dhcp_pools (interface_type, enabled, start_ip, end_ip, gateway_ip, dns_servers, lease_time)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(interface_type) DO UPDATE SET
                enabled = excluded.enabled,
                start_ip = excluded.start_ip,
                end_ip = excluded.end_ip,
                gateway_ip = excluded.gateway_ip,
                dns_servers = excluded.dns_servers,
                lease_time = excluded.lease_time,
                updated_at = CURRENT_TIMESTAMP
            """,
            (
                interface_type,
                int(bool(data.get("enabled", False))),
                data.get("start_ip", ""),
                data.get("end_ip", ""),
                data.get("gateway_ip", ""),
                ",".join(dns_servers),
                int(data.get("lease_time", 86400)),
            ),
        )
        conn.commit()
        return jsonify({"status": "success", "message": f"DHCP updated for {interface_type}"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


@network_api_bp.route("/leases", methods=["GET"])
@login_required
def get_leases():
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, interface_type, hostname, mac_address, ip_address, description, created_at
        FROM static_leases
        ORDER BY id DESC
        """
    )
    rows = cur.fetchall()
    return jsonify({"status": "success", "data": [dict(row) for row in rows]})


@network_api_bp.route("/leases", methods=["POST"])
@api_permission_required("api.network.edit")
def add_lease():
    try:
        data = request.get_json(force=True) or {}
        validate_interface_type(data["interface_type"])
        validate_mac(data["mac_address"])
        validate_ip(data["ip_address"])

        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO static_leases (interface_type, hostname, mac_address, ip_address, description)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                data["interface_type"],
                data.get("hostname", ""),
                data["mac_address"].lower(),
                data["ip_address"],
                data.get("description", ""),
            ),
        )
        conn.commit()
        return jsonify({"status": "success", "message": "Static lease added"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


@network_api_bp.route("/leases/<int:lease_id>", methods=["DELETE"])
@api_permission_required("api.network.edit")
def delete_lease(lease_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM static_leases WHERE id = ?", (lease_id,))
    conn.commit()
    return jsonify({"status": "success", "message": "Static lease deleted"})


@network_api_bp.route("/hosts", methods=["GET"])
@login_required
def list_hosts():
    conn = None
    try:
        requested_type = (request.args.get("interface_type") or "").strip().upper()
        if requested_type and requested_type not in {"LAN", "WAN", "UNKNOWN"}:
            return jsonify({"status": "error", "message": "invalid interface_type"}), 400

        refresh = _as_bool(request.args.get("refresh"), default=False)
        conn = get_db()
        cur = conn.cursor()

        discovered = 0
        if refresh:
            discovered = _refresh_tracked_hosts(cur)
            conn.commit()
            log_event(
                category="system",
                action="hosts_refresh",
                username=session.get("username", "anonymous"),
                remote_addr=request.remote_addr,
                details={"discovered_hosts": discovered},
            )

        hosts = _list_tracked_hosts(cur, interface_type_filter=requested_type or None)
        return jsonify(
            {
                "status": "success",
                "data": hosts,
                "count": len(hosts),
                "refreshed": refresh,
                "discovered_hosts": discovered,
                "live_discovery_available": sys.platform.startswith("freebsd"),
            }
        )
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@network_api_bp.route("/hosts/refresh", methods=["POST"])
@api_permission_required("api.network.edit")
def refresh_hosts():
    conn = None
    try:
        conn = get_db()
        cur = conn.cursor()
        discovered = _refresh_tracked_hosts(cur)
        conn.commit()

        log_event(
            category="system",
            action="hosts_refresh",
            username=session.get("username", "anonymous"),
            remote_addr=request.remote_addr,
            details={"discovered_hosts": discovered},
        )
        return jsonify(
            {
                "status": "success",
                "message": "Host inventory refreshed.",
                "discovered_hosts": discovered,
                "live_discovery_available": sys.platform.startswith("freebsd"),
            }
        )
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@network_api_bp.route("/web-activity", methods=["GET"])
@login_required
def web_activity():
    conn = None
    try:
        if not sys.platform.startswith("freebsd"):
            return jsonify(
                {
                    "status": "success",
                    "data": [],
                    "count": 0,
                    "message": "Live network web-activity capture is available only on FreeBSD.",
                }
            )

        requested_type = (request.args.get("interface_type") or "").strip().upper()
        if requested_type and requested_type not in {"LAN", "WAN"}:
            return jsonify({"status": "error", "message": "invalid interface_type"}), 400

        try:
            total_dns_limit = int(request.args.get("dns_limit", 120) or 120)
            total_http_limit = int(request.args.get("http_limit", 80) or 80)
        except ValueError:
            return jsonify({"status": "error", "message": "dns_limit/http_limit must be integers"}), 400

        total_dns_limit = max(10, min(total_dns_limit, 500))
        total_http_limit = max(10, min(total_http_limit, 300))
        refresh_hosts = _as_bool(request.args.get("refresh_hosts"), default=True)

        conn = get_db()
        cur = conn.cursor()

        if refresh_hosts:
            _refresh_tracked_hosts(cur)
            conn.commit()

        interfaces = _capture_interfaces(cur, requested_type)
        if not interfaces:
            return jsonify(
                {
                    "status": "success",
                    "data": [],
                    "count": 0,
                    "message": (
                        "No assigned interface ports found for capture. "
                        "Set LAN/WAN assignments first."
                    ),
                }
            )

        per_iface_dns = max(10, total_dns_limit // max(1, len(interfaces)))
        per_iface_http = max(10, total_http_limit // max(1, len(interfaces)))

        dns_rows = []
        http_rows = []
        capture_errors = []

        for _, iface_name in interfaces:
            try:
                dns_rows.extend(capture_dns_activity(iface_name, limit=per_iface_dns))
            except FreeBSDNetworkError as e:
                capture_errors.append(f"{iface_name}: {str(e)}")

            try:
                http_rows.extend(capture_http_activity(iface_name, limit=per_iface_http))
            except FreeBSDNetworkError as e:
                capture_errors.append(f"{iface_name}: {str(e)}")

        cur.execute(
            """
            SELECT ip_address, interface_type, interface_name, hostname, mac_address, policy_state, policy_note
            FROM tracked_hosts
            ORDER BY last_seen DESC
            """
        )
        host_lookup = {}
        for row in cur.fetchall():
            ip = (row["ip_address"] or "").strip()
            if not ip or ip in host_lookup:
                continue
            host_lookup[ip] = dict(row)

        rows = _aggregate_web_activity(dns_rows, http_rows, host_lookup)

        log_event(
            category="system",
            action="web_activity_sample",
            username=session.get("username", "anonymous"),
            remote_addr=request.remote_addr,
            details={
                "hosts": len(rows),
                "interfaces": [name for _, name in interfaces],
                "dns_events": len(dns_rows),
                "http_events": len(http_rows),
            },
        )

        return jsonify(
            {
                "status": "success",
                "data": rows,
                "count": len(rows),
                "interfaces": [{"interface_type": t, "interface_name": n} for t, n in interfaces],
                "dns_events": len(dns_rows),
                "http_events": len(http_rows),
                "capture_errors": capture_errors,
                "message": (
                    "Best-effort visibility: DNS domains and plain HTTP links are shown. "
                    "HTTPS full links are encrypted unless TLS interception proxy is used."
                ),
            }
        )
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@network_api_bp.route("/apply", methods=["POST"])
@api_permission_required("api.network.apply")
def apply_network():
    try:
        from app.services.network_service import run_command

        data = request.get_json(force=True) or {}
        interface_name = data["interface_name"]
        # config_type distinguishes DHCP ("dhcp") from static ("static").
        # Callers that omit it but provide an ipv4_address are treated as static.
        config_type = (data.get("config_type") or "static").lower().strip()
        ipv4_address = (data.get("ipv4_address") or "").strip()
        gateway_ip = (data.get("gateway_ip") or "").strip()

        validate_interface_name(interface_name)
        if config_type != "dhcp":
            validate_cidr(ipv4_address)
        validate_ip(gateway_ip)

        if not _network_apply_enabled():
            return jsonify(
                {
                    "status": "success",
                    "message": (
                        "Configuration saved. Live FreeBSD network apply is disabled. "
                        "Set SMARTSHIELD_ENABLE_NETWORK_APPLY=1 to enable it."
                    ),
                }
            )

        ensure_freebsd()

        if config_type == "dhcp":
            # FreeBSD 13: dhclient is in base (/sbin/dhclient).
            # FreeBSD 14: dhclient was removed; dhcpcd is the base replacement.
            # Accept whichever is present.
            import shutil
            dhcp_bin = shutil.which("dhclient") or shutil.which("dhcpcd")
            if not dhcp_bin:
                raise FreeBSDNetworkError(
                    "No DHCP client found. FreeBSD 13: dhclient is in base. "
                    "FreeBSD 14: install dhcpcd via: pkg install dhcpcd"
                )
            run_command(["ifconfig", interface_name, "up"], check=True)
            run_command([dhcp_bin, interface_name], check=True)
            return jsonify(
                {
                    "status": "success",
                    "message": f"DHCP lease requested on {interface_name} via {dhcp_bin}.",
                }
            )

        if config_type == "pppoe":
            # Write /etc/ppp/ppp.conf from DB and (re)start the ppp daemon.
            # The physical NIC name is read from wan_config; interface_name
            # in the request is ignored for PPPoE (ppp manages tun0 itself).
            from app.services.pppoe_writer import apply_pppoe
            conn = get_db()
            result = apply_pppoe(conn)
            status = "success" if result["ok"] else "error"
            code = 200 if result["ok"] else 400
            return jsonify({"status": status, "message": result["message"]}), code

        # Static: apply explicit address, then optional default gateway.
        apply_interface_ipv4(interface_name, ipv4_address)

        if gateway_ip:
            set_default_gateway(gateway_ip)

        return jsonify(
            {
                "status": "success",
                "message": f"Static address {ipv4_address} applied on {interface_name}.",
            }
        )
    except FreeBSDNetworkError as e:
        return jsonify({"status": "error", "message": str(e)}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


@network_api_bp.route("/pppoe/status", methods=["GET"])
@login_required
def pppoe_status():
    """Return live PPPoE session state (running, tun0 IP, etc.)."""
    from app.services.pppoe_writer import get_pppoe_status
    return jsonify({"status": "success", "data": get_pppoe_status()})


@network_api_bp.route("/pppoe/disconnect", methods=["POST"])
@api_permission_required("api.network.edit")
def pppoe_disconnect():
    """Tear down the active PPPoE session."""
    from app.services.pppoe_writer import disconnect_pppoe
    result = disconnect_pppoe()
    status = "success" if result["ok"] else "error"
    return jsonify({"status": status, "message": result["message"]})


@network_api_bp.route("/interfaces/<interface_type>/snapshot", methods=["GET"])
@login_required
def get_interface_snapshot(interface_type: str):
    """Return the last pre-apply snapshot for an interface (for rollback UI)."""
    try:
        validate_interface_type(interface_type)
        conn = get_db()
        cur  = conn.cursor()
        cur.execute(
            """
            SELECT id, snapshot_json, applied_at, confirmed, rollback_by
            FROM pending_interface_changes
            WHERE interface_type = ?
            ORDER BY applied_at DESC LIMIT 1
            """,
            (interface_type,),
        )
        row = cur.fetchone()
        if not row:
            return jsonify({"status": "success", "snapshot": None})
        import json as _json
        return jsonify({
            "status": "success",
            "snapshot": {
                "id":          row["id"],
                "config":      _json.loads(row["snapshot_json"]),
                "applied_at":  row["applied_at"],
                "confirmed":   bool(row["confirmed"]),
                "rollback_by": row["rollback_by"],
            },
        })
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400


@network_api_bp.route("/interfaces/<interface_type>/confirm", methods=["POST"])
@api_permission_required("api.network.edit")
def confirm_interface_apply(interface_type: str):
    """
    Mark the most recent interface apply as confirmed (administrator can still
    reach the management interface after the change).
    Clears the rollback window.
    """
    try:
        validate_interface_type(interface_type)
        conn = get_db()
        cur  = conn.cursor()
        cur.execute(
            """
            UPDATE pending_interface_changes
            SET confirmed = 1
            WHERE interface_type = ? AND confirmed = 0
            """,
            (interface_type,),
        )
        conn.commit()
        return jsonify({"status": "success", "message": f"{interface_type} change confirmed."})
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400


@network_api_bp.route("/interfaces/<interface_type>/rollback", methods=["POST"])
@api_permission_required("api.network.edit")
def rollback_interface(interface_type: str):
    """
    Restore the last pre-apply snapshot for an interface.
    Writes the saved config back to the DB (does not re-apply to OS — use /apply
    after rollback if live apply is desired).
    """
    try:
        validate_interface_type(interface_type)
        import json as _json
        conn = get_db()
        cur  = conn.cursor()
        cur.execute(
            """
            SELECT id, snapshot_json FROM pending_interface_changes
            WHERE interface_type = ? ORDER BY applied_at DESC LIMIT 1
            """,
            (interface_type,),
        )
        row = cur.fetchone()
        if not row:
            return jsonify({"status": "error", "message": "No snapshot to roll back to."}), 404

        snap = _json.loads(row["snapshot_json"])

        if interface_type == "LAN":
            cur.execute(
                """
                UPDATE lan_config SET
                    ipv4_config_type=?, ipv4_address=?, ipv4_upstream_gateway=?,
                    block_private_networks=?, block_bogon_networks=?
                WHERE id=1
                """,
                (
                    snap.get("ipv4_config_type", "static"),
                    snap.get("ipv4_address", ""),
                    snap.get("ipv4_upstream_gateway", ""),
                    int(snap.get("block_private_networks", 0)),
                    int(snap.get("block_bogon_networks", 0)),
                ),
            )
        else:
            cur.execute(
                """
                UPDATE wan_config SET
                    ipv4_config_type=?, ipv4_address=?, ipv4_upstream_gateway=?,
                    username=?, block_private_networks=?, block_bogon_networks=?
                WHERE id=1
                """,
                (
                    snap.get("ipv4_config_type", "dhcp"),
                    snap.get("ipv4_address", ""),
                    snap.get("ipv4_upstream_gateway", ""),
                    snap.get("username", ""),
                    int(snap.get("block_private_networks", 1)),
                    int(snap.get("block_bogon_networks", 1)),
                ),
            )

        # Delete the snapshot after rollback
        cur.execute("DELETE FROM pending_interface_changes WHERE id=?", (row["id"],))
        conn.commit()

        from app.audit_log import log_event
        log_event(
            category="system", action="interface_rollback",
            username=session.get("username", "anonymous"),
            remote_addr=request.remote_addr,
            details={"interface_type": interface_type},
        )
        return jsonify({"status": "success", "message": f"{interface_type} rolled back to previous config."})
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400


@network_api_bp.route("/connections", methods=["GET"])
@login_required
def get_connections():
    if not sys.platform.startswith("freebsd"):
        return jsonify(
            {
                "status": "success",
                "data": [],
                "message": "Live connection listing is available only on FreeBSD.",
            }
        )

    try:
        lines = list_live_connections()
        return jsonify({"status": "success", "data": lines})
    except FreeBSDNetworkError as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
