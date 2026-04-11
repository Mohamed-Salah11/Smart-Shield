from flask import Blueprint, jsonify, request
from app.database import get_db
from app.auth_utils import login_required
from app.services.network_service import normalize_interface_payload
import ipaddress
import os
import re
import subprocess
import sys


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
    conn.close()

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
                    "dial_on_demand": row_to_bool(wan, "dial_on_demand"),
                    "idle_timeout": wan["idle_timeout"] if wan else 0,
                    "block_private_networks": row_to_bool(wan, "block_private_networks", True),
                    "block_bogon_networks": row_to_bool(wan, "block_bogon_networks", True),
                },
            },
        }
    )


@network_api_bp.route("/interfaces/<interface_type>", methods=["PUT"])
@login_required
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
        cur = conn.cursor()

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
                    payload["password"],
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
        conn.close()
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
    conn.close()

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
@login_required
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
        conn.close()
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
    conn.close()
    return jsonify({"status": "success", "data": [dict(row) for row in rows]})


@network_api_bp.route("/leases", methods=["POST"])
@login_required
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
        conn.close()
        return jsonify({"status": "success", "message": "Static lease added"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


@network_api_bp.route("/leases/<int:lease_id>", methods=["DELETE"])
@login_required
def delete_lease(lease_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM static_leases WHERE id = ?", (lease_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "success", "message": "Static lease deleted"})


@network_api_bp.route("/apply", methods=["POST"])
@login_required
def apply_network():
    try:
        data = request.get_json(force=True) or {}
        interface_name = data["interface_name"]
        ipv4_address = data["ipv4_address"]
        gateway_ip = data.get("gateway_ip", "")

        validate_interface_name(interface_name)
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

        if not sys.platform.startswith("freebsd"):
            return jsonify(
                {
                    "status": "error",
                    "message": "Live network apply is only supported when running on FreeBSD.",
                }
            ), 400

        interface = ipaddress.ip_interface(ipv4_address)
        if interface.version != 4:
            return jsonify({"status": "error", "message": "Only IPv4 is supported for live apply."}), 400

        subprocess.run(
            [
                "ifconfig",
                interface_name,
                "inet",
                str(interface.ip),
                "netmask",
                str(interface.network.netmask),
            ],
            check=True,
        )
        subprocess.run(["ifconfig", interface_name, "up"], check=True)

        if gateway_ip:
            # Deleting default route may fail if none exists; add route afterward.
            subprocess.run(["route", "-n", "delete", "default"], check=False)
            subprocess.run(["route", "-n", "add", "default", gateway_ip], check=True)

        return jsonify(
            {
                "status": "success",
                "message": "Network settings applied on FreeBSD.",
            }
        )
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


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
        proc = subprocess.run(["sockstat", "-46"], capture_output=True, text=True, check=True)
        lines = [line for line in proc.stdout.splitlines() if line.strip()]
        return jsonify({"status": "success", "data": lines})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
