import ipaddress
import os
import subprocess
import sys
from dataclasses import dataclass
from typing import List


@dataclass
class CommandResult:
    command: List[str]
    returncode: int
    stdout: str
    stderr: str


class FreeBSDNetworkError(RuntimeError):
    pass


def _network_dry_run_enabled():
    return os.getenv("SMARTSHIELD_NETWORK_DRY_RUN", "0").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def ensure_freebsd():
    if not sys.platform.startswith("freebsd"):
        raise FreeBSDNetworkError("Live network apply is only supported on FreeBSD.")


def run_command(cmd: List[str], check=True) -> CommandResult:
    if _network_dry_run_enabled():
        return CommandResult(command=cmd, returncode=0, stdout="", stderr="")

    proc = subprocess.run(cmd, capture_output=True, text=True)
    if check and proc.returncode != 0:
        raise FreeBSDNetworkError(
            f"Command failed ({' '.join(cmd)}): {proc.stderr.strip() or proc.stdout.strip()}"
        )
    return CommandResult(
        command=cmd,
        returncode=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
    )


def apply_interface_ipv4(interface_name: str, cidr: str):
    iface = ipaddress.ip_interface(cidr)
    if iface.version != 4:
        raise FreeBSDNetworkError("Only IPv4 is supported for live apply.")
    run_command(
        [
            "ifconfig",
            interface_name,
            "inet",
            str(iface.ip),
            "netmask",
            str(iface.network.netmask),
        ],
        check=True,
    )
    run_command(["ifconfig", interface_name, "up"], check=True)


def set_default_gateway(gateway_ip: str):
    # Delete may fail if no default route exists yet.
    run_command(["route", "-n", "delete", "default"], check=False)
    run_command(["route", "-n", "add", "default", gateway_ip], check=True)


def list_live_connections():
    result = run_command(["sockstat", "-46"], check=True)
    return [line for line in (result.stdout or "").splitlines() if line.strip()]


def normalize_interface_payload(data, interface_type):
    interface_type = interface_type.upper()

    defaults = {
        "LAN": {
            "description": "LAN",
            "ipv4_config_type": "static",
            "ipv6_config_type": "none",
            "block_private_networks": False,
            "block_bogon_networks": False,
        },
        "WAN": {
            "description": "WAN",
            "ipv4_config_type": "dhcp",
            "ipv6_config_type": "none",
            "block_private_networks": True,
            "block_bogon_networks": True,
        },
    }

    base = defaults[interface_type]

    return {
        "enable_interface": bool(data.get("enable_interface", True)),
        "description": data.get("description", base["description"]),
        "ipv4_config_type": data.get("ipv4_config_type", base["ipv4_config_type"]),
        "ipv6_config_type": data.get("ipv6_config_type", base["ipv6_config_type"]),
        "mac_address": data.get("mac_address", ""),
        "mtu": data.get("mtu", ""),
        "mss": data.get("mss", ""),
        "speed_and_duplex": data.get("speed_and_duplex", "default"),
        "ipv4_address": data.get("ipv4_address", ""),
        "ipv4_upstream_gateway": data.get("ipv4_upstream_gateway", ""),
        "username": data.get("username", ""),
        "password": data.get("password", ""),
        "dial_on_demand": bool(data.get("dial_on_demand", False)),
        "idle_timeout": int(data.get("idle_timeout", 0) or 0),
        "block_private_networks": bool(
            data.get("block_private_networks", base["block_private_networks"])
        ),
        "block_bogon_networks": bool(
            data.get("block_bogon_networks", base["block_bogon_networks"])
        ),
        "assigned_port": (data.get("assigned_port") or "").strip(),
    }
