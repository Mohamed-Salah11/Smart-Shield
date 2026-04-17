import ipaddress
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import List, Optional


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


def run_command(cmd: List[str], check=True, timeout_seconds: Optional[int] = 20) -> CommandResult:
    if _network_dry_run_enabled():
        return CommandResult(command=cmd, returncode=0, stdout="", stderr="")

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        raise FreeBSDNetworkError(f"Command timed out ({' '.join(cmd)}).")

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


_ARP_LINE_RE = re.compile(
    r"^(?P<hostname>\S+)\s+\((?P<ip>[^)]+)\)\s+at\s+(?P<mac>\S+)\s+on\s+(?P<iface>\S+)"
)


def list_arp_neighbors():
    """
    Return ARP neighbors from FreeBSD as a list of dictionaries:
    {ip_address, mac_address, interface_name, hostname}
    """
    if not sys.platform.startswith("freebsd"):
        return []

    result = run_command(["arp", "-an"], check=True)
    neighbors = []

    for line in (result.stdout or "").splitlines():
        raw = line.strip()
        if not raw:
            continue
        match = _ARP_LINE_RE.match(raw)
        if not match:
            continue

        ip_address = (match.group("ip") or "").strip()
        mac_address = (match.group("mac") or "").strip().lower()
        interface_name = (match.group("iface") or "").strip()
        hostname = (match.group("hostname") or "").strip()

        # Skip unresolved entries and malformed records.
        if not ip_address or mac_address in {"(incomplete)", "incomplete"}:
            continue
        if not interface_name:
            continue

        neighbors.append(
            {
                "ip_address": ip_address,
                "mac_address": mac_address,
                "interface_name": interface_name,
                "hostname": "" if hostname in {"?", "(?)"} else hostname,
            }
        )

    return neighbors


_DNS_QUERY_RE = re.compile(
    r"^\s*(?:\d{2}:\d{2}:\d{2}\.\d+\s+)?IP6?\s+(?P<src>\S+)\s+>\s+(?P<dst>\S+):\s+"
    r"\d+\+\s+(?P<qtype>[A-Z0-9]+)\?\s+(?P<name>[^ ]+)"
)

_HTTP_PACKET_RE = re.compile(
    r"^\s*(?:\d{2}:\d{2}:\d{2}\.\d+\s+)?IP6?\s+(?P<src>\S+)\s+>\s+(?P<dst>\S+):"
)

_HTTP_METHOD_RE = re.compile(
    r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s+HTTP/\d\.\d",
    re.IGNORECASE,
)


def _extract_ip_from_endpoint(endpoint: str):
    token = (endpoint or "").strip()
    if not token:
        return ""
    if token.endswith(":"):
        token = token[:-1]

    # Strip trailing ".<port>" pattern from tcpdump endpoint fields.
    if "." in token:
        base, maybe_port = token.rsplit(".", 1)
        if maybe_port.isdigit():
            return base
    return token


def capture_dns_activity(interface_name: str, limit: int = 120):
    if not sys.platform.startswith("freebsd"):
        return []

    safe_limit = max(1, min(int(limit or 120), 500))
    iface = (interface_name or "").strip() or "any"
    cmd = [
        "tcpdump",
        "-nn",
        "-l",
        "-tt",
        "-i",
        iface,
        "udp",
        "port",
        "53",
        "-c",
        str(safe_limit),
    ]

    result = run_command(cmd, check=True, timeout_seconds=8)
    events = []

    for line in (result.stdout or "").splitlines():
        raw = line.strip()
        if not raw:
            continue
        match = _DNS_QUERY_RE.match(raw)
        if not match:
            continue

        source_ip = _extract_ip_from_endpoint(match.group("src"))
        query_name = (match.group("name") or "").rstrip(".")
        query_type = (match.group("qtype") or "").upper()
        if not source_ip or not query_name:
            continue

        events.append(
            {
                "source_ip": source_ip,
                "query_name": query_name,
                "query_type": query_type,
                "interface_name": iface,
            }
        )

    return events


def capture_http_activity(interface_name: str, limit: int = 80):
    if not sys.platform.startswith("freebsd"):
        return []

    safe_limit = max(1, min(int(limit or 80), 300))
    iface = (interface_name or "").strip() or "any"
    cmd = [
        "tcpdump",
        "-A",
        "-s",
        "0",
        "-nn",
        "-l",
        "-i",
        iface,
        "tcp",
        "port",
        "80",
        "-c",
        str(safe_limit),
    ]

    result = run_command(cmd, check=True, timeout_seconds=8)
    events = []
    current = None

    def flush_current():
        nonlocal current
        if not current:
            return
        source_ip = current.get("source_ip", "")
        method = current.get("method", "")
        path = current.get("path", "")
        host = current.get("host", "")
        if source_ip and (host or path):
            link = ""
            if host and path:
                link = f"http://{host}{path}"
            elif host:
                link = f"http://{host}/"
            events.append(
                {
                    "source_ip": source_ip,
                    "method": method or "GET",
                    "host": host,
                    "path": path,
                    "link": link,
                    "interface_name": iface,
                }
            )
        current = None

    for line in (result.stdout or "").splitlines():
        raw = line.rstrip("\r\n")
        if not raw:
            continue

        packet_match = _HTTP_PACKET_RE.match(raw.strip())
        if packet_match:
            flush_current()
            current = {
                "source_ip": _extract_ip_from_endpoint(packet_match.group("src")),
                "method": "",
                "path": "",
                "host": "",
            }
            continue

        if current is None:
            continue

        text = raw.strip()
        method_match = _HTTP_METHOD_RE.match(text)
        if method_match:
            current["method"] = method_match.group(1).upper()
            current["path"] = method_match.group(2)
            continue

        if text.lower().startswith("host:"):
            current["host"] = text.split(":", 1)[1].strip()

    flush_current()
    return events


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
