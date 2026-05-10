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


# ---------------------------------------------------------------------------
# Secret redaction helpers
# ---------------------------------------------------------------------------

_SECRET_FLAGS = {
    "-p", "--password", "-P", "--secret", "--psk",
    "--auth", "--token", "--key", "--credential",
}

_SECRET_PATTERNS = re.compile(
    r"(password|secret|psk|token|auth|key|credential)",
    re.IGNORECASE,
)


def redact_command(cmd: List[str]) -> List[str]:
    """
    Return a copy of ``cmd`` with any argument that follows a secret flag
    replaced by ``***``.  Also redacts tokens that look like
    ``--flag=secret_value``.

    This is used for logging — the original ``cmd`` is always passed to
    subprocess unchanged.
    """
    if not cmd:
        return cmd
    out = list(cmd)
    i   = 0
    while i < len(out):
        tok = out[i]
        # --flag=value form
        if "=" in tok:
            flag, _, value = tok.partition("=")
            if flag in _SECRET_FLAGS or _SECRET_PATTERNS.search(flag):
                out[i] = f"{flag}=***"
        # -flag value form
        elif tok in _SECRET_FLAGS or _SECRET_PATTERNS.search(tok):
            if i + 1 < len(out):
                out[i + 1] = "***"
        i += 1
    return out


def run_command(
    cmd: List[str],
    check: bool = True,
    timeout_seconds: Optional[int] = 20,
    _audit: bool = False,
) -> CommandResult:
    """
    Execute a system command safely.

    Parameters
    ----------
    cmd             : Argument list.  shell=True is NEVER used.
    check           : If True, raise FreeBSDNetworkError on non-zero exit.
    timeout_seconds : Kill the process if it exceeds this duration.
    _audit          : If True, emit an app-log INFO entry with the redacted
                      command.  Default False to avoid log spam for
                      high-frequency read-only calls.
    """
    if _network_dry_run_enabled():
        return CommandResult(command=cmd, returncode=0, stdout="", stderr="")

    if _audit:
        try:
            from app.app_log import log_info
            log_info("network_service", "run_command", {"cmd": redact_command(cmd)})
        except Exception:
            pass

    # On FreeBSD, when running as root, privileged binaries are called directly.
    # In non-root deployments the sudoers allowlist (bsd/etc/sudoers.d/smartshield)
    # grants the exact set of permitted commands via sudo.
    _PRIVILEGED_BINS = {
        "/sbin/pfctl", "pfctl",
        "/sbin/ifconfig", "ifconfig",
        "/sbin/route", "route",
        "/usr/sbin/service", "service",
        "/usr/sbin/sysrc", "sysrc",
        "/usr/local/sbin/unbound-control", "unbound-control",
        "/usr/sbin/ppp", "ppp",
        "pkill",
    }
    actual_cmd = list(cmd)
    if (
        sys.platform.startswith("freebsd")
        and os.getuid() != 0
        and actual_cmd
        and actual_cmd[0] in _PRIVILEGED_BINS
        and actual_cmd[0] not in {"/usr/bin/sudo", "/usr/local/bin/sudo"}
    ):
        actual_cmd = ["/usr/local/bin/sudo"] + actual_cmd

    try:
        proc = subprocess.run(
            actual_cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        raise FreeBSDNetworkError(
            f"Command timed out after {timeout_seconds}s: {' '.join(redact_command(actual_cmd))}"
        )

    if check and proc.returncode != 0:
        raise FreeBSDNetworkError(
            f"Command failed ({' '.join(redact_command(actual_cmd))}): "
            f"{proc.stderr.strip() or proc.stdout.strip()}"
        )
    return CommandResult(
        command=actual_cmd,
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


# ---------------------------------------------------------------------------
# Phase 3 — Physical NIC discovery + live interface state read-back
# ---------------------------------------------------------------------------

_IFCONFIG_IFACE_RE = re.compile(r"^(\S+):")
_IFCONFIG_INET_RE  = re.compile(r"inet\s+(\S+)\s+netmask\s+(\S+)(?:\s+broadcast\s+(\S+))?")
_IFCONFIG_STATUS_RE = re.compile(r"\bstatus:\s+(\S+)")
_IFCONFIG_MEDIA_RE  = re.compile(r"\bmedia:\s+(.+)")
_IFCONFIG_ETHER_RE  = re.compile(r"\bether\s+(\S+)")


def _hex_netmask_to_cidr(hex_mask: str) -> int:
    """Convert '0xffffff00' → 24."""
    try:
        mask_int = int(hex_mask, 16)
        return bin(mask_int).count("1")
    except ValueError:
        return 32


def list_physical_nics() -> list:
    """
    Return a list of physical (non-loopback, non-virtual) network interfaces
    detected via `ifconfig -l`.  On non-FreeBSD returns an empty list.

    Each entry: {"name": str, "flags": str, "inet": str, "cidr": str,
                 "ether": str, "status": str, "media": str}
    """
    if not sys.platform.startswith("freebsd"):
        return []

    # Get names first
    result = run_command(["ifconfig", "-l"], check=False)
    if result.returncode != 0:
        return []

    names = result.stdout.strip().split()
    skip_prefixes = ("lo", "pflog", "pfsync", "enc", "gif", "gre", "faith",
                     "stf", "lagg", "bridge", "vlan", "tun", "tap")
    names = [n for n in names if not any(n.startswith(p) for p in skip_prefixes)]

    nics = []
    for name in names:
        info = get_interface_state(name)
        if info:
            nics.append(info)
    return nics


def get_interface_state(iface_name: str) -> dict:
    """
    Return live state for a single interface as a dict:
      name, inet, cidr, ether, status, media, flags, mtu

    On non-FreeBSD returns a dict with empty/placeholder values.
    """
    if not sys.platform.startswith("freebsd"):
        return {
            "name":   iface_name,
            "inet":   "",
            "cidr":   "",
            "ether":  "",
            "status": "unknown",
            "media":  "",
            "flags":  "",
            "mtu":    "",
        }

    result = run_command(["ifconfig", iface_name], check=False)
    if result.returncode != 0:
        return {}

    text  = result.stdout
    inet  = ""
    cidr  = ""
    ether = ""
    status = "unknown"
    media  = ""
    flags  = ""
    mtu    = ""

    for line in text.splitlines():
        # inet address
        m = _IFCONFIG_INET_RE.search(line)
        if m:
            inet = m.group(1)
            hex_mask = m.group(2)
            cidr = str(_hex_netmask_to_cidr(hex_mask)) if hex_mask.startswith("0x") else hex_mask

        # MAC address
        m = _IFCONFIG_ETHER_RE.search(line)
        if m:
            ether = m.group(1)

        # Link status
        m = _IFCONFIG_STATUS_RE.search(line)
        if m:
            status = m.group(1)

        # Media
        m = _IFCONFIG_MEDIA_RE.search(line)
        if m:
            media = m.group(1).strip()

        # Flags + MTU on first line
        if "<" in line and ">" in line and not flags:
            flags_m = re.search(r"<([^>]+)>", line)
            if flags_m:
                flags = flags_m.group(1)
            mtu_m = re.search(r"\bmtu\s+(\d+)", line)
            if mtu_m:
                mtu = mtu_m.group(1)

    return {
        "name":   iface_name,
        "inet":   inet,
        "cidr":   f"{inet}/{cidr}" if inet and cidr else "",
        "ether":  ether,
        "status": status,
        "media":  media,
        "flags":  flags,
        "mtu":    mtu,
    }


def read_interface_config_from_bsd(iface_name: str) -> dict:
    """
    Read the current configuration of one interface from the live FreeBSD system.
    Combines:
      - sysrc -n ifconfig_<iface>   → determines type (dhcp / static / none)
      - ifconfig <iface>             → live assigned IP (even for DHCP)
      - sysrc -n defaultrouter       → current default gateway
    Returns dict with keys: iface, ipv4_config_type, ipv4_address, gateway, live_ip
    Non-FreeBSD: returns the dict with empty values (safe for dev environments).
    """
    result: dict = {
        "iface":            iface_name,
        "ipv4_config_type": "none",
        "ipv4_address":     "",
        "gateway":          "",
        "live_ip":          "",
    }
    if not sys.platform.startswith("freebsd") or not iface_name:
        return result

    try:
        from app.services.priv_helper import run_privileged
        rc_key = "ifconfig_" + re.sub(r"[^A-Za-z0-9_]", "_", iface_name)
        r = run_privileged("sysrc.get", key=rc_key)
        rc_val = (r.stdout or "").strip().upper()
        if rc_val == "DHCP":
            result["ipv4_config_type"] = "dhcp"
        elif "INET" in rc_val or rc_val.startswith("STATIC"):
            result["ipv4_config_type"] = "static"
        elif rc_val in ("UP", "", "NO"):
            result["ipv4_config_type"] = "none"
        else:
            # non-empty, non-DHCP → treat as static
            result["ipv4_config_type"] = "static"
    except Exception:
        pass

    # Read live IP from ifconfig (works regardless of DHCP vs static)
    try:
        state = get_interface_state(iface_name)
        live = state.get("cidr") or state.get("inet") or ""
        result["live_ip"] = live
        if result["ipv4_config_type"] == "static" and live:
            result["ipv4_address"] = live
    except Exception:
        pass

    # Read gateway from rc.conf
    try:
        r = run_privileged("sysrc.get", key="defaultrouter")
        gw = (r.stdout or "").strip()
        if gw and gw.upper() not in ("NO", ""):
            result["gateway"] = gw
    except Exception:
        pass

    return result



# ---------------------------------------------------------------------------
# Phase 3 — Interface assignment with live apply + rollback
# ---------------------------------------------------------------------------

_PING_TIMEOUT_SEC = 4   # seconds to wait for ping reply
_VERIFY_ATTEMPTS  = 3   # number of ping packets to send


def _ping(host: str) -> bool:
    """Return True if host answers ping within _PING_TIMEOUT_SEC."""
    if not host or not sys.platform.startswith("freebsd"):
        return True  # skip verification on non-FreeBSD
    result = run_command(
        ["ping", "-c", str(_VERIFY_ATTEMPTS), "-W", str(_PING_TIMEOUT_SEC * 1000), host],
        check=False,
        timeout_seconds=_PING_TIMEOUT_SEC + 5,
    )
    return result.returncode == 0


def apply_interface_with_rollback(
    iface_name: str,
    new_cidr: str,
    new_gateway: str = "",
    verify_host: str = "",
) -> dict:
    """
    Apply a new IPv4 address (CIDR) and optional default gateway to an interface.
    If connectivity verification fails, the old configuration is automatically
    restored.

    Parameters
    ----------
    iface_name   : FreeBSD interface name, e.g. "em0"
    new_cidr     : New address in CIDR notation, e.g. "192.168.1.1/24"
    new_gateway  : Default gateway IP (optional). Leave blank to skip.
    verify_host  : IP/hostname to ping after applying to verify reachability.
                   Falls back to new_gateway if empty.

    Returns
    -------
    dict with keys:
        ok          : bool
        message     : str
        rolled_back : bool
        old_state   : dict (interface state before apply)
    """
    if not sys.platform.startswith("freebsd"):
        return {
            "ok": True,
            "message": f"Non-FreeBSD — apply skipped for {iface_name} {new_cidr}",
            "rolled_back": False,
            "old_state": {},
        }

    # 1. Capture current state for potential rollback
    old_state = get_interface_state(iface_name)
    old_cidr    = old_state.get("cidr", "")
    old_ip      = old_state.get("inet", "")
    old_netmask = ""
    if old_cidr and "/" in old_cidr:
        try:
            import ipaddress as _ip
            old_netmask = str(_ip.ip_interface(old_cidr).network.netmask)
        except Exception:
            pass

    def _restore_old():
        """Best-effort restore of previous address."""
        if not old_ip or not old_netmask:
            return
        try:
            run_command(
                ["ifconfig", iface_name, "inet", old_ip, "netmask", old_netmask],
                check=False,
            )
        except Exception:
            pass

    # 2. Apply new address
    try:
        apply_interface_ipv4(iface_name, new_cidr)
    except FreeBSDNetworkError as exc:
        return {
            "ok": False,
            "message": f"Failed to apply {new_cidr} to {iface_name}: {exc}",
            "rolled_back": False,
            "old_state": old_state,
        }

    # 3. Apply new gateway (if provided)
    if new_gateway:
        try:
            set_default_gateway(new_gateway)
        except FreeBSDNetworkError as exc:
            # Gateway failed — restore old address and abort
            _restore_old()
            return {
                "ok": False,
                "message": f"Gateway apply failed ({exc}) — interface address rolled back.",
                "rolled_back": True,
                "old_state": old_state,
            }

    # 4. Verify connectivity
    target = verify_host or new_gateway
    if target:
        reachable = _ping(target)
        if not reachable:
            # Restore old address
            _restore_old()
            if old_state.get("inet"):
                # Also restore old gateway if we know it
                try:
                    run_command(["route", "-n", "delete", "default"], check=False)
                except Exception:
                    pass
            return {
                "ok": False,
                "message": (
                    f"Connectivity check failed — {target} unreachable after apply. "
                    "Configuration rolled back to previous state."
                ),
                "rolled_back": True,
                "old_state": old_state,
            }

    return {
        "ok": True,
        "message": f"Applied {new_cidr} to {iface_name}" + (f" via {new_gateway}" if new_gateway else ""),
        "rolled_back": False,
        "old_state": old_state,
    }


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


def apply_interface_config(conn) -> dict:
    """
    Read LAN and WAN config from the DB and apply each interface live.
    Skips DHCP/PPPoE WAN (those are managed by dhclient/mpd, not ifconfig).
    Returns a combined result dict with ok/message keys.
    """
    results = []

    lan = conn.execute(
        "SELECT assigned_port, ipv4_address, ipv4_upstream_gateway, ipv4_config_type "
        "FROM lan_config LIMIT 1"
    ).fetchone()

    wan = conn.execute(
        "SELECT assigned_port, ipv4_address, ipv4_upstream_gateway, ipv4_config_type "
        "FROM wan_config LIMIT 1"
    ).fetchone()

    for label, row in (("LAN", lan), ("WAN", wan)):
        if not row:
            continue
        iface   = (row["assigned_port"] or "").strip()
        cidr    = (row["ipv4_address"] or "").strip()
        gateway = (row["ipv4_upstream_gateway"] or "").strip()
        mode    = (row["ipv4_config_type"] or "static").lower()

        if not iface or not cidr or mode != "static":
            results.append({
                "iface": label,
                "ok": True,
                "message": f"{label}: skipped (mode={mode}, iface={iface or 'unset'})",
            })
            continue

        r = apply_interface_with_rollback(iface, cidr, gateway)
        results.append({"iface": label, **r})

    overall_ok = all(r["ok"] for r in results)
    return {
        "ok": overall_ok,
        "message": "; ".join(r["message"] for r in results) if results else "Nothing to apply",
        "details": results,
    }


# ---------------------------------------------------------------------------
# Virtual IPs live apply (Phase 11)
# ---------------------------------------------------------------------------

def check_gateway_reachability(gateway_ip: str, count: int = 3) -> bool:
    """
    Ping *gateway_ip* ``count`` times and return True if at least one reply arrives.
    Uses ``/sbin/ping -c <count> -q -W 1 <ip>`` on FreeBSD.
    Returns True on non-FreeBSD (dev mode — assume all reachable).
    """
    if not sys.platform.startswith("freebsd"):
        return True
    try:
        result = run_command(
            ["/sbin/ping", "-c", str(count), "-q", "-W", "1", gateway_ip],
            check=False, timeout_seconds=count + 2,
        )
        return result.returncode == 0
    except Exception:
        return False


def apply_gateway_failover(conn) -> dict:
    """
    Phase 8: Multi-WAN gateway failover.

    Iterates gateway groups ordered by priority, pings each member gateway,
    and activates the highest-priority reachable gateway as the default route.

    Returns {"ok": bool, "active_gateway": str|None, "message": str, "details": list}.
    """
    try:
        cur = conn.execute("""
            SELECT g.name, g.gateway, g.interface, gg.priority, gg.group_name
            FROM gateway_group_members gg
            JOIN gateways g ON gg.gateway_id = g.id
            WHERE g.disabled = 0
            ORDER BY gg.group_name, gg.priority ASC
        """)
        members = [dict(r) for r in cur.fetchall()]
    except Exception as exc:
        return {"ok": False, "active_gateway": None, "message": f"DB error: {exc}", "details": []}

    if not members:
        return {"ok": True, "active_gateway": None, "message": "No gateway groups configured.", "details": []}

    details = []
    active  = None

    for m in members:
        gw_ip    = (m.get("gateway") or "").strip()
        gw_name  = m.get("name", gw_ip)
        reachable = check_gateway_reachability(gw_ip)
        details.append({"gateway": gw_ip, "name": gw_name, "reachable": reachable})
        if reachable and active is None:
            active = gw_ip

    if not sys.platform.startswith("freebsd"):
        return {
            "ok": True,
            "active_gateway": active,
            "message": f"Non-FreeBSD — failover calculated: {active or 'none reachable'}",
            "details": details,
        }

    if active is None:
        return {"ok": False, "active_gateway": None, "message": "All gateways unreachable.", "details": details}

    try:
        run_command(["/sbin/route", "-n", "delete", "default"], check=False)
        r = run_command(["/sbin/route", "-n", "add", "default", active], check=False)
        ok = r.returncode == 0
        return {
            "ok":            ok,
            "active_gateway": active,
            "message":       f"Default route set to {active}." if ok else f"route add failed: {(r.stderr or r.stdout or '').strip()}",
            "details":       details,
        }
    except Exception as exc:
        return {"ok": False, "active_gateway": active, "message": str(exc), "details": details}


def apply_vips(conn) -> dict:
    """
    Apply all virtual IP entries from ``virtual_ips_configs`` to live interfaces.

    - type='ipalias': adds the address as an IP alias on the interface using
      ``ifconfig <iface> inet <ip> netmask <mask> alias``.
    - type='carp' and other types: logged as unsupported until CARP-specific
      fields (vhid, password) are added to the schema.

    On non-FreeBSD: config-only mode (no commands run).
    Returns {"ok": bool, "applied": list, "skipped": list, "message": str}.
    """
    import ipaddress as _ipa

    rows = []
    try:
        cur = conn.execute("SELECT * FROM virtual_ips_configs ORDER BY id")
        rows = [dict(r) for r in cur.fetchall()]
    except Exception as exc:
        return {"ok": False, "applied": [], "skipped": [], "message": f"DB error: {exc}"}

    applied = []
    skipped = []

    for vip in rows:
        vtype  = (vip.get("type") or "ipalias").lower()
        iface  = (vip.get("interface") or "").strip()
        addr   = (vip.get("address") or "").strip()
        prefix = int(vip.get("prefix") or 32)

        if not iface or not addr:
            skipped.append({"id": vip.get("id"), "reason": "missing interface or address"})
            continue

        if vtype in ("carp", "pfsync", "proxyarp"):
            skipped.append({
                "id": vip.get("id"),
                "type": vtype,
                "reason": f"{vtype} requires additional CARP-specific fields (vhid, password) not yet in schema",
            })
            continue

        if not sys.platform.startswith("freebsd"):
            applied.append({"id": vip.get("id"), "type": vtype, "iface": iface, "addr": addr, "dry_run": True})
            continue

        try:
            net = _ipa.ip_interface(f"{addr}/{prefix}")
            netmask = str(net.network.netmask)
            from app.services.priv_helper import run_privileged
            result = run_privileged("ifconfig.alias_add", iface=iface, ip=addr, netmask=netmask)
            ok = result.returncode == 0
            applied.append({
                "id":    vip.get("id"),
                "type":  vtype,
                "iface": iface,
                "addr":  f"{addr}/{prefix}",
                "ok":    ok,
                "message": (result.stderr or result.stdout or "").strip(),
            })
        except Exception as exc:
            applied.append({"id": vip.get("id"), "iface": iface, "addr": addr, "ok": False, "message": str(exc)})

    overall_ok = all(a.get("ok", True) for a in applied)
    msg_parts = [f"{len(applied)} VIP(s) applied"]
    if skipped:
        msg_parts.append(f"{len(skipped)} skipped")
    return {
        "ok": overall_ok,
        "applied": applied,
        "skipped": skipped,
        "message": ", ".join(msg_parts) + ".",
    }
