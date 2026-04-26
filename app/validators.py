"""
app/validators.py
-----------------
Centralized input validators for API endpoints.

Each ``validate_*`` function:
  - Accepts a raw value (str, int, etc.) and keyword options.
  - Returns the normalized/sanitized value on success.
  - Raises ``ValueError`` with a human-readable message on failure.

Use :func:`collect_errors` to run several validators at once and return all
failures rather than stopping at the first.
"""

import ipaddress
import re

# ── IP / Network ─────────────────────────────────────────────────────────────

def validate_ip(value: str, *, allow_empty: bool = True) -> str:
    """Validate an IPv4 or IPv6 address."""
    v = (value or "").strip()
    if not v:
        if allow_empty:
            return v
        raise ValueError("IP address is required")
    try:
        ipaddress.ip_address(v)
    except ValueError:
        raise ValueError(f"Invalid IP address: {v!r}")
    return v


def validate_cidr(value: str, *, allow_empty: bool = True) -> str:
    """Validate an IP address with prefix length (CIDR notation, e.g. 192.168.1.1/24)."""
    v = (value or "").strip()
    if not v:
        if allow_empty:
            return v
        raise ValueError("CIDR address is required")
    try:
        ipaddress.ip_interface(v)
    except ValueError:
        raise ValueError(f"Invalid CIDR address: {v!r}")
    return v


def validate_network(value: str, *, allow_empty: bool = True) -> str:
    """Validate a network CIDR (e.g. 192.168.0.0/24).  Host bits are ignored."""
    v = (value or "").strip()
    if not v:
        if allow_empty:
            return v
        raise ValueError("Network CIDR is required")
    try:
        ipaddress.ip_network(v, strict=False)
    except ValueError:
        raise ValueError(f"Invalid network CIDR: {v!r}")
    return v


# ── Hostname / Domain ─────────────────────────────────────────────────────────

_HOSTNAME_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
)


def validate_hostname(value: str, *, allow_empty: bool = True) -> str:
    """Validate a DNS hostname or domain name (e.g. example.com, host.lan)."""
    v = (value or "").strip().lower()
    if not v:
        if allow_empty:
            return v
        raise ValueError("Hostname is required")
    if len(v) > 253:
        raise ValueError("Hostname exceeds 253 characters")
    if not _HOSTNAME_RE.match(v):
        raise ValueError(f"Invalid hostname or domain: {v!r}")
    return v


# ── Ports ─────────────────────────────────────────────────────────────────────

def validate_port(value, *, allow_empty: bool = True):
    """Validate a single TCP/UDP port number (1–65535). Returns int or None."""
    if value is None or str(value).strip() == "":
        if allow_empty:
            return None
        raise ValueError("Port is required")
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"Port must be an integer, got {value!r}")
    if not (1 <= port <= 65535):
        raise ValueError(f"Port {port} out of range 1–65535")
    return port


_PORT_RANGE_RE = re.compile(r"^(\d{1,5})(?:[:\-](\d{1,5}))?$")


def validate_port_range(value: str, *, allow_empty: bool = True) -> str:
    """Validate a port or port range ('80', '8080-8090', '8080:8090')."""
    v = (value or "").strip()
    if not v:
        if allow_empty:
            return v
        raise ValueError("Port range is required")
    m = _PORT_RANGE_RE.match(v)
    if not m:
        raise ValueError(f"Invalid port range: {v!r}")
    start = int(m.group(1))
    end = int(m.group(2)) if m.group(2) else start
    if not (1 <= start <= 65535) or not (1 <= end <= 65535):
        raise ValueError(f"Port values out of range in: {v!r}")
    if end < start:
        raise ValueError(f"Port range end must be >= start in: {v!r}")
    return v


def validate_port_list(value: str, *, allow_empty: bool = True) -> str:
    """Validate a comma-separated list of ports / port ranges."""
    v = (value or "").strip()
    if not v:
        if allow_empty:
            return v
        raise ValueError("Port list is required")
    for part in re.split(r"[,\s]+", v):
        part = part.strip()
        if part:
            validate_port_range(part, allow_empty=False)
    return v


# ── Protocol ──────────────────────────────────────────────────────────────────

_VALID_PROTOCOLS = frozenset({
    "tcp", "udp", "tcp+udp", "icmp", "icmpv6", "esp", "ah", "gre",
    "any", "all", "",
})


def validate_protocol(value: str, *, allow_empty: bool = True) -> str:
    """Validate a network protocol string."""
    v = (value or "").strip().lower()
    if v not in _VALID_PROTOCOLS:
        raise ValueError(f"Invalid protocol: {value!r}")
    return v


# ── Interface name ────────────────────────────────────────────────────────────

_IFACE_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.:\-]{0,31}$")


def validate_interface_name(value: str, *, allow_empty: bool = True) -> str:
    """Validate a NIC name (em0, vtnet0, tun0, etc.)."""
    v = (value or "").strip()
    if not v:
        if allow_empty:
            return v
        raise ValueError("Interface name is required")
    if not _IFACE_RE.match(v):
        raise ValueError(f"Invalid interface name: {v!r}")
    return v


# ── Username ──────────────────────────────────────────────────────────────────

_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.@\-]{1,64}$")


def validate_username(value: str, *, allow_empty: bool = False) -> str:
    """Validate a username (alphanumeric plus . _ @ -)."""
    v = (value or "").strip()
    if not v:
        if allow_empty:
            return v
        raise ValueError("Username is required")
    if not _USERNAME_RE.match(v):
        raise ValueError(f"Invalid username: {v!r}")
    return v


# ── Boolean ───────────────────────────────────────────────────────────────────

def validate_boolean(value, *, default: bool = False) -> bool:
    """Coerce JSON / form booleans to Python bool."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


# ── Free text ─────────────────────────────────────────────────────────────────

def validate_description(value: str, *, max_len: int = 255) -> str:
    """Strip and length-check a free-text description."""
    v = (value or "").strip()
    if len(v) > max_len:
        raise ValueError(f"Description exceeds {max_len} characters")
    return v


def validate_name(value: str, *, max_len: int = 64, allow_empty: bool = False) -> str:
    """Validate a short identifier name (firewall alias name, schedule name, etc.)."""
    v = (value or "").strip()
    if not v:
        if allow_empty:
            return v
        raise ValueError("Name is required")
    if len(v) > max_len:
        raise ValueError(f"Name exceeds {max_len} characters")
    return v


# ── Bulk helper ───────────────────────────────────────────────────────────────

def collect_errors(**validators) -> dict:
    """
    Run each callable in *validators* and collect all ``ValueError`` messages.

    Returns a ``{field: message}`` dict; empty means all passed.

    Example::

        errors = collect_errors(
            ip=lambda: validate_ip(data["ip"], allow_empty=False),
            port=lambda: validate_port(data["port"], allow_empty=False),
        )
        if errors:
            return jsonify({"error": "Validation failed", "fields": errors}), 400
    """
    errors: dict = {}
    for field, fn in validators.items():
        try:
            fn()
        except ValueError as exc:
            errors[field] = str(exc)
    return errors
