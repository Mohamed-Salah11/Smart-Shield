"""
app/services/hostname_resolver.py
---------------------------------
Active hostname discovery for same-network devices.

LAN devices rarely have reverse-DNS (PTR) records and many never announce a
DHCP ``client-hostname``, so they show up nameless in the device inventory.
This module probes a single host with two lightweight, dependency-free UDP
queries to recover a name:

  * **NetBIOS Node Status** (UDP 137) — Windows machines answer with their
    computer name.
  * **mDNS reverse PTR** (UDP 5353) — Apple/Linux devices answer with their
    ``<name>.local`` name.

Both probes are pure-Python (``socket`` + ``struct``); nothing extra needs to
be installed on the appliance. Results are cached in-memory with a TTL because
the Network Devices page re-runs host discovery on every page load.

Public API:
    resolve_hostname(ip, timeout=1.0)   -> str   ("" when nothing answers)
    resolve_hostnames(ips, ...)         -> dict  {ip: name} for hits only
"""

from __future__ import annotations

import ipaddress
import os
import re
import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor

# --- tuning -----------------------------------------------------------------
_POSITIVE_TTL = 600     # seconds to trust a discovered name
_NEGATIVE_TTL = 120     # seconds before re-probing a silent host
_DEFAULT_TIMEOUT = 1.0  # per-probe UDP wait

_NBNS_PORT = 137
_MDNS_PORT = 5353

# --- in-memory cache --------------------------------------------------------
_CACHE_LOCK = threading.Lock()
_CACHE: dict = {}       # ip -> (name, expires_at)

_HOSTNAME_STRIP_RE = re.compile(r"[^A-Za-z0-9-]")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sanitize(name: str) -> str:
    """Reduce a raw probe result to a safe single-label hostname."""
    if not name:
        return ""
    name = name.strip().strip(".")
    name = name.split(".")[0]                 # first label only
    name = _HOSTNAME_STRIP_RE.sub("", name)   # drop anything not host-safe
    return name[:63]


def _skip_dns_name(data: bytes, off: int) -> int:
    """Advance past a DNS/NetBIOS name (handles labels and compression)."""
    while off < len(data):
        length = data[off]
        if length == 0:
            return off + 1
        if (length & 0xC0) == 0xC0:           # compression pointer
            return off + 2
        off += 1 + length
    return off


def _read_dns_name(data: bytes, off: int) -> tuple:
    """Read a (possibly compressed) DNS name; return (name, next_offset)."""
    parts = []
    while True:
        if off >= len(data):
            break
        length = data[off]
        if length == 0:
            off += 1
            break
        if (length & 0xC0) == 0xC0:
            if off + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[off + 1]
            sub, _ = _read_dns_name(data, ptr)
            if sub:
                parts.append(sub)
            off += 2
            break
        off += 1
        parts.append(data[off:off + length].decode("ascii", "ignore"))
        off += length
    return ".".join(p for p in parts if p), off


def _udp_query(ip: str, port: int, packet: bytes, timeout: float, txid: int) -> bytes:
    """Send one UDP datagram and return the first matching reply (or b'')."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("", 0))
        sock.sendto(packet, (ip, port))
        deadline = time.time() + timeout
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                return b""
            sock.settimeout(remaining)
            try:
                data, addr = sock.recvfrom(2048)
            except (socket.timeout, OSError):
                return b""
            if addr[0] != ip:
                continue
            if len(data) >= 2 and struct.unpack(">H", data[:2])[0] != txid:
                continue
            return data
    finally:
        try:
            sock.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# NetBIOS Node Status (UDP 137)
# ---------------------------------------------------------------------------

def _encode_netbios_name(name: str = "*") -> bytes:
    """First-level-encode a NetBIOS name padded to 16 bytes."""
    padded = name.encode("ascii", "ignore")[:16]
    padded = padded + b"\x00" * (16 - len(padded))
    encoded = bytearray()
    for b in padded:
        encoded.append(0x41 + (b >> 4))
        encoded.append(0x41 + (b & 0x0F))
    return bytes([len(encoded)]) + bytes(encoded) + b"\x00"


def _nbns_name(ip: str, timeout: float) -> str:
    """Query a host's NetBIOS node status; return its workstation name."""
    txid = struct.unpack(">H", os.urandom(2))[0]
    header = struct.pack(">HHHHHH", txid, 0x0000, 1, 0, 0, 0)
    question = _encode_netbios_name("*") + struct.pack(">HH", 0x0021, 0x0001)
    data = _udp_query(ip, _NBNS_PORT, header + question, timeout, txid)
    if len(data) < 12:
        return ""

    qdcount = struct.unpack(">H", data[4:6])[0]
    ancount = struct.unpack(">H", data[6:8])[0]
    if ancount < 1:
        return ""

    off = 12
    for _ in range(qdcount):                  # skip echoed question(s)
        off = _skip_dns_name(data, off) + 4
    off = _skip_dns_name(data, off)           # answer RR name
    if off + 11 > len(data):
        return ""
    off += 10                                 # type, class, ttl, rdlength
    num_names = data[off]
    off += 1

    for _ in range(num_names):
        if off + 18 > len(data):
            break
        nb_name = data[off:off + 15].decode("ascii", "ignore").rstrip()
        suffix = data[off + 15]
        flags = struct.unpack(">H", data[off + 16:off + 18])[0]
        off += 18
        # suffix 0x00 + UNIQUE (group bit clear) is the workstation name
        if suffix == 0x00 and not (flags & 0x8000):
            if nb_name and nb_name != "__MSBROWSE__":
                return nb_name
    return ""


# ---------------------------------------------------------------------------
# mDNS reverse PTR (UDP 5353)
# ---------------------------------------------------------------------------

def _encode_dns_name(name: str) -> bytes:
    out = bytearray()
    for label in name.split("."):
        if not label:
            continue
        lb = label.encode("ascii", "ignore")
        out.append(len(lb))
        out += lb
    out.append(0)
    return bytes(out)


def _mdns_name(ip: str, timeout: float) -> str:
    """Send a legacy-unicast mDNS reverse PTR query; return the .local name."""
    try:
        if ipaddress.ip_address(ip).version != 4:
            return ""
    except ValueError:
        return ""

    ptr_name = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    txid = struct.unpack(">H", os.urandom(2))[0]
    header = struct.pack(">HHHHHH", txid, 0x0000, 1, 0, 0, 0)
    # QTYPE PTR (12); QCLASS IN with the mDNS unicast-response (QU) bit set
    question = _encode_dns_name(ptr_name) + struct.pack(">HH", 0x000C, 0x8001)
    data = _udp_query(ip, _MDNS_PORT, header + question, timeout, txid)
    if len(data) < 12:
        return ""

    qdcount = struct.unpack(">H", data[4:6])[0]
    ancount = struct.unpack(">H", data[6:8])[0]
    if ancount < 1:
        return ""

    off = 12
    for _ in range(qdcount):                  # skip echoed question(s)
        off = _skip_dns_name(data, off) + 4
    for _ in range(ancount):
        off = _skip_dns_name(data, off)
        if off + 10 > len(data):
            break
        rr_type, _rr_class, _ttl, rdlength = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        if rr_type == 0x000C:                 # PTR
            name, _ = _read_dns_name(data, off)
            return name
        off += rdlength
    return ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def resolve_hostname(ip: str, timeout: float = _DEFAULT_TIMEOUT) -> str:
    """
    Return a discovered hostname for *ip*, or "" if nothing answers.

    Tries NetBIOS first (Windows), then mDNS (Apple/Linux). Results — including
    misses — are cached so repeated discovery passes stay cheap.
    """
    ip = (ip or "").strip()
    if not ip:
        return ""

    now = time.time()
    with _CACHE_LOCK:
        cached = _CACHE.get(ip)
        if cached and cached[1] > now:
            return cached[0]

    name = ""
    try:
        name = _sanitize(_nbns_name(ip, timeout))
        if not name:
            name = _sanitize(_mdns_name(ip, timeout))
    except Exception:
        name = ""

    ttl = _POSITIVE_TTL if name else _NEGATIVE_TTL
    with _CACHE_LOCK:
        _CACHE[ip] = (name, time.time() + ttl)
    return name


def resolve_hostnames(ips, max_workers: int = 16,
                      timeout: float = _DEFAULT_TIMEOUT) -> dict:
    """
    Probe many IPs in parallel; return {ip: name} for hits only.

    Safe to call with any iterable of IP strings; never raises.
    """
    targets = []
    seen = set()
    for ip in ips or []:
        ip = (ip or "").strip()
        if ip and ip not in seen:
            seen.add(ip)
            targets.append(ip)
    if not targets:
        return {}

    results: dict = {}
    workers = max(1, min(max_workers, len(targets)))
    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for ip, name in zip(targets,
                                pool.map(lambda t: resolve_hostname(t, timeout),
                                         targets)):
                if name:
                    results[ip] = name
    except Exception:
        pass
    return results
