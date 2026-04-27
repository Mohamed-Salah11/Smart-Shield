"""
wol_sender.py
-------------
Wake-on-LAN magic packet sender.

Sends an IEEE 802.3 Magic Packet™ — 6 bytes of 0xFF followed by
the target MAC address repeated 16 times — via a UDP broadcast.

No external tool needed; Python's socket library is sufficient.

Public API
----------
send_wol(mac, interface, broadcast_ip)  -> dict {"ok", "message"}
validate_wol(mac, interface)            -> list[str]
"""

import re
import socket

_MAC_RE = re.compile(r"^([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$")
_WOL_PORT = 9          # Standard WoL port (also 7 is common)
_BROADCAST = "255.255.255.255"


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_wol(mac: str, interface: str = "") -> list:
    errors = []
    m = (mac or "").strip()
    if not m:
        errors.append("MAC address is required.")
    elif not _MAC_RE.match(m):
        errors.append(f"MAC address {m!r} is not valid (expected XX:XX:XX:XX:XX:XX).")
    iface = (interface or "").strip()
    if not iface:
        errors.append("Interface is required.")
    return errors


# ---------------------------------------------------------------------------
# Magic packet
# ---------------------------------------------------------------------------

def _build_magic_packet(mac: str) -> bytes:
    """Build the 102-byte magic packet for the given MAC address."""
    clean = mac.replace(":", "").replace("-", "").upper()
    if len(clean) != 12:
        raise ValueError(f"Invalid MAC address: {mac!r}")
    mac_bytes = bytes.fromhex(clean)
    return b"\xff" * 6 + mac_bytes * 16


def send_wol(mac: str, interface: str = "", broadcast_ip: str = _BROADCAST) -> dict:
    """
    Send a Wake-on-LAN magic packet.
    Returns ``{"ok": bool, "message": str, "mac": str, "interface": str}``.
    """
    errors = validate_wol(mac, interface)
    if errors:
        return {"ok": False, "message": "; ".join(errors), "mac": mac, "interface": interface}

    try:
        packet = _build_magic_packet(mac)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            # Bind to specific interface if possible (works on FreeBSD + Linux)
            try:
                import sys
                if sys.platform.startswith(("freebsd", "linux")):
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                                    interface.encode() + b"\x00")
            except (AttributeError, OSError):
                pass
            sock.sendto(packet, (broadcast_ip, _WOL_PORT))
        return {
            "ok": True,
            "message": f"Magic packet sent to {mac} on {interface} (broadcast {broadcast_ip}).",
            "mac": mac,
            "interface": interface,
        }
    except Exception as exc:
        return {"ok": False, "message": str(exc), "mac": mac, "interface": interface}
