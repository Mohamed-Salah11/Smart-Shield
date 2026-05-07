"""
captive_portal.py
-----------------
Captive portal enforcement using PF tables.

Architecture
------------
Enforcement model: PF tables (pf.conf anchor "captive_portal")
  - Unauthenticated hosts → blocked except DNS + HTTP redirect to portal
  - Authenticated hosts → added to pf table "authenticated_clients"
  - Portal redirect:  rdr rule sends HTTP to local portal web server

Authentication: local users first; RADIUS is out of scope for Phase 4.
Session management: SQLite `captive_sessions` table with expiry.
Vouchers: pre-generated codes with duration and bandwidth limits.

Public API
----------
authenticate_session(conn, mac, ip, username, duration_minutes) -> dict
logout_session(conn, session_id)                                 -> dict
get_active_sessions(conn)                                        -> list
expire_sessions(conn)                                            -> int
generate_voucher(conn, duration_minutes, bandwidth_kbps)        -> dict
redeem_voucher(conn, code, mac, ip)                             -> dict
get_captive_status(conn)                                         -> dict
generate_pf_anchor(conn)                                         -> str
apply_captive_portal(conn)                                       -> dict
"""

import os
import secrets
import sys
import time
from datetime import datetime, timezone, timedelta

from app.services.priv_helper import run_privileged

_CP_ANCHOR_PATH   = "/etc/pf.captive_portal.conf"
_CP_ANCHOR_NAME   = "captive_portal"
_CP_REDIRECT_IP   = "127.0.0.1"
_CP_REDIRECT_PORT = 5000  # matches gunicorn bind port in rc.d/smart_shield
def _default_portal_ip(conn) -> str:
    try:
        import ipaddress
        row = conn.execute("SELECT ipv4_address FROM lan_config WHERE id=1").fetchone()
        if row and row["ipv4_address"]:
            return str(ipaddress.ip_interface(row["ipv4_address"]).ip)
    except Exception:
        pass
    return _CP_REDIRECT_IP


def _rows(conn, sql, params=()):
    cur = conn.cursor()
    cur.execute(sql, params)
    return [dict(r) for r in cur.fetchall()]


def _now_ts() -> int:
    return int(time.time())


# ---------------------------------------------------------------------------
# Session management
# ---------------------------------------------------------------------------

def authenticate_session(
    conn, mac: str, ip: str, username: str = "", duration_minutes: int = 60
) -> dict:
    """
    Create a new authenticated captive portal session.
    Adds the client IP to the PF authenticated table if on FreeBSD.
    """
    mac   = (mac or "").strip().lower()
    ip    = (ip or "").strip()
    uname = (username or "").strip()

    if not ip:
        return {"ok": False, "message": "IP address is required."}
    # MAC is optional — use the IP as a fallback key so dev mode works without ARP
    if not mac:
        mac = f"ip:{ip}"

    expires_at = _now_ts() + duration_minutes * 60
    conn.execute(
        """
        INSERT INTO captive_sessions
            (mac_address, ip_address, username, expires_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(mac_address) DO UPDATE SET
            ip_address=excluded.ip_address,
            username=excluded.username,
            expires_at=excluded.expires_at,
            logged_out=0,
            created_at=CURRENT_TIMESTAMP
        """,
        (mac, ip, uname, expires_at),
    )
    conn.commit()

    # Add to PF table on FreeBSD
    if sys.platform.startswith("freebsd"):
        try:
            result = run_privileged("pf.table_add", table="authenticated_clients", ip=ip)
            if result.returncode != 0:
                message = (result.stderr or result.stdout or "pf.table_add failed").strip()
                conn.execute(
                    "UPDATE captive_sessions SET logged_out=1 WHERE mac_address=?",
                    (mac,),
                )
                conn.commit()
                return {"ok": False, "message": message}
        except Exception as exc:
            conn.execute(
                "UPDATE captive_sessions SET logged_out=1 WHERE mac_address=?",
                (mac,),
            )
            conn.commit()
            return {"ok": False, "message": str(exc)}

    return {"ok": True, "message": f"Session created for {ip} ({uname or mac})."}


def logout_session(conn, session_id: int) -> dict:
    rows = _rows(conn, "SELECT ip_address FROM captive_sessions WHERE id=?", (session_id,))
    if not rows:
        return {"ok": False, "message": "Session not found."}
    ip = rows[0]["ip_address"]
    conn.execute(
        "UPDATE captive_sessions SET logged_out=1 WHERE id=?", (session_id,)
    )
    conn.commit()

    if sys.platform.startswith("freebsd"):
        try:
            from app.services.network_service import run_command
            from app.services.priv_helper import run_privileged
            run_privileged("pf.table_delete", table="authenticated_clients", ip=ip)
        except Exception:
            pass

    return {"ok": True, "message": f"Session {session_id} logged out."}


def get_active_sessions(conn) -> list:
    now = _now_ts()
    return _rows(
        conn,
        """
        SELECT id, mac_address, ip_address, username, created_at, expires_at
        FROM captive_sessions
        WHERE logged_out=0 AND expires_at > ?
        ORDER BY created_at DESC
        """,
        (now,),
    )


def expire_sessions(conn) -> int:
    """Remove expired sessions from PF table and mark as logged out. Returns count."""
    now  = _now_ts()
    rows = _rows(
        conn,
        "SELECT id, ip_address FROM captive_sessions WHERE logged_out=0 AND expires_at <= ?",
        (now,),
    )
    if not rows:
        return 0

    for row in rows:
        if sys.platform.startswith("freebsd"):
            try:
                from app.services.network_service import run_command
                from app.services.priv_helper import run_privileged
                run_privileged("pf.table_delete", table="authenticated_clients", ip=row["ip_address"])
            except Exception:
                pass

    ids = [r["id"] for r in rows]
    placeholders = ",".join("?" * len(ids))
    conn.execute(
        f"UPDATE captive_sessions SET logged_out=1 WHERE id IN ({placeholders})", ids
    )
    conn.commit()
    return len(rows)


# ---------------------------------------------------------------------------
# Vouchers
# ---------------------------------------------------------------------------

def generate_voucher(
    conn, duration_minutes: int = 60, bandwidth_kbps: int = 0
) -> dict:
    code = secrets.token_urlsafe(8).upper()[:8]
    conn.execute(
        """
        INSERT INTO captive_vouchers (code, duration_minutes, bandwidth_kbps)
        VALUES (?, ?, ?)
        """,
        (code, duration_minutes, bandwidth_kbps),
    )
    conn.commit()
    return {
        "ok": True,
        "code": code,
        "duration_minutes": duration_minutes,
        "bandwidth_kbps": bandwidth_kbps,
    }


def redeem_voucher(conn, code: str, mac: str, ip: str) -> dict:
    code = (code or "").strip().upper()
    rows = _rows(
        conn,
        "SELECT * FROM captive_vouchers WHERE code=? AND redeemed=0",
        (code,),
    )
    if not rows:
        return {"ok": False, "message": "Voucher not found or already used."}

    voucher = rows[0]
    conn.execute(
        "UPDATE captive_vouchers SET redeemed=1, redeemed_at=CURRENT_TIMESTAMP WHERE id=?",
        (voucher["id"],),
    )
    conn.commit()

    return authenticate_session(
        conn, mac, ip,
        username=f"voucher:{code}",
        duration_minutes=voucher["duration_minutes"],
    )


# ---------------------------------------------------------------------------
# PF anchor generation
# ---------------------------------------------------------------------------

def generate_pf_anchor(conn) -> str:
    """
    Generate the PF anchor rules for the captive portal.
    This anchor is loaded by the main pf.conf.
    """
    rows = conn.execute(
        "SELECT value_json FROM service_state WHERE key_name='captive_portal_settings'"
    ).fetchone()
    import json
    settings = json.loads(rows["value_json"]) if rows else {}

    portal_ip = (settings.get("portal_ip") or _default_portal_ip(conn)).strip()
    portal_port = settings.get("portal_port") or _CP_REDIRECT_PORT
    dns_allow   = bool(settings.get("allow_dns", True))
    http_port   = settings.get("http_redirect_port") or 80

    # Prefer the interface stored in captive portal settings; fall back to
    # the LAN assigned_port from the interface config table.
    lan_iface = (settings.get("lan_interface") or "").strip()
    if not lan_iface:
        try:
            row = conn.execute(
                "SELECT assigned_port FROM lan_config WHERE id=1"
            ).fetchone()
            lan_iface = (row["assigned_port"] if row else "") or "em1"
        except Exception:
            lan_iface = "em1"

    lines = [
    "# ============================================================",
    "# Smart Shield - Captive Portal / Content Filter PF anchor",
    "# Generated by app/services/captive_portal.py",
    "# DO NOT EDIT MANUALLY",
    "# ============================================================",
    "",
    "# Translation rules first",
    f"rdr on {lan_iface} proto tcp from !<authenticated_clients> to any port {http_port} -> {portal_ip} port {portal_port}",
    "",
    "# Filter rules",
    f"pass in quick on {lan_iface} from <authenticated_clients> to any keep state",
    f"pass in quick on {lan_iface} proto tcp from any to {portal_ip} port {portal_port} keep state",
   ]

    if dns_allow:
     lines += [
        f"pass in quick on {lan_iface} proto udp from any to {portal_ip} port 53 keep state",
        f"pass in quick on {lan_iface} proto tcp from any to {portal_ip} port 53 keep state",
    ]

    lines += [
    "",
    "# Block everything else from unauthenticated clients before the generic LAN pass rule",
    f"block in quick on {lan_iface} from !<authenticated_clients> to any",
    ]
    return "\n".join(lines) + "\n"


def apply_captive_portal(conn) -> dict:
    conf = generate_pf_anchor(conn)

    import json
    rows = conn.execute(
        "SELECT value_json FROM service_state WHERE key_name='captive_portal_settings'"
    ).fetchone()
    settings = json.loads(rows["value_json"]) if rows else {}

    if not sys.platform.startswith("freebsd"):
        return {"ok": True, "message": "Non-FreeBSD — captive portal anchor generated but not applied.",
                "conf": conf}

    try:
        with open(_CP_ANCHOR_PATH, "w") as fh:
            fh.write(conf)
        from app.services.priv_helper import run_privileged

        run_privileged(
    "pf.anchor_reload",
    anchor_name=_CP_ANCHOR_NAME,
    config_path=_CP_ANCHOR_PATH,
)

# Ensure PF table exists and is readable.
        run_privileged("pf.table_show", table="authenticated_clients")
    except Exception as exc:
        return {"ok": False, "message": str(exc), "conf": conf}

    from app.audit_log import log_event
    log_event(
        category="system", action="captive_portal_apply",
        username="system", remote_addr="",
        details={"ok": True},
    )
    return {"ok": True, "message": "Captive portal anchor applied.", "conf": conf}


def authenticate_radius(conn, username: str, password: str) -> dict:
    """
    Authenticate a user against the RADIUS server configured in
    captive_portal_config (columns radius_server / radius_secret).

    Uses a raw RADIUS Access-Request over UDP — no third-party library needed.
    Returns {"ok": bool, "message": str}.
    """
    import hashlib
    import hmac
    import ipaddress
    import socket
    import struct

    username = (username or "").strip()
    password = (password or "").strip()
    if not username or not password:
        return {"ok": False, "message": "Username and password are required."}

    # Load config
    try:
        row = conn.execute(
            "SELECT radius_server, radius_secret FROM captive_portal_config WHERE id=1"
        ).fetchone()
    except Exception:
        row = None

    if not row:
        # Fall back to service_state blob
        import json as _json
        srow = conn.execute(
            "SELECT value_json FROM service_state WHERE key_name='captive_portal_settings'"
        ).fetchone()
        settings = _json.loads(srow["value_json"]) if srow else {}
        radius_server = settings.get("radius_server", "")
        radius_secret = settings.get("radius_secret", "")
    else:
        radius_server = (row["radius_server"] or "").strip()
        radius_secret = (row["radius_secret"] or "").strip()

    if not radius_server or not radius_secret:
        return {"ok": False, "message": "RADIUS server not configured."}

    # Parse host:port
    if ":" in radius_server:
        host, port_str = radius_server.rsplit(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            port = 1812
    else:
        host, port = radius_server, 1812

    secret = radius_secret.encode()

    # Build RADIUS Access-Request packet (RFC 2865)
    CODE_ACCESS_REQUEST  = 1
    CODE_ACCESS_ACCEPT   = 2
    CODE_ACCESS_REJECT   = 3
    ATTR_USER_NAME       = 1
    ATTR_USER_PASSWORD   = 2
    ATTR_NAS_IP_ADDRESS  = 4

    identifier    = secrets.randbelow(256)
    authenticator = secrets.token_bytes(16)

    # Encode User-Password: XOR with MD5(secret + authenticator)
    def _encode_password(pw: str, auth: bytes, sec: bytes) -> bytes:
        pw_bytes = pw.encode("utf-8")
        # Pad to multiple of 16
        pad_len  = (16 - (len(pw_bytes) % 16)) % 16
        pw_bytes = pw_bytes + b"\x00" * pad_len
        result   = b""
        prev     = auth
        for i in range(0, len(pw_bytes), 16):
            digest = hashlib.md5(sec + prev).digest()
            chunk  = bytes(a ^ b for a, b in zip(pw_bytes[i:i+16], digest))
            result += chunk
            prev    = chunk
        return result

    enc_pw = _encode_password(password, authenticator, secret)

    def _attr(atype: int, value: bytes) -> bytes:
        return bytes([atype, len(value) + 2]) + value

    attrs = (
        _attr(ATTR_USER_NAME, username.encode("utf-8"))
        + _attr(ATTR_USER_PASSWORD, enc_pw)
    )
    try:
        nas_ip = socket.gethostbyname(socket.gethostname())
        attrs += _attr(ATTR_NAS_IP_ADDRESS, socket.inet_aton(nas_ip))
    except Exception:
        pass

    length  = 20 + len(attrs)
    packet  = struct.pack("!BBH16s", CODE_ACCESS_REQUEST, identifier, length, authenticator)
    packet += attrs

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        sock.sendto(packet, (host, port))
        response, _ = sock.recvfrom(4096)
        sock.close()
    except socket.timeout:
        return {"ok": False, "message": "RADIUS server timed out."}
    except OSError as exc:
        return {"ok": False, "message": f"RADIUS socket error: {exc}"}

    if len(response) < 20:
        return {"ok": False, "message": "Malformed RADIUS response."}

    resp_code = response[0]
    if resp_code == CODE_ACCESS_ACCEPT:
        return {"ok": True, "message": "RADIUS authentication succeeded."}
    if resp_code == CODE_ACCESS_REJECT:
        return {"ok": False, "message": "RADIUS authentication rejected."}
    return {"ok": False, "message": f"Unexpected RADIUS response code {resp_code}."}


def get_captive_status(conn) -> dict:
    active = get_active_sessions(conn)
    expire_sessions(conn)
    import json
    rows = conn.execute(
        "SELECT value_json FROM service_state WHERE key_name='captive_portal_settings'"
    ).fetchone()
    settings = json.loads(rows["value_json"]) if rows else {}
    enabled = bool(settings.get("enabled", False))
    return {
        "enabled": enabled,
        "active_sessions": len(active),
        "state": "running" if enabled else "stopped",
    }
