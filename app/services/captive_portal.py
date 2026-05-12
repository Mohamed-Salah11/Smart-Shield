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
import ssl
import socket
import sys
import threading
import time
from datetime import datetime, timezone, timedelta

from app.services.priv_helper import run_privileged

_CP_ANCHOR_PATH   = "/etc/pf.captive_portal.conf"
_CP_ANCHOR_NAME   = "captive_portal"
_CP_REDIRECT_IP   = "127.0.0.1"
_CP_REDIRECT_PORT = 80    # nginx listens on LAN IP:80 and proxies to Flask
_CP_HTTPS_PORT    = 5443  # HTTPS redirect listener for port-443 interception
_CP_CERT_PATH     = "/etc/smart_shield_block.crt"
_CP_KEY_PATH      = "/etc/smart_shield_block.key"

# Guard so the HTTPS redirect thread is only started once per process
_https_thread_started = threading.Event()
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
    conn, mac: str, ip: str, username: str = "",
    duration_minutes: int = 60, is_superuser: bool = False
) -> dict:
    """
    Create a new authenticated captive portal session.
    Adds the client IP to the PF authenticated table if on FreeBSD.
    Admin (superuser) sessions are also added to admin_bypass_clients to skip content policy.
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
            (mac_address, ip_address, username, is_superuser, expires_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(mac_address) DO UPDATE SET
            ip_address=excluded.ip_address,
            username=excluded.username,
            is_superuser=excluded.is_superuser,
            expires_at=excluded.expires_at,
            logged_out=0,
            created_at=CURRENT_TIMESTAMP
        """,
        (mac, ip, uname, int(is_superuser), expires_at),
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

        # Admin accounts also bypass content policy at PF level
        if is_superuser:
            try:
                run_privileged("pf.table_add", table="admin_bypass_clients", ip=ip)
            except Exception:
                pass

    return {"ok": True, "message": f"Session created for {ip} ({uname or mac})."}


def logout_session(conn, session_id: int) -> dict:
    rows = _rows(conn, "SELECT ip_address, is_superuser FROM captive_sessions WHERE id=?", (session_id,))
    if not rows:
        return {"ok": False, "message": "Session not found."}
    ip = rows[0]["ip_address"]
    was_superuser = bool(rows[0]["is_superuser"])
    conn.execute(
        "UPDATE captive_sessions SET logged_out=1 WHERE id=?", (session_id,)
    )
    conn.commit()

    if sys.platform.startswith("freebsd"):
        try:
            from app.services.priv_helper import run_privileged
            run_privileged("pf.table_delete", table="authenticated_clients", ip=ip)
        except Exception:
            pass
        if was_superuser:
            try:
                run_privileged("pf.table_delete", table="admin_bypass_clients", ip=ip)
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
    """Remove expired sessions from PF tables and mark as logged out. Returns count."""
    now  = _now_ts()
    rows = _rows(
        conn,
        "SELECT id, ip_address, is_superuser FROM captive_sessions WHERE logged_out=0 AND expires_at <= ?",
        (now,),
    )
    if not rows:
        return 0

    for row in rows:
        if sys.platform.startswith("freebsd"):
            try:
                run_privileged("pf.table_delete", table="authenticated_clients", ip=row["ip_address"])
            except Exception:
                pass
            if row.get("is_superuser"):
                try:
                    run_privileged("pf.table_delete", table="admin_bypass_clients", ip=row["ip_address"])
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


def disable_voucher(conn, voucher_id: int, disabled: bool) -> dict:
    row = conn.execute(
        "SELECT id FROM captive_vouchers WHERE id=?", (voucher_id,)
    ).fetchone()
    if not row:
        return {"ok": False, "message": "Voucher not found."}
    conn.execute(
        "UPDATE captive_vouchers SET disabled=? WHERE id=?",
        (1 if disabled else 0, voucher_id),
    )
    conn.commit()
    return {"ok": True, "disabled": disabled}


def redeem_voucher(conn, code: str, mac: str, ip: str) -> dict:
    code = (code or "").strip().upper()
    # First check if the voucher exists at all (redeemed or not, disabled or not)
    all_rows = _rows(conn, "SELECT * FROM captive_vouchers WHERE code=?", (code,))
    if not all_rows:
        return {"ok": False, "message": "Voucher not found or already used."}
    voucher_candidate = all_rows[0]
    if voucher_candidate.get("disabled"):
        return {"ok": False, "message": "Voucher is disabled."}
    rows = _rows(
        conn,
        "SELECT * FROM captive_vouchers WHERE code=? AND redeemed=0 AND disabled=0",
        (code,),
    )
    if not rows:
        return {"ok": False, "message": "Voucher not found or already used."}

    voucher = rows[0]
    # Stage the redemption — do NOT commit yet
    conn.execute(
        "UPDATE captive_vouchers SET redeemed=1, redeemed_at=CURRENT_TIMESTAMP WHERE id=?",
        (voucher["id"],),
    )
    # Attempt session creation; authenticate_session manages its own DB state
    result = authenticate_session(
        conn, mac, ip,
        username=f"voucher:{code}",
        duration_minutes=voucher["duration_minutes"],
    )
    if not result.get("ok"):
        # Undo the redemption mark so the voucher can be retried
        conn.execute(
            "UPDATE captive_vouchers SET redeemed=0, redeemed_at=NULL WHERE id=?",
            (voucher["id"],),
        )
        conn.commit()
        return result
    # Authentication succeeded — commit the redemption mark
    conn.commit()
    return result


# ---------------------------------------------------------------------------
# Self-signed cert + HTTPS redirect server
# ---------------------------------------------------------------------------

def generate_self_signed_cert(cert_path: str, key_path: str, ip: str) -> None:
    """Generate a self-signed TLS certificate for the block-page HTTPS listener."""
    import datetime as _dt
    import ipaddress as _ipmod
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Smart Shield Block Page")])
    san: list = [x509.DNSName("smartshield.local")]
    try:
        san.append(x509.IPAddress(_ipmod.IPv4Address(ip)))
    except Exception:
        pass

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_dt.datetime.utcnow())
        .not_valid_after(_dt.datetime.utcnow() + _dt.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .sign(key, hashes.SHA256())
    )
    with open(cert_path, "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as fh:
        fh.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))


def _handle_https_redirect(raw_conn: socket.socket, ctx: ssl.SSLContext,
                           portal_ip: str, portal_port: int) -> None:
    try:
        with ctx.wrap_socket(raw_conn, server_side=True) as tls:
            data = b""
            try:
                data = tls.recv(4096)
            except Exception:
                pass
            host = ""
            for line in data.decode("utf-8", "replace").splitlines():
                if line.lower().startswith("host:"):
                    host = line.split(":", 1)[1].strip().split(":")[0]
                    break

            portal_url = f"http://{portal_ip}:{portal_port}/portal/block"
            if host:
                portal_url += f"?domain={host}"

            display_host = host or "this site"
            body = (
                "<!DOCTYPE html><html><head>"
                "<meta charset='utf-8'>"
                "<meta name='viewport' content='width=device-width,initial-scale=1'>"
                f"<title>Blocked — Smart Shield</title>"
                "<style>"
                "*{box-sizing:border-box;margin:0;padding:0}"
                "body{background:linear-gradient(135deg,#0f172a,#1e3a5f);min-height:100vh;"
                "display:flex;align-items:center;justify-content:center;"
                "font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;padding:1rem}"
                ".card{background:#fff;border-radius:12px;box-shadow:0 20px 60px rgba(0,0,0,.5);"
                "width:100%;max-width:420px;overflow:hidden;text-align:center}"
                ".hdr{background:#1e3a5f;color:#fff;padding:1.4rem 2rem}"
                ".hdr .ic{font-size:2rem;display:block;margin-bottom:.3rem}"
                ".hdr h1{font-size:1.15rem;font-weight:700;letter-spacing:.02em}"
                ".hdr p{font-size:.78rem;opacity:.7;margin-top:.2rem}"
                ".body{padding:1.5rem 2rem 1.75rem}"
                ".notice{background:#fef2f2;border-left:4px solid #dc2626;"
                "padding:.9rem 1.2rem;border-radius:0 6px 6px 0;text-align:left;margin-bottom:1.25rem}"
                ".notice strong{color:#991b1b;font-size:.88rem}"
                ".notice code{background:#fee2e2;border-radius:3px;padding:1px 5px;"
                "font-size:.85rem;color:#7f1d1d;word-break:break-all}"
                ".notice p{font-size:.8rem;color:#b91c1c;margin-top:.3rem;line-height:1.4}"
                ".btn{display:block;width:100%;padding:.75rem;background:#1e3a5f;color:#fff;"
                "border-radius:6px;font-size:.95rem;font-weight:700;text-decoration:none;"
                "transition:background .2s;margin-bottom:.65rem}"
                ".btn:hover{background:#2d5a8f}"
                ".btn-v{background:#f0fdf4;color:#166534;border:1px solid #bbf7d0}"
                ".btn-v:hover{background:#dcfce7}"
                ".hint{font-size:.72rem;color:#9ca3af;margin-top:.5rem;line-height:1.5}"
                ".ftr{font-size:.72rem;color:#9ca3af;padding:.7rem;border-top:1px solid #f1f5f9}"
                "</style></head><body><div class='card'>"
                "<div class='hdr'><span class='ic'>🛡️</span>"
                "<h1>Smart Shield — Content Police</h1>"
                "<p>Network access control &amp; content filtering</p></div>"
                "<div class='body'>"
                "<div class='notice'>"
                f"<strong>🚫 Site blocked: <code>{display_host}</code></strong>"
                "<p>This domain is restricted by the content policy.<br>"
                "Sign in below to bypass filtering for your device.</p>"
                "</div>"
                f"<a href='{portal_url}' class='btn'>🔐 Proceed to Login</a>"
                f"<a href='{portal_url}' class='btn btn-v'>🎟 Use a Voucher Code</a>"
                "<p class='hint'>Your session will allow access for the duration of your visit.</p>"
                "</div>"
                "<div class='ftr'>Protected by Smart Shield &middot; Content Police Filter</div>"
                "</div></body></html>"
            )
            body_bytes = body.encode("utf-8")
            response = (
                f"HTTP/1.1 200 OK\r\n"
                f"Content-Type: text/html; charset=utf-8\r\n"
                f"Content-Length: {len(body_bytes)}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode() + body_bytes
            try:
                tls.sendall(response)
            except Exception:
                pass
    except Exception:
        pass
    finally:
        try:
            raw_conn.close()
        except Exception:
            pass


def _https_redirect_worker(portal_ip: str, portal_port: int,
                           cert_path: str, key_path: str) -> None:
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", _CP_HTTPS_PORT))
            srv.listen(32)
            while True:
                try:
                    conn, _ = srv.accept()
                    threading.Thread(
                        target=_handle_https_redirect,
                        args=(conn, ctx, portal_ip, portal_port),
                        daemon=True,
                    ).start()
                except Exception:
                    continue
    except Exception:
        pass


def start_https_redirect_server(portal_ip: str, portal_port: int,
                                cert_path: str, key_path: str) -> None:
    """Start the HTTPS→HTTP redirect listener if not already running."""
    if _https_thread_started.is_set():
        return
    _https_thread_started.set()
    t = threading.Thread(
        target=_https_redirect_worker,
        args=(portal_ip, portal_port, cert_path, key_path),
        daemon=True,
        name="https-block-redirect",
    )
    t.start()


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

    portal_ip   = (settings.get("portal_ip") or _default_portal_ip(conn)).strip()
    portal_port = settings.get("portal_port") or _CP_REDIRECT_PORT
    dns_allow   = bool(settings.get("allow_dns", True))
    http_port   = settings.get("http_redirect_port") or 80
    # strict_mode=True blocks ALL unauthenticated traffic (not just HTTP redirects).
    # Authenticated clients still pass freely; the portal itself is always reachable.
    strict_mode = bool(settings.get("strict_mode", False))

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

    # Upstream DNS for authenticated clients — bypasses Unbound's block redirects
    # so after auth, blocked domains resolve to their real IPs.
    upstream_dns = (settings.get("upstream_dns") or "8.8.8.8").strip()

    mode_comment = (
        "# Strict captive portal: ALL unauthenticated traffic is blocked.\n"
        "# Only the portal itself and (optionally) DNS queries are allowed."
        if strict_mode else
        "# Soft captive portal: redirect HTTP only — all other traffic passes normally.\n"
        "# HTTPS interception and block-all are intentionally omitted so that\n"
        "# unauthenticated clients retain full internet access; only port-80 browsing\n"
        "# is redirected to the login page. Content-policy DNS blocking is independent."
    )

    lines = [
        "# ============================================================",
        "# Smart Shield - Captive Portal / Content Filter PF anchor",
        "# Generated by app/services/captive_portal.py",
        "# DO NOT EDIT MANUALLY",
        "# ============================================================",
        "",
        mode_comment,
        "",
        "# Translation rules (unauthenticated HTTP → portal login)",
        f"rdr on {lan_iface} proto tcp from !<authenticated_clients> to any port {http_port} -> {portal_ip} port {portal_port}",
        "",
        "# DNS bypass for authenticated clients — route to upstream resolver instead of",
        "# Unbound so that previously blocked domains return their real IPs after login.",
        f"rdr on {lan_iface} proto udp from <authenticated_clients> to any port 53 -> {upstream_dns} port 53",
        f"rdr on {lan_iface} proto tcp from <authenticated_clients> to any port 53 -> {upstream_dns} port 53",
        "",
        "# Filter rules — authenticated clients pass all traffic",
        f"pass in quick on {lan_iface} from <authenticated_clients> to any keep state",
        "# Portal itself is always reachable (needed for login page)",
        f"pass in quick on {lan_iface} proto tcp from any to {portal_ip} port {portal_port} keep state",
    ]

    if dns_allow:
        lines += [
            f"pass in quick on {lan_iface} proto udp from any to {portal_ip} port 53 keep state",
            f"pass in quick on {lan_iface} proto tcp from any to {portal_ip} port 53 keep state",
        ]

    if strict_mode:
        # In strict mode also allow DHCP (port 67/68) so clients can get an IP address,
        # and DNS to Unbound (needed so browser can resolve the portal hostname).
        lines += [
            "",
            "# DHCP must pass so unauthenticated clients can acquire an IP",
            f"pass in quick on {lan_iface} proto udp from any port 68 to any port 67 keep state",
            "",
            "# Block everything else from unauthenticated clients",
            f"block in quick on {lan_iface} from !<authenticated_clients> to any",
        ]
    else:
        lines += [
            "",
            "# Allow all other traffic — content policy and firewall rules handle blocking.",
            f"pass in on {lan_iface} from !<authenticated_clients> to any keep state",
        ]

    return "\n".join(lines) + "\n"


def apply_captive_portal(conn) -> dict:
    import json
    rows = conn.execute(
        "SELECT value_json FROM service_state WHERE key_name='captive_portal_settings'"
    ).fetchone()
    settings = json.loads(rows["value_json"]) if rows else {}

    # Only apply the block-all PF anchor when captive portal is explicitly enabled.
    # Default is False so DNS-only content filtering never activates the block-all rule.
    if not settings.get("enabled", False):
        if sys.platform.startswith("freebsd"):
            try:
                with open(_CP_ANCHOR_PATH, "w") as fh:
                    fh.write("# captive portal disabled\n")
                from app.services.priv_helper import run_privileged
                run_privileged("pf.anchor_reload",
                               anchor_name=_CP_ANCHOR_NAME,
                               config_path=_CP_ANCHOR_PATH)
            except Exception:
                pass
        return {"ok": True, "message": "Captive portal disabled — PF anchor cleared."}

    conf = generate_pf_anchor(conn)

    portal_ip   = (settings.get("portal_ip") or _default_portal_ip(conn)).strip()
    portal_port = settings.get("portal_port") or _CP_REDIRECT_PORT

    # HTTPS interception is disabled (soft captive portal mode — see generate_pf_anchor).
    # The HTTPS redirect server is no longer started.

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
        "active_sessions_count": len(active),
        "state": "running" if enabled else "stopped",
    }
