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
generate_pf_anchor(conn)                                         -> dict  ({"rdr": str, "filter": str})
generate_pf_anchor_preview(conn)                                 -> str   (human-readable concat for UI)
apply_captive_portal(conn)                                       -> dict
"""

import logging
import os
import secrets
import ssl
import socket
import sys
import threading
import time
from datetime import datetime, timezone, timedelta

from app.services.bypass_policy import bypass_tables_for
from app.services.priv_helper import run_privileged

_log = logging.getLogger(__name__)

_CP_RDR_NAME      = "captive_portal_rdr"
_CP_FILTER_NAME   = "captive_portal_filter"
_CP_RDR_PATH      = "/etc/pf.captive_portal.rdr.conf"
_CP_FILTER_PATH   = "/etc/pf.captive_portal.filter.conf"
_CP_REDIRECT_IP   = "127.0.0.1"
_CP_REDIRECT_PORT = 80    # nginx listens on LAN IP:80 and proxies to Flask
_CP_HTTPS_PORT    = 5443  # HTTPS redirect listener for port-443 interception
_CP_CERT_PATH     = "/etc/smart_shield_block.crt"
_CP_KEY_PATH      = "/etc/smart_shield_block.key"

# Files used by reconcile_captive_pf_tables() to atomically replace PF tables.
from app.config import _ss_dir as _ss_dir_cp
_CP_AUTH_TABLE_FILE  = os.path.join(_ss_dir_cp("/var/db"), "captive_authenticated_ips.txt")
_CP_ADMIN_TABLE_FILE = os.path.join(_ss_dir_cp("/var/db"), "captive_admin_bypass_ips.txt")

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
# Rate limiting (captive_auth_attempts)
# ---------------------------------------------------------------------------

def record_captive_auth_attempt(
    conn, ip: str, username: str = "", auth_type: str = "", success: bool = False
) -> None:
    """Record one captive-portal authentication attempt for rate limiting."""
    try:
        conn.execute(
            "INSERT INTO captive_auth_attempts "
            "(ip_address, username, auth_type, success, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            ((ip or "").strip(), (username or "").strip(),
             (auth_type or "").strip(), 1 if success else 0, _now_ts()),
        )
        conn.commit()
    except Exception:
        # Never let logging break the auth flow.
        pass


def too_many_recent_attempts(
    conn, ip: str, window_seconds: int = 300, max_attempts: int = 10,
    auth_type: str = "",
) -> bool:
    """
    Return True if the given IP has made `max_attempts` failed attempts in the
    last `window_seconds`. Successful attempts do not count toward the cap.
    `auth_type` optionally restricts the check to a single type (e.g. voucher).
    """
    ip = (ip or "").strip()
    if not ip:
        return False
    cutoff = _now_ts() - max(1, int(window_seconds))
    try:
        if auth_type:
            row = conn.execute(
                "SELECT COUNT(*) AS c FROM captive_auth_attempts "
                "WHERE ip_address=? AND success=0 AND auth_type=? AND created_at >= ?",
                (ip, auth_type, cutoff),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT COUNT(*) AS c FROM captive_auth_attempts "
                "WHERE ip_address=? AND success=0 AND created_at >= ?",
                (ip, cutoff),
            ).fetchone()
        return bool(row and row["c"] >= max_attempts)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Session management
# ---------------------------------------------------------------------------

def _grant_captive_policy_exemption(conn, ip, username="", duration_minutes=0):
    """captive_auth_required mode: exempt a freshly-authenticated client from
    DNS content policy.

    Flags ``tracked_hosts.is_policy_exempt`` (marked ``exempt_source=
    'captive_session'`` so it can be revoked on logout without clobbering
    admin/manual exemptions) and regenerates Unbound so the client's /32 enters
    ``policy_exemption_view`` and resolves blocked domains upstream again. This
    is what makes the "sign in to access the site" promise real and stops the
    post-login bridge.html loop. Best-effort — failures are logged, never raised
    into the auth path. On non-FreeBSD ``apply_unbound`` is a validate-only
    dry-run.
    """
    ip = (ip or "").strip()
    if not ip:
        return
    try:
        cur = conn.execute(
            "UPDATE tracked_hosts SET is_policy_exempt=1, exempt_source='captive_session' "
            "WHERE ip_address=?",
            (ip,),
        )
        if cur.rowcount == 0:
            conn.execute(
                "INSERT INTO tracked_hosts "
                "(interface_type, ip_address, discovered_via, is_policy_exempt, exempt_source) "
                "VALUES ('UNKNOWN', ?, 'captive_session', 1, 'captive_session')",
                (ip,),
            )
        conn.commit()
    except Exception as exc:
        _log.warning("captive_portal: failed to set policy exemption for %s: %s", ip, exc)
        return

    try:
        from app.services.dns_writer import apply_unbound
        res = apply_unbound(conn)
        if not res.get("ok"):
            _log.warning("captive_portal: apply_unbound after exempting %s failed: %s",
                         ip, res.get("message"))
    except Exception as exc:
        _log.warning("captive_portal: apply_unbound raised exempting %s: %s", ip, exc)

    try:
        from app.audit_log import log_event
        log_event(
            category="admin_audit", action="content_policy_session_bypass",
            username=username or "", remote_addr=ip,
            details={"ip": ip, "username": username,
                     "duration_minutes": duration_minutes,
                     "mode": "captive_auth_required",
                     "exempt_source": "captive_session", "enabled": True},
            severity="high",
        )
    except Exception:
        pass


def _clear_captive_policy_exemption(conn, ip, reason="session_end"):
    """Revoke a captive-session DNS exemption granted by
    :func:`_grant_captive_policy_exemption`.

    Only clears rows marked ``exempt_source='captive_session'`` so an admin or
    manual exemption on the same IP is left untouched. Regenerates Unbound and
    audits only when something actually changed. Best-effort, like the existing
    PF-table reconcile path.
    """
    ip = (ip or "").strip()
    if not ip:
        return
    try:
        cur = conn.execute(
            "UPDATE tracked_hosts SET is_policy_exempt=0, exempt_source='' "
            "WHERE ip_address=? AND exempt_source='captive_session'",
            (ip,),
        )
        changed = cur.rowcount
        conn.commit()
    except Exception as exc:
        _log.warning("captive_portal: failed to clear policy exemption for %s: %s", ip, exc)
        return
    if not changed:
        return

    try:
        from app.services.dns_writer import apply_unbound
        res = apply_unbound(conn)
        if not res.get("ok"):
            _log.warning("captive_portal: apply_unbound after clearing exemption for %s failed: %s",
                         ip, res.get("message"))
    except Exception as exc:
        _log.warning("captive_portal: apply_unbound raised clearing %s: %s", ip, exc)

    try:
        from app.audit_log import log_event
        log_event(
            category="admin_audit", action="content_policy_session_bypass",
            username="", remote_addr=ip,
            details={"ip": ip, "enabled": False, "reason": reason,
                     "exempt_source": "captive_session"},
            severity="medium",
        )
    except Exception:
        pass


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
    # `created_at` is intentionally NOT updated on ON CONFLICT so that
    # `get_active_sessions()` ordering and audit logs preserve the first-auth
    # timestamp even when the same device re-authenticates.
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
            logged_out=0
        """,
        (mac, ip, uname, int(is_superuser), expires_at),
    )
    conn.commit()

    # P.2: in captive_auth_required mode a successful login must actually lift
    # the DNS content block for this client (otherwise the blocked domain keeps
    # resolving to the LAN IP and the user dead-ends in bridge.html). Other
    # modes intentionally keep the block, so this is gated on the mode.
    try:
        from app.services.content_policy import get_content_policy_mode
        _grant_dns_exempt = get_content_policy_mode(conn) == "captive_auth_required"
    except Exception:
        _grant_dns_exempt = False

    # Add to PF table on FreeBSD
    if sys.platform.startswith("freebsd"):
        # On PF failure, DELETE the session row rather than mark logged_out=1.
        # Marking logged_out leaves an orphan that pollutes audit views and
        # confuses the voucher rollback path in redeem_voucher().
        try:
            result = run_privileged("pf.table_add", table="authenticated_clients", ip=ip)
            if result.returncode != 0:
                message = (result.stderr or result.stdout or "pf.table_add failed").strip()
                conn.execute("DELETE FROM captive_sessions WHERE mac_address=?", (mac,))
                conn.commit()
                return {"ok": False, "message": message}
        except Exception as exc:
            conn.execute("DELETE FROM captive_sessions WHERE mac_address=?", (mac,))
            conn.commit()
            return {"ok": False, "message": str(exc)}

        # Admin accounts also bypass content policy at PF level. If this fails,
        # the session itself is still valid — surface a partial-success flag so
        # the caller/UI can warn that content-policy will still apply.
        if is_superuser:
            try:
                bypass = run_privileged("pf.table_add", table="admin_bypass_clients", ip=ip)
                bypass_ok = getattr(bypass, "returncode", 0) == 0
                bypass_msg = (getattr(bypass, "stderr", "") or getattr(bypass, "stdout", "") or "").strip()
            except Exception as exc:
                bypass_ok, bypass_msg = False, str(exc)
            # admin_bypass_toggle: a superuser session grants full bypass —
            # captive portal AND content policy. Compliance needs to see this.
            try:
                from app.audit_log import log_event
                log_event(
                    category="admin_audit", action="admin_bypass_toggle",
                    username=uname or "", remote_addr=ip,
                    details={"ip": ip, "enabled": bypass_ok,
                             "reason": "superuser_portal_login",
                             "bypass_scope": "captive_portal+content_policy"},
                    severity="high",
                )
            except Exception:
                pass
            if not bypass_ok:
                try:
                    import logging
                    logging.getLogger(__name__).warning(
                        "admin_bypass_clients pf.table_add failed for %s: %s", ip, bypass_msg,
                    )
                except Exception:
                    pass
                if _grant_dns_exempt:
                    _grant_captive_policy_exemption(conn, ip, uname, duration_minutes)
                return {
                    "ok": True,
                    "partial": True,
                    "message": (
                        f"Session active for {ip} ({uname or mac}), but admin "
                        f"bypass could not be applied — content policy will still apply."
                    ),
                }

    if _grant_dns_exempt:
        _grant_captive_policy_exemption(conn, ip, uname, duration_minutes)
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
        except Exception as exc:
            _log.warning("captive_portal: failed to remove %s from authenticated_clients: %s", ip, exc)
        if was_superuser:
            try:
                run_privileged("pf.table_delete", table="admin_bypass_clients", ip=ip)
            except Exception as exc:
                _log.warning("captive_portal: failed to remove %s from admin_bypass_clients: %s", ip, exc)
            try:
                from app.audit_log import log_event
                log_event(
                    category="admin_audit", action="admin_bypass_toggle",
                    username=session_id and "" or "", remote_addr=ip,
                    details={"ip": ip, "enabled": False,
                             "reason": "session_logout",
                             "session_id": session_id},
                    severity="medium",
                )
            except Exception:
                pass

    # P.2: revoke any captive-session DNS exemption granted at login so the
    # content block re-applies to this client. Only clears captive-session
    # exemptions (not admin/manual). Best-effort; also regenerates Unbound.
    _clear_captive_policy_exemption(conn, ip, reason="session_logout")

    # Re-apply DNS filter so this client is redirected by content policy again
    try:
        from app.services.dns_filter import apply_dns_filter
        apply_dns_filter(conn)
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
            except Exception as exc:
                _log.warning("captive_portal: failed to expire %s from authenticated_clients: %s",
                             row["ip_address"], exc)
            if row.get("is_superuser"):
                try:
                    run_privileged("pf.table_delete", table="admin_bypass_clients", ip=row["ip_address"])
                except Exception as exc:
                    _log.warning("captive_portal: failed to expire %s from admin_bypass_clients: %s",
                                 row["ip_address"], exc)
                try:
                    from app.audit_log import log_event
                    log_event(
                        category="admin_audit", action="admin_bypass_toggle",
                        username="", remote_addr=row["ip_address"],
                        details={"ip": row["ip_address"], "enabled": False,
                                 "reason": "session_expired",
                                 "session_id": row["id"]},
                        severity="medium",
                    )
                except Exception:
                    pass

        # P.2: revoke captive-session DNS exemptions on expiry (all platforms;
        # apply_unbound is a no-op dry-run off FreeBSD and only regenerates when
        # a row actually changed).
        _clear_captive_policy_exemption(conn, row["ip_address"], reason="session_expired")

    ids = [r["id"] for r in rows]
    placeholders = ",".join("?" * len(ids))
    conn.execute(
        f"UPDATE captive_sessions SET logged_out=1 WHERE id IN ({placeholders})", ids
    )
    conn.commit()

    # Re-apply DNS filter so expired clients are subject to content policy again
    try:
        from app.services.dns_filter import apply_dns_filter
        apply_dns_filter(conn)
    except Exception:
        pass

    return len(rows)


def reconcile_captive_pf_tables(conn) -> dict:
    """
    Rebuild the captive PF tables from the captive_sessions DB so that the
    runtime state can never silently drift after a crash, manual pfctl edit,
    or process restart. Safe to call repeatedly.
    """
    # First drop expired sessions so we never re-add stale IPs.
    try:
        expire_sessions(conn)
    except Exception as exc:
        _log.warning("captive_portal: expire_sessions failed during reconcile: %s", exc)

    if not sys.platform.startswith("freebsd"):
        return {"ok": True, "skipped": "not freebsd"}

    active = _rows(
        conn,
        "SELECT ip_address, is_superuser FROM captive_sessions "
        "WHERE logged_out=0 AND expires_at > ?",
        (_now_ts(),),
    )
    auth_ips  = sorted({r["ip_address"] for r in active if r.get("ip_address")})
    admin_ips = sorted({r["ip_address"] for r in active
                        if r.get("ip_address") and r.get("is_superuser")})

    def _replace(table: str, file_path: str, ips: list) -> tuple:
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, "w") as fh:
                for ip in ips:
                    fh.write(ip + "\n")
            r = run_privileged("pf.table_replace_file", table=table, file_path=file_path)
            if getattr(r, "returncode", 0) != 0:
                return False, (getattr(r, "stderr", "") or getattr(r, "stdout", "") or "").strip()
            return True, ""
        except Exception as exc:
            return False, str(exc)

    auth_ok,  auth_msg  = _replace("authenticated_clients", _CP_AUTH_TABLE_FILE,  auth_ips)
    admin_ok, admin_msg = _replace("admin_bypass_clients",  _CP_ADMIN_TABLE_FILE, admin_ips)

    if not (auth_ok and admin_ok):
        return {"ok": False,
                "message": f"reconcile failed: auth={auth_msg or 'ok'} admin={admin_msg or 'ok'}",
                "auth": len(auth_ips), "admin": len(admin_ips)}
    return {"ok": True, "auth": len(auth_ips), "admin": len(admin_ips)}


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
        .not_valid_before(_dt.datetime.now(_dt.timezone.utc))
        .not_valid_after(_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=3650))
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
    """Handle a TLS connection that PF redirected here from port 443.

    We do NOT attempt to render a per-domain "pretty" block page — browsers
    will reject the self-signed cert for any real hostname, so promising a
    nice landing page is impossible without TLS interception. Instead we send
    a minimal HTTP 302 to the portal HTTPS landing and let the client decide
    whether to trust the cert there.
    """
    try:
        with ctx.wrap_socket(raw_conn, server_side=True) as tls:
            try:
                tls.recv(4096)   # drain the request line; we ignore Host/path
            except Exception:
                pass
            portal_url = f"https://{portal_ip}/portal/"
            body = (
                "<!DOCTYPE html><html><body>"
                f"Redirecting to <a href=\"{portal_url}\">{portal_url}</a>"
                "</body></html>"
            ).encode("utf-8")
            response = (
                "HTTP/1.1 302 Found\r\n"
                f"Location: {portal_url}\r\n"
                "Content-Type: text/html; charset=utf-8\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Connection: close\r\n\r\n"
            ).encode() + body
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


def ensure_https_redirect_cert(portal_ip: str) -> dict:
    """Generate the self-signed cert/key if they are missing.

    Returns {"ok": True} when the cert is present after the call, otherwise
    {"ok": False, "message": ...}.
    """
    if os.path.exists(_CP_CERT_PATH) and os.path.exists(_CP_KEY_PATH):
        return {"ok": True}
    try:
        cert_dir = os.path.dirname(_CP_CERT_PATH)
        if cert_dir:
            os.makedirs(cert_dir, exist_ok=True)
        generate_self_signed_cert(_CP_CERT_PATH, _CP_KEY_PATH, portal_ip)
        try:
            os.chmod(_CP_KEY_PATH, 0o600)
            os.chmod(_CP_CERT_PATH, 0o644)
        except Exception:
            pass
        return {"ok": True}
    except Exception as exc:
        return {"ok": False, "message": str(exc)}


# ---------------------------------------------------------------------------
# PF anchor generation
# ---------------------------------------------------------------------------

def generate_pf_anchor(conn) -> dict:
    """
    Generate the PF anchor rules for the captive portal.

    Returns a dict with two keys:
      - "rdr":    translation rules (rdr only) for the captive_portal_rdr anchor
      - "filter": filter rules (pass/block only) for the captive_portal_filter anchor

    PF requires translation rules to be loaded into a separate anchor from
    filter rules; emitting them mixed into a single anchor body causes pfctl
    to reject the ruleset with "syntax error" on the first rdr after a pass.
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
    # Strict mode is the appliance default. Authenticated clients still pass
    # freely; the portal itself is always reachable.
    strict_mode = bool(settings.get("strict_mode", True))
    # Opt-in: only when explicitly enabled do admin_bypass_clients reach upstream
    # DNS directly. Default is False so content policy keeps applying after login.
    dns_bypass_admin = bool(settings.get("dns_bypass_for_admin", False))

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

    # Upstream DNS only used when dns_bypass_for_admin is explicitly enabled.
    upstream_dns = (settings.get("upstream_dns") or "8.8.8.8").strip()

    mode_comment = (
        "# Strict captive portal: ALL unauthenticated traffic is blocked.\n"
        "# Only the portal itself and (optionally) DNS queries are allowed."
        if strict_mode else
        "# Soft captive portal: redirect HTTP only — all other traffic passes normally.\n"
        "# Soft mode is for testing/splash-page deployments only and does not\n"
        "# provide real network access control."
    )

    header = [
        "# ============================================================",
        "# Smart Shield - Captive Portal / Content Filter PF anchor",
        "# Generated by app/services/captive_portal.py",
        "# DO NOT EDIT MANUALLY",
        "# ============================================================",
        "",
        mode_comment,
        "",
    ]

    # ── Translation rules (rdr only) ───────────────────────────────────────
    # PF evaluates rdr top-down and the first match wins, so every `no rdr`
    # exemption must be emitted BEFORE the catch-all `rdr` it exempts. The
    # bypass-table list per layer lives in app/services/bypass_policy.py so
    # every filter generator agrees on who skips which enforcement layer.
    rdr_lines = list(header) + [
        "# Force ALL LAN DNS through Unbound so content policy keeps applying.",
        "# Authenticated and whitelisted clients are NOT exempt by default —",
        "# they still resolve through Unbound so DNS/content-policy stays in",
        "# effect. Only admin_bypass_clients may opt out via dns_bypass_for_admin.",
    ]

    if dns_bypass_admin:
        rdr_lines += [
            "",
            "# Opt-in: admin_bypass_clients skip the DNS redirect entirely and",
            "# reach the configured upstream resolver directly. Emitted FIRST so",
            "# the catch-all DNS rdr below cannot short-circuit them.",
        ]
        for table in bypass_tables_for("captive_portal_dns"):
            rdr_lines.append(
                f"no rdr on {lan_iface} proto udp from <{table}> to any port 53"
            )
            rdr_lines.append(
                f"no rdr on {lan_iface} proto tcp from <{table}> to any port 53"
            )

    rdr_lines += [
        "",
        f"rdr on {lan_iface} proto udp from any to !{portal_ip} port 53 -> {portal_ip} port 53",
        f"rdr on {lan_iface} proto tcp from any to !{portal_ip} port 53 -> {portal_ip} port 53",
        "",
        "# Defense-in-depth: bypass clients also skip the HTTP redirect at the",
        "# rdr layer, so a misordered filter anchor cannot accidentally portal",
        "# them. The filter anchor's pass-in-quick rules remain the primary",
        "# enforcement; this is belt-and-braces.",
    ]
    for table in bypass_tables_for("captive_portal_http"):
        rdr_lines.append(
            f"no rdr on {lan_iface} proto tcp from <{table}> to any port {http_port}"
        )
    rdr_lines += [
        "",
        "# Redirect unauthenticated HTTP (port 80) to the portal login page.",
        f"rdr on {lan_iface} proto tcp from any to any port {http_port} -> {portal_ip} port {portal_port}",
    ]

    if not strict_mode:
        rdr_lines += [
            "",
            "# Soft mode: HTTPS may optionally be redirected to the portal HTTPS landing",
            "# (best-effort — browsers will still flag the self-signed cert).",
            f"rdr on {lan_iface} proto tcp from any to any port 443 -> {portal_ip} port {_CP_HTTPS_PORT}",
        ]

    # ── Filter rules (pass / block only) ───────────────────────────────────
    # PF labels (smartshield:captive_portal:*) tag every rule so the firewall
    # log collector can attribute the pflog event to captive-portal enforcement
    # rather than mislabelling it as user_rule / default_deny. Block rules carry
    # the 'log' keyword so they actually surface in pflog0.
    filter_lines = list(header) + [
        "# Pass authenticated / whitelisted / admin-bypass clients FIRST so the",
        "# block rule at the end never matches them. Order matters: 'quick' makes",
        "# each rule terminal on match.",
        f"pass in quick on {lan_iface} from <authenticated_clients> to any "
        f'label "smartshield:captive_portal:allow_auth" keep state',
        f"pass in quick on {lan_iface} from <device_whitelist>      to any "
        f'label "smartshield:captive_portal:allow_device_wl" keep state',
        f"pass in quick on {lan_iface} from <access_whitelist>      to any "
        f'label "smartshield:captive_portal:allow_access_wl" keep state',
        f"pass in quick on {lan_iface} from <admin_bypass_clients>  to any "
        f'label "smartshield:captive_portal:allow_admin_bypass" keep state',
        "",
        "# DHCP must work before authentication so clients can acquire an IP.",
        f"pass in quick on {lan_iface} proto udp from any port 68 to any port 67 "
        f'label "smartshield:captive_portal:allow_dhcp" keep state',
        "",
        "# Portal itself is always reachable (needed for login page and HTTPS landing).",
        f"pass in quick on {lan_iface} proto tcp from any to {portal_ip} port {portal_port} "
        f'label "smartshield:captive_portal:allow_portal_http" keep state',
        f"pass in quick on {lan_iface} proto tcp from any to {portal_ip} port 443 "
        f'label "smartshield:captive_portal:allow_portal_https" keep state',
    ]

    if dns_allow:
        filter_lines += [
            f"pass in quick on {lan_iface} proto udp from any to {portal_ip} port 53 "
            f'label "smartshield:captive_portal:allow_dns_udp" keep state',
            f"pass in quick on {lan_iface} proto tcp from any to {portal_ip} port 53 "
            f'label "smartshield:captive_portal:allow_dns_tcp" keep state',
        ]

    if strict_mode:
        filter_lines += [
            "",
            "# Strict mode: reject HTTPS with a clean TCP RST so the browser shows",
            "# 'connection refused' instead of a misleading TLS error from a self-signed cert.",
            f"block return in log quick on {lan_iface} proto tcp from any to any port 443 "
            f'label "smartshield:captive_portal:block_unauth_https"',
            "",
            "# Block everything else. Unauthenticated clients only have HTTP redirect + DNS.",
            f"block in log quick on {lan_iface} from any to any "
            f'label "smartshield:captive_portal:block_unauth"',
        ]
    else:
        filter_lines += [
            "",
            "# Soft mode: allow remaining traffic after rdr decisions.",
            f"pass in on {lan_iface} from any to any "
            f'label "smartshield:captive_portal:soft_pass" keep state',
        ]

    return {
        "rdr":    "\n".join(rdr_lines) + "\n",
        "filter": "\n".join(filter_lines) + "\n",
    }


def generate_pf_anchor_preview(conn) -> str:
    """Human-readable concatenation of both anchor files for the admin UI preview."""
    parts = generate_pf_anchor(conn)
    return (
        "# ── captive_portal_rdr anchor (/etc/pf.captive_portal.rdr.conf) ──\n"
        + parts["rdr"]
        + "\n# ── captive_portal_filter anchor (/etc/pf.captive_portal.filter.conf) ──\n"
        + parts["filter"]
    )


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
                from app.services.config_file_utils import atomic_write
                from app.services.priv_helper import run_privileged
                for path, name in (
                    (_CP_RDR_PATH,    _CP_RDR_NAME),
                    (_CP_FILTER_PATH, _CP_FILTER_NAME),
                ):
                    atomic_write(path, "# captive portal disabled\n")
                    run_privileged("pf.anchor_reload",
                                   anchor_name=name,
                                   config_path=path)
            except Exception as exc:
                _log.warning("captive_portal: failed to clear PF anchors on disable: %s", exc)
        return {"ok": True, "message": "Captive portal disabled — PF anchors cleared."}

    conf = generate_pf_anchor(conn)

    # Static section-order check: rdr block must contain no filter rules and
    # vice versa. Catches accidental cross-pollination if the generator is
    # edited later without keeping the split clean.
    try:
        from app.services.pf_static_validator import (
            validate_section_order, PfRuleOrderError,
        )
        validate_section_order(conf["rdr"])
        validate_section_order(conf["filter"])
    except PfRuleOrderError as exc:
        return {"ok": False, "message": f"Captive portal rule-order error: {exc}", "conf": conf}

    portal_ip   = (settings.get("portal_ip") or _default_portal_ip(conn)).strip()
    portal_port = settings.get("portal_port") or _CP_REDIRECT_PORT

    if not sys.platform.startswith("freebsd"):
        return {"ok": True, "message": "Non-FreeBSD — captive portal anchors generated but not applied.",
                "conf": conf}

    try:
        from app.services.config_file_utils import atomic_write
        from app.services.priv_helper import run_privileged

        atomic_write(_CP_RDR_PATH,    conf["rdr"])
        atomic_write(_CP_FILTER_PATH, conf["filter"])

        run_privileged(
            "pf.anchor_reload",
            anchor_name=_CP_RDR_NAME,
            config_path=_CP_RDR_PATH,
        )
        run_privileged(
            "pf.anchor_reload",
            anchor_name=_CP_FILTER_NAME,
            config_path=_CP_FILTER_PATH,
        )

        # Ensure PF table exists and is readable.
        run_privileged("pf.table_show", table="authenticated_clients")
    except Exception as exc:
        return {"ok": False, "message": str(exc), "conf": conf}

    # Make sure the self-signed cert/key exist before the HTTPS daemon tries to load them.
    # Failure here is fatal — the daemon would otherwise silently die in ctx.load_cert_chain().
    cert_result = ensure_https_redirect_cert(portal_ip)
    if not cert_result.get("ok"):
        return {
            "ok": False,
            "message": "Captive portal HTTPS redirect certificate could not be created: "
                       + cert_result.get("message", "unknown error"),
            "conf": conf,
        }

    # Start the HTTPS→HTTP redirect daemon so port-5443 receives rdr'd HTTPS connections.
    # The thread is idempotent — it only starts once per process lifetime.
    start_https_redirect_server(portal_ip, portal_port, _CP_CERT_PATH, _CP_KEY_PATH)

    # Reconcile the PF tables to match the DB. Without this, a fresh apply
    # leaves the anchor live with whatever the kernel had cached.
    try:
        reconcile_captive_pf_tables(conn)
    except Exception as exc:
        _log.warning("captive_portal: reconcile after apply failed: %s", exc)

    from app.audit_log import log_event
    log_event(
        category="system", action="captive_portal_apply",
        username="system", remote_addr="",
        details={"ok": True},
    )
    return {"ok": True, "message": "Captive portal anchor applied.", "conf": conf}


def authenticate_radius(conn, username: str, password: str) -> dict:
    """
    Authenticate a user against the RADIUS server configured in the
    ``captive_portal_settings`` service_state blob (keys radius_server /
    radius_secret).

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

    # Load config from the captive_portal_settings service_state blob.
    import json as _json
    srow = conn.execute(
        "SELECT value_json FROM service_state WHERE key_name='captive_portal_settings'"
    ).fetchone()
    settings = _json.loads(srow["value_json"]) if srow else {}
    radius_server = (settings.get("radius_server") or "").strip()
    radius_secret = (settings.get("radius_secret") or "").strip()

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


def try_password_auth(conn, username: str, password: str) -> dict:
    """
    Shared credential check used by both the portal HTML route and the public
    captive-auth API endpoint.

    Tries RADIUS first (if configured), then falls back to the local `users`
    table. Keeps the API and portal in lockstep so a credential that logs in
    via the portal also logs in via /api/captive-portal/authenticate.

    Returns
    -------
    dict with keys:
      ok               - bool
      auth_type        - "radius" | "local" | ""  (empty on failure)
      is_superuser     - bool (local users only — RADIUS has no superuser concept here)
      message          - detailed reason; callers MUST sanitize before returning
                         to unauthenticated clients (see routes/portal.py).
    """
    username = (username or "").strip()
    password = (password or "").strip()
    if not username or not password:
        return {
            "ok": False, "auth_type": "", "is_superuser": False,
            "message": "Username and password are required.",
        }

    # 1. RADIUS first — only if a server is actually configured. authenticate_radius
    # returns ok=False / "RADIUS server not configured." when not set up; treat
    # that as "skip RADIUS, try local" rather than a credential failure.
    radius_result = authenticate_radius(conn, username, password)
    if radius_result.get("ok"):
        return {
            "ok": True, "auth_type": "radius", "is_superuser": False,
            "message": radius_result.get("message", ""),
        }

    radius_msg = (radius_result.get("message") or "").lower()
    radius_configured = "not configured" not in radius_msg

    # 2. Local users — werkzeug password hash check against the users table.
    try:
        from werkzeug.security import check_password_hash as _chk
        row = conn.execute(
            "SELECT password, is_superuser FROM users "
            "WHERE username=? AND (status IS NULL OR status='active')",
            (username,),
        ).fetchone()
    except Exception as exc:
        return {
            "ok": False, "auth_type": "", "is_superuser": False,
            "message": f"Local user lookup failed: {exc}",
        }

    if row and _chk(row["password"], password):
        return {
            "ok": True, "auth_type": "local",
            "is_superuser": bool(row["is_superuser"]),
            "message": "Local authentication succeeded.",
        }

    # 3. Both failed. Preserve the RADIUS error if it was a real rejection
    # (not a "not configured") for internal logging — the caller is responsible
    # for translating to a generic client-facing string.
    if radius_configured:
        return {
            "ok": False, "auth_type": "", "is_superuser": False,
            "message": radius_result.get("message") or "Authentication failed.",
        }
    return {
        "ok": False, "auth_type": "", "is_superuser": False,
        "message": "Invalid username or password.",
    }


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
        "active_sessions_count": len(active),
        "state": "running" if enabled else "stopped",
    }
