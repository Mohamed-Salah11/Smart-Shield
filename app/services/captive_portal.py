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

_CP_ANCHOR_PATH  = "/etc/pf.captive_portal.conf"
_CP_ANCHOR_NAME  = "captive_portal"
_CP_REDIRECT_IP  = "127.0.0.1"
_CP_REDIRECT_PORT = 8081


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

    if not mac or not ip:
        return {"ok": False, "message": "MAC and IP are required."}

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
            from app.services.network_service import run_command
            run_command(
                ["pfctl", "-t", "authenticated_clients", "-T", "add", ip],
                check=False,
            )
        except Exception:
            pass

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
            run_command(
                ["pfctl", "-t", "authenticated_clients", "-T", "delete", ip],
                check=False,
            )
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
                run_command(
                    ["pfctl", "-t", "authenticated_clients", "-T", "delete", row["ip_address"]],
                    check=False,
                )
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

    lan_iface   = (settings.get("lan_interface") or "em1").strip()
    portal_ip   = (settings.get("portal_ip") or _CP_REDIRECT_IP).strip()
    portal_port = settings.get("portal_port") or _CP_REDIRECT_PORT
    dns_allow   = bool(settings.get("allow_dns", True))
    http_port   = settings.get("http_redirect_port") or 80

    lines = [
        "# ============================================================",
        "# Smart Shield — Captive Portal PF anchor",
        "# Generated by app/services/captive_portal.py",
        "# DO NOT EDIT MANUALLY",
        "# ============================================================",
        "",
        "# Authenticated clients pass through",
        f"pass in on {lan_iface} from <authenticated_clients> to any keep state",
        "",
        "# Allow DNS for all clients so they can reach the portal",
    ]
    if dns_allow:
        lines += [
            f"pass in on {lan_iface} proto udp from any to any port 53 keep state",
            f"pass in on {lan_iface} proto tcp from any to any port 53 keep state",
        ]
    lines += [
        "",
        "# Allow access to portal itself",
        f"pass in on {lan_iface} proto tcp from any to {portal_ip} port {portal_port} keep state",
        "",
        "# Redirect unauthenticated HTTP to portal",
        f"rdr on {lan_iface} proto tcp from any to any port {http_port} -> {portal_ip} port {portal_port}",
        "",
        "# Block everything else",
        f"block in on {lan_iface} all",
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
        from app.services.network_service import run_command
        run_command(["pfctl", "-a", _CP_ANCHOR_NAME, "-f", _CP_ANCHOR_PATH], check=True)
        # Ensure PF table exists
        run_command(["pfctl", "-t", "authenticated_clients", "-T", "show"], check=False)
    except Exception as exc:
        return {"ok": False, "message": str(exc), "conf": conf}

    from app.audit_log import log_event
    log_event(
        category="system", action="captive_portal_apply",
        username="system", remote_addr="",
        details={"ok": True},
    )
    return {"ok": True, "message": "Captive portal anchor applied.", "conf": conf}


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
