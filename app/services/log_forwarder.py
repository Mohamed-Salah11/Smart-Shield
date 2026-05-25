"""
log_forwarder.py
----------------
Forward Smart Shield audit events to an upstream SIEM (Splunk, FortiAnalyzer,
QRadar, Elastic, …) as RFC 5424 syslog or CEF.

A background daemon thread tails the indexed `events` table by row id; the
last-forwarded id is persisted in `siem_state` so no event is sent twice
across restarts.  Forwarding is disabled by default and configured through
the `log_forwarding` blob in `siem_state`.
"""

from __future__ import annotations

import json
import socket
import ssl
import threading
import time
from datetime import datetime, timezone

_STARTED    = threading.Event()
_CONFIG_KEY = "log_forwarding"
_OFFSET_KEY = "log_forward_offset"
_ERROR_KEY  = "log_forward_last_error"
_OK_KEY     = "log_forward_last_success"
_BATCH      = 500


def _clean_port(value, default: int = 514) -> int:
    """Coerce a config port to a valid 1-65535 int, never raising."""
    try:
        port = int(value if value is not None else default)
    except (TypeError, ValueError):
        port = default
    return max(1, min(port, 65535))


def _set_state(conn, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO siem_state (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=CURRENT_TIMESTAMP",
        (key, value),
    )
    conn.commit()

# Smart Shield severity -> syslog severity (RFC 5424: 0 emerg .. 7 debug)
_SYSLOG_SEV = {"critical": 2, "high": 3, "medium": 4, "low": 5, "info": 6}
# Smart Shield severity -> CEF severity (0-10)
_CEF_SEV    = {"critical": 10, "high": 8, "medium": 6, "low": 3, "info": 1}
_FACILITY   = 16  # local0


# ---------------------------------------------------------------------------
# Configuration (stored in siem_state)
# ---------------------------------------------------------------------------

def _default_config() -> dict:
    return {
        "enabled":     False,
        "host":        "",
        "port":        514,
        "protocol":    "udp",       # udp | tcp | tls
        "format":      "rfc5424",   # rfc5424 | cef
        "tls_verify":  True,        # verify upstream cert when protocol=tls
        "tls_ca_path": "",          # optional path to a CA bundle for verification
    }


def load_config(conn) -> dict:
    cfg = _default_config()
    try:
        row = conn.execute(
            "SELECT value FROM siem_state WHERE key = ?", (_CONFIG_KEY,)
        ).fetchone()
        if row and row[0]:
            cfg.update(json.loads(row[0]))
    except Exception:
        pass
    return cfg


def save_config(conn, cfg: dict) -> dict:
    merged = _default_config()
    merged.update({
        "enabled":     bool(cfg.get("enabled")),
        "host":        (cfg.get("host") or "").strip(),
        "port":        _clean_port(cfg.get("port")),
        "protocol":    cfg.get("protocol") if cfg.get("protocol") in ("udp", "tcp", "tls") else "udp",
        "format":      cfg.get("format") if cfg.get("format") in ("rfc5424", "cef") else "rfc5424",
        "tls_verify":  bool(cfg.get("tls_verify", True)),
        "tls_ca_path": (cfg.get("tls_ca_path") or "").strip(),
    })
    conn.execute(
        "INSERT INTO siem_state (key, value, updated_at) "
        "VALUES (?, ?, CURRENT_TIMESTAMP) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value, "
        "updated_at = CURRENT_TIMESTAMP",
        (_CONFIG_KEY, json.dumps(merged)),
    )
    conn.commit()
    return merged


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------

def _hostname() -> str:
    try:
        return socket.gethostname() or "smartshield"
    except Exception:
        return "smartshield"


def _format_rfc5424(ev: dict) -> str:
    sev = _SYSLOG_SEV.get(ev.get("severity", "info"), 6)
    pri = _FACILITY * 8 + sev
    ts  = ev.get("timestamp") or datetime.now(timezone.utc).isoformat()
    msg = "%s/%s user=%s src=%s %s" % (
        ev.get("category", "-"), ev.get("action", "-"),
        ev.get("username", "-"), ev.get("remote_addr", "-"),
        json.dumps(ev.get("details", {}), ensure_ascii=True),
    )
    # <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
    return "<%d>1 %s %s SmartShield - %s - %s" % (
        pri, ts, _hostname(), (ev.get("action") or "event")[:32], msg)


def _cef_escape(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")


def _cef_ext(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace("=", "\\=").replace("\n", " ")


def _format_cef(ev: dict) -> str:
    sev = _CEF_SEV.get(ev.get("severity", "info"), 1)
    act = ev.get("action", "event")
    d   = ev.get("details", {}) or {}
    ext = [
        "rt="    + _cef_ext(ev.get("timestamp", "")),
        "cat="   + _cef_ext(ev.get("category", "")),
        "suser=" + _cef_ext(ev.get("username", "")),
        "src="   + _cef_ext(ev.get("remote_addr", "") or d.get("src_ip", "")),
    ]
    if d.get("dst_ip"):
        ext.append("dst=" + _cef_ext(d["dst_ip"]))
    if d.get("dst_port"):
        ext.append("dpt=" + _cef_ext(d["dst_port"]))
    ext.append("msg=" + _cef_ext(json.dumps(d, ensure_ascii=True)))
    header = "CEF:0|SmartShield|Firewall|1.0|%s|%s|%d|" % (
        _cef_escape(act), _cef_escape(act), sev)
    return header + " ".join(ext)


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------

def _send(cfg: dict, payloads: list) -> tuple:
    """Send formatted log lines to the configured collector.

    Returns ``(ok, error)`` so the caller can record the failure reason in
    siem_state for a visible health signal (a bare False was swallowed before).
    """
    host  = cfg.get("host", "")
    port  = _clean_port(cfg.get("port"))
    proto = cfg.get("protocol", "udp")
    if not host:
        return False, "no upstream host configured"
    try:
        if proto == "udp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                for p in payloads:
                    sock.sendto(p.encode("utf-8", "replace"), (host, port))
            finally:
                sock.close()
        else:
            sock = socket.create_connection((host, port), timeout=10)
            try:
                if proto == "tls":
                    verify  = bool(cfg.get("tls_verify", True))
                    ca_path = (cfg.get("tls_ca_path") or "").strip() or None
                    # Default-secure context: verifies certs against the system
                    # trust store (or a user-supplied CA bundle) and checks the
                    # hostname. The admin can explicitly opt out for self-signed
                    # upstream collectors via the UI toggle.
                    ctx = ssl.create_default_context(cafile=ca_path)
                    if not verify:
                        ctx.check_hostname = False
                        ctx.verify_mode    = ssl.CERT_NONE
                    sock = ctx.wrap_socket(sock, server_hostname=host)
                for p in payloads:
                    sock.sendall((p + "\n").encode("utf-8", "replace"))
            finally:
                sock.close()
        return True, ""
    except Exception as exc:
        return False, str(exc)


# ---------------------------------------------------------------------------
# Forwarding loop
# ---------------------------------------------------------------------------

def _format_event(row, fmt: str) -> str:
    try:
        details = json.loads(row["details"]) if row["details"] else {}
    except Exception:
        details = {}
    try:
        from app.app_log import _redact
        details = _redact(details)
    except Exception:
        pass
    ev = {
        "timestamp":   row["ts"],
        "severity":    row["severity"] or "info",
        "category":    row["category"] or "",
        "action":      row["action"] or "",
        "username":    row["username"] or "",
        "remote_addr": row["remote_addr"] or "",
        "details":     details,
    }
    return _format_cef(ev) if fmt == "cef" else _format_rfc5424(ev)


def _forward_tick():
    from app.audit_log import _events_db
    conn = _events_db()
    if conn is None:
        return
    try:
        cfg = load_config(conn)
        if not cfg.get("enabled") or not cfg.get("host"):
            return

        row = conn.execute(
            "SELECT value FROM siem_state WHERE key = ?", (_OFFSET_KEY,)
        ).fetchone()
        if row is None:
            # First run while enabled — start from "now"; do not flood the
            # collector with the entire backfilled history.
            maxid = conn.execute(
                "SELECT COALESCE(MAX(id), 0) AS m FROM events"
            ).fetchone()["m"]
            conn.execute(
                "INSERT INTO siem_state (key, value) VALUES (?, ?)",
                (_OFFSET_KEY, str(maxid)),
            )
            conn.commit()
            return
        last_id = int(row[0] or 0)

        rows = conn.execute(
            "SELECT id, ts, severity, category, action, username, remote_addr, details "
            "FROM events WHERE id > ? ORDER BY id LIMIT ?",
            (last_id, _BATCH),
        ).fetchall()
        if not rows:
            return

        payloads = [_format_event(r, cfg.get("format", "rfc5424")) for r in rows]
        ok, err = _send(cfg, payloads)
        if ok:
            conn.execute(
                "INSERT INTO siem_state (key, value, updated_at) "
                "VALUES (?, ?, CURRENT_TIMESTAMP) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value, "
                "updated_at = CURRENT_TIMESTAMP",
                (_OFFSET_KEY, str(rows[-1]["id"])),
            )
            conn.commit()
            # Clear any stale error + stamp the last successful forward so the
            # admin UI can show forwarding health.
            _set_state(conn, _OK_KEY, datetime.now(timezone.utc).isoformat())
            _set_state(conn, _ERROR_KEY, "")
        else:
            # Surface the transport failure instead of silently dropping it;
            # offset is NOT advanced, so the batch is retried next tick.
            _set_state(conn, _ERROR_KEY, (err or "send failed")[:1000])
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _forward_loop():
    while True:
        try:
            _forward_tick()
        except Exception:
            pass
        time.sleep(5)


def start_log_forwarder():
    """Start the log-forwarding daemon thread (idempotent per process)."""
    if _STARTED.is_set():
        return
    _STARTED.set()
    threading.Thread(target=_forward_loop, name="log-forwarder",
                     daemon=True).start()
