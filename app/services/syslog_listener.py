"""
app/services/syslog_listener.py
-------------------------------
Optional UDP syslog ingest. Off by default. When enabled, a background
thread binds to a configurable bind-address/port and parses incoming
RFC 3164 ("BSD") and RFC 5424 messages into Smart Shield audit events.

Each accepted message is written through ``audit_log.log_event`` with
category ``external_syslog`` so it flows through the same indexing,
TI-enrichment, retention, and correlation pipelines as native events.

Configuration lives in ``siem_state.syslog_listener`` as JSON:
  {"enabled": true, "bind_ip": "0.0.0.0", "bind_port": 5140,
   "trust_remote_hostname": false}

The default bind port is 5140 (not 514) so the appliance does not collide
with the BSD syslogd that ships on FreeBSD. Operators who want true
port-514 ingest should disable the system syslogd first.
"""

from __future__ import annotations

import json
import re
import socket
import threading
import time
from datetime import datetime, timezone


_STARTED = threading.Event()
_CONFIG_KEY = "syslog_listener"

# RFC 5424 severities: 0 emerg, 1 alert, 2 crit, 3 err, 4 warn, 5 notice, 6 info, 7 debug
_SEV_MAP = {
    0: "critical", 1: "critical", 2: "critical", 3: "high",
    4: "medium",   5: "low",      6: "info",     7: "info",
}

_RFC3164_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>"
    r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<msg>.*)$"
)
_RFC5424_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>1\s+"
    r"(?P<ts>\S+)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<app>\S+)\s+"
    r"(?P<procid>\S+)\s+"
    r"(?P<msgid>\S+)\s+"
    r"(?:-|\[.*?\])\s*"
    r"(?P<msg>.*)$"
)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def _default_config() -> dict:
    return {
        "enabled":               False,
        "bind_ip":               "0.0.0.0",
        "bind_port":             5140,
        "trust_remote_hostname": False,
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
    try:
        cfg["bind_port"] = max(1, min(int(cfg.get("bind_port", 5140)), 65535))
    except (TypeError, ValueError):
        cfg["bind_port"] = 5140
    cfg["enabled"] = bool(cfg.get("enabled"))
    cfg["trust_remote_hostname"] = bool(cfg.get("trust_remote_hostname"))
    cfg["bind_ip"] = (cfg.get("bind_ip") or "0.0.0.0").strip() or "0.0.0.0"
    return cfg


def save_config(conn, cfg: dict) -> dict:
    merged = _default_config()
    try:
        port = int(cfg.get("bind_port") or 5140)
    except (TypeError, ValueError):
        port = 5140
    merged.update({
        "enabled":               bool(cfg.get("enabled")),
        "bind_ip":               (cfg.get("bind_ip") or "0.0.0.0").strip() or "0.0.0.0",
        "bind_port":             max(1, min(port, 65535)),
        "trust_remote_hostname": bool(cfg.get("trust_remote_hostname")),
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
# Parser
# ---------------------------------------------------------------------------

def parse_syslog(raw: str, peer_ip: str, trust_remote_hostname: bool) -> dict:
    """
    Parse one syslog payload into a Smart Shield event dict.

    Always returns a dict — unparseable input falls back to category=external_syslog
    with the entire raw line in details.message, so nothing is silently dropped.
    """
    text = (raw or "").strip()
    if not text:
        return {}

    pri      = 13           # local0.notice fallback
    severity = "info"
    facility = 1
    host     = peer_ip
    app      = "syslog"
    msg      = text

    m = _RFC5424_RE.match(text)
    if m:
        try:
            pri = int(m.group("pri"))
        except (TypeError, ValueError):
            pri = 13
        if trust_remote_hostname:
            host = m.group("host") or peer_ip
        app = m.group("app") or "syslog"
        msg = m.group("msg") or ""
    else:
        m = _RFC3164_RE.match(text)
        if m:
            try:
                pri = int(m.group("pri"))
            except (TypeError, ValueError):
                pri = 13
            if trust_remote_hostname:
                host = m.group("host") or peer_ip
            msg = m.group("msg") or ""

    facility = pri // 8
    sev_num  = pri % 8
    severity = _SEV_MAP.get(sev_num, "info")

    return {
        "severity": severity,
        "details": {
            "facility":   facility,
            "syslog_sev": sev_num,
            "hostname":   host,
            "app":        app,
            "message":    msg[:2000],
            "source_ip":  peer_ip,
        },
    }


# ---------------------------------------------------------------------------
# Listener loop
# ---------------------------------------------------------------------------

def _listener_loop():
    from app.audit_log import _events_db, log_event
    while True:
        conn = _events_db()
        if conn is None:
            time.sleep(30)
            continue
        try:
            cfg = load_config(conn)
        finally:
            try: conn.close()
            except Exception: pass

        if not cfg["enabled"]:
            time.sleep(30)
            continue

        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((cfg["bind_ip"], cfg["bind_port"]))
            sock.settimeout(2.0)
            log_event(
                category="system", action="syslog_listener_started",
                username="siem", remote_addr="",
                details={"bind_ip": cfg["bind_ip"], "bind_port": cfg["bind_port"]},
            )
        except Exception as exc:
            log_event(
                category="system", action="syslog_listener_bind_failed",
                severity="high", username="siem", remote_addr="",
                details={"bind_ip": cfg["bind_ip"], "bind_port": cfg["bind_port"],
                         "error": str(exc)},
            )
            if sock is not None:
                try: sock.close()
                except Exception: pass
            time.sleep(60)
            continue

        # Re-read config every 30 s so toggling the UI doesn't require a restart.
        next_cfg_check = time.time() + 30
        try:
            while True:
                if time.time() > next_cfg_check:
                    conn = _events_db()
                    if conn is not None:
                        try:
                            new_cfg = load_config(conn)
                        finally:
                            try: conn.close()
                            except Exception: pass
                        if (new_cfg["bind_ip"]   != cfg["bind_ip"]
                            or new_cfg["bind_port"] != cfg["bind_port"]
                            or not new_cfg["enabled"]):
                            break
                        cfg = new_cfg
                    next_cfg_check = time.time() + 30
                try:
                    data, addr = sock.recvfrom(8192)
                except socket.timeout:
                    continue
                except OSError:
                    break
                peer_ip = addr[0] if addr else ""
                try:
                    text = data.decode("utf-8", errors="replace")
                except Exception:
                    text = ""
                parsed = parse_syslog(text, peer_ip, cfg["trust_remote_hostname"])
                if not parsed:
                    continue
                log_event(
                    category="external_syslog",
                    action="syslog_message",
                    severity=parsed.get("severity", "info"),
                    username="syslog",
                    remote_addr=peer_ip,
                    details=parsed.get("details", {}),
                )
        finally:
            try: sock.close()
            except Exception: pass
        time.sleep(1)   # restart loop will re-read config and re-bind


def start_syslog_listener():
    """Start the syslog listener daemon thread (idempotent)."""
    if _STARTED.is_set():
        return
    _STARTED.set()
    threading.Thread(target=_listener_loop, name="syslog-listener",
                     daemon=True).start()
