"""
siem_collector.py
-----------------
Background SIEM data collectors for Smart Shield.

Five daemon threads feed security events into the central audit log:
  1. IDS alerts      — tails /var/log/suricata/eve.json          (every 10s)
  2. DHCP events     — parses /var/db/dhcpd/dhcpd.leases         (every 30s)
  3. DNS queries     — tails /var/log/unbound/query.log           (every 15s)
  4. PF connections  — pfctl -s states (new connections only)     (every 60s)
  5. Anomaly detect  — brute-force + IDS-flood from audit log     (every 60s)

All threads are daemon threads — they die silently when the app exits.
All threads catch every exception internally — they never crash the app.
On non-FreeBSD (dev/Windows) all collectors exit immediately after one no-op cycle.
"""

import json
import os
import re
import sys
import threading
import time
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_EVE_JSON_PATH    = "/var/log/suricata/eve.json"
_DHCPD_LEASES     = "/var/db/dhcpd/dhcpd.leases"
_UNBOUND_QUERY_LOG = "/var/log/unbound/query.log"

_ON_FREEBSD = sys.platform.startswith("freebsd")

_STARTED = threading.Event()   # prevent double-start in dev reloader


# ---------------------------------------------------------------------------
# Offset persistence helpers
# ---------------------------------------------------------------------------

def _load_offset(key: str, default: int = 0) -> int:
    """Read a persisted byte offset from the siem_state table."""
    try:
        from app.database import get_db
        row = get_db().execute(
            "SELECT value FROM siem_state WHERE key=?", (key,)
        ).fetchone()
        if row:
            return int(row["value"])
    except Exception:
        pass
    return default


def _save_offset(key: str, value: int):
    """Write a byte offset to the siem_state table. Silent on failure."""
    try:
        from app.database import get_db
        db = get_db()
        db.execute(
            "INSERT INTO siem_state (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)"
            " ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=CURRENT_TIMESTAMP",
            (key, str(value)),
        )
        db.commit()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# LAN interface / subnet auto-detection
# ---------------------------------------------------------------------------

_lan_info_cache: dict = {}


def _get_lan_info() -> dict:
    """Return LAN interface name, IP, and subnet from lan_config DB.
    Falls back to em1 / 192.168.1.0/24 if not configured.
    Cached for 5 minutes to avoid repeated DB hits per poll cycle.
    """
    import ipaddress
    cache = _lan_info_cache
    if cache.get("_ts") and (time.time() - cache["_ts"]) < 300:
        return cache

    defaults = {
        "iface":  "em1",
        "ip":     "192.168.1.1",
        "subnet": "192.168.1.0/24",
        "_ts":    time.time(),
    }
    try:
        from app.database import get_db
        row = get_db().execute(
            "SELECT assigned_port, ip_address, subnet_bits FROM lan_config LIMIT 1"
        ).fetchone()
        if row and (row["assigned_port"] or "").strip():
            iface  = row["assigned_port"].strip()
            lan_ip = (row["ip_address"] or "192.168.1.1").strip()
            bits   = int(row["subnet_bits"] or 24)
            net    = str(ipaddress.ip_interface(f"{lan_ip}/{bits}").network)
            cache.update({"iface": iface, "ip": lan_ip,
                          "subnet": net, "_ts": time.time()})
            return cache
    except Exception:
        pass
    cache.update(defaults)
    return cache


def _is_lan_ip(ip: str) -> bool:
    """Return True if *ip* belongs to the configured LAN subnet."""
    import ipaddress
    try:
        lan = _get_lan_info()
        return ipaddress.ip_address(ip) in ipaddress.ip_network(lan["subnet"])
    except Exception:
        return False


def _lookup_tracked_host(ip: str) -> dict:
    """Return hostname + MAC from tracked_hosts for *ip*. Returns {} on miss."""
    try:
        from app.database import get_db
        row = get_db().execute(
            "SELECT hostname, mac_address FROM tracked_hosts WHERE ip_address=? LIMIT 1",
            (ip,),
        ).fetchone()
        return dict(row) if row else {}
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Port → service / severity mapping
# ---------------------------------------------------------------------------

_PORT_MAP: dict = {
    22:    ("SSH",        "medium"),
    23:    ("Telnet",     "high"),
    3389:  ("RDP",        "high"),
    5900:  ("VNC",        "high"),
    1194:  ("OpenVPN",    "medium"),
    500:   ("IPSec-IKE",  "medium"),
    4500:  ("IPSec-NAT",  "medium"),
    1701:  ("L2TP",       "medium"),
    21:    ("FTP",        "medium"),
    20:    ("FTP-Data",   "low"),
    25:    ("SMTP",       "low"),
    587:   ("SMTP-TLS",   "low"),
    110:   ("POP3",       "low"),
    143:   ("IMAP",       "low"),
    3306:  ("MySQL",      "high"),
    5432:  ("PostgreSQL", "high"),
    27017: ("MongoDB",    "high"),
    6379:  ("Redis",      "high"),
    1433:  ("MSSQL",      "high"),
    445:   ("SMB",        "high"),
    139:   ("NetBIOS",    "high"),
    135:   ("RPC",        "medium"),
    53:    ("DNS",        "info"),
    80:    ("HTTP",       "info"),
    443:   ("HTTPS",      "info"),
    8080:  ("HTTP-Alt",   "info"),
    8443:  ("HTTPS-Alt",  "info"),
}

# IDS severity: Suricata integer 1–4 → string
_IDS_SEV = {1: "critical", 2: "high", 3: "medium", 4: "low"}


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _log(category: str, action: str, remote_addr: str = "",
         details: dict = None, severity: str = "info"):
    """Write one SIEM event to the audit log. Never raises."""
    try:
        from app.audit_log import log_event
        log_event(
            category=category,
            action=action,
            username="siem",
            remote_addr=remote_addr,
            details=details or {},
            severity=severity,
        )
    except Exception:
        pass


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _tail_file(path: str, offset: int) -> tuple[list[str], int]:
    """Read new lines from *path* starting at byte *offset*. Returns (lines, new_offset)."""
    try:
        size = os.path.getsize(path)
    except OSError:
        return [], offset

    # File was rotated/truncated
    if size < offset:
        offset = 0

    if size == offset:
        return [], offset

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            fh.seek(offset)
            lines = fh.readlines()
            new_offset = fh.tell()
        return [l.rstrip("\n") for l in lines if l.strip()], new_offset
    except OSError:
        return [], offset


# ---------------------------------------------------------------------------
# 1. IDS Alert Collector
# ---------------------------------------------------------------------------

def _run_ids_collector(state: dict):
    while True:
        try:
            _collect_ids_alerts(state)
        except Exception:
            pass
        time.sleep(10)


def _collect_ids_alerts(state: dict):
    if not os.path.exists(_EVE_JSON_PATH):
        return

    prev_offset = state.get("ids_offset", 0)
    lines, state["ids_offset"] = _tail_file(_EVE_JSON_PATH, prev_offset)
    if state["ids_offset"] != prev_offset:
        _save_offset("ids_offset", state["ids_offset"])

    for line in lines:
        try:
            evt = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue

        if evt.get("event_type") != "alert":
            continue

        alert  = evt.get("alert", {})
        src_ip = evt.get("src_ip", "")
        sev    = _IDS_SEV.get(int(alert.get("severity") or 4), "low")

        # Enrich with hostname if src is a LAN device
        host = _lookup_tracked_host(src_ip) if _is_lan_ip(src_ip) else {}

        _log("ids", "ids_alert", remote_addr=src_ip, severity=sev, details={
            "src_ip":    src_ip,
            "src_port":  evt.get("src_port"),
            "dest_ip":   evt.get("dest_ip", ""),
            "dest_port": evt.get("dest_port"),
            "proto":     evt.get("proto", ""),
            "signature": alert.get("signature", ""),
            "severity":  sev,
            "category":  alert.get("category", ""),
            "action":    alert.get("action", ""),
            "hostname":  host.get("hostname", ""),
            "mac":       host.get("mac_address", ""),
        })


# ---------------------------------------------------------------------------
# 2. DHCP Lease Collector
# ---------------------------------------------------------------------------

def _run_dhcp_collector(state: dict):
    while True:
        try:
            _collect_dhcp_events(state)
        except Exception:
            pass
        time.sleep(30)


_LEASE_BLOCK_RE = re.compile(
    r'lease\s+([\d.]+)\s*\{([^}]*)\}',
    re.DOTALL,
)
_FIELD_RE = re.compile(r'^\s*(\S+)\s+(.*?);', re.MULTILINE)


def _parse_leases(text: str) -> list:
    leases = []
    for m in _LEASE_BLOCK_RE.finditer(text):
        ip = m.group(1)
        body = m.group(2)
        fields = {k: v.strip('"') for k, v in _FIELD_RE.findall(body)}
        mac      = fields.get("hardware ethernet", "").strip()
        hostname = fields.get("client-hostname", "").strip()
        ends     = fields.get("ends", "").strip()
        binding  = fields.get("binding state", "").strip()
        if binding == "active" and mac:
            leases.append({"ip": ip, "mac": mac, "hostname": hostname, "expires": ends})
    return leases


def _collect_dhcp_events(state: dict):
    if not os.path.exists(_DHCPD_LEASES):
        return

    try:
        with open(_DHCPD_LEASES, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return

    leases = _parse_leases(text)
    seen: set = state.setdefault("dhcp_seen", set())

    for lease in leases:
        key = (lease["ip"], lease["mac"])
        if key in seen:
            continue
        seen.add(key)
        _log("connection", "dhcp_lease_assigned", remote_addr=lease["ip"], details=lease)

        # Update tracked_hosts as a side-effect
        try:
            from app.database import get_db
            db = get_db()
            db.execute(
                """
                INSERT INTO tracked_hosts (ip_address, mac_address, hostname,
                    interface_type, discovered_via, first_seen, last_seen)
                VALUES (?, ?, ?, 'LAN', 'dhcp', datetime('now'), datetime('now'))
                ON CONFLICT(ip_address) DO UPDATE SET
                    last_seen=datetime('now'),
                    hostname=excluded.hostname
                """,
                (lease["ip"], lease["mac"], lease["hostname"] or ""),
            )
            db.commit()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# 3. DNS Query Collector (requires Unbound query logging enabled)
# ---------------------------------------------------------------------------

def _run_dns_collector(state: dict):
    while True:
        try:
            _collect_dns_queries(state)
        except Exception:
            pass
        time.sleep(15)


# Unbound query log format:
# [timestamp] unbound[pid:tid] info: 192.168.1.5 A example.com. NOERROR 0.001234
_UNBOUND_QUERY_RE = re.compile(
    r'info:\s+([\d.:a-fA-F]+)\s+(\w+)\s+([\w.\-]+?\.?)\s+(\w+)'
)


def _collect_dns_queries(state: dict):
    if not os.path.exists(_UNBOUND_QUERY_LOG):
        return

    prev_offset = state.get("dns_offset", 0)
    lines, state["dns_offset"] = _tail_file(_UNBOUND_QUERY_LOG, prev_offset)
    if state["dns_offset"] != prev_offset:
        _save_offset("dns_offset", state["dns_offset"])

    # Load blocked domains once per cycle for fast lookup
    blocked: set = state.get("blocked_domains", set())

    for line in lines:
        m = _UNBOUND_QUERY_RE.search(line)
        if not m:
            continue

        client_ip   = m.group(1)
        qtype       = m.group(2)
        query_name  = m.group(3).rstrip(".")
        response    = m.group(4)

        is_blocked = query_name in blocked or response in ("NXDOMAIN", "SERVFAIL")

        # Only log blocked queries or NXDOMAIN responses to keep volume low
        if not is_blocked:
            continue

        _log("connection", "dns_query", remote_addr=client_ip, details={
            "query":   query_name,
            "type":    qtype,
            "response": response,
            "blocked": is_blocked,
        })


def _refresh_blocked_domains(state: dict):
    """Load blocked domains from DB into state for DNS collector."""
    try:
        from app.database import get_db
        db = get_db()
        rows = db.execute(
            "SELECT domain FROM filter_dns_rules WHERE enabled=1 AND action='block'"
        ).fetchall()
        state["blocked_domains"] = {r["domain"] for r in rows}
    except Exception:
        state.setdefault("blocked_domains", set())


# ---------------------------------------------------------------------------
# 4. PF Connection Tracker
# ---------------------------------------------------------------------------

def _run_pf_collector(state: dict):
    while True:
        try:
            _collect_pf_connections(state)
        except Exception:
            pass
        time.sleep(60)


_PF_STATE_RE = re.compile(
    r'(\w+)\s+([\d.]+):(\d+)\s+->\s+([\d.]+):(\d+)'
)


def _collect_pf_connections(state: dict):
    if not _ON_FREEBSD:
        return

    try:
        import subprocess
        result = subprocess.run(
            ["pfctl", "-s", "states"],
            capture_output=True, text=True, timeout=10,
        )
        output = result.stdout or ""
    except Exception:
        return

    lan        = _get_lan_info()
    current:  set = set()
    previous: set = state.get("pf_seen", set())

    for line in output.splitlines():
        m = _PF_STATE_RE.search(line)
        if not m:
            continue
        proto, src_ip, src_port, dst_ip, dst_port = (
            m.group(1), m.group(2), m.group(3), m.group(4), m.group(5),
        )

        # Only track connections originating from LAN devices
        if not _is_lan_ip(src_ip):
            continue

        key = (proto, src_ip, src_port, dst_ip, dst_port)
        current.add(key)

        if key not in previous:
            try:
                dport_int = int(dst_port)
            except ValueError:
                dport_int = 0
            service, sev = _PORT_MAP.get(dport_int, ("", "info"))
            host = _lookup_tracked_host(src_ip)
            details = {
                "proto":      proto,
                "src_ip":     src_ip,
                "src_port":   int(src_port),
                "dst_ip":     dst_ip,
                "dst_port":   dport_int,
                "service":    service,
                "hostname":   host.get("hostname", ""),
                "mac":        host.get("mac_address", ""),
                "interface":  lan["iface"],
                "lan_subnet": lan["subnet"],
            }
            _log("connection", "pf_new_conn", remote_addr=src_ip,
                 severity=sev, details=details)

            # Raise a separate security alert for insecure/dangerous protocols
            if dport_int in (23, 21, 5900, 139):  # Telnet, FTP, VNC, NetBIOS
                _log("security", "insecure_protocol_detected",
                     remote_addr=src_ip, severity="high",
                     details={
                         "protocol":  service or str(dport_int),
                         "src":       f"{src_ip}:{src_port}",
                         "dst":       f"{dst_ip}:{dst_port}",
                         "hostname":  host.get("hostname", ""),
                         "mac":       host.get("mac_address", ""),
                         "interface": lan["iface"],
                     })

    state["pf_seen"] = current


# ---------------------------------------------------------------------------
# 5. Anomaly Detector
# ---------------------------------------------------------------------------

def _run_anomaly_detector(state: dict):
    while True:
        try:
            _detect_anomalies(state)
        except Exception:
            pass
        time.sleep(60)


def _detect_anomalies(state: dict):
    from app.audit_log import tail_events

    recent = tail_events(limit=300)
    now_ts = time.time()
    window = 5 * 60   # 5-minute sliding window

    alerted: dict = state.setdefault("alerted", {})

    # Clean up old alert cooldowns (10-minute cooldown)
    expired = [k for k, t in alerted.items() if now_ts - t > 600]
    for k in expired:
        del alerted[k]

    # ── Brute-force detection: >5 login_failed from same IP in 5 min ──
    fail_counts: dict = {}
    for evt in recent:
        if evt.get("action") != "login_failed":
            continue
        try:
            ts = datetime.fromisoformat(evt.get("timestamp", "")).timestamp()
        except (ValueError, TypeError):
            continue
        if now_ts - ts > window:
            continue
        ip = evt.get("remote_addr", "unknown")
        fail_counts[ip] = fail_counts.get(ip, 0) + 1

    for ip, count in fail_counts.items():
        if count >= 5:
            key = f"brute_force:{ip}"
            if key not in alerted:
                alerted[key] = now_ts
                _log("security", "brute_force_detected", remote_addr=ip, details={
                    "count":          count,
                    "window_minutes": 5,
                    "target":         "admin login",
                })

    # ── IDS flood: >10 ids_alert from same src_ip in 5 min ──
    ids_counts: dict = {}
    ids_sigs:   dict = {}
    for evt in recent:
        if evt.get("category") != "ids" or evt.get("action") != "ids_alert":
            continue
        try:
            ts = datetime.fromisoformat(evt.get("timestamp", "")).timestamp()
        except (ValueError, TypeError):
            continue
        if now_ts - ts > window:
            continue
        src = evt.get("remote_addr", "unknown")
        ids_counts[src] = ids_counts.get(src, 0) + 1
        sig = (evt.get("details") or {}).get("signature", "")
        if sig:
            ids_sigs.setdefault(src, []).append(sig)

    for src, count in ids_counts.items():
        if count >= 10:
            key = f"ids_flood:{src}"
            if key not in alerted:
                alerted[key] = now_ts
                top_sig = ""
                sigs = ids_sigs.get(src, [])
                if sigs:
                    top_sig = max(set(sigs), key=sigs.count)
                _log("security", "ids_flood_detected", remote_addr=src, details={
                    "count":          count,
                    "window_minutes": 5,
                    "top_signature":  top_sig,
                })


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

def start_siem_collectors():
    """
    Start all five SIEM background collector threads.
    Safe to call multiple times — only starts once per process.
    On non-FreeBSD the collectors silently do nothing.
    """
    if _STARTED.is_set():
        return
    _STARTED.set()

    shared_state: dict = {
        "ids_offset":  _load_offset("ids_offset", 0),
        "dns_offset":  _load_offset("dns_offset", 0),
        "dhcp_seen":   set(),
        "pf_seen":     set(),
        "alerted":     {},
    }

    # Pre-load blocked domains for DNS collector
    try:
        _refresh_blocked_domains(shared_state)
    except Exception:
        pass

    collectors = [
        ("siem-ids",       _run_ids_collector,      shared_state),
        ("siem-dhcp",      _run_dhcp_collector,      shared_state),
        ("siem-dns",       _run_dns_collector,        shared_state),
        ("siem-pf",        _run_pf_collector,         shared_state),
        ("siem-anomaly",   _run_anomaly_detector,     shared_state),
    ]

    for name, target, state in collectors:
        t = threading.Thread(target=target, args=(state,), name=name, daemon=True)
        t.start()


def get_collector_status() -> dict:
    """
    Return the current status of the SIEM collector threads.
    Used by health_monitor.check_all_services() for the health dashboard.
    """
    started = _STARTED.is_set()

    if not _ON_FREEBSD:
        return {
            "running": False,
            "state":   "dry-run",
            "message": "SIEM collectors run on FreeBSD only",
        }

    if not started:
        return {
            "running": False,
            "state":   "stopped",
            "message": "SIEM collectors have not been started",
        }

    # Check that the collector daemon threads are actually alive.
    alive = [t for t in threading.enumerate() if t.name.startswith("siem-")]
    if alive:
        return {
            "running": True,
            "state":   "running",
            "message": f"{len(alive)} collector thread(s) active",
        }

    return {
        "running": False,
        "state":   "stopped",
        "message": "SIEM collector threads have exited unexpectedly",
    }
