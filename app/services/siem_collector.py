"""
siem_collector.py
-----------------
Background SIEM data collectors for Smart Shield.

SOC vs. firewall separation
---------------------------
Events emitted from this module use ``log_event`` (NOT ``log_soc_event``),
so they are visible to both the firewall dashboard and the SOC portal by
default. Actions taken from inside the SOC portal go through
``log_soc_event`` which stamps ``details.soc_origin = True``, and the
firewall dashboard queries pass ``hide_soc=1`` to exclude SOC-originated
rows. Do not collapse the two — the boundary keeps analyst work from
polluting operator-facing firewall traffic counts (review §5.2).

Seven daemon threads feed security events into the central audit log:
  1. IDS alerts      — tails /var/log/suricata/eve.json          (every 10s)
  2. DHCP events     — parses /var/db/dhcpd/dhcpd.leases         (every 30s)
  3. DNS queries     — tails /var/log/unbound/query.log           (every 15s)
  4. PF connections  — pfctl -s states (new connections only)     (every 60s)
  5. Anomaly detect  — brute-force + IDS-flood from audit log     (every 60s)
  6. SSH / auth.log  — tails /var/log/auth.log for SSH events     (every 15s)
  7. System messages — tails /var/log/messages for kernel events  (every 30s)

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
_AUTH_LOG         = "/var/log/auth.log"
_MESSAGES_LOG     = "/var/log/messages"

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

    The ``lan_config.ipv4_address`` column stores the LAN address in CIDR form
    (e.g. ``192.168.50.1/24``) — there is no separate ``subnet_bits`` column.
    Falls back to em1 / 192.168.50.0/24 (project lab subnet) if not configured.
    Cached for 5 minutes to avoid repeated DB hits per poll cycle.
    """
    import ipaddress
    import logging
    cache = _lan_info_cache
    if cache.get("_ts") and (time.time() - cache["_ts"]) < 300:
        return cache

    defaults = {
        "iface":  "em1",
        "ip":     "192.168.50.1",
        "subnet": "192.168.50.0/24",
        "_ts":    time.time(),
    }
    try:
        from app.database import get_db
        row = get_db().execute(
            "SELECT assigned_port, ipv4_address FROM lan_config LIMIT 1"
        ).fetchone()
        if row and (row["assigned_port"] or "").strip():
            iface = row["assigned_port"].strip()
            cidr  = (row["ipv4_address"] or "").strip()
            if "/" in cidr:
                iface_obj = ipaddress.ip_interface(cidr)
                cache.update({
                    "iface":  iface,
                    "ip":     str(iface_obj.ip),
                    "subnet": str(iface_obj.network),
                    "_ts":    time.time(),
                })
                return cache
            logging.warning(
                "siem_collector: lan_config.ipv4_address has no CIDR (%r); "
                "falling back to %s", cidr, defaults["subnet"],
            )
    except Exception as exc:
        logging.warning("siem_collector: _get_lan_info DB read failed: %s", exc)
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

# File extensions and MIME types that warrant a security alert when downloaded
_SUSPICIOUS_EXTENSIONS = frozenset({
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta",
    ".scr", ".com", ".pif", ".msi", ".msp", ".jar",
})
_SUSPICIOUS_MIME_TYPES = frozenset({
    "application/x-msdownload", "application/x-dosexec",
    "application/x-executable", "application/x-msi",
    "application/x-msdos-program",
})

# HTTP User-Agent patterns used by scripted downloaders / C2 agents
_C2_USER_AGENT_RE = re.compile(
    r"(?:powershell|wget|curl\b|python-requests|python-urllib|go-http-client|"
    r"nmap|masscan|zgrab|sqlmap|nikto|hydra|metasploit|msfvenom|empire|"
    r"cobalt.strike|beef|sliver|havoc)",
    re.IGNORECASE,
)

# URIs that end with an executable extension (before query string)
_EXE_URI_RE = re.compile(
    r"\.(exe|dll|bat|cmd|ps1|vbs|hta|msi|scr|com|pif|jar)(?:\?|#|$)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _log(category: str, action: str, remote_addr: str = "",
         details: dict = None, severity: str = "info") -> str:
    """Write one SIEM event to the audit log. Never raises.

    Returns the new event's ``event_uuid`` so callers that need to dual-write
    into a specialised table (e.g. ``firewall_events``) can share the same
    join key.  Returns ``""`` on any failure.
    """
    try:
        from app.audit_log import log_event
        return log_event(
            category=category,
            action=action,
            username="siem",
            remote_addr=remote_addr,
            details=details or {},
            severity=severity,
        ) or ""
    except Exception:
        return ""


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


def _handle_alert_event(evt: dict):
    """Process a Suricata alert event into the audit log."""
    alert  = evt.get("alert", {})
    src_ip = evt.get("src_ip", "")
    sev    = _IDS_SEV.get(int(alert.get("severity") or 4), "low")
    host   = _lookup_tracked_host(src_ip) if _is_lan_ip(src_ip) else {}

    details: dict = {
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
    }

    # Include HTTP context when Suricata attaches it to the alert
    http = evt.get("http", {})
    if http:
        details["http_url"]      = http.get("url", "")
        details["http_hostname"] = http.get("hostname", "")
        details["http_agent"]    = http.get("http_user_agent", "")

    # Include TLS SNI when present
    tls = evt.get("tls", {})
    if tls:
        details["tls_sni"] = tls.get("sni", "")

    event_uuid = _log("ids", "ids_alert", remote_addr=src_ip,
                      severity=sev, details=details)

    # Wave C: route high-severity IDS alerts through alert_service so the
    # SOC queue is deduplicated. We only mint an alert for medium-and-up
    # signatures — low-grade noise (severity 4) stays in the events feed
    # but does not flood the SOC alerts table.
    if sev in ("critical", "high", "medium"):
        try:
            from app.services.alert_service import create_or_update_alert
            from app.audit_log import _events_db
            sig_id = str(alert.get("signature_id") or alert.get("gid") or "")
            dedup_key = (
                f"ids:{sig_id}:{src_ip}:{evt.get('dest_ip','')}"
                if sig_id else
                f"ids:{alert.get('signature','')}:{src_ip}:{evt.get('dest_ip','')}"
            )
            ac = _events_db()
            if ac is not None:
                try:
                    create_or_update_alert(
                        ac,
                        dedup_key=dedup_key,
                        title=alert.get("signature")
                              or "Intrusion Detection Alert",
                        severity=sev,
                        category="ids",
                        alert_type="ids_alert",
                        description=alert.get("category") or "",
                        source_event_uuid=event_uuid,
                        src_ip=src_ip,
                        dst_ip=evt.get("dest_ip", ""),
                        hostname=host.get("hostname", ""),
                        mac=host.get("mac_address", ""),
                        rule_id=sig_id,
                        rule_name=alert.get("signature", ""),
                        signature_id=sig_id,
                        details={
                            "category":  alert.get("category", ""),
                            "proto":     evt.get("proto", ""),
                            "dst_port":  evt.get("dest_port"),
                            "tls_sni":   (evt.get("tls") or {}).get("sni", ""),
                            "http_url":  (evt.get("http") or {}).get("url", ""),
                        },
                    )
                    ac.commit()
                finally:
                    try:
                        ac.close()
                    except Exception:
                        pass
        except Exception:
            pass


def _handle_fileinfo_event(evt: dict):
    """
    Process a Suricata fileinfo event.  Logs high-severity alerts for
    executable and scripting file types downloaded through the network.
    """
    fi       = evt.get("fileinfo", {})
    filename = (fi.get("filename") or "").strip()
    if not filename:
        return

    _, ext = os.path.splitext(filename.lower())
    magic  = (fi.get("magic") or "").lower()
    http   = evt.get("http", {})
    mime   = (http.get("http_content_type") or "").lower().split(";")[0].strip()

    suspicious = (
        ext in _SUSPICIOUS_EXTENSIONS
        or mime in _SUSPICIOUS_MIME_TYPES
        or "executable" in magic
        or "pe32" in magic
        or "mz header" in magic
    )
    if not suspicious:
        return

    src_ip  = evt.get("src_ip", "")
    tracked = _lookup_tracked_host(src_ip) if _is_lan_ip(src_ip) else {}

    _log("file_download", "exe_download_detected",
         remote_addr=src_ip, severity="high",
         details={
             "src_ip":     src_ip,
             "dest_ip":    evt.get("dest_ip", ""),
             "dest_port":  evt.get("dest_port"),
             "filename":   filename,
             "extension":  ext,
             "magic":      fi.get("magic", ""),
             "size":       fi.get("size", 0),
             "md5":        fi.get("md5", ""),
             "sha256":     fi.get("sha256", ""),
             "mime":       mime,
             "http_url":   http.get("url", ""),
             "http_host":  http.get("hostname", ""),
             "http_agent": http.get("http_user_agent", ""),
             "state":      fi.get("state", ""),
             "hostname":   tracked.get("hostname", ""),
             "mac":        tracked.get("mac_address", ""),
         })


def _handle_http_event(evt: dict):
    """
    Process a Suricata http event.  Logs alerts when:
    - The URI points to an executable file type  (file_download category)
    - The User-Agent matches known C2/scripted-downloader patterns  (ids category)
    """
    http   = evt.get("http", {})
    url    = http.get("url", "")
    agent  = http.get("http_user_agent", "")
    host   = http.get("hostname", "")

    is_exe_url  = bool(_EXE_URI_RE.search(url)) if url else False
    is_c2_agent = bool(_C2_USER_AGENT_RE.search(agent)) if agent else False

    if not (is_exe_url or is_c2_agent):
        return

    src_ip  = evt.get("src_ip", "")
    tracked = _lookup_tracked_host(src_ip) if _is_lan_ip(src_ip) else {}

    base_details = {
        "src_ip":      src_ip,
        "dest_ip":     evt.get("dest_ip", ""),
        "dest_port":   evt.get("dest_port"),
        "http_url":    url,
        "http_host":   host,
        "http_agent":  agent,
        "http_method": http.get("http_method", ""),
        "http_status": http.get("status", 0),
        "hostname":    tracked.get("hostname", ""),
        "mac":         tracked.get("mac_address", ""),
    }

    if is_exe_url:
        # Extract the bare filename from the URI path
        path_part = url.split("?")[0].split("#")[0]
        base_details["filename"] = path_part.rsplit("/", 1)[-1]
        _log("file_download", "exe_url_detected",
             remote_addr=src_ip, severity="high", details=base_details)

    if is_c2_agent:
        _log("ids", "c2_agent_detected",
             remote_addr=src_ip, severity="medium", details=base_details)


def _collect_ids_alerts(state: dict):
    """
    Read new lines from eve.json and dispatch each event to the appropriate
    handler based on event_type:
      alert    → _handle_alert_event    (IDS signature match)
      fileinfo → _handle_fileinfo_event (file download tracking)
      http     → _handle_http_event     (EXE URI / C2 user-agent detection)
    """
    if not os.path.exists(_EVE_JSON_PATH):
        return
    from app.services.collector_health import heartbeat, record_dead_letter

    prev_offset = state.get("ids_offset", 0)
    lines, new_offset = _tail_file(_EVE_JSON_PATH, prev_offset)

    collected = 0
    dropped = 0
    for line in lines:
        try:
            evt = json.loads(line)
        except (json.JSONDecodeError, ValueError) as exc:
            dropped += 1
            record_dead_letter("suricata_eve",
                               source_type="ids",
                               reason=f"json_decode: {exc}",
                               raw_payload=line,
                               bump_dropped=False)
            continue

        event_type = evt.get("event_type", "")
        if event_type == "alert":
            _handle_alert_event(evt); collected += 1
        elif event_type == "fileinfo":
            _handle_fileinfo_event(evt); collected += 1
        elif event_type == "http":
            _handle_http_event(evt); collected += 1

    # Persist offset only after all events from this batch are written.
    if new_offset != prev_offset:
        _save_offset("ids_offset", new_offset)
        state["ids_offset"] = new_offset
    heartbeat("suricata_eve", source_type="ids",
              path=_EVE_JSON_PATH, offset=new_offset,
              events_added=collected, dropped_added=dropped,
              last_error="" if collected or dropped == 0 else None)


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

        # Update tracked_hosts as a side-effect.
        # The unique index is on (interface_type, ip_address) — not just ip_address.
        try:
            from app.database import get_db
            db = get_db()
            db.execute(
                """
                INSERT INTO tracked_hosts
                    (ip_address, mac_address, hostname,
                     interface_type, discovered_via, first_seen, last_seen)
                VALUES (?, ?, ?, 'LAN', 'dhcp', datetime('now'), datetime('now'))
                ON CONFLICT(interface_type, ip_address) DO UPDATE SET
                    last_seen   = datetime('now'),
                    mac_address = excluded.mac_address,
                    hostname    = CASE WHEN excluded.hostname != ''
                                       THEN excluded.hostname
                                       ELSE tracked_hosts.hostname END
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
    _refresh_blocked_domains(state)          # initial load at startup
    _refresh_counter = 0
    while True:
        try:
            _collect_dns_queries(state)
        except Exception:
            pass
        _refresh_counter += 1
        if _refresh_counter >= 20:           # every 20 × 15s = 5 minutes
            try:
                _refresh_blocked_domains(state)
            except Exception:
                pass
            _refresh_counter = 0
        time.sleep(15)


# Unbound query log format varies by version:
#   Old: info: 192.168.1.5 A example.com. NOERROR 0.001234
#   New: info: 192.168.1.5#12345 A example.com. IN NOERROR 0.001234
# group1=client_ip  group2=first-word  group3=second-word  group4=rcode-or-class
# _collect_dns_queries determines name vs qtype from the captured groups.
_UNBOUND_QUERY_RE = re.compile(
    r'info:\s+'
    r'([\d.a-fA-F:]+)(?:#\d+)?'    # group1: client_ip (strip optional #port)
    r'\s+([\w.\-]+\.?)'             # group2: first token (qtype or query_name)
    r'\s+([\w.\-]+\.?)'             # group3: second token
    r'(?:\s+\w+)?'                  # optional third token (class IN, or another field)
    r'\s+(\w+)'                     # group4: rcode (NOERROR, NXDOMAIN, SERVFAIL…)
)


def _read_dns_logging_mode() -> str:
    """Operator-controlled mode: ``off`` | ``blocked_only`` | ``all``.

    Persisted in ``siem_state`` (seeded by migration v39). Cached on the
    state dict for 30s to avoid hitting the DB per log line.
    """
    try:
        from app.database import get_db
        row = get_db().execute(
            "SELECT value FROM siem_state WHERE key = 'dns_logging_mode'"
        ).fetchone()
        if row and row["value"] in ("off", "blocked_only", "all"):
            return row["value"]
    except Exception:
        pass
    return "blocked_only"


def _insert_dns_event(event_uuid: str, ts: str, client_ip: str,
                      query_name: str, qtype: str, response: str,
                      blocked: bool, host: dict, raw_line: str):
    """Mirror a parsed DNS query into the dns_events specialised table."""
    if not event_uuid:
        return
    try:
        from app.audit_log import _events_db
    except Exception:
        return
    conn = _events_db()
    if conn is None:
        return
    # Resolve the domain through the unified policy map so the row carries
    # the matched parent domain, canonical action, and source filter — not
    # just the Unbound-derived `blocked` heuristic.
    policy = None
    matched_domain = None
    action_canonical = "allow"
    policy_source = ""
    category = ""
    try:
        from app.services.content_policy import resolve_domain_policy
        from app.database import get_db
        policy = resolve_domain_policy(get_db(), query_name)
        if policy is not None:
            matched_domain = policy.domain
            action_canonical = policy.action
            policy_source = policy.source
    except Exception:
        pass

    # Final blocked flag: policy says block_all/redirect/whitelist-only OR the
    # collector's caller already saw an Unbound-side block hint.
    is_blocked_final = bool(blocked) or (
        policy is not None and policy.action in (
            "block_all", "redirect", "allow_whitelist_only"
        )
    )

    try:
        conn.execute(
            "INSERT INTO dns_events ("
            "  event_uuid, ts, client_ip, query, qtype, rcode, action, "
            "  blocked, matched_domain, policy_source, category, "
            "  hostname, mac, raw_line"
            ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                event_uuid, ts, client_ip, query_name, qtype, response,
                action_canonical if is_blocked_final else "allow",
                1 if is_blocked_final else 0,
                matched_domain,
                policy_source,
                category,
                host.get("hostname", "") if host else "",
                host.get("mac_address", "") if host else "",
                raw_line[:4096] if raw_line else "",
            ),
        )
        conn.commit()
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _domain_matches_policy(query_name: str, blocked_domains: set) -> bool:
    """True when *query_name* or any parent domain is in the blocked set.

    Subdomain-aware: a policy on ``example.com`` matches ``ads.example.com``.
    Used so the collector's blocked-mode filter and severity match what the
    DNS policy actually enforces (not just exact-string equality).
    """
    q = (query_name or "").strip(".").lower()
    if not q:
        return False
    parts = q.split(".")
    candidates = [".".join(parts[i:]) for i in range(len(parts))]
    return any(c in blocked_domains for c in candidates)


def _collect_dns_queries(state: dict):
    if not os.path.exists(_UNBOUND_QUERY_LOG):
        return

    # Refresh the logging-mode cache every 30s so operator changes take
    # effect quickly without hammering the settings table per query.
    now = time.time()
    if now - state.get("dns_mode_ts", 0) > 30:
        state["dns_logging_mode"] = _read_dns_logging_mode()
        state["dns_mode_ts"] = now
    mode = state.get("dns_logging_mode") or "blocked_only"
    if mode == "off":
        return

    prev_offset = state.get("dns_offset", 0)
    lines, new_offset = _tail_file(_UNBOUND_QUERY_LOG, prev_offset)

    # Load blocked domains once per cycle for fast lookup
    blocked: set = state.get("blocked_domains", set())

    # Only advance the saved offset once the whole batch processed — a
    # transient DB/parse error must not skip unprocessed lines forever.
    processed_ok = False
    try:
        for line in lines:
            m = _UNBOUND_QUERY_RE.search(line)
            if not m:
                continue
            try:
                client_ip = m.group(1)
                g2, g3    = m.group(2), m.group(3)
                response  = m.group(4)

                # Determine which token is the qtype vs the query name.
                # Qtypes are short all-uppercase words (A, AAAA, MX, TXT, PTR…).
                # Query names contain dots and mixed case.
                if re.match(r'^[A-Z]{1,10}$', g2):
                    qtype, query_name = g2, g3.rstrip(".")
                else:
                    query_name, qtype = g2.rstrip("."), g3

                # Policy match is subdomain-aware. NXDOMAIN/SERVFAIL are DNS
                # outcomes, not proof of a policy block — counting them as
                # blocked produced false security alerts, so they no longer do.
                is_blocked = _domain_matches_policy(query_name, blocked)

                if mode == "blocked_only" and not is_blocked:
                    continue
                # mode == "all" — log every query

                host = _lookup_tracked_host(client_ip) if _is_lan_ip(client_ip) else {}
                event_uuid = _log(
                    "connection", "dns_query", remote_addr=client_ip,
                    severity="medium" if is_blocked else "info",
                    details={
                        "query":    query_name,
                        "type":     qtype,
                        "response": response,
                        "blocked":  is_blocked,
                        "client_ip": client_ip,
                        "hostname": host.get("hostname", ""),
                        "mac":      host.get("mac_address", ""),
                    },
                )
                _insert_dns_event(event_uuid, _now_utc(), client_ip, query_name,
                                  qtype, response, is_blocked, host, line)
            except Exception as exc:
                try:
                    from app.services.collector_health import record_dead_letter
                    record_dead_letter("dns_queries", source_type="dns",
                                       reason=f"parse_failed: {exc}",
                                       raw_payload=line)
                except Exception:
                    pass
        processed_ok = True
    finally:
        if processed_ok and new_offset != prev_offset:
            _save_offset("dns_offset", new_offset)
            state["dns_offset"] = new_offset


def _refresh_blocked_domains(state: dict):
    """Load enforcing domains (across DNS / web / app filters) for the DNS
    collector. Uses the unified policy map so canonical action values
    (``block_all``, ``allow_whitelist_only``, ``redirect``) are honoured the
    same as the legacy ``block`` string.
    """
    try:
        from app.database import get_db
        from app.services.content_policy import build_domain_policy_map
        db = get_db()
        policies = build_domain_policy_map(db)
        state["blocked_domains"] = {
            d for d, p in policies.items()
            if p.action in ("block_all", "allow_whitelist_only", "redirect")
        }
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

            # Routine new-connection logging is intentionally NOT emitted here
            # — it is very high volume and is now covered by the siem-pflog
            # packet collector. Only the security signal below is kept.

            # Raise a security alert for insecure/dangerous protocols
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
# 4b. PF packet-log collector (pflog0)
#
# PF rules emit the `log` keyword (see pf_generator.py), copying matched
# packets to the pflog0 pseudo-interface.  This collector tails pflog0 via
# tcpdump so blocked (and, opt-in, passed) packets become `firewall` events,
# capturing short-lived and dropped flows the 60 s `pfctl -s states` snapshot
# misses.
# ---------------------------------------------------------------------------

_PFLOG_COOLDOWN = 120   # seconds — suppress repeats of the same flow


def _firewall_event_severity(parsed: dict, policy_source: str = "") -> str:
    """Severity ladder for the firewall_events row.

    The ladder reflects what an operator wants paged on:

      * pass                                  — info
      * block of any kind                     — low (baseline)
      * block on privileged-port destination  — medium
      * block on WAN-inbound admin-port       — high (likely scan)
      * block whose label is ``ids``          — high (IDS-sourced)
      * block whose label is ``soc``          — high (analyst block)

    ``policy_source`` comes from the parsed pflog label
    (``_policy_source_from_label``); it lets the ladder treat an IDS-triggered
    block as high-severity without needing to look up the rule_id again.
    """
    action = parsed.get("action") or ""
    if action != "block":
        return "info"

    if policy_source in ("ids", "soc"):
        return "high"

    dst_port = parsed.get("dst_port")
    direction = parsed.get("direction") or ""
    # WAN inbound to admin/SSH/etc. — anyone scanning the WAN side is loud
    # enough to surface above routine bogon/private-net blocks.
    if direction == "in" and dst_port in (22, 443, 5000, 8443):
        return "high"

    if dst_port is not None and 0 < dst_port < 1024:
        return "medium"
    return "low"


# Known policy sources emitted by pf_generator / captive_portal labels.
# Anything else is collapsed to ``external_or_unlabeled`` so the UI can offer a
# stable filter dropdown without surprise values from third-party PF anchors.
_KNOWN_POLICY_SOURCES = frozenset({
    "user_rule", "default_deny", "captive_portal", "content_policy",
    "hardening", "admin", "ids", "soc",
})


def _policy_source_from_label(label) -> tuple[str, str]:
    """Decode a ``smartshield:<source>:<detail>`` label into ``(source, detail)``.

    Returns ``("external_or_unlabeled", "")`` for missing / non-Smart-Shield
    labels so every ``firewall_events`` row still has a meaningful
    ``policy_source`` value, and the UI's source filter can offer a single
    catch-all option instead of leaking raw anchor names.
    """
    if not label:
        return "external_or_unlabeled", ""
    parts = str(label).split(":", 2)
    if len(parts) < 2 or parts[0] != "smartshield":
        return "external_or_unlabeled", ""
    source = parts[1] or "external_or_unlabeled"
    detail = parts[2] if len(parts) > 2 else ""
    if source not in _KNOWN_POLICY_SOURCES:
        # Surface the actual token in the detail field so debugging is easy
        # while keeping the source value stable for filtering.
        return "external_or_unlabeled", f"{source}:{detail}" if detail else source
    return source, detail


def _insert_firewall_event(parsed: dict, event_uuid: str, ts: str,
                           host: dict, severity: str):
    """Mirror a parsed pflog packet into the firewall_events table.

    Best-effort: the events-table write is the durability guarantee, so any
    failure here is swallowed — the row will still be queryable from the
    generic events feed even if this dedicated insert fails.
    """
    try:
        from app.audit_log import _events_db
    except Exception:
        return
    conn = _events_db()
    if conn is None:
        return
    policy_source, _detail = _policy_source_from_label(parsed.get("rule_label"))
    # Recompute severity now that we know the policy source — IDS-/SOC-emitted
    # blocks deserve a higher tier than a routine privileged-port drop.
    severity = _firewall_event_severity(parsed, policy_source=policy_source)
    try:
        conn.execute(
            "INSERT INTO firewall_events ("
            "  event_uuid, ts, action, direction, interface, ip_version, "
            "  protocol, src_ip, src_port, dst_ip, dst_port, rule_id, "
            "  rule_label, tcp_flags, icmp_type, packet_length, "
            "  hostname, mac, severity, policy_source, raw_line"
            ") VALUES (?,?,?,?,?,?, ?,?,?,?,?,?, ?,?,?,?, ?,?,?,?,?)",
            (
                event_uuid, ts,
                parsed.get("action") or "",
                parsed.get("direction"),
                parsed.get("interface"),
                parsed.get("ip_version"),
                parsed.get("protocol"),
                parsed.get("src_ip"),
                parsed.get("src_port"),
                parsed.get("dst_ip"),
                parsed.get("dst_port"),
                parsed.get("rule_id"),
                parsed.get("rule_label"),
                parsed.get("tcp_flags"),
                parsed.get("icmp_type"),
                parsed.get("packet_length"),
                host.get("hostname", "") if host else "",
                host.get("mac_address", "") if host else "",
                severity,
                policy_source,
                parsed.get("raw_line"),
            ),
        )
        conn.commit()
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _handle_pflog_line(state: dict, line: str):
    """Parse one tcpdump-pflog line into a firewall event and a firewall_events row."""
    from app.services.parsers.pf_parser import parse_pflog_line
    parsed = parse_pflog_line(line)
    if not parsed:
        # Garbled / non-rule lines (tcpdump banners, truncated buffers) —
        # only DLQ the ones that LOOK like rule events but failed to parse,
        # so we do not flood the dead-letter table with normal noise.
        if "rule " in line and "(match)" in line:
            try:
                from app.services.collector_health import record_dead_letter
                record_dead_letter("pflog0", source_type="firewall",
                                   reason="pf_parser_no_match",
                                   raw_payload=line)
            except Exception:
                pass
        return

    action    = parsed.get("action") or ""
    direction = parsed.get("direction") or ""
    iface     = parsed.get("interface") or ""
    src_ip    = parsed.get("src_ip") or ""
    dst_ip    = parsed.get("dst_ip") or ""
    dst_port  = parsed.get("dst_port")
    proto     = parsed.get("protocol") or ""

    if action == "pass" and not state.get("pflog_log_passes"):
        return                       # blocks logged by default; passes opt-in

    # Per-flow cooldown so a chatty scanner cannot flood the event log.
    seen = state.setdefault("pflog_seen", {})
    key  = (action, src_ip, dst_ip, dst_port)
    now  = time.time()
    if now - seen.get(key, 0) < _PFLOG_COOLDOWN:
        return
    seen[key] = now
    if len(seen) > 5000:                       # bound memory
        for k in [k for k, t in seen.items() if now - t > _PFLOG_COOLDOWN]:
            seen.pop(k, None)

    host = _lookup_tracked_host(src_ip) if src_ip else {}
    severity = _firewall_event_severity(parsed)

    event_uuid = _log(
        category="firewall",
        action="pf_block" if action == "block" else "pf_pass",
        remote_addr=src_ip,
        details={
            "direction":  direction,
            "interface":  iface,
            "proto":      proto,
            "protocol":   proto,        # alias picked up by normalisation
            "src_ip":     src_ip,
            "src_port":   parsed.get("src_port"),
            "dst_ip":     dst_ip,
            "dst_port":   dst_port,
            "ip_version": parsed.get("ip_version"),
            "tcp_flags":  parsed.get("tcp_flags"),
            "icmp_type":  parsed.get("icmp_type"),
            "rule_id":    parsed.get("rule_id"),
            "hostname":   host.get("hostname", ""),
            "mac":        host.get("mac_address", ""),
            "raw_line":   parsed.get("raw_line"),
        },
        severity=severity,
    )

    # Mirror into the specialised firewall_events table so the upcoming
    # /firewall/logs page can filter on indexed columns rather than JSON.
    if event_uuid:
        _insert_firewall_event(parsed, event_uuid, _now_utc(), host, severity)


def _run_pflog_collector(state: dict):
    """Tail pflog0 via tcpdump; restart the subprocess if it dies."""
    if not _ON_FREEBSD:
        return
    import subprocess
    while True:
        proc = None
        try:
            # ``-v`` is what makes tcpdump print the PF rule label
            # (``[label "smartshield:<source>:<detail>"]``) in the rule header
            # — without it the label is dropped and the firewall log can't tell
            # captive_portal events apart from hardening / user_rule events.
            proc = subprocess.Popen(
                ["tcpdump", "-l", "-n", "-e", "-v", "-i", "pflog0"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, bufsize=1,
            )
            for line in proc.stdout:
                try:
                    _handle_pflog_line(state, line)
                except Exception:
                    pass
        except Exception:
            pass
        finally:
            if proc is not None:
                try:
                    proc.kill()
                except Exception:
                    pass
        time.sleep(10)   # tcpdump exited — wait, then restart


# ---------------------------------------------------------------------------
# 5. Correlation engine driver
#
# The previously hard-coded brute-force / IDS-flood detectors are now two
# default rows in the `correlation_rules` table; this thread simply runs the
# user-configurable correlation engine every 60 s.
# ---------------------------------------------------------------------------

def _run_anomaly_detector(state: dict):
    while True:
        try:
            from app.services.correlation_engine import evaluate
            evaluate()
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
                _log("security", "brute_force_detected", remote_addr=ip,
                     severity="high",
                     details={
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
                _log("security", "ids_flood_detected", remote_addr=src,
                     severity="high",
                     details={
                         "count":          count,
                         "window_minutes": 5,
                         "top_signature":  top_sig,
                     })


# ---------------------------------------------------------------------------
# 6. SSH / Auth Log Collector
# ---------------------------------------------------------------------------

_SSH_FAIL_RE = re.compile(
    r'sshd\[\d+\]: Failed (\S+) for (?:invalid user )?(\S+) from ([\d.a-fA-F:]+) port (\d+)'
)
_SSH_OK_RE = re.compile(
    r'sshd\[\d+\]: Accepted (\S+) for (\S+) from ([\d.a-fA-F:]+) port (\d+)'
)
_SU_FAIL_RE = re.compile(
    r'su: BAD SU (\S+) to (\S+)'
)


def _run_syslog_collector(state: dict):
    while True:
        try:
            _collect_syslog_events(state)
        except Exception:
            pass
        time.sleep(15)


def _collect_syslog_events(state: dict):
    if not os.path.exists(_AUTH_LOG):
        return

    prev_offset = state.get("syslog_offset", 0)
    lines, new_offset = _tail_file(_AUTH_LOG, prev_offset)

    processed_ok = False
    try:
        for line in lines:
          try:
            m = _SSH_FAIL_RE.search(line)
            if m:
                method, user, src_ip, port = m.group(1), m.group(2), m.group(3), m.group(4)
                host = _lookup_tracked_host(src_ip) if _is_lan_ip(src_ip) else {}
                _log("security", "ssh_login_failed", remote_addr=src_ip, severity="medium",
                     details={
                         "method":   method,
                         "user":     user,
                         "src_ip":   src_ip,
                         "port":     int(port),
                         "hostname": host.get("hostname", ""),
                     })
                continue

            m = _SSH_OK_RE.search(line)
            if m:
                method, user, src_ip, port = m.group(1), m.group(2), m.group(3), m.group(4)
                host = _lookup_tracked_host(src_ip) if _is_lan_ip(src_ip) else {}
                _log("session", "ssh_login_success", remote_addr=src_ip, severity="info",
                     details={
                         "method":   method,
                         "user":     user,
                         "src_ip":   src_ip,
                         "port":     int(port),
                         "hostname": host.get("hostname", ""),
                     })
                continue

            m = _SU_FAIL_RE.search(line)
            if m:
                from_user, to_user = m.group(1), m.group(2)
                _log("security", "su_attempt_failed", remote_addr="", severity="high",
                     details={"from_user": from_user, "to_user": to_user})
          except Exception as exc:
            try:
                from app.services.collector_health import record_dead_letter
                record_dead_letter("auth_syslog", source_type="auth",
                                   reason=f"parse_failed: {exc}", raw_payload=line)
            except Exception:
                pass
        processed_ok = True
    finally:
        if processed_ok and new_offset != prev_offset:
            _save_offset("syslog_offset", new_offset)
            state["syslog_offset"] = new_offset


# ---------------------------------------------------------------------------
# 7. System Messages Collector
# ---------------------------------------------------------------------------

_KERN_PANIC_RE  = re.compile(r'kernel: panic')
_LINK_STATE_RE  = re.compile(
    r'((?:em|vtnet|igb|ix|bge|cxl|bnxt)\d+): link state changed to (UP|DOWN)',
    re.IGNORECASE,
)
_PF_OVERLOAD_RE = re.compile(r'pf: (?:src limit|table.*full|overload)', re.IGNORECASE)
_CARP_RE        = re.compile(r'(carp\d+).*?became (MASTER|BACKUP)', re.IGNORECASE)
_OOM_RE         = re.compile(r'kernel: (?:pid \d+.*?out of swap|swap_pager)')


def _run_system_collector(state: dict):
    while True:
        try:
            _collect_system_events(state)
        except Exception:
            pass
        time.sleep(30)


def _collect_system_events(state: dict):
    if not os.path.exists(_MESSAGES_LOG):
        return

    prev_offset = state.get("messages_offset", 0)
    lines, new_offset = _tail_file(_MESSAGES_LOG, prev_offset)

    processed_ok = False
    try:
        for line in lines:
          try:
            if _KERN_PANIC_RE.search(line):
                _log("system", "kernel_panic", severity="critical",
                     details={"message": line.strip()[-200:]})
                continue

            m = _LINK_STATE_RE.search(line)
            if m:
                iface, new_state = m.group(1), m.group(2).upper()
                sev = "high" if new_state == "DOWN" else "info"
                _log("network", "link_state_change", severity=sev,
                     details={"interface": iface, "state": new_state,
                              "message": line.strip()[-200:]})
                continue

            if _PF_OVERLOAD_RE.search(line):
                _log("security", "pf_table_overload", severity="high",
                     details={"message": line.strip()[-200:]})
                continue

            m = _CARP_RE.search(line)
            if m:
                iface, new_state = m.group(1), m.group(2).upper()
                _log("network", "carp_state_change", severity="medium",
                     details={"interface": iface, "state": new_state,
                              "message": line.strip()[-200:]})
                continue

            if _OOM_RE.search(line):
                _log("system", "out_of_memory", severity="critical",
                     details={"message": line.strip()[-200:]})
          except Exception as exc:
            try:
                from app.services.collector_health import record_dead_letter
                record_dead_letter("system_messages", source_type="system",
                                   reason=f"parse_failed: {exc}", raw_payload=line)
            except Exception:
                pass
        processed_ok = True
    finally:
        if processed_ok and new_offset != prev_offset:
            _save_offset("messages_offset", new_offset)
            state["messages_offset"] = new_offset


# ---------------------------------------------------------------------------
# 8b. VPN log tailer — strongSwan (IPsec) + mpd5 (L2TP)
#
# Complements the OpenVPN hook script + session poller: tails the daemon
# log files and converts the structured lines into `vpn` events so IPsec
# IKE failures / child SA installs and L2TP sessions show up in the same
# pipeline as Suricata alerts.
# ---------------------------------------------------------------------------

_STRONGSWAN_LOG = "/var/log/strongswan.log"
_MPD5_LOG       = "/var/log/mpd.log"

_IPSEC_AUTH_RE = re.compile(
    r"(?:received|sending|generating)\s+(?P<kind>IKE_AUTH|AUTHENTICATION_FAILED|"
    r"CHILD_SA_INSTALLED|ESTABLISHED|DELETE)",
    re.IGNORECASE,
)
_IPSEC_PEER_RE = re.compile(
    r"(?:peer|remote)[^0-9A-Fa-f]*"
    r"(?P<peer>(?:\d{1,3}(?:\.\d{1,3}){3})|(?:[0-9A-Fa-f:]+:[0-9A-Fa-f:]+))"
)
_MPD_OPEN_RE  = re.compile(r"\[(?P<bundle>L\d+(?:-\d+)?)\]\s+Link:?\s+OPEN")
_MPD_CLOSE_RE = re.compile(r"\[(?P<bundle>L\d+(?:-\d+)?)\]\s+Link:?\s+(?:CLOSE|SHUTDOWN)")


def _run_vpn_log_tailer(state: dict):
    while True:
        try:
            _collect_strongswan_lines(state)
            _collect_mpd5_lines(state)
        except Exception:
            pass
        time.sleep(30)


def _collect_strongswan_lines(state: dict):
    if not os.path.exists(_STRONGSWAN_LOG):
        return
    prev_offset = state.get("strongswan_offset",
                            _load_offset("strongswan_offset", 0))
    lines, new_offset = _tail_file(_STRONGSWAN_LOG, prev_offset)

    processed_ok = False
    try:
        for line in lines:
            m = _IPSEC_AUTH_RE.search(line)
            if not m:
                continue
            try:
                kind = m.group("kind").upper()
                peer_match = _IPSEC_PEER_RE.search(line)
                peer = peer_match.group("peer") if peer_match else ""

                if "FAIL" in kind:
                    action, severity = "vpn_auth_fail", "medium"
                elif "INSTALLED" in kind or "ESTABLISHED" in kind:
                    action, severity = "vpn_connect", "info"
                elif "DELETE" in kind:
                    action, severity = "vpn_disconnect", "info"
                else:
                    action, severity = "vpn_event", "info"

                _log("vpn", action, remote_addr=peer, severity=severity,
                     details={"vpn": "ipsec", "kind": kind,
                              "message": line.strip()[-512:]})
            except Exception as exc:
                try:
                    from app.services.collector_health import record_dead_letter
                    record_dead_letter("strongswan", source_type="vpn",
                                       reason=f"parse_failed: {exc}", raw_payload=line)
                except Exception:
                    pass
        processed_ok = True
    finally:
        if processed_ok and new_offset != prev_offset:
            _save_offset("strongswan_offset", new_offset)
            state["strongswan_offset"] = new_offset


def _collect_mpd5_lines(state: dict):
    if not os.path.exists(_MPD5_LOG):
        return
    prev_offset = state.get("mpd5_offset", _load_offset("mpd5_offset", 0))
    lines, new_offset = _tail_file(_MPD5_LOG, prev_offset)

    processed_ok = False
    try:
        for line in lines:
          try:
            m = _MPD_OPEN_RE.search(line)
            if m:
                _log("vpn", "vpn_connect", severity="info",
                     details={"vpn": "l2tp", "bundle": m.group("bundle"),
                              "message": line.strip()[-512:]})
                continue
            m = _MPD_CLOSE_RE.search(line)
            if m:
                _log("vpn", "vpn_disconnect", severity="info",
                     details={"vpn": "l2tp", "bundle": m.group("bundle"),
                              "message": line.strip()[-512:]})
          except Exception as exc:
            try:
                from app.services.collector_health import record_dead_letter
                record_dead_letter("mpd5", source_type="vpn",
                                   reason=f"parse_failed: {exc}", raw_payload=line)
            except Exception:
                pass
        processed_ok = True
    finally:
        if processed_ok and new_offset != prev_offset:
            _save_offset("mpd5_offset", new_offset)
            state["mpd5_offset"] = new_offset


# ---------------------------------------------------------------------------
# 9. VPN session collector — OpenVPN client connect/disconnect
# ---------------------------------------------------------------------------

def _run_vpn_collector(state: dict):
    while True:
        try:
            _collect_vpn_sessions(state)
        except Exception:
            pass
        time.sleep(30)


def _collect_vpn_sessions(state: dict):
    if not _ON_FREEBSD:
        return
    try:
        from app.database import get_db
        from app.services.openvpn_writer import get_connected_clients
        # NOTE: column is `disabled`, not `enabled` — earlier copy of this
        # collector silently matched zero rows because of the wrong WHERE.
        servers = get_db().execute(
            "SELECT id FROM openvpn_servers WHERE COALESCE(disabled, 0) = 0"
        ).fetchall()
    except Exception:
        return

    seen = state.setdefault("vpn_seen", {})        # server_id -> {common_name: real_addr}
    for srv in servers:
        sid = srv["id"]
        try:
            clients = get_connected_clients(sid)
        except Exception:
            continue
        current = {c.get("common_name", ""): c
                   for c in clients if c.get("common_name")}
        prev = seen.get(sid, {})

        for cn, c in current.items():
            if cn not in prev:
                _log("vpn", "vpn_client_connected", severity="info",
                     remote_addr=(c.get("real_address", "") or "").split(":")[0],
                     details={"vpn": "openvpn", "server_id": sid,
                              "common_name": cn,
                              "real_address": c.get("real_address", ""),
                              "virtual_address": c.get("virtual_address", "")})
        for cn in prev:
            if cn not in current:
                _log("vpn", "vpn_client_disconnected", severity="info",
                     details={"vpn": "openvpn", "server_id": sid,
                              "common_name": cn})
        seen[sid] = {cn: c.get("real_address", "") for cn, c in current.items()}


# ---------------------------------------------------------------------------
# 10. Health collector — service crash/recovery, cert expiry, WAN-IP change
# ---------------------------------------------------------------------------

_HEALTH_SERVICES = ["pf", "unbound", "isc-dhcpd", "suricata", "nginx", "openvpn"]
_WAN_INET_RE = re.compile(r'\binet (\d{1,3}(?:\.\d{1,3}){3})')


def _run_health_collector(state: dict):
    while True:
        try:
            _collect_health(state)
        except Exception:
            pass
        time.sleep(60)


def _collect_health(state: dict):
    if not _ON_FREEBSD:
        return

    # ── Service watch — transition-only (running -> stopped / stopped -> running)
    try:
        from app.services.service_manager import service_status
        svc_state = state.setdefault("svc_state", {})
        for svc in _HEALTH_SERVICES:
            try:
                running = bool(service_status(svc).get("running", False))
            except Exception:
                continue
            prev = svc_state.get(svc)
            if prev is not None and prev != running:
                if running:
                    _log("system", "service_recovered", severity="medium",
                         details={"service": svc})
                else:
                    _log("system", "service_down", severity="high",
                         details={"service": svc})
            svc_state[svc] = running
    except Exception:
        pass

    # ── Certificate expiry — checked hourly, logged once per cert+status
    now = time.time()
    if now - state.get("cert_check_ts", 0) >= 3600:
        state["cert_check_ts"] = now
        try:
            from app.database import get_db
            from app.services.cert_manager import get_expiring_certs
            alerted = state.setdefault("cert_alerted", set())
            for c in get_expiring_certs(get_db()).get("certs", []):
                status = c.get("status")
                if status not in ("expired", "expiring_soon"):
                    continue
                key = (c.get("id"), status)
                if key in alerted:
                    continue
                alerted.add(key)
                _log("system",
                     "cert_expired" if status == "expired" else "cert_expiring",
                     severity="high" if status == "expired" else "medium",
                     details={"cert_id": c.get("id"), "name": c.get("name"),
                              "days_remaining": c.get("days_remaining"),
                              "not_after": c.get("not_after")})
        except Exception:
            pass

    # ── WAN-IP change
    try:
        from app.database import get_db
        row = get_db().execute(
            "SELECT assigned_port FROM wan_config WHERE id=1"
        ).fetchone()
        iface = (row["assigned_port"] if row else "") or ""
        if iface:
            import subprocess
            out = subprocess.run(["ifconfig", iface], capture_output=True,
                                 text=True, timeout=5).stdout or ""
            m = _WAN_INET_RE.search(out)
            wan_ip = m.group(1) if m else ""
            prev_ip = state.get("wan_ip")
            if wan_ip and prev_ip is not None and wan_ip != prev_ip:
                _log("network", "wan_ip_changed", severity="medium",
                     details={"interface": iface, "old_ip": prev_ip,
                              "new_ip": wan_ip})
            if wan_ip:
                state["wan_ip"] = wan_ip
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

def start_siem_collectors():
    """
    Start all ten SIEM background collector threads.
    Safe to call multiple times — only starts once per process.
    On non-FreeBSD the collectors silently do nothing.
    """
    if _STARTED.is_set():
        return
    _STARTED.set()

    shared_state: dict = {
        "ids_offset":        _load_offset("ids_offset",        0),
        "dns_offset":        _load_offset("dns_offset",        0),
        "syslog_offset":     _load_offset("syslog_offset",     0),
        "messages_offset":   _load_offset("messages_offset",   0),
        "strongswan_offset": _load_offset("strongswan_offset", 0),
        "mpd5_offset":       _load_offset("mpd5_offset",       0),
        "dhcp_seen":         set(),
        "pf_seen":           set(),
        "pflog_seen":        {},
        "alerted":           {},
    }

    collectors = [
        ("siem-ids",       _run_ids_collector,      shared_state),
        ("siem-dhcp",      _run_dhcp_collector,      shared_state),
        ("siem-dns",       _run_dns_collector,        shared_state),
        ("siem-pf",        _run_pf_collector,         shared_state),
        ("siem-pflog",     _run_pflog_collector,      shared_state),
        ("siem-anomaly",   _run_anomaly_detector,     shared_state),
        ("siem-syslog",    _run_syslog_collector,     shared_state),
        ("siem-system",    _run_system_collector,     shared_state),
        ("siem-vpn",       _run_vpn_collector,        shared_state),
        ("siem-vpn-log",   _run_vpn_log_tailer,       shared_state),
        ("siem-health",    _run_health_collector,     shared_state),
    ]

    for name, target, state in collectors:
        t = threading.Thread(target=target, args=(state,), name=name, daemon=True)
        t.start()

    # Background pruner: keeps the indexed `events` table bounded.
    try:
        from app.services.events_retention import start_retention_pruner
        start_retention_pruner()
    except Exception:
        pass

    # Optional UDP syslog ingest — disabled by default; the listener thread
    # spins up regardless and stays idle when the config has enabled=False.
    try:
        from app.services.syslog_listener import start_syslog_listener
        start_syslog_listener()
    except Exception:
        pass

    # Saved-search scheduler — also drives the hourly risk-score decay.
    try:
        from app.services.saved_searches import start_scheduler as _start_sched
        _start_sched()
    except Exception:
        pass

    # IDS self-healing watchdog — restarts Suricata when ids_config.enabled=1
    # but the daemon has died. Rate-limited (5 min cooldown, ≤6 attempts/h)
    # and disable-able per appliance via ids_config.watchdog_enabled.
    try:
        from app.services.ids_watchdog import start_ids_watchdog
        start_ids_watchdog()
    except Exception:
        pass


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
