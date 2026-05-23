"""
ids_writer.py
-------------
Generates Suricata YAML configuration from Smart Shield's ids_config /
ids_rulesets tables and manages the suricata service on FreeBSD.

FreeBSD package:  pkg install suricata
Service name:     suricata
Config path:      /usr/local/etc/suricata/suricata.yaml
Rules dir:        /usr/local/etc/suricata/rules/
Logs:             /var/log/suricata/

Public API
----------
generate_suricata_yaml(conn)     -> str
write_suricata_config(conn)      -> {"ok", "message", "conf"}
update_rules(conn)               -> {"ok", "message", "updated": [...]}
get_ids_status()                 -> {"ok", "running", "mode", "message", "alerts_today"}
toggle_ids(conn, enabled: bool)  -> {"ok", "message"}
"""

import json
import os
import sys
import textwrap

from app.services.network_service import run_command, FreeBSDNetworkError
from app.services.service_manager import service_action, sysrc_set

_SURICATA_CONF_DIR    = "/usr/local/etc/suricata"
_SURICATA_CONF_PATH   = "/usr/local/etc/suricata/suricata.yaml"
_SURICATA_RULES_DIR   = "/usr/local/etc/suricata/rules"
# suricata-update writes a single merged rule file here (not per-source)
_SURICATA_UPDATE_RULES = "/var/lib/suricata/rules/suricata.rules"
_SURICATA_LOG_DIR     = "/var/log/suricata"
_SURICATA_RUN_DIR     = "/var/run/suricata"
_SERVICE_NAME         = "suricata"


# ---------------------------------------------------------------------------
# In-memory phase tracker for the Enable button lifecycle
# ---------------------------------------------------------------------------
# Surfaces the toggle lifecycle to the GUI without persisting to SQLite.
# Process state is a runtime concern — keeping it in memory avoids the
# "DB says enabled but daemon isn't running" divergence that the rest of
# this module carefully avoids by deriving running-state from pgrep every
# call. The GUI calls /ids/api/diagnostics to read this between requests.

_PHASES = ("STOPPED", "UPDATING_RULES", "VALIDATING_CONFIG",
           "LOADING_KMOD", "STARTING", "RUNNING", "ERROR")

_IDS_STATE = {
    "phase": "STOPPED",
    "error": None,
    "last_phase_at": None,
    "last_success_at": None,
}


def _set_phase(phase, error=None):
    """Update the in-memory IDS phase. Unknown phases are silently dropped."""
    import time
    if phase not in _PHASES:
        return
    _IDS_STATE["phase"] = phase
    _IDS_STATE["error"] = error
    _IDS_STATE["last_phase_at"] = time.time()
    if phase == "RUNNING":
        _IDS_STATE["last_success_at"] = _IDS_STATE["last_phase_at"]


def get_ids_phase():
    """Return a snapshot copy of the phase tracker — safe to JSON-serialize."""
    return dict(_IDS_STATE)


def _find_suricata_update() -> "str | None":
    """Return the absolute path to suricata-update, or None if absent.

    Preference order:
      1. Project venv binary — clean isolated dependency metadata, avoids the
         pkg_resources.ResolutionError that affects system-Python installs.
      2. Direct path probes — /usr/local/bin is frequently missing from the
         daemon's PATH on FreeBSD, so probe explicitly.
      3. PATH lookup as a last resort.
    """
    import shutil
    # 1. Same Python as the running app (works regardless of where the venv lives).
    venv_bin = os.path.join(os.path.dirname(sys.executable), "suricata-update")
    if os.path.isfile(venv_bin) and os.access(venv_bin, os.X_OK):
        return venv_bin
    # 2. Conventional system locations.
    for candidate in ("/usr/local/bin/suricata-update", "/usr/bin/suricata-update"):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    # 3. Anything else on PATH.
    return shutil.which("suricata-update")


def _mem_budget() -> str:
    """
    Return ``'low'`` for small appliances (≲2 GiB RAM), else ``'normal'``.

    Suricata's detect engine plus its memcaps must fit alongside the rest of
    the Smart Shield stack (gunicorn, nginx, unbound, dhcpd…). On a small box
    the larger defaults get the daemon OOM-killed shortly after it starts
    processing traffic.
    """
    if not sys.platform.startswith("freebsd"):
        return "normal"
    try:
        r = run_command(["sysctl", "-n", "hw.physmem"], check=False)
        physmem = int((r.stdout or "0").strip() or 0)
    except Exception:
        physmem = 0
    # hw.physmem is in bytes; treat ≤2.5 GiB as "low" (covers 2 GB boxes).
    if physmem and physmem <= 2_684_354_560:
        return "low"
    return "normal"


def ensure_rules_file() -> bool:
    """
    Guarantee the merged Suricata rules file exists.

    Suricata (and ``suricata -T``) warns and loads 0 rules when the file named
    in ``rule-files`` is absent — and on some builds the test mode then fails
    outright, which deadlocks first-time enable. Creating an empty placeholder
    makes the deep check pass cleanly; real rules from ``suricata-update``
    simply overwrite it. Returns True when a file is present. Never raises.
    """
    if not sys.platform.startswith("freebsd"):
        return True
    try:
        os.makedirs(os.path.dirname(_SURICATA_UPDATE_RULES), exist_ok=True)
        if not os.path.exists(_SURICATA_UPDATE_RULES):
            with open(_SURICATA_UPDATE_RULES, "a"):
                pass
        return True
    except Exception:
        return False


def ensure_rules_present(conn) -> dict:
    """
    Make sure a usable rules file exists before the deep check or a daemon
    start. Creates the empty placeholder, and when the merged file is still
    empty fetches it once via suricata-update.

    A failed fetch is non-fatal — the placeholder keeps the deep check
    passing and Suricata starts with 0 rules until the operator retries.
    Shared by ``toggle_ids`` and the watchdog so both bootstrap identically.
    Returns ``{"ok", "fetched": bool, "degraded": bool, "rules_size": int,
    "rules_path", "message"}`` so callers can warn loudly when a daemon would
    start with an empty ruleset. ``degraded`` is True whenever the merged rules
    file is empty (0 bytes). Never raises.
    """
    def _size() -> int:
        try:
            return os.path.getsize(_SURICATA_UPDATE_RULES)
        except OSError:
            return 0

    ensure_rules_file()
    if not sys.platform.startswith("freebsd"):
        return {"ok": True, "fetched": False, "degraded": False, "rules_size": 0,
                "rules_path": _SURICATA_UPDATE_RULES, "message": "non-freebsd"}

    size = _size()
    if size > 0:
        return {"ok": True, "fetched": False, "degraded": False, "rules_size": size,
                "rules_path": _SURICATA_UPDATE_RULES, "message": "rules already present"}
    if not _find_suricata_update():
        return {"ok": True, "fetched": False, "degraded": True, "rules_size": 0,
                "rules_path": _SURICATA_UPDATE_RULES,
                "message": "suricata-update not installed — starting with 0 rules"}

    fetch = update_rules(conn)
    ensure_rules_file()   # restore the placeholder if a failed run left nothing
    size = _size()
    try:
        from app.audit_log import log_event
        log_event(
            category="security", action="ids_auto_fetch_rules",
            severity="medium" if fetch.get("ok") else "high",
            username="system", remote_addr="",
            details={"ok": bool(fetch.get("ok")),
                     "message": (fetch.get("message") or "")[:512],
                     "rules_path": _SURICATA_UPDATE_RULES},
        )
    except Exception:
        pass
    return {"ok": True, "fetched": bool(fetch.get("ok")),
            "degraded": size == 0, "rules_size": size,
            "rules_path": _SURICATA_UPDATE_RULES,
            "source_warnings": fetch.get("source_warnings", []),
            "message": fetch.get("message", "")}


def _scan_dmesg_for_oom() -> str:
    """
    Return a one-line description if dmesg shows Suricata was recently
    OOM-killed, else "". Used to turn a silent crash loop into an
    actionable message.
    """
    if not sys.platform.startswith("freebsd"):
        return ""
    try:
        r = run_command(["dmesg"], check=False)
        lines = (r.stdout or "").splitlines()
    except Exception:
        return ""
    for line in reversed(lines):
        low = line.lower()
        if "suricata" in low and ("out of swap space" in low or "killed" in low):
            return line.strip()
    return ""


def _rows(conn, sql, params=()):
    cur = conn.cursor()
    cur.execute(sql, params)
    return [dict(r) for r in cur.fetchall()]


def _cfg(conn) -> dict:
    rows = _rows(conn, "SELECT * FROM ids_config WHERE id=1")
    return rows[0] if rows else {}


def _clean_iface(name: str) -> str:
    """
    Sanitise an interface name pulled from `assigned_port` or similar.

    Smart Shield stores ports in two formats:
      * raw kernel name, e.g. ``em0``
      * legacy "<name> (<mac>)" pulled from the picker, e.g. ``em0 (00:0c:29:a1:2b:3c)``

    Suricata only accepts the kernel name. Strip everything after the first
    whitespace token; that's the canonical port. Falls back to ``em0`` when
    the input is empty so the YAML generator never produces a blank
    ``interface:`` field (which would crash Suricata at startup).
    """
    s = (name or "").strip()
    if not s:
        return "em0"
    return s.split()[0]


def _derive_lan_home_net(conn) -> str:
    """Default Suricata HOME_NET to the configured LAN subnet.

    A LAN-side IDS should treat the LAN network as "home" so EXTERNAL_NET
    (``!$HOME_NET``) precisely means "everything off-LAN". Reads the LAN
    interface address (``lan_config.ipv4_address``, e.g. ``192.168.1.1/24``)
    and returns its network (``192.168.1.0/24``). Falls back to the broad
    RFC1918 ``192.168.0.0/16`` range when the LAN address isn't usable yet
    (fresh install, or a LAN still on DHCP with no address recorded).
    """
    try:
        import ipaddress
        row = conn.execute(
            "SELECT ipv4_address FROM lan_config LIMIT 1"
        ).fetchone()
        if row and row["ipv4_address"]:
            return str(ipaddress.ip_interface(row["ipv4_address"].strip()).network)
    except Exception:
        pass
    return "192.168.0.0/16"


def _validate_cidr_list(value: str) -> "tuple[bool, str]":
    """
    Return ``(ok, error)`` for an IP/CIDR list (the shape Suricata's
    ``HOME_NET`` accepts). Empty string is treated as OK — the writer
    substitutes a default. Items may be comma-separated; ``!`` negation
    is allowed in front of each entry.

    Used as a preflight by ``validate_suricata_yaml`` so a malformed
    HOME_NET produces an actionable error instead of a silent daemon exit
    at parse time.
    """
    import ipaddress as _ipa
    v = (value or "").strip()
    if not v:
        return (True, "")
    for raw in v.split(","):
        item = raw.strip()
        if not item:
            continue
        if item.startswith("!"):
            item = item[1:].strip()
        if not item:
            return (False, "empty entry in HOME_NET / EXTERNAL_NET")
        # Allow plain dollar-var references (Suricata syntax: $HOME_NET).
        if item.startswith("$"):
            continue
        try:
            _ipa.ip_network(item, strict=False)
        except ValueError:
            return (False, f"'{item}' is not a valid IP / CIDR")
    return (True, "")


# ---------------------------------------------------------------------------
# Daemon log tail — surfaced in the GUI so operators can self-diagnose
# silent Suricata exits without ssh access.
# ---------------------------------------------------------------------------

def tail_suricata_log(lines: int = 200, source: str = "suricata") -> dict:
    """
    Read the last *lines* lines of ``/var/log/suricata/<source>.log``.

    source = "suricata"  → daemon log (errors, rule load summary, exits)
    source = "fast"      → fast.log alert stream
    source = "stats"     → throughput / drop counters

    Returns ``{"ok", "path", "lines": [str, ...], "missing": bool,
              "message": str}``. Every line is capped at 1024 chars and
    has terminating CRLFs stripped. The function never raises.
    """
    src = (source or "suricata").strip().lower()
    if src not in ("suricata", "fast", "stats"):
        return {"ok": False, "path": "", "lines": [], "missing": True,
                "message": f"unknown log source '{source}'"}
    try:
        n = max(1, min(int(lines or 200), 2000))
    except (TypeError, ValueError):
        n = 200

    path = f"{_SURICATA_LOG_DIR}/{src}.log"
    if not os.path.exists(path):
        return {"ok": True, "path": path, "lines": [], "missing": True,
                "message": f"{path} does not exist yet"}

    try:
        # Read the tail without pulling the whole file into memory — Suricata
        # logs can grow large between rotations.
        chunk_size = 8192
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            # Heuristic: ~200 chars / line × n lines, with a safety multiplier.
            want = min(size, max(chunk_size, n * 240 * 2))
            fh.seek(max(0, size - want))
            blob = fh.read()
        text = blob.decode("utf-8", errors="replace")
        raw_lines = text.splitlines()[-n:]
    except Exception as exc:
        return {"ok": False, "path": path, "lines": [], "missing": False,
                "message": f"read failed: {exc}"}

    cleaned = []
    for ln in raw_lines:
        # Strip ANSI colour escapes — Suricata uses them in <Error>/<Warn> markers.
        line = ln.replace("\r", "")
        while "\x1b[" in line:
            i = line.index("\x1b[")
            j = line.find("m", i + 2)
            if j < 0:
                break
            line = line[:i] + line[j + 1:]
        cleaned.append(line[:1024])
    return {"ok": True, "path": path, "lines": cleaned, "missing": False,
            "message": ""}


# ---------------------------------------------------------------------------
# YAML generator
# ---------------------------------------------------------------------------

def generate_suricata_yaml(conn, force_ids_mode: bool = False) -> str:
    cfg = _cfg(conn)
    if not cfg:
        cfg = {}

    mode        = cfg.get("mode", "ids") if not force_ids_mode else "ids"
    # Interface resolution mirrors routes/ids.py display: an explicit ids_config
    # value wins; otherwise the IDS monitors the LAN side by default. LAN-side
    # inspection gives real internal-host attribution (WAN is post-NAT) and far
    # less internet-scan noise, which is the higher-value detection on this
    # appliance. Fall back to the configured LAN port, then "em1" (the LAN
    # default used by pf_generator) as a last resort.
    #
    # NOTE: _clean_iface("") returns "em0", so the empty case is guarded
    # explicitly here — otherwise the lan_config lookup below would be dead code
    # and Suricata would silently bind to em0 regardless of the real LAN port.
    raw_iface   = (cfg.get("interface") or "").strip()
    interface   = _clean_iface(raw_iface) if raw_iface else ""
    if not interface:
        try:
            row = conn.execute(
                "SELECT assigned_port FROM lan_config LIMIT 1"
            ).fetchone()
            if row and row["assigned_port"]:
                interface = _clean_iface(row["assigned_port"])
        except Exception:
            pass
    if not interface:
        interface = "em1"
    # HOME_NET: explicit operator value wins; otherwise derive the LAN subnet
    # so EXTERNAL_NET (!$HOME_NET) is precise for LAN-side monitoring.
    home_net    = (cfg.get("home_net") or "").strip() or _derive_lan_home_net(conn)
    ext_net     = cfg.get("external_net") or "!$HOME_NET"
    eve_enabled = bool(cfg.get("eve_json_enabled", 1))
    fast_log    = bool(cfg.get("fast_log_enabled", 1))
    max_pending = int(cfg.get("max_pending_packets") or 1024)
    stats_int   = int(cfg.get("stats_interval") or 8)

    # Memory budget — small appliances get conservative memcaps so Suricata
    # is not OOM-killed shortly after it starts processing traffic.
    mem_budget = _mem_budget()
    if mem_budget == "low":
        detect_profile    = "low"
        defrag_memcap     = "16mb"
        flow_memcap       = "32mb"
        stream_memcap     = "32mb"
        reassembly_memcap = "64mb"
        host_memcap       = "16mb"
        max_pending       = min(max_pending, 256)
    else:
        detect_profile    = "medium"
        defrag_memcap     = "32mb"
        flow_memcap       = "128mb"
        stream_memcap     = "64mb"
        reassembly_memcap = "256mb"
        host_memcap       = "32mb"

    # Active rulesets.
    # suricata-update writes a single combined file (_SURICATA_UPDATE_RULES).
    # Only rulesets with an explicit local_path get their own entry in rule-files.
    rulesets = _rows(conn, "SELECT * FROM ids_rulesets WHERE enabled=1 ORDER BY id")
    rule_files = []
    has_update_managed = False
    for rs in rulesets:
        lp = (rs.get("local_path") or "").strip()
        if lp:
            if lp not in rule_files:
                rule_files.append(lp)
        else:
            has_update_managed = True

    if has_update_managed or not rule_files:
        rule_files.insert(0, _SURICATA_UPDATE_RULES)

    # Drop rule files that do not exist on disk — a missing file makes
    # `suricata -T` warn and load 0 rules. The merged suricata-update file is
    # always kept; ensure_rules_file() guarantees it exists before a real run.
    if sys.platform.startswith("freebsd"):
        rule_files = [p for p in rule_files
                      if p == _SURICATA_UPDATE_RULES or os.path.exists(p)]
    if not rule_files:
        rule_files = [_SURICATA_UPDATE_RULES]

    # Emit relative names for files inside default-rule-path; keep absolute
    # paths for operator local_path entries that live elsewhere. Matches the
    # standard Suricata layout and avoids duplicating the prefix on every line.
    default_rule_path = os.path.dirname(_SURICATA_UPDATE_RULES)
    rule_files_rel = []
    for p in rule_files:
        if os.path.dirname(p) == default_rule_path:
            rule_files_rel.append(os.path.basename(p))
        else:
            rule_files_rel.append(p)
    rule_files = rule_files_rel

    # Build capture config depending on mode.
    # FreeBSD does not support af-packet (Linux AF_PACKET socket).
    # IDS mode uses pcap (portable, works on FreeBSD via BPF).
    # IPS mode uses netmap (FreeBSD-native inline capture).
    if mode == "ips":
        capture_section = textwrap.dedent(f"""\
            netmap:
              - interface: {interface}
                threads: auto
                copy-mode: ips
                copy-iface: {interface}
        """)
        runmode = "workers"
    else:
        capture_section = textwrap.dedent(f"""\
            pcap:
              - interface: {interface}
                checksum-checks: no
        """)
        runmode = "autofp"

    # EVE log outputs
    outputs_list = []
    if eve_enabled:
        outputs_list.append(textwrap.dedent("""\
            - eve-log:
                enabled: yes
                filetype: regular
                filename: /var/log/suricata/eve.json
                types:
                  - alert:
                      payload: yes
                      metadata: yes
                  - dns
                  - http:
                      extended: yes
                  - tls:
                      extended: yes
                  - files:
                      force-magic: yes
                      force-filestore: no
                  - flow:
                      all: no
                  - stats:
                      totals: yes
        """))
    if fast_log:
        outputs_list.append(textwrap.dedent("""\
            - fast:
                enabled: yes
                filename: /var/log/suricata/fast.log
                append: yes
        """))
    outputs_list.append(textwrap.dedent("""\
        - stats:
            enabled: yes
            filename: /var/log/suricata/stats.log
            append: yes
            totals: yes
            threads: no
    """))

    outputs_yaml = "\n".join(outputs_list)

    rule_files_yaml = "\n".join(f"  - {p}" for p in rule_files)

    yaml = f"""\
%YAML 1.1
---
# ============================================================
# Smart Shield — auto-generated suricata.yaml
# Generated by app/services/ids_writer.py
# Mode: {mode.upper()}  Interface: {interface}  Memory budget: {mem_budget}
# ============================================================

vars:
  address-groups:
    HOME_NET: "[{home_net}]"
    EXTERNAL_NET: "{ext_net}"
    HTTP_SERVERS: "$HOME_NET"
    SMTP_SERVERS: "$HOME_NET"
    SQL_SERVERS: "$HOME_NET"
    DNS_SERVERS: "$HOME_NET"
    TELNET_SERVERS: "$HOME_NET"
    AIM_SERVERS: "$EXTERNAL_NET"
    DC_SERVERS: "$HOME_NET"
    DNP3_SERVER: "$HOME_NET"
    DNP3_CLIENT: "$HOME_NET"
    MODBUS_CLIENT: "$HOME_NET"
    MODBUS_SERVER: "$HOME_NET"
    ENIP_CLIENT: "$HOME_NET"
    ENIP_SERVER: "$HOME_NET"

  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: 1521
    SSH_PORTS: 22
    DNP3_PORTS: 20000
    MODBUS_PORTS: 502
    FILE_DATA_PORTS: "[$HTTP_PORTS,110,143]"
    FTP_PORTS: 21
    GENEVE_PORTS: 6081
    VXLAN_PORTS: 4789
    TEREDO_PORTS: 3544

default-log-dir: {_SURICATA_LOG_DIR}

stats:
  enabled: yes
  interval: {stats_int}

outputs:
{outputs_yaml}
{capture_section}
app-layer:
  protocols:
    rdp:
      enabled: yes
    krb5:
      enabled: yes
    snmp:
      enabled: yes
    ikev2:
      enabled: yes
    tls:
      enabled: yes
      detection-ports:
        dp: 443
    http2:
      enabled: yes
    smtp:
      enabled: yes
    imap:
      enabled: yes
    ssh:
      enabled: yes
    ftp:
      enabled: yes
    dns:
      tcp:
        enabled: yes
      udp:
        enabled: yes
    http:
      enabled: yes
      libhtp:
        default-config:
          personality: IDS
          request-body-limit: 100kb
          response-body-limit: 100kb
          double-decode-path: no
          double-decode-query: no

threading:
  set-cpu-affinity: no
  cpu-affinity:
    - management-cpu-set:
        cpu: [ 0 ]
    - receive-cpu-set:
        cpu: [ 0 ]
    - worker-cpu-set:
        cpu: [ "all" ]
        mode: "exclusive"
        prio:
          low: [ 0 ]
          medium: [ "1-2" ]
          high: [ 3 ]
          default: "medium"
  detect-thread-ratio: 1.0

detect:
  profile: {detect_profile}
  custom-values:
    toclient-groups: 3
    toserver-groups: 25
  sgh-mpm-context: auto
  inspection-recursion-limit: 3000
  prefilter:
    default: mpm
  grouping:
  profiling:
    grouping:
      dump-to-disk: false

mpm-algo: auto
spm-algo: auto

runmode: {runmode}

max-pending-packets: {max_pending}

default-packet-size: 1514

host-mode: auto

home-net-ranges:
  - {home_net}

defrag:
  memcap: {defrag_memcap}
  hash-size: 65536
  trackers: 65535
  max-frags: 65535
  prealloc: yes
  timeout: 60

flow:
  memcap: {flow_memcap}
  hash-size: 65536
  prealloc: 10000
  emergency-recovery: 30

vlan:
  use-for-tracking: true

stream:
  memcap: {stream_memcap}
  checksum-validation: yes
  inline: {str(mode == 'ips').lower()}
  reassembly:
    memcap: {reassembly_memcap}
    depth: 1mb
    toserver-chunk-size: 2560
    toclient-chunk-size: 2560
    randomize-chunk-size: yes

host:
  hash-size: 4096
  prealloc: 1000
  memcap: {host_memcap}

default-rule-path: {default_rule_path}
rule-files:
{rule_files_yaml}

classification-file: {_SURICATA_CONF_DIR}/classification.config
reference-config-file: {_SURICATA_CONF_DIR}/reference.config

suppress-version-message: yes
"""
    return yaml


# ---------------------------------------------------------------------------
# Write config
# ---------------------------------------------------------------------------

def validate_suricata_yaml(text: str) -> tuple:
    """
    Validate the Suricata YAML via ``suricata -T -c <file>``.
    Returns ``(True, "")`` on success, ``(False, error)`` on failure.
    On non-FreeBSD or if suricata is not installed, returns ``(True, "skipped")``.

    Includes a fast CIDR preflight on the HOME_NET / EXTERNAL_NET keys —
    Suricata exits silently if these are malformed, producing a
    "marked enabled but not running" loop that's hard to diagnose from
    the GUI. Catch it here with an actionable error first.
    """
    import re as _re
    for var in ("HOME_NET", "EXTERNAL_NET"):
        m = _re.search(rf'^\s*{var}\s*:\s*"?\[?(.*?)\]?"?\s*$',
                       text, _re.MULTILINE)
        if not m:
            continue
        candidate = m.group(1).strip().strip('"')
        ok_pf, err = _validate_cidr_list(candidate)
        if not ok_pf:
            return (False, f"{var} preflight failed: {err}")

    import shutil, tempfile, os as _os
    if not sys.platform.startswith("freebsd"):
        return (True, "skipped-non-freebsd")
    if not shutil.which("suricata"):
        return (True, "skipped-suricata-not-found")

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, prefix="ss_ids_"
        ) as f:
            f.write(text)
            tmp_path = f.name
        result = run_command(["suricata", "-T", "-c", tmp_path], check=False)
        ok  = result.returncode == 0
        msg = (result.stderr or result.stdout or "").strip()
        return (ok, msg)
    except FreeBSDNetworkError as exc:
        return (False, str(exc))
    finally:
        if tmp_path:
            try:
                _os.unlink(tmp_path)
            except Exception:
                pass


def _kldstat_netmap_loaded() -> bool:
    """Return True when `kldstat -n netmap` reports the module is loaded.

    Wrapped in its own helper so callers (validate_ips_safety, get_diagnostics)
    and tests can stub a single call site.
    """
    if not sys.platform.startswith("freebsd"):
        return False
    try:
        r = run_command(["kldstat", "-n", "netmap"], check=False)
        return r.returncode == 0
    except FreeBSDNetworkError:
        return False


def _persist_netmap_load_yes() -> dict:
    """Write `netmap_load="YES"` to /boot/loader.conf so the live kldload
    survives reboot. Best-effort: a failure here does not undo the live load —
    we return a warning string that the caller can surface to the operator.
    """
    if not sys.platform.startswith("freebsd"):
        return {"ok": True, "warning": ""}
    try:
        from app.services.priv_helper import run_privileged, PrivilegedActionError
        from app.services.network_service import FreeBSDNetworkError as _FBNE
        try:
            result = run_privileged(
                "sysrc.loader_set",
                key="netmap_load",
                value="YES",
            )
            if result.returncode == 0:
                return {"ok": True, "warning": ""}
            err = (result.stderr or result.stdout or "").strip()
            return {
                "ok": False,
                "warning": (
                    "netmap is loaded for this boot, but persisting "
                    f"netmap_load=\"YES\" to /boot/loader.conf failed: {err or 'unknown error'}. "
                    "A reboot will revert the IPS-mode kernel module."
                ),
            }
        except (PrivilegedActionError, _FBNE) as exc:
            return {
                "ok": False,
                "warning": (
                    "netmap is loaded for this boot, but persisting "
                    f"netmap_load=\"YES\" to /boot/loader.conf failed: {exc}. "
                    "A reboot will revert the IPS-mode kernel module."
                ),
            }
    except Exception as exc:  # pragma: no cover - defensive
        return {"ok": False,
                "warning": f"Could not call sysrc.loader_set: {exc}"}


def _ensure_netmap_loaded(conn) -> dict:
    """Make sure netmap.ko is loaded, kldload'ing it on demand if not.

    The install policy at bsd/install.sh deliberately leaves feature-dependent
    kernel modules (netmap, dummynet, carp/pfsync) unloaded at install time
    so a fresh box doesn't carry capabilities it isn't using. priv_helper's
    "kldload" action + the sudoers grant for `/sbin/kldload netmap` exist
    precisely so we can load it on demand from this code path.

    Returns:
        {"ok": True/False, "warning": str or "", "message": str}

    `ok=True` means netmap is loaded now (either it already was, or we just
    loaded it). `warning` carries non-fatal info such as "live load worked
    but persisting to loader.conf failed". `message` is the hard-error text
    when `ok=False` (used verbatim in validate_ips_safety's errors list).
    """
    _set_phase("LOADING_KMOD")
    if _kldstat_netmap_loaded():
        # Already loaded — still try to persist so a reboot keeps it. Failure
        # is a warning, not an error.
        persist = _persist_netmap_load_yes()
        return {"ok": True,
                "warning": persist.get("warning", ""),
                "message": "netmap already loaded"}

    if not sys.platform.startswith("freebsd"):
        # No way to load on dev hosts — caller decides whether to hard-fail.
        return {"ok": False, "warning": "",
                "message": "netmap.ko cannot be auto-loaded on non-FreeBSD."}

    # Auto-load via priv_helper. sudoers grants `/sbin/kldload netmap`.
    try:
        from app.services.priv_helper import run_privileged, PrivilegedActionError
        load_result = run_privileged("kldload", module="netmap")
        load_err = (load_result.stderr or load_result.stdout or "").strip()
    except (PrivilegedActionError, FreeBSDNetworkError) as exc:
        return {
            "ok": False, "warning": "",
            "message": (
                f"Could not load netmap.ko: {exc}. "
                "Run 'kldload netmap' manually or add 'netmap_load=\"YES\"' "
                "to /boot/loader.conf."
            ),
        }

    # Re-check — kldload exit code doesn't always reflect actual load state
    # on some FreeBSD builds (e.g. when the module is already loaded by
    # another process between the first kldstat and the kldload call).
    if not _kldstat_netmap_loaded():
        return {
            "ok": False, "warning": "",
            "message": (
                "Tried to auto-load netmap.ko but kldstat still reports it as "
                f"missing. kldload output: {load_err or 'empty'}. "
                "Run 'kldload netmap' manually to diagnose."
            ),
        }

    # Loaded successfully — persist to loader.conf for next boot.
    persist = _persist_netmap_load_yes()
    return {"ok": True,
            "warning": persist.get("warning", ""),
            "message": "netmap.ko loaded on demand"}


def validate_ips_safety(conn) -> dict:
    """
    Additional safety checks required before enabling IPS mode.

    Performs these checks on FreeBSD:
    1. Interface is selected.       (hard error — IPS cannot bind)
    2. netmap.ko kernel module loaded. If missing, *auto-load* via
       `priv_helper.kldload` and persist `netmap_load="YES"` to
       /boot/loader.conf. Only a load failure is a hard error now; a
       loader.conf persist failure is just a warning so the operator
       knows reboot will revert.
    3. The NIC driver is in the known-good netmap driver list. (warning — the
       list is non-exhaustive, so an unknown driver is surfaced, not blocked)

    Returns a structured result so callers can hard-block on ``errors`` while
    still surfacing ``warnings``::

        {"ok": bool, "errors": [str, ...], "warnings": [str, ...]}

    ``ok`` is True only when there are no hard errors. Informational/success
    text is NOT mixed into the error list (a previous version did, which made
    the gate impossible to evaluate reliably).
    """
    errors: list = []
    warnings: list = []
    cfg = _cfg(conn)
    interface = (cfg.get("interface") or "").strip()
    if not interface:
        errors.append("IPS mode requires an interface to be selected.")
        return {"ok": False, "errors": errors, "warnings": warnings}

    if not sys.platform.startswith("freebsd"):
        warnings.append(
            "IPS mode uses netmap(4) inline capture. Verify your NIC supports netmap "
            "before enabling IPS (check: kldload netmap). IPS mode will drop traffic on "
            "misconfiguration."
        )
        return {"ok": True, "errors": errors, "warnings": warnings}

    # Check 1: netmap kernel module — try to auto-load if missing.
    netmap = _ensure_netmap_loaded(conn)
    if not netmap.get("ok"):
        errors.append(netmap.get("message") or
                      "netmap.ko could not be loaded; IPS mode is unavailable.")
    elif netmap.get("warning"):
        warnings.append(netmap["warning"])

    # Check 2: NIC driver compatibility — warning (list is non-exhaustive).
    _NETMAP_SUPPORTED_PREFIXES = (
        "em", "igb", "ixgbe", "ixl", "re", "vtnet", "vmx", "bnxt", "ix",
    )
    import re as _re
    driver = _re.match(r"^([a-z]+)", interface)
    if driver:
        drv = driver.group(1)
        if not any(drv.startswith(p) for p in _NETMAP_SUPPORTED_PREFIXES):
            warnings.append(
                f"NIC driver '{drv}' may not support netmap(4). "
                f"Known-good drivers: {', '.join(_NETMAP_SUPPORTED_PREFIXES)}. "
                "Test carefully — IPS mode will silently drop traffic if netmap fails."
            )

    return {"ok": not errors, "errors": errors, "warnings": warnings}


def write_suricata_config(conn) -> dict:
    conf = generate_suricata_yaml(conn)

    if not sys.platform.startswith("freebsd"):
        return {"ok": True, "message": "Non-FreeBSD — suricata.yaml generated but not written.", "conf": conf}

    os.makedirs(_SURICATA_CONF_DIR, exist_ok=True)
    os.makedirs(_SURICATA_LOG_DIR, exist_ok=True)
    os.makedirs(_SURICATA_RUN_DIR, exist_ok=True)
    os.makedirs(_SURICATA_RULES_DIR, exist_ok=True)
    # Guarantee the merged rules file exists so the deep check never fails
    # on a missing file (real rules from suricata-update overwrite it).
    ensure_rules_file()

    from app.services.config_file_utils import atomic_write, backup_config
    try:
        backup_config(_SURICATA_CONF_PATH)
        atomic_write(_SURICATA_CONF_PATH, conf, mode=0o644)
        return {"ok": True, "message": f"Written to {_SURICATA_CONF_PATH}", "conf": conf}
    except OSError as exc:
        return {"ok": False, "message": str(exc), "conf": conf}


# ---------------------------------------------------------------------------
# Rule updates via suricata-update
# ---------------------------------------------------------------------------

def update_rules(conn) -> dict:
    """
    Run suricata-update to download/update all enabled rulesets.
    suricata-update writes a single merged file to _SURICATA_UPDATE_RULES.
    """
    if not sys.platform.startswith("freebsd"):
        return {"ok": True, "message": "Non-FreeBSD — rule update skipped.", "updated": [],
                "rules_path": _SURICATA_UPDATE_RULES}

    su_bin = _find_suricata_update()
    if not su_bin:
        # Lazy install into the project venv (sys.executable is the venv python
        # under gunicorn). Avoids the pkg_resources.ResolutionError from
        # --break-system-packages installs into system Python.
        run_command(
            [sys.executable, "-m", "pip", "install", "--upgrade",
             "suricata-update", "idstools", "pyyaml"],
            check=False,
        )
        su_bin = _find_suricata_update()

    if not su_bin:
        py_ver = f"{sys.version_info.major}{sys.version_info.minor}"
        return {
            "ok": False,
            "message": (
                f"suricata-update not found. Install it: "
                f"pkg install py{py_ver}-suricata-update"
            ),
            "updated": [],
        }

    # Refresh the source index first (non-fatal if it fails — offline deployments).
    # The default 20s ceiling can trip on slow links; bump to 180s for the index fetch.
    run_command([su_bin, "update-sources"], check=False, timeout_seconds=180)

    # Enable/register each managed ruleset source. Capture per-source failures
    # so the UI can show exactly which feed could not be added/enabled instead
    # of silently merging fewer rulesets than the operator configured.
    source_warnings: list = []
    rulesets = _rows(conn, "SELECT * FROM ids_rulesets WHERE enabled=1")
    for rs in rulesets:
        url  = (rs.get("url") or "").strip()
        name = (rs.get("name") or "").strip()
        lp   = (rs.get("local_path") or "").strip()
        if not name or lp:
            continue  # skip local-path-only rulesets and unnamed entries
        cmd = [su_bin, "add-source", name, url] if url else [su_bin, "enable-source", name]
        rc = run_command(cmd, check=False)
        if rc.returncode != 0:
            detail = (rc.stderr or rc.stdout or "").strip().replace("\n", " ")
            source_warnings.append(f"{name}: {detail[:200]}" if detail else name)

    # Run the actual download + merge. Pin --output so the merged file lands at
    # the path the generated YAML reads (the tool's default has drifted across
    # versions). 300s covers a cold first-time multi-ruleset download.
    rules_dir = os.path.dirname(_SURICATA_UPDATE_RULES)
    result = run_command([su_bin, "--output", rules_dir],
                         check=False, timeout_seconds=300)
    ok  = result.returncode == 0
    out = (result.stdout or result.stderr or "").strip()

    # A failed or timed-out run must not leave the YAML pointing at a missing
    # file. Restore the placeholder before reporting back.
    ensure_rules_file()

    if ok and not os.path.exists(_SURICATA_UPDATE_RULES):
        return {
            "ok": False,
            "message": (f"suricata-update exited 0 but did not write "
                        f"{_SURICATA_UPDATE_RULES}"),
            "updated": [],
            "rules_path": _SURICATA_UPDATE_RULES,
            "rules_size": 0,
            "source_warnings": source_warnings,
        }

    size = (os.path.getsize(_SURICATA_UPDATE_RULES)
            if os.path.exists(_SURICATA_UPDATE_RULES) else 0)
    msg = (
        f"Rules fetched → {_SURICATA_UPDATE_RULES} ({size} bytes)" if ok
        else f"suricata-update failed: {out[:500]}"
    )
    if source_warnings:
        msg += f" | source issues: {'; '.join(source_warnings)}"
    return {
        "ok": ok,
        "message": msg,
        "updated": [],
        "rules_path": _SURICATA_UPDATE_RULES,
        "rules_size": size,
        "source_warnings": source_warnings,
    }


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

def get_ids_status(conn=None) -> dict:
    """Return running status + today's alert count (from eve.json)."""
    mode = "ids"
    cfg_enabled = False
    if conn is not None:
        try:
            row = conn.execute("SELECT mode, enabled FROM ids_config WHERE id=1").fetchone()
            if row:
                mode = (row["mode"] or "ids").lower()
                cfg_enabled = bool(row["enabled"])
        except Exception:
            pass

    if not sys.platform.startswith("freebsd"):
        return {"ok": True, "running": False, "mode": mode, "message": "Non-FreeBSD host",
                "alerts_today": 0, "cfg_enabled": cfg_enabled}

    # Check if process is running
    result = run_command(["pgrep", "-x", "suricata"], check=False)
    running = result.returncode == 0

    alerts_today = 0
    eve_path = f"{_SURICATA_LOG_DIR}/eve.json"
    if os.path.exists(eve_path):
        try:
            from datetime import datetime, timezone
            today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            with open(eve_path, "r", errors="replace") as f:
                for line in f:
                    if '"event_type":"alert"' in line and today in line:
                        alerts_today += 1
        except Exception:
            pass

    signatures_loaded = _count_signatures()

    if not signatures_loaded:
        message = "Running, NO signatures loaded" if running else "Stopped, NO signatures loaded"
    else:
        message = "Running" if running else "Stopped"

    return {
        "ok": True,
        "running": running,
        "mode": mode,
        "message": message,
        "alerts_today": alerts_today,
        "cfg_enabled": cfg_enabled,
        "signatures_loaded": signatures_loaded,
    }


def _count_signatures() -> int:
    """Count real Suricata rule actions in the merged rules file.

    Signature-coverage gauge. Counts real rule actions only (alert/drop/
    reject/pass) so include-files and comments do not inflate the apparent
    coverage. A running suricata with 0 signatures is the failure mode we
    warn about in install.sh (§Fv12 P1-02): the daemon happily starts on an
    empty ruleset and the UI must not call that state "ready".
    """
    try:
        if not os.path.exists(_SURICATA_UPDATE_RULES):
            return 0
        count = 0
        with open(_SURICATA_UPDATE_RULES, "r", errors="replace") as f:
            for line in f:
                head = line[:8]
                if (head.startswith("alert ") or head.startswith("drop ")
                        or head.startswith("reject ") or head.startswith("pass ")):
                    count += 1
        return count
    except Exception:
        return 0


def get_diagnostics(conn=None) -> dict:
    """One-call snapshot of every IDS-related runtime fact for the GUI panel.

    Shape is stable so the panel can render a 2-column table without
    case-splitting on which fields are present. Never raises.
    """
    cfg = {}
    if conn is not None:
        try:
            cfg = _cfg(conn) or {}
        except Exception:
            cfg = {}

    rules_path = _SURICATA_UPDATE_RULES
    try:
        rules_size = os.path.getsize(rules_path) if os.path.exists(rules_path) else 0
    except OSError:
        rules_size = 0

    config_path = _SURICATA_CONF_PATH
    config_exists = os.path.exists(config_path)

    running = False
    try:
        if sys.platform.startswith("freebsd"):
            r = run_command(["pgrep", "-x", "suricata"], check=False)
            running = r.returncode == 0
    except FreeBSDNetworkError:
        running = False

    rc_enabled = False
    try:
        from app.services.service_manager import sysrc_get
        rc_enabled = (sysrc_get("suricata_enable") or "").strip().upper() == "YES"
    except Exception:
        rc_enabled = False

    log_tail = []
    try:
        t = tail_suricata_log(lines=20)
        if t.get("ok"):
            log_tail = t.get("lines", []) or []
    except Exception:
        log_tail = []

    phase_state = get_ids_phase()

    return {
        "ok": True,
        "phase": phase_state.get("phase"),
        "error": phase_state.get("error"),
        "last_phase_at": phase_state.get("last_phase_at"),
        "last_success_at": phase_state.get("last_success_at"),
        "mode": (cfg.get("mode") or "ids").lower(),
        "interface": (cfg.get("interface") or "").strip(),
        "cfg_enabled": bool(cfg.get("enabled")),
        "running": running,
        "rc_enabled": rc_enabled,
        "signatures_loaded": _count_signatures(),
        "rules_file": rules_path,
        "rules_size": rules_size,
        "config_path": config_path,
        "config_exists": config_exists,
        "netmap_loaded": _kldstat_netmap_loaded(),
        "log_tail": log_tail,
    }


# ---------------------------------------------------------------------------
# Enable / disable
# ---------------------------------------------------------------------------

def _write_enabled(conn, enabled: bool) -> None:
    """Persist the IDS enabled state to the DB. Called only after the service
    action succeeds so the DB always reflects what is actually running."""
    conn.execute(
        "UPDATE ids_config SET enabled=?, updated_at=CURRENT_TIMESTAMP WHERE id=1",
        (1 if enabled else 0,),
    )
    conn.commit()


def toggle_ids(conn, enabled: bool) -> dict:
    """
    Enable or disable Suricata.
    DB is updated AFTER the service action succeeds so enabled state in the DB
    always matches whether Suricata is actually running.
    """
    cfg = _cfg(conn)
    mode = (cfg.get("mode") or "ids").lower()

    # IPS mode safety gate — hard-block on any structured error (missing
    # interface or unloaded netmap); pass warnings through for the UI.
    if enabled and mode == "ips":
        safety = validate_ips_safety(conn)
        if not safety["ok"]:
            err_msg = " | ".join(safety["errors"])
            _set_phase("ERROR", err_msg)
            return {"ok": False, "rolled_back": False,
                    "phase": "ERROR",
                    "message": err_msg,
                    "warnings": safety.get("warnings", [])}

    # Non-FreeBSD: update DB directly (no service to manage)
    if not sys.platform.startswith("freebsd"):
        _write_enabled(conn, enabled)
        _set_phase("RUNNING" if enabled else "STOPPED")
        return {"ok": True, "rolled_back": False,
                "phase": "RUNNING" if enabled else "STOPPED",
                "message": f"IDS {'enabled' if enabled else 'disabled'} (non-FreeBSD, not applied)"}

    if enabled:
        ips_mode = (mode == "ips")

        # --- Bootstrap rules BEFORE the deep check -------------------------
        # The deep check (`suricata -T`) and the daemon both need a rules file
        # present; fetch first so a missing file cannot fail validation and
        # strand the auto-fetch behind it. Keep the result so we can surface a
        # zero-rule "degraded" start to the operator instead of claiming a
        # clean success.
        _set_phase("UPDATING_RULES")
        rules_state = ensure_rules_present(conn)

        # Explicit local_path rulesets must exist — these are operator-set.
        missing = []
        for rs in _rows(conn, "SELECT local_path FROM ids_rulesets WHERE enabled=1"):
            lp = (rs.get("local_path") or "").strip()
            if lp and not os.path.exists(lp):
                missing.append(lp)
        if missing:
            err_msg = f"Rule file(s) not found: {', '.join(missing)}. Check local_path settings."
            _set_phase("ERROR", err_msg)
            return {
                "ok": False,
                "rolled_back": False,
                "phase": "ERROR",
                "message": err_msg,
            }

        # --- Deep check, then write config --------------------------------
        _set_phase("VALIDATING_CONFIG")
        conf_text = generate_suricata_yaml(conn)
        ok, err   = validate_suricata_yaml(conf_text)
        if not ok:
            err_msg = f"Suricata YAML validation failed: {err}"
            _set_phase("ERROR", err_msg)
            return {"ok": False, "rolled_back": False,
                    "phase": "ERROR",
                    "message": err_msg}
        write_result = write_suricata_config(conn)
        if not write_result["ok"]:
            _set_phase("ERROR", write_result.get("message", "config write failed"))
            return {**write_result, "rolled_back": False, "phase": "ERROR"}

        # Persist rc.conf FIRST — fail fast if sysrc is unavailable
        sysrc_result = sysrc_set("suricata_enable", "YES")
        if not sysrc_result["ok"]:
            err_msg = f"Failed to set suricata_enable in rc.conf: {sysrc_result.get('message', '')}"
            _set_phase("ERROR", err_msg)
            return {"ok": False, "rolled_back": False,
                    "phase": "ERROR",
                    "message": err_msg}

        _set_phase("STARTING")
        r = service_action(_SERVICE_NAME, "restart")
        if not r["ok"]:
            # Service failed — revert rc.conf and config file; leave DB as disabled
            sysrc_set("suricata_enable", "NO")
            from app.services.config_file_utils import rollback_config
            rb = rollback_config(_SURICATA_CONF_PATH)

            # IPS→IDS safe fallback
            if ips_mode:
                ids_conf = generate_suricata_yaml(conn, force_ids_mode=True)
                ok_ids, _ = validate_suricata_yaml(ids_conf)
                if ok_ids:
                    try:
                        from app.services.config_file_utils import atomic_write
                        atomic_write(_SURICATA_CONF_PATH, ids_conf, mode=0o644)
                        sysrc_set("suricata_enable", "YES")
                        r2 = service_action(_SERVICE_NAME, "restart")
                        if r2["ok"]:
                            _write_enabled(conn, True)
                            _set_phase("RUNNING")
                            return {
                                **r2,
                                "rolled_back": False,
                                "phase": "RUNNING",
                                "fallback": True,
                                "message": r2["message"] + " — fell back to IDS (pcap) mode after IPS start failure",
                            }
                    except Exception:
                        pass
                sysrc_set("suricata_enable", "NO")

            err_msg = r.get("message", "restart failed")
            _set_phase("ERROR", err_msg)
            return {"ok": False, "rolled_back": rb.get("ok", False),
                    "phase": "ERROR",
                    "message": err_msg,
                    "rollback_message": rb.get("message", "")}

        # service command exited 0, but FreeBSD's init script exits 0 even when
        # the daemon crashes immediately on startup. Poll pgrep for up to 15s,
        # accepting a result only after the process has been seen alive on
        # two consecutive checks (otherwise we'd claim success during the
        # tiny window between fork() and the child's exit on bad config).
        import time as _time
        deadline       = _time.time() + 15.0
        consecutive_ok = 0
        alive          = False
        while _time.time() < deadline:
            pgrep = run_command(["pgrep", "-x", "suricata"], check=False)
            if pgrep.returncode == 0:
                consecutive_ok += 1
                if consecutive_ok >= 2:
                    alive = True
                    break
            else:
                consecutive_ok = 0
            _time.sleep(0.5)

        if not alive:
            sysrc_set("suricata_enable", "NO")
            from app.services.config_file_utils import rollback_config
            rb = rollback_config(_SURICATA_CONF_PATH)
            # DB must reflect reality — Suricata isn't running, so enabled=0.
            try:
                _write_enabled(conn, False)
            except Exception:
                pass

            # Collect last lines of suricata log for actionable diagnostics.
            log_snippet = ""
            tail = tail_suricata_log(lines=12)
            if tail.get("ok") and tail.get("lines"):
                log_snippet = "\n".join(tail["lines"])

            # If the kernel OOM-killed Suricata, say so — the cure is fewer
            # rules / smaller memcaps, not "check the daemon log".
            oom = _scan_dmesg_for_oom()
            if oom:
                headline = (
                    "Suricata was killed by the kernel — out of memory. "
                    "Reduce the enabled rulesets or lower the memcaps "
                    f"(this box uses the '{_mem_budget()}' memory profile). "
                    f"dmesg: {oom}"
                )
            else:
                headline = (
                    "Suricata process exited shortly after start. "
                    "Open the Daemon log panel for the full reason."
                )

            err_msg = (
                f"{headline} "
                f"Service output: {r.get('message', '').strip()}"
                + (f" | Log: {log_snippet[:400]}" if log_snippet else "")
            )
            _set_phase("ERROR", err_msg)
            return {
                "ok": False,
                "rolled_back": rb.get("ok", False),
                "phase": "ERROR",
                "message": err_msg,
                "rollback_message": rb.get("message", ""),
                "log_tail": log_snippet,
                "oom_killed": bool(oom),
            }

        # Confirmed running — persist enabled=1 and surface the startup banner.
        _write_enabled(conn, True)
        _set_phase("RUNNING")
        startup_tail = tail_suricata_log(lines=12)
        degraded   = bool(rules_state.get("degraded"))
        base_msg   = r.get("message", "")
        if degraded:
            base_msg = (
                (base_msg + " — " if base_msg else "")
                + "WARNING: Suricata started with 0 rules. Run 'Update Rules' once the "
                  "appliance is online so the IDS can actually detect threats."
            )
        return {**r, "rolled_back": False,
                "phase": "RUNNING",
                "message": base_msg,
                "degraded": degraded,
                "rules_size": rules_state.get("rules_size", 0),
                "source_warnings": rules_state.get("source_warnings", []),
                "startup_log": startup_tail.get("lines", []) if startup_tail.get("ok") else []}

    else:
        # Disabling: stop the service, then update DB (stop failures are non-fatal)
        sysrc_set("suricata_enable", "NO")
        r = service_action(_SERVICE_NAME, "stop")
        _write_enabled(conn, False)
        _set_phase("STOPPED")
        return {**r, "rolled_back": False, "phase": "STOPPED"}


def apply_ids(conn) -> dict:
    """
    Re-apply the current IDS configuration to a running Suricata.

    Composes the same ordering ``toggle_ids`` uses on enable — rules bootstrap
    → yaml write → validate → restart — so reload-all picks up config changes
    without bypassing the rule-file guarantee that caused first-time start to
    fail. A no-op when ``ids_config.enabled`` is 0.

    The ``suricata -T`` validation between write and restart matches the
    pattern used by dhcp_writer / dns_writer / openvpn_writer / ipsec_writer:
    a bad config must never reach ``service suricata restart``, which would
    leave the IDS in the "marked enabled but not running" state that's
    awkward to recover from via the web UI alone.
    """
    cfg = _cfg(conn)
    if not cfg.get("enabled"):
        return {"ok": True, "message": "IDS disabled; skipped"}

    rules = ensure_rules_present(conn)
    if not rules.get("ok"):
        return {"ok": False,
                "message": rules.get("message", "rule bootstrap failed")}

    written = write_suricata_config(conn)
    if not written.get("ok"):
        return written

    ok, err = validate_suricata_yaml(written.get("conf", ""))
    if not ok:
        return {"ok": False,
                "message": f"suricata.yaml validation failed: {err}",
                "conf": written.get("conf", "")}

    restart = service_action(_SERVICE_NAME, "restart")
    return {"ok": bool(restart.get("ok")),
            "message": restart.get("message", "")}


# ---------------------------------------------------------------------------
# Block-on-alert: push IDS-detected IPs to PF table
# ---------------------------------------------------------------------------

def push_blocked_ips_to_pf(conn) -> dict:
    """
    Read recent HIGH severity IDS alerts from audit_log,
    extract source IPs, write to a file, then replace the ss_ids_blocks PF table.
    Returns {"ok": bool, "count": int, "message": str}.
    """
    import ipaddress as _ip

    blocked_ips = set()
    try:
        rows = conn.execute(
            """
            SELECT details FROM audit_log
            WHERE category='ids' AND created_at > datetime('now', '-1 hour')
            LIMIT 1000
            """
        ).fetchall()
        for row in rows:
            try:
                d = json.loads(row["details"] if hasattr(row, "keys") else row[0])
                src = (d.get("src_ip") or "").strip()
                if src:
                    _ip.ip_address(src)   # validate
                    blocked_ips.add(src)
            except Exception:
                pass
    except Exception as exc:
        return {"ok": False, "count": 0, "message": f"DB query failed: {exc}"}

    from app.config import _ss_dir
    _IDS_BLOCK_FILE = os.path.join(_ss_dir("/var/db"), "ids_blocked_ips.txt")

    try:
        os.makedirs(os.path.dirname(_IDS_BLOCK_FILE), exist_ok=True)
        with open(_IDS_BLOCK_FILE, "w") as fh:
            fh.write("\n".join(sorted(blocked_ips)) + "\n")
    except Exception as exc:
        return {"ok": False, "count": 0, "message": f"Could not write IP file: {exc}"}

    if not sys.platform.startswith("freebsd"):
        return {"ok": True, "count": len(blocked_ips),
                "message": f"Non-FreeBSD — {len(blocked_ips)} IPs written to file (pfctl not called)"}

    try:
        from app.services.priv_helper import run_privileged
        r = run_privileged(
            "pf.table_replace_file",
            table="ss_ids_blocks",
            file_path=_IDS_BLOCK_FILE,
        )
        if r.returncode == 0:
            return {"ok": True, "count": len(blocked_ips),
                    "message": f"ss_ids_blocks table updated with {len(blocked_ips)} IPs"}
        return {"ok": False, "count": len(blocked_ips),
                "message": f"pfctl table_replace failed: {(r.stderr or r.stdout or '').strip()}"}
    except Exception as exc:
        return {"ok": False, "count": len(blocked_ips), "message": str(exc)}


# ---------------------------------------------------------------------------
# Threat table expiration
# ---------------------------------------------------------------------------

def expire_threat_intel_table(seconds: int = 86400) -> dict:
    """
    Remove expired IPs from the ss_threat_intel PF table.
    Entries older than `seconds` (default 24h) are expired.
    """
    if not sys.platform.startswith("freebsd"):
        return {"ok": True, "message": "Non-FreeBSD — table expire skipped (dry-run)"}
    try:
        from app.services.priv_helper import run_privileged
        r = run_privileged("pf.table_expire", table="ss_threat_intel", seconds=str(seconds))
        if r.returncode == 0:
            return {"ok": True, "message": f"ss_threat_intel: expired entries older than {seconds}s"}
        return {"ok": False, "message": (r.stderr or r.stdout or "pfctl expire failed").strip()}
    except Exception as exc:
        return {"ok": False, "message": str(exc)}
