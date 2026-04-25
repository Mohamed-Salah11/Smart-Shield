"""
freebsd_setup.py
----------------
Authoritative registry of every directory path and external tool Smart Shield
depends on.  Called once at application startup via create_app().

Design
------
* ensure_dirs()     — idempotent: creates missing dirs, never raises
* check_tools()     — inspects which FreeBSD packages / binaries are present
* preflight_check() — full report: dirs + tools, suitable for a status page

On non-FreeBSD hosts (Windows dev) only the app-data dirs derived from env
vars are created; hardcoded /usr/local / /var paths are skipped silently.
"""

import os
import shutil
import sys
from dataclasses import dataclass, field
from typing import List, Optional

_ON_FREEBSD = sys.platform.startswith("freebsd")


# ---------------------------------------------------------------------------
# Directory manifest
# ---------------------------------------------------------------------------

@dataclass
class DirSpec:
    path: str
    mode: int = 0o755
    freebsd_only: bool = False       # skip on non-FreeBSD
    description: str = ""


def _app_dirs() -> List[DirSpec]:
    """App-data dirs that depend on env vars — created on every platform."""
    db_path    = os.getenv("SMARTSHIELD_DB_PATH",    _default_db())
    cfg_path   = os.getenv("SMARTSHIELD_CONFIG_PATH", _default_cfg())
    upload_dir = os.getenv("SMARTSHIELD_UPLOAD_DIR",  _default_uploads())
    audit_path = os.getenv("SMARTSHIELD_AUDIT_LOG_PATH", _default_audit())

    return [
        DirSpec(os.path.dirname(os.path.abspath(db_path)),
                description="Smart Shield SQLite database"),
        DirSpec(os.path.dirname(os.path.abspath(cfg_path)),
                description="Smart Shield config JSON"),
        DirSpec(os.path.abspath(upload_dir),
                description="User profile picture uploads"),
        DirSpec(os.path.dirname(os.path.abspath(audit_path)),
                description="Smart Shield audit log"),
    ]


def _default_db():
    if _ON_FREEBSD:   return "/var/db/smart-shield/data.db"
    if sys.platform.startswith("win"):
        return os.path.join(os.getenv("LOCALAPPDATA", "."), "SmartShield", "data.db")
    return "data.db"

def _default_cfg():
    if _ON_FREEBSD:   return "/usr/local/etc/smart-shield/config.json"
    return "config.json"

def _default_uploads():
    if _ON_FREEBSD:   return "/var/db/smart-shield/uploads/profile_pictures"
    return os.path.join("static", "uploads", "profile_pictures")

def _default_audit():
    if _ON_FREEBSD:   return "/var/log/smart-shield/audit.log"
    return "audit.log"


# All dirs that must exist on FreeBSD
_FREEBSD_DIRS: List[DirSpec] = [
    # ── Smart Shield runtime ──────────────────────────────────────────────
    DirSpec("/var/db/smart-shield",
            description="Smart Shield database root"),
    DirSpec("/var/db/smart-shield/uploads/profile_pictures",
            description="User profile picture uploads"),
    DirSpec("/var/log/smart-shield",
            description="Smart Shield application + audit logs"),
    DirSpec("/var/run/smart-shield",
            description="Smart Shield PID file"),
    DirSpec("/usr/local/etc/smart-shield",
            description="Smart Shield env + config.json"),
    DirSpec("/usr/local/share/smart-shield",
            description="Smart Shield application code"),

    # ── PF (packet filter) ────────────────────────────────────────────────
    # /etc already exists; no dir to create — pf.conf goes at /etc/pf.conf

    # ── ISC DHCPd ─────────────────────────────────────────────────────────
    DirSpec("/var/db/dhcpd",
            description="DHCP lease database"),

    # ── Unbound (DNS resolver) ────────────────────────────────────────────
    DirSpec("/usr/local/etc/unbound",
            description="Unbound configuration"),

    # ── OpenVPN ───────────────────────────────────────────────────────────
    DirSpec("/usr/local/etc/openvpn",
            description="OpenVPN server configs"),
    DirSpec("/usr/local/etc/openvpn/keys",  mode=0o700,
            description="OpenVPN key material (restricted)"),
    DirSpec("/var/log/openvpn",
            description="OpenVPN status + access logs"),

    # ── L2TP / mpd5 ──────────────────────────────────────────────────────
    DirSpec("/usr/local/etc/mpd5",
            description="mpd5 L2TP/PPP configuration"),
    DirSpec("/var/run/mpd5",
            description="mpd5 runtime PIDs/sockets"),

    # ── IPsec / strongSwan ────────────────────────────────────────────────
    # ipsec.conf + ipsec.secrets go to /usr/local/etc — dir already exists
    DirSpec("/var/run/openvpn",
            description="OpenVPN PID files"),

    # ── Suricata IDS/IPS ──────────────────────────────────────────────────
    DirSpec("/usr/local/etc/suricata",
            description="Suricata YAML config"),
    DirSpec("/usr/local/etc/suricata/rules",
            description="Suricata rule files"),
    DirSpec("/var/log/suricata",
            description="Suricata EVE JSON + fast log"),
    DirSpec("/var/run/suricata",
            description="Suricata PID + socket"),

    # ── Nginx (TLS reverse proxy) ─────────────────────────────────────────
    DirSpec("/usr/local/etc/nginx",
            description="Nginx configuration"),
    DirSpec("/var/log/nginx",
            description="Nginx access + error logs"),
    DirSpec("/var/run/nginx",
            description="Nginx PID"),
]


# ---------------------------------------------------------------------------
# Tool manifest
# ---------------------------------------------------------------------------

@dataclass
class ToolSpec:
    name: str           # friendly display name
    binary: str         # absolute path to check with os.path.exists
    pkg: str            # `pkg install <pkg>` name
    optional: bool = False
    description: str = ""
    alt_binary: str = ""  # fallback path to check


_TOOLS: List[ToolSpec] = [
    # ── FreeBSD base (no install needed) ─────────────────────────────────
    ToolSpec("pfctl",    "/sbin/pfctl",     "",
             description="Packet filter control — FreeBSD base system"),
    ToolSpec("ifconfig", "/sbin/ifconfig",  "",
             description="Interface configuration — FreeBSD base system"),
    ToolSpec("route",    "/sbin/route",     "",
             description="Routing table management — FreeBSD base system"),
    ToolSpec("ping",     "/sbin/ping",      "",
             description="Connectivity check — FreeBSD base system"),
    ToolSpec("arp",      "/usr/sbin/arp",   "",
             description="ARP table — FreeBSD base system"),
    ToolSpec("sysrc",    "/usr/sbin/sysrc", "",
             description="rc.conf editor — FreeBSD base system"),
    ToolSpec("sockstat", "/usr/bin/sockstat", "",
             description="Open socket list — FreeBSD base system"),
    ToolSpec("tcpdump",  "/usr/sbin/tcpdump", "",
             description="Packet capture — FreeBSD base system"),
    ToolSpec("pgrep",    "/bin/pgrep",       "",
             description="Process search — FreeBSD base system"),

    # ── pkg + Python ──────────────────────────────────────────────────────
    ToolSpec("pkg",      "/usr/sbin/pkg",   "",
             description="Package manager — FreeBSD base"),
    ToolSpec("python3",  "/usr/local/bin/python3", "python3",
             description="Python 3 runtime"),
    ToolSpec("git",      "/usr/local/bin/git", "git",
             description="Source control"),
    ToolSpec("sqlite3",  "/usr/local/bin/sqlite3", "sqlite3",
             description="SQLite CLI (used by smartshieldctl)"),

    # ── Gunicorn (installed via pip in .venv) ─────────────────────────────
    ToolSpec("gunicorn",
             "/usr/local/share/smart-shield/.venv/bin/gunicorn",
             "gunicorn (pip)",
             description="Production WSGI server",
             alt_binary="/usr/local/bin/gunicorn"),

    # ── DHCP ──────────────────────────────────────────────────────────────
    ToolSpec("dhcpd",
             "/usr/local/sbin/dhcpd",
             "isc-dhcp44-server",
             optional=True,
             description="ISC DHCP server"),

    # ── DNS resolver ──────────────────────────────────────────────────────
    ToolSpec("unbound",
             "/usr/local/sbin/unbound",
             "unbound",
             optional=True,
             alt_binary="/usr/sbin/unbound",
             description="Unbound DNS resolver"),

    # ── OpenVPN ───────────────────────────────────────────────────────────
    ToolSpec("openvpn",
             "/usr/local/sbin/openvpn",
             "openvpn",
             optional=True,
             description="OpenVPN daemon"),

    # ── IPsec ─────────────────────────────────────────────────────────────
    ToolSpec("charon (strongSwan)",
             "/usr/local/libexec/ipsec/charon",
             "strongswan",
             optional=True,
             alt_binary="/usr/local/sbin/ipsec",
             description="strongSwan IKEv2 daemon"),
    ToolSpec("ipsec (swanctl)",
             "/usr/local/sbin/swanctl",
             "strongswan",
             optional=True,
             alt_binary="/usr/local/sbin/ipsec",
             description="strongSwan control tool"),

    # ── L2TP ──────────────────────────────────────────────────────────────
    ToolSpec("mpd5",
             "/usr/local/sbin/mpd5",
             "mpd5",
             optional=True,
             description="Multi-link PPP daemon for L2TP/IPsec"),

    # ── IDS/IPS ───────────────────────────────────────────────────────────
    ToolSpec("suricata",
             "/usr/local/bin/suricata",
             "suricata",
             optional=True,
             description="Suricata IDS/IPS engine"),
    ToolSpec("suricata-update",
             "/usr/local/bin/suricata-update",
             "py311-suricata-update",
             optional=True,
             description="Suricata rule management tool"),

    # ── Nginx (reverse proxy + TLS) ───────────────────────────────────────
    ToolSpec("nginx",
             "/usr/local/sbin/nginx",
             "nginx",
             optional=True,
             description="Nginx TLS reverse proxy (recommended for production)"),

    # ── ca_root_nss (HTTPS rule downloads, pip) ───────────────────────────
    ToolSpec("ca_root_nss",
             "/usr/local/share/certs/ca-root-nss.crt",
             "ca_root_nss",
             description="Mozilla CA bundle (required for HTTPS)"),
]


# ---------------------------------------------------------------------------
# ensure_dirs — called at every startup
# ---------------------------------------------------------------------------

def ensure_dirs() -> List[dict]:
    """
    Create every required directory.  Returns a list of result dicts:
      {"path": str, "created": bool, "ok": bool, "error": str}
    Never raises.
    """
    results = []

    # Always ensure app-data dirs (platform-agnostic)
    specs_to_create = list(_app_dirs())

    # On FreeBSD also create the service dirs
    if _ON_FREEBSD:
        specs_to_create.extend(_FREEBSD_DIRS)

    seen = set()
    for spec in specs_to_create:
        path = spec.path
        if not path or path in seen:
            continue
        seen.add(path)
        try:
            existed = os.path.isdir(path)
            os.makedirs(path, mode=spec.mode, exist_ok=True)
            results.append({"path": path, "created": not existed, "ok": True, "error": ""})
        except OSError as exc:
            results.append({"path": path, "created": False, "ok": False, "error": str(exc)})

    return results


# ---------------------------------------------------------------------------
# check_tools — FreeBSD only
# ---------------------------------------------------------------------------

def check_tools() -> List[dict]:
    """
    Check which tools are available on the system.  Returns list of dicts:
      {"name", "pkg", "binary", "present", "optional", "description"}
    On non-FreeBSD returns an empty list.
    """
    if not _ON_FREEBSD:
        return []

    results = []
    for t in _TOOLS:
        present = os.path.exists(t.binary)
        if not present and t.alt_binary:
            present = os.path.exists(t.alt_binary) or bool(shutil.which(t.alt_binary.split("/")[-1]))
        if not present:
            # final fallback: PATH lookup by name
            present = bool(shutil.which(t.name.split()[0]))
        results.append({
            "name":        t.name,
            "pkg":         t.pkg,
            "binary":      t.binary,
            "present":     present,
            "optional":    t.optional,
            "description": t.description,
        })
    return results


# ---------------------------------------------------------------------------
# preflight_check — combines dirs + tools into one report
# ---------------------------------------------------------------------------

def preflight_check() -> dict:
    """
    Return a full preflight report.  Suitable for a /system/preflight UI page.

    {
      "dirs":   [{"path", "ok", "created", "error"}, ...],
      "tools":  [{"name", "pkg", "present", "optional", "description"}, ...],
      "missing_required": [...tool names...],
      "overall_ok": bool,
    }
    """
    dirs   = ensure_dirs()        # also ensures dirs are created
    tools  = check_tools()

    missing_required = [t["name"] for t in tools if not t["present"] and not t["optional"]]
    dir_errors       = [d["path"] for d in dirs if not d["ok"]]

    overall_ok = (len(missing_required) == 0 and len(dir_errors) == 0)

    return {
        "dirs":              dirs,
        "tools":             tools,
        "missing_required":  missing_required,
        "dir_errors":        dir_errors,
        "overall_ok":        overall_ok,
    }
