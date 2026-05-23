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


# Phase 11: canonical path is now `smartshield` (no hyphen). On in-place
# upgrades from older installs the legacy `smart-shield` directory may exist
# alongside (or instead of) the new one — install.sh creates a compat
# symlink, but operators sometimes wipe symlinks during cleanup. Resolve at
# import time so the preflight check / dir manifest reach the right tree even
# when no symlink is in place.
def _ss(parent: str, *, new: str = "smartshield", old: str = "smart-shield") -> str:
    if not _ON_FREEBSD:
        return os.path.join(parent, new)
    new_path = os.path.join(parent, new)
    old_path = os.path.join(parent, old)
    # Prefer the legacy path ONLY when it exists AND the new one does not.
    if os.path.isdir(old_path) and not os.path.isdir(new_path):
        return old_path
    return new_path


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
    if _ON_FREEBSD:   return os.path.join(_ss("/var/db"), "data.db")
    if sys.platform.startswith("win"):
        return os.path.join(os.getenv("LOCALAPPDATA", "."), "SmartShield", "data.db")
    return "data.db"

def _default_cfg():
    if _ON_FREEBSD:   return os.path.join(_ss("/usr/local/etc"), "config.json")
    return "config.json"

def _default_uploads():
    if _ON_FREEBSD:   return os.path.join(_ss("/var/db"), "uploads", "profile_pictures")
    return os.path.join("static", "uploads", "profile_pictures")

def _default_audit():
    if _ON_FREEBSD:   return os.path.join(_ss("/var/log"), "audit.log")
    return "audit.log"


# All dirs that must exist on FreeBSD
_FREEBSD_DIRS: List[DirSpec] = [
    # ── Smart Shield runtime ──────────────────────────────────────────────
    DirSpec(_ss("/var/db"),
            description="Smart Shield database root"),
    DirSpec(os.path.join(_ss("/var/db"), "uploads/profile_pictures"),
            description="User profile picture uploads"),
    DirSpec(_ss("/var/log"),
            description="Smart Shield application + audit logs"),
    DirSpec(_ss("/var/run"),
            description="Smart Shield PID file"),
    DirSpec(_ss("/usr/local/etc"),
            description="Smart Shield env + config.json"),
    DirSpec(_ss("/usr/local/share"),
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


# Canonical tool manifest for the appliance. This is the single source of truth
# for "what binaries must/should exist"; the FreeBSD installer's verification
# loop (bsd/install.sh) and feature_registry.py's required/optional_commands are
# kept in sync with this list by hand (install.sh's check runs before the venv
# exists, so it can't import this module).
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
    ToolSpec("ppp",      "/usr/sbin/ppp",    "",
             description="User-mode PPP daemon — FreeBSD base system (required for PPPoE WAN)"),

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
    # Primary path matches the canonical `smartshield` layout install.sh
    # creates today. alt_binary covers two fallbacks tried in order by
    # check_tools(): the legacy hyphenated path (in-place upgrades) and a
    # system-wide `pip install gunicorn` outside any venv.
    ToolSpec("gunicorn",
             os.path.join(_ss("/usr/local/share"), ".venv/bin/gunicorn"),
             "gunicorn (pip)",
             description="Production WSGI server",
             alt_binary="/usr/local/share/smart-shield/.venv/bin/gunicorn"),

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

    # ── Additional base diagnostics / kernel / network tools ──────────────
    # FreeBSD base system (pkg=""); used by diagnostics pages, writers, and
    # priv_helper actions (kldload, dnctl, etc.).
    ToolSpec("kldload",  "/sbin/kldload",   "",
             description="Load kernel module (netmap for IPS, etc.) — base"),
    ToolSpec("kldstat",  "/sbin/kldstat",   "",
             description="List loaded kernel modules — base"),
    ToolSpec("sysctl",   "/sbin/sysctl",    "",
             description="Kernel state (IP forwarding, etc.) — base"),
    ToolSpec("dmesg",    "/sbin/dmesg",     "",
             description="Kernel message buffer (OOM diagnostics) — base"),
    ToolSpec("dnctl",    "/sbin/dnctl",     "",
             description="dummynet traffic-shaper control — base"),
    ToolSpec("service",  "/usr/sbin/service", "",
             description="rc.d service control — base"),
    ToolSpec("netstat",  "/usr/bin/netstat", "",
             description="Network statistics / routing table — base"),
    ToolSpec("ndp",      "/usr/sbin/ndp",   "",
             description="IPv6 neighbour table — base"),
    ToolSpec("pkill",    "/bin/pkill",      "",
             description="Signal processes by name — base"),
    ToolSpec("ntpd",     "/usr/sbin/ntpd",  "",
             description="NTP daemon (clock sync for TLS) — base"),
    ToolSpec("ntpq",     "/usr/sbin/ntpq",  "",
             description="NTP query tool — base"),
    ToolSpec("rtadvd",   "/usr/sbin/rtadvd", "",
             description="IPv6 Router Advertisement daemon — base"),
    ToolSpec("bsnmpd",   "/usr/sbin/bsnmpd", "",
             description="SNMP daemon — base"),
    ToolSpec("openssl",  "/usr/bin/openssl", "",
             description="TLS/cert tooling — base"),

    # ── Optional feature daemons / CLIs (pkg-installed) ───────────────────
    ToolSpec("kea-dhcp6", "/usr/local/sbin/kea-dhcp6", "kea",
             optional=True, description="Kea DHCPv6 server"),
    ToolSpec("miniupnpd", "/usr/local/sbin/miniupnpd", "miniupnpd",
             optional=True, description="UPnP IGD daemon"),
    ToolSpec("igmpproxy", "/usr/local/sbin/igmpproxy", "igmpproxy",
             optional=True, description="IGMP multicast proxy"),
    ToolSpec("ddclient",  "/usr/local/sbin/ddclient", "ddclient",
             optional=True, description="Dynamic DNS update client"),
    ToolSpec("mrtg",      "/usr/local/bin/mrtg", "mrtg",
             optional=True, description="Traffic grapher"),
    ToolSpec("ipsec (strongSwan CLI)", "/usr/local/sbin/ipsec", "strongswan",
             optional=True, description="strongSwan ipsec control CLI"),

    # ── DNS / resolver helper CLIs ────────────────────────────────────────
    ToolSpec("unbound-checkconf", "/usr/local/sbin/unbound-checkconf", "unbound",
             optional=True, alt_binary="/usr/sbin/unbound-checkconf",
             description="Unbound config validator"),
    ToolSpec("unbound-control", "/usr/local/sbin/unbound-control", "unbound",
             optional=True, alt_binary="/usr/sbin/unbound-control",
             description="Unbound runtime control"),
    ToolSpec("nsupdate", "/usr/local/bin/nsupdate", "bind-tools",
             description="Dynamic DNS update tool (bind-tools)"),
    ToolSpec("dig", "/usr/local/bin/dig", "bind-tools",
             alt_binary="/usr/bin/drill",
             description="DNS lookup tool (bind-tools; drill fallback)"),
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

    # Bootstrap config.json from the example template if it doesn't exist yet.
    _ensure_config_json()

    return results


def _ensure_config_json():
    """Copy config.example.json → config.json on first run if the file is absent."""
    import json as _json

    cfg_path = os.getenv(
        "SMARTSHIELD_CONFIG_PATH",
        os.path.join(_ss("/usr/local/etc"), "config.json") if _ON_FREEBSD else "config.json",
    )
    if os.path.exists(cfg_path):
        return  # already present

    # Locate the example template relative to this file's package root
    base     = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    example  = os.path.join(base, "config.example.json")
    if not os.path.exists(example):
        return  # nothing to bootstrap from

    try:
        with open(example, "r", encoding="utf-8") as fh:
            data = _json.load(fh)
        os.makedirs(os.path.dirname(os.path.abspath(cfg_path)), exist_ok=True)
        with open(cfg_path, "w", encoding="utf-8") as fh:
            _json.dump(data, fh, indent=4)
    except OSError:
        pass


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

def _check_disk_space(path: str = "/var", min_mb: int = 500) -> dict:
    """Return disk space info for *path*. Warns when free space < min_mb."""
    try:
        stat = shutil.disk_usage(path)
        free_mb = stat.free // (1024 * 1024)
        ok = free_mb >= min_mb
        return {
            "path":    path,
            "free_mb": free_mb,
            "ok":      ok,
            "warning": "" if ok else f"Only {free_mb} MB free on {path} (minimum {min_mb} MB recommended).",
        }
    except Exception as exc:
        return {"path": path, "free_mb": -1, "ok": True, "warning": f"Could not check disk space: {exc}"}


def _check_freebsd_version(min_major: int = 13) -> dict:
    """Check that the FreeBSD major version meets the minimum requirement."""
    if not _ON_FREEBSD:
        return {"version": "n/a", "ok": True, "warning": ""}
    try:
        import subprocess
        r = subprocess.run(["uname", "-r"], capture_output=True, text=True, timeout=5)
        version_str = r.stdout.strip()  # e.g. "13.2-RELEASE-p4"
        major = int(version_str.split(".")[0])
        ok = major >= min_major
        return {
            "version": version_str,
            "major":   major,
            "ok":      ok,
            "warning": "" if ok else f"FreeBSD {version_str} is older than {min_major}.x — upgrade recommended.",
        }
    except Exception as exc:
        return {"version": "unknown", "ok": True, "warning": f"Could not determine FreeBSD version: {exc}"}


def _check_pfctl_usable() -> dict:
    """Verify pfctl can query PF status without error."""
    if not _ON_FREEBSD:
        return {"ok": True, "warning": ""}
    try:
        import subprocess
        r = subprocess.run(["pfctl", "-s", "info"], capture_output=True, text=True, timeout=5)
        ok = r.returncode == 0
        return {
            "ok":      ok,
            "warning": "" if ok else f"pfctl -s info failed (rc={r.returncode}): {(r.stderr or '').strip()}",
        }
    except Exception as exc:
        return {"ok": False, "warning": f"pfctl check failed: {exc}"}


def _check_kernel_capability(cap_name: str) -> dict:
    """
    Check whether a FreeBSD kernel capability is available.

    Supported cap_name values:
      dummynet   — IP dummynet traffic shaping (IPFW pipes)
      carp       — Common Address Redundancy Protocol
      pfsync     — PF state synchronisation
      netmap     — netmap fast-path I/O (required for Suricata IPS)
      ipv6       — IPv6 kernel support
    """
    if not _ON_FREEBSD:
        return {"cap": cap_name, "ok": True, "warning": ""}

    import subprocess

    sysctl_map = {
        "dummynet": "net.inet.ip.dummynet.count",
        "carp":     "net.inet.carp.allow",
        "pfsync":   "net.pfsync.stats",
        "netmap":   "dev.netmap.version",
        "ipv6":     "net.inet6.ip6.forwarding",
    }

    node = sysctl_map.get(cap_name)
    if not node:
        return {"cap": cap_name, "ok": False,
                "warning": f"Unknown capability: {cap_name}"}

    try:
        r = subprocess.run(["sysctl", "-n", node],
                           capture_output=True, text=True, timeout=5)
        ok = r.returncode == 0
        return {
            "cap":     cap_name,
            "ok":      ok,
            "warning": "" if ok else f"Kernel capability '{cap_name}' unavailable "
                                     f"(sysctl {node} failed). "
                                     f"Some features may not work.",
        }
    except Exception as exc:
        return {"cap": cap_name, "ok": False,
                "warning": f"Could not check capability '{cap_name}': {exc}"}


def _check_kernel_capabilities() -> list:
    """Return capability check results for all relevant FreeBSD kernel options."""
    caps = ["dummynet", "carp", "pfsync", "netmap", "ipv6"]
    return [_check_kernel_capability(c) for c in caps]


def _check_syntax_validators() -> list:
    """
    Verify that installed daemons can validate their own config syntax.
    Returns a list of {"name", "ok", "warning"} dicts.
    """
    if not _ON_FREEBSD:
        return []

    import subprocess

    validators = []

    # pfctl — core firewall (must always be available)
    try:
        import tempfile, os
        with tempfile.NamedTemporaryFile(mode="w", suffix=".conf",
                                        delete=False, prefix="ss_pf_chk_") as f:
            f.write("set block-policy drop\npass all\n")
            tmp = f.name
        r = subprocess.run(["pfctl", "-nf", tmp],
                           capture_output=True, text=True, timeout=5)
        os.unlink(tmp)
        validators.append({
            "name":    "pfctl -nf",
            "ok":      r.returncode == 0,
            "warning": "" if r.returncode == 0
                       else f"pfctl syntax check failed: {(r.stderr or '').strip()}",
        })
    except Exception as exc:
        validators.append({"name": "pfctl -nf", "ok": False,
                           "warning": f"pfctl validator error: {exc}"})

    # unbound-checkconf
    try:
        unbound_conf = "/usr/local/etc/unbound/unbound.conf"
        if os.path.exists(unbound_conf):
            r = subprocess.run(["unbound-checkconf", unbound_conf],
                               capture_output=True, text=True, timeout=5)
            validators.append({
                "name":    "unbound-checkconf",
                "ok":      r.returncode == 0,
                "warning": "" if r.returncode == 0
                           else f"unbound config error: {(r.stderr or r.stdout or '').strip()}",
            })
        else:
            validators.append({
                "name": "unbound-checkconf",
                "ok":   True,
                "warning": "unbound.conf not yet generated — will validate on first apply.",
            })
    except FileNotFoundError:
        validators.append({"name": "unbound-checkconf", "ok": False,
                           "warning": "unbound-checkconf not found — install unbound."})
    except Exception as exc:
        validators.append({"name": "unbound-checkconf", "ok": False,
                           "warning": f"unbound-checkconf error: {exc}"})

    # dhcpd -t (ISC DHCPd)
    try:
        dhcpd_conf = "/usr/local/etc/dhcpd.conf"
        if os.path.exists(dhcpd_conf):
            r = subprocess.run(["dhcpd", "-t", "-cf", dhcpd_conf],
                               capture_output=True, text=True, timeout=5)
            validators.append({
                "name":    "dhcpd -t",
                "ok":      r.returncode == 0,
                "warning": "" if r.returncode == 0
                           else f"dhcpd config error: {(r.stderr or '').strip()}",
            })
        else:
            validators.append({
                "name": "dhcpd -t",
                "ok":   True,
                "warning": "dhcpd.conf not yet generated — will validate on first apply.",
            })
    except FileNotFoundError:
        validators.append({"name": "dhcpd -t", "ok": True,
                           "warning": "dhcpd not installed (optional — needed for DHCP server)."})
    except Exception as exc:
        validators.append({"name": "dhcpd -t", "ok": False,
                           "warning": f"dhcpd validator error: {exc}"})

    # suricata -T
    try:
        suricata_yaml = "/usr/local/etc/suricata/suricata.yaml"
        if shutil.which("suricata") and os.path.exists(suricata_yaml):
            r = subprocess.run(["suricata", "-T", "-c", suricata_yaml],
                               capture_output=True, text=True, timeout=15)
            validators.append({
                "name":    "suricata -T",
                "ok":      r.returncode == 0,
                "warning": "" if r.returncode == 0
                           else f"suricata config error: {(r.stderr or r.stdout or '').strip()[:200]}",
            })
        elif shutil.which("suricata"):
            validators.append({
                "name": "suricata -T",
                "ok":   True,
                "warning": "suricata.yaml not yet generated — will validate on first apply.",
            })
    except Exception as exc:
        validators.append({"name": "suricata -T", "ok": False,
                           "warning": f"suricata validator error: {exc}"})

    return validators


def preflight_check() -> dict:
    """
    Return a full preflight report.  Suitable for a /system/preflight UI page.

    {
      "dirs":              [{"path", "ok", "created", "error"}, ...],
      "tools":             [{"name", "pkg", "present", "optional", "description"}, ...],
      "missing_required":  [...tool names...],
      "dir_errors":        [...paths...],
      "warnings":          [...warning strings...],
      "kernel_caps":       [{"cap", "ok", "warning"}, ...],
      "validators":        [{"name", "ok", "warning"}, ...],
      "system_info":       {"freebsd_version", "disk_var_free_mb", "pfctl_ok"},
      "overall_ok":        bool,
    }
    """
    dirs  = ensure_dirs()
    tools = check_tools()

    missing_required = [t["name"] for t in tools if not t["present"] and not t["optional"]]
    dir_errors       = [d["path"] for d in dirs if not d["ok"]]

    disk   = _check_disk_space("/var" if _ON_FREEBSD else ".")
    ver    = _check_freebsd_version()
    pf_chk = _check_pfctl_usable()
    kcaps  = _check_kernel_capabilities()
    valids = _check_syntax_validators()

    warnings = []
    if not disk["ok"]:
        warnings.append(disk["warning"])
    if not ver["ok"]:
        warnings.append(ver["warning"])
    if not pf_chk["ok"]:
        warnings.append(pf_chk["warning"])
    for cap in kcaps:
        if not cap["ok"] and cap["warning"]:
            warnings.append(cap["warning"])
    for v in valids:
        if not v["ok"] and v["warning"]:
            warnings.append(v["warning"])

    # overall_ok requires required tools present and no dir errors
    # kernel capability failures are advisory (degrade features, not the whole appliance)
    overall_ok = (len(missing_required) == 0 and len(dir_errors) == 0)

    return {
        "dirs":             dirs,
        "tools":            tools,
        "missing_required": missing_required,
        "dir_errors":       dir_errors,
        "warnings":         warnings,
        "kernel_caps":      kcaps,
        "validators":       valids,
        "system_info": {
            "freebsd_version":  ver.get("version", "n/a"),
            "disk_var_free_mb": disk.get("free_mb", -1),
            "pfctl_ok":         pf_chk["ok"],
        },
        "overall_ok": overall_ok,
    }
