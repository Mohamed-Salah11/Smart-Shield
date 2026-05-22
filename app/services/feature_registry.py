"""
feature_registry.py
--------------------
Single source of truth for every Smart Shield appliance feature and its
runtime capability status.

Each feature entry maps a canonical key to required commands, services, and
the current operating mode: live | dry-run | config-only | unsupported |
degraded | unavailable.

The registry is queried at startup and on demand via /api/status/features.
"""

import os
import shutil
import sys
from dataclasses import dataclass, field
from typing import List, Optional

_ON_FREEBSD = sys.platform.startswith("freebsd")


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Feature:
    key: str                                    # canonical key, e.g. "pf_firewall"
    name: str                                   # display name
    description: str = ""
    required_commands: List[str] = field(default_factory=list)
    required_services: List[str] = field(default_factory=list)
    optional_commands: List[str] = field(default_factory=list)
    freebsd_only: bool = False
    category: str = "core"                      # core | vpn | ids | services | filtering


# ---------------------------------------------------------------------------
# Feature manifest
# ---------------------------------------------------------------------------

_FEATURES: List[Feature] = [
    # ── Core firewall ──────────────────────────────────────────────────────
    Feature(
        key="pf_firewall",
        name="PF Firewall",
        description="Packet filter firewall — WAN/LAN rules, NAT, aliases",
        required_commands=["pfctl"],
        required_services=["pf"],
        freebsd_only=True,
        category="core",
    ),
    Feature(
        key="network_interfaces",
        name="Network Interfaces",
        description="LAN/WAN interface assignment and configuration",
        required_commands=["ifconfig", "sysrc"],
        freebsd_only=True,
        category="core",
    ),
    Feature(
        key="routing",
        name="Routing",
        description="Static routes and gateway management",
        required_commands=["route"],
        freebsd_only=True,
        category="core",
    ),
    Feature(
        key="nat",
        name="NAT",
        description="Outbound NAT, port forwards, 1:1 NAT, NPt",
        required_commands=["pfctl"],
        freebsd_only=True,
        category="core",
    ),
    Feature(
        key="firewall_schedules",
        name="Firewall Schedules",
        description="Time-based firewall rule activation windows",
        required_commands=["pfctl"],
        freebsd_only=True,
        category="core",
    ),
    Feature(
        key="virtual_ips",
        name="Virtual IPs / CARP",
        description="IP aliases and CARP high-availability virtual IPs",
        required_commands=["pfctl", "ifconfig"],
        freebsd_only=True,
        category="core",
    ),
    Feature(
        key="high_availability",
        name="High Availability (CARP + pfsync)",
        description="CARP failover and pfsync state synchronisation",
        required_commands=["pfctl"],
        freebsd_only=True,
        category="core",
    ),
    Feature(
        key="certificates",
        name="Certificate Manager",
        description="CA, server, and client certificate lifecycle management",
        required_commands=[],
        freebsd_only=False,
        category="core",
    ),
    Feature(
        key="backup_restore",
        name="Backup / Restore",
        description="Configuration backup and restore",
        required_commands=[],
        freebsd_only=False,
        category="core",
    ),

    # ── DHCP ──────────────────────────────────────────────────────────────
    Feature(
        key="dhcpv4",
        name="DHCP Server (IPv4)",
        description="ISC DHCPd — IP address assignment for LAN clients",
        required_commands=["dhcpd"],
        required_services=["isc-dhcpd"],
        freebsd_only=True,
        category="services",
    ),
    Feature(
        key="dhcpv6",
        name="DHCP Server (IPv6)",
        description="Kea DHCPv6 — IPv6 address and prefix assignment",
        optional_commands=["kea-dhcp6"],
        freebsd_only=True,
        category="services",
    ),

    # ── DNS ───────────────────────────────────────────────────────────────
    Feature(
        key="dns_resolver",
        name="DNS Resolver (Unbound)",
        description="Unbound recursive DNS resolver / forwarder",
        required_commands=["unbound", "unbound-checkconf"],
        # The unbound package's rc.d service is `unbound` (what install.sh enables
        # and the rest of the app manages) — NOT the base-system `local_unbound`.
        required_services=["unbound"],
        freebsd_only=True,
        category="services",
    ),
    Feature(
        key="dns_filtering",
        name="DNS Filtering",
        description="Domain-based DNS block / allow / redirect rules",
        required_commands=["unbound"],
        freebsd_only=True,
        category="filtering",
    ),

    # ── Filtering ─────────────────────────────────────────────────────────
    Feature(
        key="web_filtering",
        name="Web / Domain Filtering",
        description="Domain-level content filtering (DNS-based)",
        required_commands=["unbound"],
        freebsd_only=True,
        category="filtering",
    ),
    Feature(
        key="app_filtering",
        name="Application Filtering",
        description="Application-level block by domain / port signatures",
        required_commands=["pfctl", "unbound"],
        freebsd_only=True,
        category="filtering",
    ),

    # ── Captive Portal ────────────────────────────────────────────────────
    Feature(
        key="captive_portal",
        name="Captive Portal",
        description="HTTP redirect portal for guest / BYOD access control",
        required_commands=["pfctl"],
        freebsd_only=True,
        category="services",
    ),

    # ── VPN ───────────────────────────────────────────────────────────────
    Feature(
        key="openvpn",
        name="OpenVPN",
        description="OpenVPN server and client configuration with PKI",
        required_commands=["openvpn"],
        required_services=["openvpn"],
        freebsd_only=True,
        category="vpn",
    ),
    Feature(
        key="ipsec",
        name="IPsec (strongSwan)",
        description="Site-to-site and mobile IPsec via strongSwan / swanctl",
        required_commands=["ipsec"],
        required_services=["strongswan"],
        freebsd_only=True,
        category="vpn",
    ),
    Feature(
        key="l2tp",
        name="L2TP",
        description="L2TP/IPsec VPN via mpd5",
        required_commands=["mpd5"],
        required_services=["mpd5"],
        freebsd_only=True,
        category="vpn",
    ),

    # ── IDS / IPS ─────────────────────────────────────────────────────────
    Feature(
        key="suricata_ids",
        name="Suricata IDS",
        description="Suricata intrusion detection in IDS (passive) mode",
        required_commands=["suricata"],
        required_services=["suricata"],
        freebsd_only=True,
        category="ids",
    ),
    Feature(
        key="suricata_ips",
        name="Suricata IPS",
        description="Suricata intrusion prevention — requires netmap kernel support",
        required_commands=["suricata"],
        required_services=["suricata"],
        freebsd_only=True,
        category="ids",
    ),
    Feature(
        key="threat_intel",
        name="Threat Intelligence Feeds",
        description="abuse.ch URLhaus / MalwareBazaar / ThreatFox integration",
        required_commands=[],
        freebsd_only=False,
        category="ids",
    ),

    # ── Network services ──────────────────────────────────────────────────
    Feature(
        key="ddns",
        name="Dynamic DNS",
        description="Automatic WAN IP updates via ddclient",
        required_commands=["ddclient"],
        required_services=["ddclient"],
        freebsd_only=True,
        category="services",
    ),
    Feature(
        key="ntp",
        name="NTP",
        description="Network time synchronisation",
        required_commands=["ntpd"],
        required_services=["ntpd"],
        freebsd_only=True,
        category="services",
    ),
    Feature(
        key="snmp",
        name="SNMP",
        description="Simple Network Management Protocol monitoring",
        required_commands=["bsnmpd"],
        required_services=["bsnmpd"],
        freebsd_only=True,
        category="services",
    ),
    Feature(
        key="upnp",
        name="UPnP",
        description="Universal Plug and Play port mapping",
        required_commands=["miniupnpd"],
        required_services=["miniupnpd"],
        freebsd_only=True,
        category="services",
    ),
    Feature(
        key="igmp_proxy",
        name="IGMP Proxy",
        description="Multicast routing via IGMP proxy",
        required_commands=["igmpproxy"],
        required_services=["igmpproxy"],
        freebsd_only=True,
        category="services",
    ),
    Feature(
        key="mrtg",
        name="Traffic Graphs (MRTG)",
        description="Interface bandwidth usage graphs",
        optional_commands=["mrtg"],
        freebsd_only=True,
        category="services",
    ),
    Feature(
        key="siem",
        name="SIEM / Log Collection",
        description="Structured event logging and collection",
        required_commands=[],
        freebsd_only=False,
        category="services",
    ),
    Feature(
        key="ai_chatbot",
        name="AI Chatbot",
        description="Groq-powered AI assistant",
        required_commands=[],
        freebsd_only=False,
        category="services",
    ),
]

# Build a lookup dict
_FEATURE_MAP: dict = {f.key: f for f in _FEATURES}


# ---------------------------------------------------------------------------
# Capability evaluation
# ---------------------------------------------------------------------------

def _cmd_present(cmd: str) -> bool:
    """Return True if a command binary is found in PATH or common absolute paths."""
    if shutil.which(cmd):
        return True
    abs_paths = [
        f"/sbin/{cmd}", f"/usr/sbin/{cmd}", f"/usr/bin/{cmd}",
        f"/usr/local/sbin/{cmd}", f"/usr/local/bin/{cmd}",
    ]
    return any(os.path.exists(p) for p in abs_paths)


def _service_present(svc: str) -> bool:
    """Return True if a service script exists in the rc.d directories.
    On non-FreeBSD (dev machines) always returns True so features aren't
    incorrectly reported as unavailable during development."""
    if not sys.platform.startswith("freebsd"):
        return True
    for svcdir in ("/etc/rc.d", "/usr/local/etc/rc.d"):
        if os.path.exists(os.path.join(svcdir, svc)):
            return True
    return False


def _feature_mode(feature: Feature) -> str:
    """
    Determine the current operating mode for a feature.

    Returns one of:
      live          all requirements met, network apply enabled
      dry-run       all requirements met but apply is disabled
      config-only   non-FreeBSD; data stored but never applied to OS
      unsupported   platform does not support this feature at all
      degraded      optional deps missing; core function may still work
      unavailable   required commands or services missing on FreeBSD
    """
    from app.services.runtime_mode import current_mode as _runtime_mode

    runtime = _runtime_mode()

    if feature.freebsd_only and not _ON_FREEBSD:
        return "unsupported"

    if not _ON_FREEBSD:
        return "config-only"

    # Required commands must all be present
    missing_cmds = [c for c in feature.required_commands if not _cmd_present(c)]
    if missing_cmds:
        return "unavailable"

    # Special env-key checks
    if feature.key == "threat_intel" and not os.getenv("ABUSECH_AUTH_KEY", "").strip():
        return "degraded"
    if feature.key == "ai_chatbot" and not os.getenv("GROQ_API_KEY", "").strip():
        return "unavailable"

    # Optional commands — if missing, feature is degraded not broken
    missing_opt = [c for c in feature.optional_commands if not _cmd_present(c)]
    if missing_opt:
        return "degraded"

    if runtime in ("dry-run", "development"):
        return "dry-run"
    if runtime == "degraded":
        return "degraded"

    return "live"


def _feature_status(feature: Feature) -> dict:
    """Return a full status dict for a single feature."""
    fmode = _feature_mode(feature)
    missing_cmds = [c for c in feature.required_commands if not _cmd_present(c)] if _ON_FREEBSD else []
    missing_svcs = [s for s in feature.required_services if not _service_present(s)] if _ON_FREEBSD else []
    missing_opt  = [c for c in feature.optional_commands if not _cmd_present(c)] if _ON_FREEBSD else []

    color_map = {
        "live":        "green",
        "dry-run":     "yellow",
        "config-only": "blue",
        "unsupported": "gray",
        "degraded":    "orange",
        "unavailable": "red",
    }

    return {
        "key":              feature.key,
        "name":             feature.name,
        "description":      feature.description,
        "category":         feature.category,
        "freebsd_only":     feature.freebsd_only,
        "mode":             fmode,
        "color":            color_map.get(fmode, "gray"),
        "missing_commands": missing_cmds,
        "missing_services": missing_svcs,
        "missing_optional": missing_opt,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_feature_status(key: str) -> Optional[dict]:
    """Return status dict for one feature, or None if the key is unknown."""
    f = _FEATURE_MAP.get(key)
    return _feature_status(f) if f else None


def get_all_features() -> List[dict]:
    """Return status dicts for every registered feature."""
    return [_feature_status(f) for f in _FEATURES]


def get_features_by_category() -> dict:
    """Return {category: [status_dict, ...]} organised by UI grouping."""
    result: dict = {}
    for f in _FEATURES:
        result.setdefault(f.category, []).append(_feature_status(f))
    return result


def is_feature_live(key: str) -> bool:
    """Return True only when the named feature is in live operating mode."""
    f = _FEATURE_MAP.get(key)
    return _feature_mode(f) == "live" if f else False


def feature_summary() -> dict:
    """Return aggregate mode counts plus total: {live, dry-run, degraded, …, total}."""
    counts: dict = {}
    for f in _FEATURES:
        m = _feature_mode(f)
        counts[m] = counts.get(m, 0) + 1
    counts["total"] = len(_FEATURES)
    return counts
