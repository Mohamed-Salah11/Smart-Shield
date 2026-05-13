"""
chatbot_service.py
------------------
SmartShield AI agent powered by Groq with function calling.

The agent can query live system data (firewall rules, logs, service health,
DHCP leases, IDS alerts, content policy, VPN status) and search the web for
security topics. It uses an agentic loop so the model can call multiple tools
before forming a final answer.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

import requests

SYSTEM_PROMPT = """You are SmartShield AI, an expert network security assistant integrated
into the Smart Shield firewall appliance. You have direct access to real-time data from
this specific installation through the tools provided.

Guidelines:
- ALWAYS use tools to fetch current data before answering questions about system state,
  logs, rules, or configuration. Never fabricate or guess system values.
- Be specific to THIS installation, not generic. Quote actual IPs, rule names, and counts.
- Flag any security concerns you notice in the data (failed logins, IDS alerts, open ports).
- For external security questions (CVEs, best practices) use search_web.
- Keep answers concise and actionable. Use bullet points for lists.
- If a tool fails or returns an error, tell the user and suggest what to check manually.

Agent capabilities (require user confirmation before executing):
- You can block or unblock domains via the DNS filter using block_domain / unblock_domain.
- You can add firewall block rules using add_firewall_block_rule.
- When a user asks you to perform a write action (block a domain, add a rule, etc.):
  1. Respond with a clear numbered list of EXACTLY what you will do, where, and what the effect will be.
  2. End with "Shall I apply this?" and wait for the user to confirm.
  3. ONLY after the user says yes (e.g. "yes", "do it", "go ahead") — call the tool.
     The system will then show an approval card before the change is applied.
  Do NOT call write tools without explicit user confirmation first.
- Use get_firewall_help when users ask how to configure, navigate, or find any section of
  this firewall's UI. Always prefer this tool over guessing at page names or menu paths.

Content policy:
- Filter rules have two actions: 'block' (Redirect to block page — blocks ALL clients) and
  'allow' (Allow whitelist only — blocks non-whitelisted LAN devices, passes whitelisted ones).
- Use get_tracked_hosts to see which devices are whitelisted and get_content_policy to inspect
  active rules. Whitelisted devices are managed in Network → Devices.

General conversation:
- You are a helpful AI assistant as well as a firewall expert. For casual or off-topic questions
  (greetings, general knowledge, time, date, math, etc.) respond naturally and helpfully without
  using tools. Only use firewall tools when the question is specifically about THIS system's state.
"""

# ---------------------------------------------------------------------------
# Groq key resolution (DB-first → env fallback)
# ---------------------------------------------------------------------------

def _load_groq_key(conn) -> str:
    """Read Groq API key from service_state (encrypted) then fall back to env var."""
    try:
        row = conn.execute(
            "SELECT value_json FROM service_state WHERE key_name='chatbot_settings'"
        ).fetchone()
        if row:
            settings = json.loads(row["value_json"])
            encrypted = settings.get("groq_api_key", "")
            if encrypted:
                from app.secret_store import decrypt_secret
                return decrypt_secret(encrypted)
    except Exception:
        pass
    return os.environ.get("GROQ_API_KEY", "")


# ---------------------------------------------------------------------------
# Tool definitions (Groq/OpenAI function-calling format)
# ---------------------------------------------------------------------------

TOOLS = [
    {
        "name": "get_system_health",
        "description": (
            "Get the current running status of all Smart Shield services "
            "(PF firewall, DHCP, Unbound/DNS, OpenVPN, IPSec, IDS/Suricata, etc.) "
            "and basic system resource usage."
        ),
        "parameters": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_audit_logs",
        "description": (
            "Search and retrieve Smart Shield audit logs. Use this to analyse "
            "login attempts, configuration changes, firewall events, and security incidents."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "description": "Filter by category: session, system, security, browsing, ids (optional)",
                },
                "limit": {
                    "type": "integer",
                    "description": "Max entries to return (1–200). Default 50.",
                },
                "search": {
                    "type": "string",
                    "description": "Text search within log messages or details.",
                },
            },
            "required": [],
        },
    },
    {
        "name": "get_firewall_rules",
        "description": (
            "Get the active firewall rules from Smart Shield. "
            "Returns the rule set requested: floating (global), wan, lan, or all."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "rule_type": {
                    "type": "string",
                    "enum": ["floating", "wan", "lan", "all"],
                    "description": "Which rule set to retrieve.",
                }
            },
            "required": ["rule_type"],
        },
    },
    {
        "name": "get_network_config",
        "description": (
            "Get the current network configuration: LAN IP/subnet, WAN type and IP, "
            "interface port assignments, and DHCP pool settings."
        ),
        "parameters": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_dhcp_leases",
        "description": (
            "Get the current active DHCP leases — shows all devices that have received "
            "IP addresses from this Smart Shield appliance."
        ),
        "parameters": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_tracked_hosts",
        "description": (
            "Get all auto-discovered LAN devices tracked by Smart Shield (via ARP and DHCP). "
            "Shows hostname, IP address, MAC address, first seen date, and whitelist status. "
            "Use this when the user asks about connected devices, whitelisted devices, "
            "or which devices can bypass 'Allow whitelist only' content policy rules."
        ),
        "parameters": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_ids_alerts",
        "description": (
            "Get recent IDS/IPS (Suricata) intrusion detection alerts. "
            "Use this to analyse active threats and security incidents."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Max alerts to return (1–100). Default 20.",
                }
            },
            "required": [],
        },
    },
    {
        "name": "get_content_policy",
        "description": (
            "Get the current content policy rules: DNS filter rules (blocked/allowed domains), "
            "web filter rules, and application filter rules."
        ),
        "parameters": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_vpn_status",
        "description": (
            "Get the current VPN configuration and connection status for "
            "OpenVPN servers/clients, IPSec tunnels, and L2TP."
        ),
        "parameters": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "search_web",
        "description": (
            "Search the internet for firewall configuration guides, security advisories, "
            "CVE information, or best practices. Use when the user asks about external "
            "security topics not specific to this appliance."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search query focused on network security, firewalls, or FreeBSD topics.",
                }
            },
            "required": ["query"],
        },
    },
    {
        "name": "get_firewall_help",
        "description": (
            "Get detailed guidance on how to use a specific section of the Smart Shield "
            "firewall UI. Use this whenever a user asks 'how do I configure X', "
            "'where do I find Y', 'what does the VPN page do', or any navigation/how-to "
            "question about this appliance. "
            "Sections: dashboard, firewall, nat, dhcp, dhcpv6, dns, ids, vpn, "
            "routing, content_policy, devices, captive_portal, certificates, system, siem."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "section": {
                    "type": "string",
                    "description": "The section name, e.g. 'firewall', 'vpn', 'ids', 'dhcp'.",
                }
            },
            "required": ["section"],
        },
    },
    # ── Write / action tools (require user confirmation) ──────────────────
    {
        "name": "block_domain",
        "description": (
            "Block a domain via the DNS content filter. "
            "Use this when the user asks to block a website or domain. "
            "This requires user confirmation before it is applied."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Domain to block (e.g. facebook.com). Do not include 'https://' or paths.",
                },
                "category": {
                    "type": "string",
                    "description": "Category label for the rule (e.g. social-media, gaming, adult). Default: custom.",
                },
                "description": {
                    "type": "string",
                    "description": "Short reason for the block (shown in the filter list).",
                },
            },
            "required": ["domain"],
        },
    },
    {
        "name": "unblock_domain",
        "description": (
            "Remove a DNS block rule for a domain, restoring access. "
            "Use when the user asks to unblock or allow a previously blocked domain. "
            "Requires user confirmation."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Domain to unblock (e.g. facebook.com).",
                },
            },
            "required": ["domain"],
        },
    },
    {
        "name": "add_firewall_block_rule",
        "description": (
            "Add a floating firewall rule to block traffic by IP, network, or port. "
            "Use this when the user asks to block an IP address, subnet, or specific port. "
            "Requires user confirmation before it is applied."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "description": {
                    "type": "string",
                    "description": "Human-readable label for this rule (required).",
                },
                "source": {
                    "type": "string",
                    "description": "Source IP or network to block (e.g. 192.168.1.50 or any). Default: any.",
                },
                "destination": {
                    "type": "string",
                    "description": "Destination IP or network (e.g. 1.2.3.4 or any). Default: any.",
                },
                "protocol": {
                    "type": "string",
                    "enum": ["any", "tcp", "udp", "icmp", "tcp/udp"],
                    "description": "Protocol. Default: any.",
                },
                "dest_port": {
                    "type": "string",
                    "description": "Destination port or range to block (e.g. 80 or 80:443). Leave empty for all ports.",
                },
                "direction": {
                    "type": "string",
                    "enum": ["in", "out", "any"],
                    "description": "Traffic direction. Default: any.",
                },
            },
            "required": ["description"],
        },
    },
]

# Tools that mutate system state — intercepted for user confirmation
_WRITE_TOOLS = {"block_domain", "unblock_domain", "add_firewall_block_rule"}

# Groq/OpenAI tool format wraps each schema in {"type": "function", "function": ...}
_GROQ_TOOLS = [{"type": "function", "function": t} for t in TOOLS]


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

def _execute_tool(conn, name: str, args: dict) -> Any:
    try:
        if name == "get_system_health":
            return _tool_health(conn)
        if name == "get_audit_logs":
            return _tool_audit_logs(conn, args)
        if name == "get_firewall_rules":
            return _tool_firewall_rules(conn, args)
        if name == "get_network_config":
            return _tool_network_config(conn)
        if name == "get_dhcp_leases":
            return _tool_dhcp_leases(conn)
        if name == "get_tracked_hosts":
            return _tool_tracked_hosts(conn)
        if name == "get_ids_alerts":
            return _tool_ids_alerts(conn, args)
        if name == "get_content_policy":
            return _tool_content_policy(conn)
        if name == "get_vpn_status":
            return _tool_vpn_status(conn)
        if name == "search_web":
            return _tool_search_web(args.get("query", ""), conn=conn)
        if name == "get_firewall_help":
            return _tool_firewall_help(args)
        return {"error": f"Unknown tool: {name}"}
    except Exception as exc:
        return {"error": str(exc)}


def _tool_health(conn) -> dict:
    from app.services.service_manager import get_all_service_health
    try:
        health = get_all_service_health()
    except Exception:
        health = {}
    try:
        counts = {
            "firewall_rules_floating": conn.execute("SELECT COUNT(*) FROM firewall_rules_floating WHERE disabled=0").fetchone()[0],
            "firewall_rules_wan":      conn.execute("SELECT COUNT(*) FROM firewall_rules_wan WHERE disabled=0").fetchone()[0],
            "firewall_rules_lan":      conn.execute("SELECT COUNT(*) FROM firewall_rules_lan WHERE disabled=0").fetchone()[0],
            "dhcp_leases_static":      conn.execute("SELECT COUNT(*) FROM static_leases").fetchone()[0],
            "dns_filter_rules_enabled": conn.execute("SELECT COUNT(*) FROM filter_dns_rules WHERE enabled=1").fetchone()[0],
        }
    except Exception:
        counts = {}
    return {"health": health, "counts": counts, "platform": sys.platform}


def _tool_audit_logs(conn, args: dict) -> dict:
    from app.audit_log import tail_events
    category = args.get("category") or None
    limit    = min(int(args.get("limit") or 50), 200)
    search   = args.get("search") or ""
    events   = tail_events(limit=limit, category=category)
    if search:
        events = [e for e in events
                  if search.lower() in (e.get("action", "") + str(e.get("details", ""))).lower()]
    return {"count": len(events), "events": events}


def _tool_firewall_rules(conn, args: dict) -> dict:
    rule_type = args.get("rule_type", "all")
    result: dict = {}
    tables = {
        "floating": "firewall_rules_floating",
        "wan":      "firewall_rules_wan",
        "lan":      "firewall_rules_lan",
    }
    targets = list(tables.items()) if rule_type == "all" else [(rule_type, tables.get(rule_type, ""))]
    for key, table in targets:
        if table:
            rows = [dict(r) for r in conn.execute(f"SELECT * FROM {table} ORDER BY rule_order")]
            result[key] = rows
    return result


def _tool_network_config(conn) -> dict:
    lan = dict(conn.execute("SELECT * FROM lan_config WHERE id=1").fetchone() or {})
    wan = dict(conn.execute("SELECT * FROM wan_config WHERE id=1").fetchone() or {})
    ifaces = [dict(r) for r in conn.execute("SELECT * FROM interface_assignments")]
    pools  = [dict(r) for r in conn.execute("SELECT * FROM dhcp_pools")]
    return {"lan": lan, "wan": wan, "interfaces": ifaces, "dhcp_pools": pools}


def _tool_dhcp_leases(conn) -> dict:
    try:
        from app.services.dhcp_writer import get_live_leases
        leases = get_live_leases()
    except Exception:
        leases = [dict(r) for r in conn.execute("SELECT * FROM static_leases")]
    return {"count": len(leases), "leases": leases}


def _tool_tracked_hosts(conn) -> dict:
    hosts = [dict(r) for r in conn.execute(
        "SELECT id, hostname, ip_address, mac_address, interface_type, "
        "first_seen, last_seen, is_whitelisted FROM tracked_hosts ORDER BY first_seen DESC"
    )]
    whitelisted = [h for h in hosts if h.get("is_whitelisted")]
    return {
        "total": len(hosts),
        "whitelisted_count": len(whitelisted),
        "hosts": hosts,
    }


def _tool_ids_alerts(conn, args: dict) -> dict:
    limit = min(int(args.get("limit") or 20), 100)
    try:
        from app.services.ids_service import get_recent_alerts
        alerts = get_recent_alerts(limit=limit)
    except Exception:
        ids_row = conn.execute("SELECT * FROM ids_config WHERE id=1").fetchone()
        alerts  = []
        return {"ids_config": dict(ids_row) if ids_row else {}, "alerts": alerts,
                "note": "IDS alert log not accessible on this platform."}
    return {"count": len(alerts), "alerts": alerts}


def _tool_content_policy(conn) -> dict:
    dns_rules = [dict(r) for r in conn.execute(
        "SELECT domain, action, category, enabled FROM filter_dns_rules ORDER BY domain"
    )]
    web_rules = [dict(r) for r in conn.execute(
        "SELECT url_pattern, action, category, enabled FROM filter_web_rules ORDER BY url_pattern"
    )]
    app_rules = [dict(r) for r in conn.execute(
        "SELECT app_name, action, block_dns, block_ports, ports, category, enabled FROM filter_app_rules"
    )]
    try:
        whitelisted_count = conn.execute(
            "SELECT COUNT(*) FROM tracked_hosts WHERE is_whitelisted=1"
        ).fetchone()[0]
    except Exception:
        whitelisted_count = 0
    return {
        "action_legend": {
            "block": "Redirect to block page — blocks ALL clients regardless of whitelist",
            "allow": "Allow whitelist only — blocks non-whitelisted clients, passes whitelisted devices",
        },
        "whitelisted_device_count": whitelisted_count,
        "dns_filter":  {"count": len(dns_rules), "rules": dns_rules},
        "web_filter":  {"count": len(web_rules), "rules": web_rules},
        "app_filter":  {"count": len(app_rules), "rules": app_rules},
    }


def _tool_vpn_status(conn) -> dict:
    openvpn_servers = [dict(r) for r in conn.execute(
        "SELECT id, description, mode, protocol, port, tunnel_network, enabled FROM openvpn_servers"
    )]
    openvpn_clients = [dict(r) for r in conn.execute(
        "SELECT id, description, server_hostname, port, enabled FROM openvpn_clients"
    )]
    ipsec_p1 = [dict(r) for r in conn.execute(
        "SELECT id, description, ike_version, remote_gateway, enabled FROM ipsec_phase1"
    )]
    l2tp_row = conn.execute("SELECT server_address, enabled FROM l2tp_config WHERE id=1").fetchone()
    return {
        "openvpn": {"servers": openvpn_servers, "clients": openvpn_clients},
        "ipsec":   {"phase1_tunnels": ipsec_p1},
        "l2tp":    dict(l2tp_row) if l2tp_row else {},
    }


def _load_search_settings(conn) -> dict:
    """Read Google CSE key/cx from service_state or env vars."""
    try:
        row = conn.execute(
            "SELECT value_json FROM service_state WHERE key_name='chatbot_settings'"
        ).fetchone()
        if row:
            s = json.loads(row["value_json"])
            key = (s.get("google_cse_key") or "").strip() or os.environ.get("GOOGLE_CSE_KEY", "").strip()
            cx  = (s.get("google_cse_cx")  or "").strip() or os.environ.get("GOOGLE_CSE_CX",  "").strip()
            return {"key": key, "cx": cx}
    except Exception:
        pass
    return {
        "key": os.environ.get("GOOGLE_CSE_KEY", "").strip(),
        "cx":  os.environ.get("GOOGLE_CSE_CX",  "").strip(),
    }


def _tool_search_web(query: str, conn=None) -> dict:
    """Search the web. Uses Google Custom Search if configured, else DuckDuckGo."""
    if not query.strip():
        return {"error": "Empty query."}

    # Tier 1: Google Custom Search (if configured)
    if conn is not None:
        try:
            cse = _load_search_settings(conn)
            if cse["key"] and cse["cx"]:
                resp = requests.get(
                    "https://www.googleapis.com/customsearch/v1",
                    params={"key": cse["key"], "cx": cse["cx"], "q": query, "num": 5},
                    timeout=10,
                    headers={"User-Agent": "SmartShield-AI/1.0"},
                )
                data = resp.json()
                if "items" in data:
                    return {
                        "query": query,
                        "source": "google",
                        "results": [
                            {
                                "title":   i.get("title", ""),
                                "source":  i.get("link", ""),
                                "snippet": i.get("snippet", ""),
                            }
                            for i in data["items"]
                        ],
                    }
        except Exception:
            pass  # fall through to DDG

    # Tier 2: DuckDuckGo Instant Answers (no key required)
    try:
        resp = requests.get(
            "https://api.duckduckgo.com/",
            params={"q": query, "format": "json", "no_html": "1", "skip_disambig": "1"},
            timeout=8,
            headers={"User-Agent": "SmartShield-AI/1.0"},
        )
        data = resp.json()
        results = []
        if data.get("AbstractText"):
            results.append({
                "title":   data.get("Heading", ""),
                "source":  data.get("AbstractURL", ""),
                "snippet": data["AbstractText"],
            })
        for r in data.get("Results", [])[:4]:
            if isinstance(r, dict) and r.get("Text"):
                results.append({"title": r.get("Text", "")[:80], "source": r.get("FirstURL", ""), "snippet": r["Text"]})
        for r in data.get("RelatedTopics", [])[:4]:
            if isinstance(r, dict) and r.get("Text"):
                results.append({"title": "", "source": r.get("FirstURL", ""), "snippet": r["Text"]})
        if results:
            return {"query": query, "source": "duckduckgo", "results": results}
        return {
            "query": query,
            "source": "duckduckgo",
            "results": [{"snippet": "No results found. The query may be too specific — try rephrasing or use broader terms."}],
        }
    except Exception as exc:
        return {"error": f"Web search failed: {exc}"}


_FIREWALL_GUIDE = {
    "dashboard": {
        "title": "Dashboard",
        "url": "/",
        "description": "Central overview: service health cards, live WAN/LAN traffic sparklines, "
                       "recent alert count, and gateway status.",
        "common_tasks": [
            "Check if all services (PF, DHCP, DNS, IDS) are running — each card shows green/red status",
            "See current WAN IP and uptime in the WAN card",
            "Click a service card to jump to its configuration page",
        ],
    },
    "firewall": {
        "title": "Firewall Rules",
        "url": "/firewall/rules",
        "description": "Manage PF packet-filter rules across three tabs: Floating (global, "
                       "any-interface), WAN (inbound from internet), and LAN (outbound from clients).",
        "common_tasks": [
            "Add a rule: click 'Add Rule' on the relevant tab, fill in Protocol/Source/Destination/Port, then Apply",
            "Disable a rule temporarily: toggle the enable switch without deleting it",
            "Rule order matters — rules are evaluated top-to-bottom; first match wins",
            "Use the Floating tab for rules that apply regardless of interface (IDS bypass, management access)",
            "WAN rules mainly control port-forwarding and inbound blocks; LAN rules control client egress",
        ],
        "tips": "Changes require clicking 'Apply Changes' — unsaved changes show a banner at the top.",
    },
    "nat": {
        "title": "NAT / Advanced Firewall",
        "url": "/firewall/nat",
        "description": "Port forwarding (DNAT), outbound NAT overrides, bogon/private-net blocking, "
                       "NAT reflection, policy-based routing, and CARP virtual IPs.",
        "common_tasks": [
            "Forward port 443 to an internal server: Add port-forward rule, set Destination Port=443, Redirect IP=server IP",
            "Enable bogon blocking: check 'Block Bogons' toggle in the Hardening card",
            "Enable NAT reflection (hairpin): toggle 'NAT Reflection' for accessing port-forwarded services from LAN",
        ],
    },
    "dhcp": {
        "title": "DHCP Server (IPv4)",
        "url": "/dhcp",
        "description": "Configure the ISC DHCPv4 server: address pools, lease time, DNS servers, "
                       "gateway, domain, static leases (MAC→IP mapping), and DHCP options.",
        "common_tasks": [
            "Change IP pool range: edit the Pool start/end addresses in the main settings card",
            "Reserve a fixed IP for a device: Static Leases tab → Add, enter MAC address and desired IP",
            "Check active leases: the Leases tab shows all currently assigned IPs with hostnames",
            "Change DNS servers served to clients: set DNS1/DNS2 fields (default: this appliance's LAN IP)",
        ],
    },
    "dhcpv6": {
        "title": "DHCPv6 / RA",
        "url": "/dhcp/ipv6",
        "description": "Configure DHCPv6 address pools and Router Advertisement (RA) settings for IPv6 clients.",
        "common_tasks": [
            "Enable IPv6 DHCP: set a prefix pool and enable RA on the LAN interface",
            "Configure prefix delegation: set PD Prefix to delegate from upstream ISP",
        ],
    },
    "dns": {
        "title": "DNS / Unbound",
        "url": "/dns",
        "description": "Unbound recursive DNS resolver. Settings include listen port, DNSSEC, "
                       "DNS-over-TLS (DoT), local host overrides, and access control.",
        "common_tasks": [
            "Add a local hostname override: DNS → Local Overrides → Add, enter hostname and IP",
            "Enable DNSSEC: toggle DNSSEC in the main settings form",
            "Enable DNS-over-TLS: set upstream DoT server (e.g. 1.1.1.1@853)",
            "Block a domain: use Content Policy → DNS Filter instead — not Unbound directly",
        ],
    },
    "ids": {
        "title": "IDS / IPS (Suricata)",
        "url": "/ids",
        "description": "Intrusion Detection/Prevention with Suricata. Four tabs: "
                       "Status & Alerts (live alert feed with search/filter), "
                       "Configuration (mode, interface, HOME_NET), "
                       "Rulesets (enable/disable rule sources), "
                       "Threat Feeds (abuse.ch API key for IOC lookups).",
        "common_tasks": [
            "Enable IDS: click the Enable button at top; set an interface in Configuration tab first",
            "Switch to IPS mode (active blocking): Configuration → Mode = IPS (requires netmap kernel module)",
            "Add Emerging Threats rules: Rulesets → Add Source, name='et/open'",
            "Update rules to latest version: Rulesets → Update Rules button",
            "Look up a suspicious IP or domain: Threat Feeds tab → IOC Lookup input",
            "Filter alerts by severity: use the severity dropdown above the alerts table",
            "Search alerts by signature or IP: type in the search box above the alerts table",
        ],
        "tips": "IPS mode requires the netmap kernel module and a compatible NIC. If IPS fails, "
                "Smart Shield automatically falls back to IDS mode. EVE JSON logging must be enabled "
                "in Configuration for the alert viewer to work.",
    },
    "vpn": {
        "title": "VPN",
        "url": "/vpn",
        "description": "Three VPN subsystems: OpenVPN (site-to-site or road-warrior with certs), "
                       "IPSec (IKEv1/v2 tunnels), and L2TP/IPSec (Windows/mobile remote access).",
        "common_tasks": [
            "Create a road-warrior OpenVPN server: VPN → OpenVPN → Servers → Add, mode=tun; "
            "generate or import a CA certificate first from the Certificates page",
            "Add an OpenVPN client: VPN → OpenVPN → Clients → Add, set server hostname and port",
            "Create an IPSec tunnel: VPN → IPSec → Phase 1 → Add, then add Phase 2 selectors",
            "Enable L2TP for Windows/mobile: VPN → L2TP → enable, set server IP range and shared secret",
        ],
    },
    "routing": {
        "title": "Routing",
        "url": "/routing",
        "description": "Three sub-pages: Gateways (define upstream routers with health monitoring), "
                       "Static Routes (add specific network routes), "
                       "Gateway Groups (failover/load-balance across multiple gateways).",
        "common_tasks": [
            "Add a gateway: Routing → Gateways → Add, enter gateway IP and interface",
            "Add a static route: Routing → Static Routes → Add, enter destination network and gateway",
            "Set up WAN failover: create two gateways, then Routing → Gateway Groups → Add, "
            "assign gateways to tiers (Tier 1 = primary, Tier 2 = backup)",
            "Check gateway health: gateway list shows reachable/unreachable status with last-seen time",
        ],
    },
    "content_policy": {
        "title": "Content Policy",
        "url": "/content-policy",
        "description": (
            "Three filtering layers: DNS Filter (block domains at DNS resolution), "
            "Web Filter (URL pattern blocking), App Filter (block by application ports/protocol). "
            "Each rule has two actions: 'Redirect to block page' (blocks ALL clients) or "
            "'Allow whitelist only' (blocks non-whitelisted LAN devices, passes whitelisted ones). "
            "Whitelisted devices are managed in Network → Devices."
        ),
        "common_tasks": [
            "Block a domain for everyone: DNS Filter → Add Rule, enter domain, "
            "action='Redirect to block page', click Apply",
            "Restrict a domain to trusted devices only: DNS Filter → Add Rule, "
            "action='Allow whitelist only'; then mark those devices as whitelisted in Network → Devices",
            "Block an app/port category: App Filter → Add, enter ports, action='Redirect to block page'",
            "See which devices are whitelisted: Network → Devices — each row has a Whitelist toggle",
        ],
    },
    "devices": {
        "title": "Network Devices",
        "url": "/api/network/devices",
        "description": (
            "Lists all auto-discovered LAN devices (hostname, IP, MAC address, first seen date). "
            "Devices are captured when they join the network via ARP or DHCP. "
            "Each device has a Whitelist toggle — whitelisted devices bypass 'Allow whitelist only' "
            "content policy rules and can access those domains/apps."
        ),
        "common_tasks": [
            "See all LAN devices: Network → Devices shows hostname, IP, MAC, and join date",
            "Whitelist a device: toggle the Whitelist switch next to the device — takes effect immediately",
            "Refresh device list: click Refresh to re-scan ARP table for newly joined devices",
            "Find a device by IP or MAC: use the search box at the top of the table",
        ],
    },
    "captive_portal": {
        "title": "Captive Portal",
        "url": "/captive-portal",
        "description": "Redirect unauthenticated clients to a login/voucher page before granting "
                       "internet access. Supports time-limited vouchers and per-session bandwidth limits.",
        "common_tasks": [
            "Enable captive portal: set interface, enable toggle, then apply",
            "Create time-limited vouchers: Vouchers tab → Add voucher, set duration and bandwidth limit",
            "View active sessions: Sessions tab shows connected clients and expiry times",
            "Manually log out a client: click Logout next to the session in the Sessions tab",
        ],
    },
    "certificates": {
        "title": "Certificates",
        "url": "/certificates",
        "description": "PKI management: create Certificate Authorities (CAs), issue server/client "
                       "certificates, and import external certificate/key pairs. Used by OpenVPN and HTTPS.",
        "common_tasks": [
            "Create a CA: Certificates → Add CA, fill in Common Name and validity period",
            "Issue a server cert: Certificates → Add Certificate, select the CA, type=server",
            "Issue a client cert for VPN: type=client, enter client common name",
            "Import an existing cert/key pair: use the Import tab, paste PEM-encoded cert and key",
        ],
    },
    "system": {
        "title": "System Settings",
        "url": "/system/general-setup",
        "description": "Hostname, timezone, admin password, SSH access, firmware/package updates, "
                       "config backups/restore, SmartShield AI key, and scheduled tasks.",
        "common_tasks": [
            "Change admin password: System → General Setup → Admin Password section",
            "Configure the AI chatbot: System → General Setup → SmartShield AI section, paste Groq API key",
            "Download config backup: System → Backup → Download",
            "Restore from backup: System → Backup → Restore, upload the backup file",
            "Enable SSH access: System → Advanced → Admin Access → Enable SSH",
        ],
    },
    "siem": {
        "title": "SIEM / Live Log Monitor",
        "url": "/status/system-logs",
        "description": "Real-time event stream from the audit log. "
                       "Filters by category (session, system, security, browsing, IDS), "
                       "action type, and free-text search. Exports to JSON. Auto-polls every 5 seconds.",
        "common_tasks": [
            "Find login failures: filter Category=Security, or use the Action filter → Auth Events",
            "Watch IDS alerts live: filter Category=IDS/IPS",
            "Search for activity from a specific IP: type the IP in the search box",
            "Export logs: click Export button (downloads JSON of current view)",
            "Pause auto-scroll: scroll down in the log viewport",
            "Adjust refresh rate: use the refresh dropdown (2s/5s/10s/30s/paused)",
        ],
    },
}


def _tool_firewall_help(args: dict) -> dict:
    """Return UI guidance for a Smart Shield section by fuzzy name match."""
    section = (args.get("section") or "").lower().strip()
    for key, data in _FIREWALL_GUIDE.items():
        if key == section or key in section or section in key:
            return {"section": key, "found": True, **data}
    return {
        "found": False,
        "message": f"No guide found for '{section}'. Available sections:",
        "sections": [
            {"key": k, "title": v["title"], "url": v["url"]}
            for k, v in _FIREWALL_GUIDE.items()
        ],
    }


# ---------------------------------------------------------------------------
# Pending-action helpers
# ---------------------------------------------------------------------------

def _describe_pending_action(tool: str, args: dict) -> tuple:
    """Return (summary, detail) strings for a pending write action."""
    if tool == "block_domain":
        domain = args.get("domain", "unknown")
        cat    = args.get("category", "custom")
        return (
            f"Block {domain} in DNS filter",
            f"Add {domain} to the DNS block list (category: {cat}). "
            f"All DNS queries for {domain} and its subdomains will be redirected to the Smart Shield block page.",
        )
    if tool == "unblock_domain":
        domain = args.get("domain", "unknown")
        return (
            f"Unblock {domain} from DNS filter",
            f"Remove the DNS block rule for {domain}, restoring normal access.",
        )
    if tool == "add_firewall_block_rule":
        desc  = args.get("description", "Block rule")
        src   = args.get("source", "any")
        dst   = args.get("destination", "any")
        port  = args.get("dest_port", "")
        proto = args.get("protocol", "any")
        port_str = f":{port}" if port else ""
        return (
            f"Add firewall block rule: {desc}",
            f"Create a floating BLOCK rule — {proto.upper()} {src} → {dst}{port_str}. Description: {desc}",
        )
    return (f"Execute: {tool}", f"Arguments: {json.dumps(args)}")


def execute_approved_action(conn, action: dict, username: str) -> dict:
    """Execute a write action that has been approved by the user."""
    tool = action.get("tool", "")
    args = action.get("args", {})

    try:
        from app.services.apply_state import (
            record_apply_start, record_apply_result, record_dry_run,
        )
        import sys as _sys
        _dry = not _sys.platform.startswith("freebsd")

        if tool == "block_domain":
            domain      = args.get("domain", "").strip()
            category    = args.get("category", "custom")
            description = args.get("description", "Blocked via SmartShield AI")
            if not domain:
                return {"ok": False, "reply": "Domain name is required."}
            from app.services.dns_filter import add_dns_filter_rule, apply_dns_filter
            add_dns_filter_rule(conn, domain, action="block", category=category, description=description)
            if _dry:
                record_dry_run(conn, "dns_filtering", applied_by=username)
                result = {"ok": True, "message": "dry-run"}
            else:
                job_id = record_apply_start(conn, "dns_filtering", applied_by=username,
                                            notes="chatbot:block_domain")
                result = apply_dns_filter(conn)
                record_apply_result(conn, job_id, ok=result.get("ok", False),
                                    message=result.get("message", ""))
            if result["ok"] or result.get("message") == "dry-run":
                reply = (
                    f"**{domain}** has been added to the DNS block list and the filter has been applied. "
                    f"All DNS queries for {domain} and its subdomains are now blocked."
                )
            else:
                reply = f"Rule saved but DNS reload failed: {result['message']}. Restart Unbound to apply."
            return {"ok": True, "reply": reply}

        if tool == "unblock_domain":
            domain = args.get("domain", "").strip()
            if not domain:
                return {"ok": False, "reply": "Domain name is required."}
            from app.services.dns_filter import get_dns_filter_rules, delete_dns_filter_rule, apply_dns_filter
            rules   = get_dns_filter_rules(conn)
            matched = [r for r in rules if r["domain"].lower() == domain.lower()]
            if not matched:
                return {"ok": True, "reply": f"No DNS block rule found for **{domain}** — it may already be unblocked."}
            for r in matched:
                delete_dns_filter_rule(conn, r["id"])
            if _dry:
                record_dry_run(conn, "dns_filtering", applied_by=username)
                result = {"ok": True, "message": "dry-run"}
            else:
                job_id = record_apply_start(conn, "dns_filtering", applied_by=username,
                                            notes="chatbot:unblock_domain")
                result = apply_dns_filter(conn)
                record_apply_result(conn, job_id, ok=result.get("ok", False),
                                    message=result.get("message", ""))
            suffix = "" if result["ok"] else f" (DNS reload failed: {result['message']})"
            return {"ok": True, "reply": f"DNS block rule for **{domain}** has been removed.{suffix}"}

        if tool == "add_firewall_block_rule":
            description = args.get("description", "AI-generated block rule")
            source      = args.get("source", "any")
            destination = args.get("destination", "any")
            protocol    = args.get("protocol", "any")
            dest_port   = args.get("dest_port", "")
            # Coerce: PF requires explicit proto when port filtering (no "any" + port)
            if dest_port and protocol in ("any", ""):
                protocol = "tcp"

            cursor = conn.cursor()
            cursor.execute("SELECT COALESCE(MAX(rule_order), 0) + 1 FROM firewall_rules_floating")
            new_order = cursor.fetchone()[0]
            cursor.execute(
                """
                INSERT INTO firewall_rules_floating
                    (action, disabled, interface, protocol, source, source_port,
                     destination, dest_port, gateway, queue, schedule, description, rule_order)
                VALUES (?, 0, ?, ?, ?, '', ?, ?, '', '', '', ?, ?)
                """,
                # interface="" means any interface; direction is not a DB column
                ("block", "", protocol, source, destination, dest_port, description, new_order),
            )
            conn.commit()
            if _dry:
                record_dry_run(conn, "pf_firewall", applied_by=username)
                pf_ok = True
            else:
                job_id = record_apply_start(conn, "pf_firewall", applied_by=username,
                                            notes="chatbot:add_firewall_block_rule")
                try:
                    from app.services.pf_generator import reload_pf_rules
                    pf_result = reload_pf_rules(conn)
                    pf_ok = pf_result.get("ok", True)
                    record_apply_result(conn, job_id, ok=pf_ok,
                                        message=pf_result.get("message", ""))
                except Exception as _exc:
                    record_apply_result(conn, job_id, ok=False, message=str(_exc))
                    pf_ok = False
            return {
                "ok": True,
                "reply": (
                    f"Firewall block rule **{description}** has been added "
                    f"({source} → {destination}, {protocol.upper()}). "
                    + ("Changes have been applied." if pf_ok else "Rule saved; PF reload failed — restart manually.")
                ),
            }

        return {"ok": False, "reply": f"Unknown action type: {tool}"}

    except Exception as exc:
        return {"ok": False, "reply": f"Failed to execute action: {exc}"}


# ---------------------------------------------------------------------------
# Agentic chat loop (Groq)
# ---------------------------------------------------------------------------

def process_chat(conn, messages: list, username: str) -> dict:
    """
    Run the SmartShield AI agent loop using Groq.

    Accepts `messages` in the format [{"role": "user"/"assistant", "content": str}].
    Returns {"ok": True, "reply": str, "messages": updated_list} or {"ok": False, "message": str}.
    """
    api_key = _load_groq_key(conn)
    if not api_key:
        return {"ok": False, "message": "GROQ_API_KEY not configured. Add it via Admin → Settings → SmartShield AI."}

    try:
        from groq import Groq
    except ImportError:
        return {"ok": False, "message": "Groq SDK not installed. Run: pip install groq"}

    client = Groq(api_key=api_key)

    # Build internal message chain: system prompt prepended to the full conversation history.
    internal_messages: list = [{"role": "system", "content": SYSTEM_PROMPT}] + list(messages)

    max_iterations = 8

    for _ in range(max_iterations):
        try:
            response = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=internal_messages,
                tools=_GROQ_TOOLS,
                tool_choice="auto",
            )
        except Exception as exc:
            return {"ok": False, "message": f"Groq API error: {exc}"}

        msg = response.choices[0].message

        if not msg.tool_calls:
            # No tool calls — this is the final text response.
            reply = msg.content or ""
            updated = list(messages) + [{"role": "assistant", "content": reply}]
            return {"ok": True, "reply": reply, "messages": updated}

        # Check if any call is a write action requiring user confirmation.
        write_call = next(
            (tc for tc in msg.tool_calls if tc.function.name in _WRITE_TOOLS), None
        )
        if write_call:
            args = json.loads(write_call.function.arguments)
            summary, detail = _describe_pending_action(write_call.function.name, args)
            agent_text = (
                f"I can {summary.lower()}. Please review the details below and approve or cancel."
            )
            updated = list(messages) + [{"role": "assistant", "content": agent_text}]
            return {
                "ok": True,
                "reply": agent_text,
                "messages": updated,
                "pending_action": {
                    "tool":    write_call.function.name,
                    "args":    args,
                    "summary": summary,
                    "detail":  detail,
                },
            }

        # Execute all read-only tool calls and feed results back into the message chain.
        internal_messages.append(msg)  # assistant turn that contains tool_calls
        for tc in msg.tool_calls:
            tool_args = json.loads(tc.function.arguments)
            result    = _execute_tool(conn, tc.function.name, tool_args)
            internal_messages.append({
                "role":         "tool",
                "tool_call_id": tc.id,
                "content":      json.dumps(result, default=str),
            })

    return {"ok": False, "message": "Agent loop ended without a final response. Please try again."}
