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
import re
import sys
from typing import Any

import requests

SYSTEM_PROMPT = """You are SmartShield AI, an expert network security assistant integrated
into the Smart Shield firewall appliance. You have direct access to real-time data from
this specific installation through the tools provided.

SCOPE — STRICT (read this first):
- You assist ONLY with: this firewall appliance, the SOC (Security Operations Center)
  portal, network security, threat analysis, incident response, and security best practices.
- For ANY request outside that scope (greetings beyond a one-line hello, general knowledge,
  math, weather, news, coding help, personal questions, entertainment, trivia, etc.) you MUST
  politely decline and redirect. Reply with a single short sentence, e.g.:
  "I'm SmartShield AI — I can only help with firewall, SOC, and network-security topics."
  Do NOT answer the off-topic question, even partially, and do NOT call any tool for it.
- General security questions (CVEs, attack techniques, hardening, protocols) ARE in scope —
  answer them, and use search_web for external or up-to-date facts.

Guidelines:
- ALWAYS use tools to fetch current data before answering questions about system state,
  logs, rules, cases, alerts, or configuration. Never fabricate or guess system values.
- Be specific to THIS installation, not generic. Quote actual IPs, rule names, and counts.
- Flag any security concerns you notice in the data (failed logins, IDS alerts, open ports).
- Keep answers concise and actionable. Use bullet points for lists.
- If a tool fails or returns an error, tell the user and suggest what to check manually.

Agent capabilities:
- Firewall: block/unblock domains (block_domain / unblock_domain) and add firewall block
  rules (add_firewall_block_rule).
- SOC portal: open, annotate, escalate and close security cases, and triage alerts
  (open_soc_case, add_soc_case_note, escalate_soc_case, close_soc_case, triage_soc_alert).

SOC portal (helping the SOC team):
- The SOC portal uses a tiered analyst model: L1 (triage) < L2 (investigation) < L3 (incident
  response). The current user's tier determines which SOC write actions they may take.
- Use get_soc_cases / get_soc_case_detail to review incident cases, get_soc_alerts to review
  the live security/IDS alert queue and its triage status, get_threat_intel_status for feed
  health, and lookup_threat_intel to check an IP / domain / URL / file-hash against abuse.ch.
- Tier rules for SOC write actions: open_soc_case = L1+, add_soc_case_note = L2+,
  escalate_soc_case = L1 or L2 (L3 is already top tier and cannot escalate), close_soc_case =
  L1/L2 may close ONLY as false_positive while L3 may also close as resolved,
  triage_soc_alert = L1+. NEVER offer an action the current user's tier cannot perform —
  instead tell them which tier is required.

How-to questions (IMPORTANT):
- For ANY question containing "how to", "steps to", "guide me", "show me how", "how do I",
  "what are the steps", "walk me through", or similar phrasing:
  Call get_firewall_help for the most relevant section and return the manual UI steps.
  NEVER call write tools for how-to questions. Answer with the steps only.

When asked to PERFORM an action (block a domain, add a rule, open a case, escalate, etc.):
  1. Call get_firewall_help for the relevant section to retrieve the manual UI steps.
  2. Present those steps as a clear numbered list tailored to the specific request
     (e.g. substitute the actual domain name, port, IP, or case id into the steps).
  3. End with exactly: "Would you like me to apply this for you automatically?"
  4. ONLY after the user replies with explicit confirmation (yes, do it, go ahead, apply,
     sure, please, ok, yeah, confirm) — call the write tool.
     The system will then show an approval card before the change is applied.
  NEVER call a write tool on the first request. Always give manual steps + ask first.

- Use get_app_structure when asked what features, pages, or sections SmartShield has,
  or when the user asks "what can you do" / "what does this system have".

Content policy:
- Filter rules have two actions: 'block' (Redirect to block page — blocks ALL clients) and
  'allow' (Allow whitelist only — blocks non-whitelisted LAN devices, passes whitelisted ones).
- Use get_tracked_hosts to see which devices are whitelisted and get_content_policy to inspect
  active rules. Whitelisted devices are managed in Network → Devices.
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
            "CVE information, threat intelligence, or security best practices. "
            "RESTRICTED: only security, firewall, and network topics are permitted — "
            "queries unrelated to security are rejected. Do not use this for general "
            "knowledge, news, or off-topic searches."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Security-focused search query (firewalls, CVEs, threats, FreeBSD, network security).",
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
            "routing, content_policy, devices, captive_portal, certificates, system, "
            "siem, soc_portal, soc."
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
    {
        "name": "get_app_structure",
        "description": (
            "Get the full list of pages, features, and sections available in this SmartShield "
            "installation. Use when the user asks what this system can do, what pages/sections "
            "exist, or what features are available. Returns all registered URL routes and a "
            "summary of each guide section."
        ),
        "parameters": {"type": "object", "properties": {}, "required": []},
    },
    # ── SOC portal read tools ─────────────────────────────────────────────
    {
        "name": "get_soc_cases",
        "description": (
            "List SOC incident cases from the SIEM. Use when the user asks about "
            "security cases, open incidents, closed cases, or case workload."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "status": {
                    "type": "string",
                    "enum": ["open", "closed", "all"],
                    "description": "Filter by case status. Default: open.",
                },
                "limit": {
                    "type": "integer",
                    "description": "Max cases to return (1–100). Default 50.",
                },
            },
            "required": [],
        },
    },
    {
        "name": "get_soc_case_detail",
        "description": (
            "Get the full detail of a single SOC case: metadata, all investigation "
            "notes, and linked security events. Use when the user asks about a "
            "specific case by its id."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "case_id": {
                    "type": "integer",
                    "description": "The numeric id of the SOC case.",
                }
            },
            "required": ["case_id"],
        },
    },
    {
        "name": "get_soc_alerts",
        "description": (
            "Get the SOC alert queue — recent security and IDS events enriched with "
            "their triage status (new, acknowledged, false_positive, escalated). "
            "Use when the user asks about alerts to triage or recent security events."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "status": {
                    "type": "string",
                    "enum": ["new", "acknowledged", "false_positive", "escalated", "all"],
                    "description": "Filter by triage status. Default: all.",
                },
                "limit": {
                    "type": "integer",
                    "description": "Max alerts to return (1–100). Default 30.",
                },
            },
            "required": [],
        },
    },
    {
        "name": "lookup_threat_intel",
        "description": (
            "Look up an indicator of compromise (IOC) against abuse.ch threat "
            "intelligence. Accepts an IP address, domain/hostname, URL, or file "
            "hash (MD5/SHA1/SHA256) and auto-selects ThreatFox, URLhaus, or "
            "MalwareBazaar. Use to check whether an IP, domain, URL, or file is malicious."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "indicator": {
                    "type": "string",
                    "description": "The IOC to check: an IP, domain, URL, or file hash.",
                }
            },
            "required": ["indicator"],
        },
    },
    {
        "name": "get_threat_intel_status",
        "description": (
            "Get the status of the abuse.ch threat-intelligence feed: last update "
            "time, indicator count, and the PF blocklist table it feeds. Use when "
            "the user asks if threat feeds are up to date."
        ),
        "parameters": {"type": "object", "properties": {}, "required": []},
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
    # ── SOC portal write tools (tier-gated, require user confirmation) ─────
    {
        "name": "open_soc_case",
        "description": (
            "Open a new SOC incident case. Requires SOC tier L1 or higher. "
            "Requires user confirmation before it is created."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "title": {
                    "type": "string",
                    "description": "Short case title (required).",
                },
                "description": {
                    "type": "string",
                    "description": "Description of the incident or concern.",
                },
                "severity": {
                    "type": "string",
                    "enum": ["low", "medium", "high", "critical"],
                    "description": "Case severity. Default: medium.",
                },
            },
            "required": ["title"],
        },
    },
    {
        "name": "add_soc_case_note",
        "description": (
            "Add an investigation note to an existing SOC case. Requires SOC tier "
            "L2 or higher. Requires user confirmation."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "case_id": {"type": "integer", "description": "Target case id."},
                "note": {"type": "string", "description": "The investigation note text."},
            },
            "required": ["case_id", "note"],
        },
    },
    {
        "name": "escalate_soc_case",
        "description": (
            "Escalate a SOC case up one tier (L1→L2 or L2→L3). The current user "
            "must be L1 or L2 — L3 is the top tier and cannot escalate further. "
            "Requires user confirmation."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "case_id": {"type": "integer", "description": "Target case id."},
                "note": {"type": "string", "description": "Optional escalation note."},
            },
            "required": ["case_id"],
        },
    },
    {
        "name": "close_soc_case",
        "description": (
            "Close a SOC case. L1 and L2 analysts may close only as 'false_positive'; "
            "L3 may also close as 'resolved'. Requires user confirmation."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "case_id": {"type": "integer", "description": "Target case id."},
                "closure_type": {
                    "type": "string",
                    "enum": ["false_positive", "resolved"],
                    "description": "How the case is being closed. Default: resolved.",
                },
                "resolution": {
                    "type": "string",
                    "description": "Short closing summary / resolution note.",
                },
            },
            "required": ["case_id"],
        },
    },
    {
        "name": "triage_soc_alert",
        "description": (
            "Triage a SOC alert by marking it acknowledged or false_positive. "
            "Requires SOC tier L1 or higher. Requires user confirmation."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "event_key": {
                    "type": "string",
                    "description": "The alert's event key (event timestamp from get_soc_alerts).",
                },
                "action": {
                    "type": "string",
                    "enum": ["acknowledge", "false_positive"],
                    "description": "Triage action to apply.",
                },
                "note": {"type": "string", "description": "Optional triage note."},
            },
            "required": ["event_key", "action"],
        },
    },
]

# Tools that mutate system state — intercepted for user confirmation
_WRITE_TOOLS = {
    "block_domain", "unblock_domain", "add_firewall_block_rule",
    "open_soc_case", "add_soc_case_note", "escalate_soc_case",
    "close_soc_case", "triage_soc_alert",
}

# SOC write tools — gated by the user's SOC tier instead of is_superuser.
_SOC_WRITE_TOOLS = {
    "open_soc_case", "add_soc_case_note", "escalate_soc_case",
    "close_soc_case", "triage_soc_alert",
}

# Firewall/DNS write tools — require an admin (is_superuser) session. These are
# not exposed on the SOC portal surface, which has no admin session.
_FIREWALL_WRITE_TOOLS = {"block_domain", "unblock_domain", "add_firewall_block_rule"}

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
        if name == "get_app_structure":
            return _tool_app_structure()
        if name == "get_soc_cases":
            return _tool_soc_cases(conn, args)
        if name == "get_soc_case_detail":
            return _tool_soc_case_detail(conn, args)
        if name == "get_soc_alerts":
            return _tool_soc_alerts(conn, args)
        if name == "lookup_threat_intel":
            return _tool_lookup_threat_intel(args.get("indicator", ""))
        if name == "get_threat_intel_status":
            return _tool_threat_intel_status(conn)
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


# ---------------------------------------------------------------------------
# SOC portal read tools
# ---------------------------------------------------------------------------

def _tool_soc_cases(conn, args: dict) -> dict:
    status = (args.get("status") or "open").lower()
    limit  = min(int(args.get("limit") or 50), 100)
    cols = ("id, title, severity, status, created_by, assigned_to, "
            "escalation_tier, closure_type, created_at, updated_at")
    if status == "all":
        rows = conn.execute(
            f"SELECT {cols} FROM siem_cases ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    else:
        if status not in ("open", "closed"):
            status = "open"
        rows = conn.execute(
            f"SELECT {cols} FROM siem_cases WHERE status=? ORDER BY created_at DESC LIMIT ?",
            (status, limit),
        ).fetchall()
    cases = [dict(r) for r in rows]
    return {"status_filter": status, "count": len(cases), "cases": cases}


def _tool_soc_case_detail(conn, args: dict) -> dict:
    try:
        case_id = int(args.get("case_id"))
    except (TypeError, ValueError):
        return {"error": "A numeric case_id is required."}
    case = conn.execute("SELECT * FROM siem_cases WHERE id=?", (case_id,)).fetchone()
    if not case:
        return {"error": f"No SOC case found with id {case_id}."}
    notes = [dict(r) for r in conn.execute(
        "SELECT note, created_by, created_at FROM siem_case_notes "
        "WHERE case_id=? ORDER BY created_at ASC", (case_id,)
    )]
    events = [dict(r) for r in conn.execute(
        "SELECT event_timestamp, event_action, event_category, event_summary "
        "FROM siem_case_events WHERE case_id=? ORDER BY event_timestamp ASC", (case_id,)
    )]
    return {"case": dict(case), "notes": notes, "linked_events": events}


def _tool_soc_alerts(conn, args: dict) -> dict:
    status_filter = (args.get("status") or "all").lower()
    limit = min(int(args.get("limit") or 30), 100)
    from app.audit_log import tail_events_since
    events = tail_events_since(limit=500, categories=["security", "ids"])

    # Build lookups of the latest triage action: uuid-keyed (preferred) and
    # timestamp-keyed (fallback for pre-v35 rows whose backfill missed).
    action_map: dict = {}    # by event_uuid
    action_legacy: dict = {} # by timestamp
    if events:
        uuids = [e.get("event_uuid", "") for e in events if e.get("event_uuid")]
        keys  = [e.get("timestamp", "")  for e in events if e.get("timestamp")]
        if uuids:
            u_ph = ",".join("?" * len(uuids))
            for r in conn.execute(
                f"SELECT event_uuid, action, taken_by, taken_at, note, case_id "
                f"FROM siem_alert_actions WHERE event_uuid IN ({u_ph}) "
                f"ORDER BY taken_at ASC",
                uuids,
            ):
                if r["event_uuid"]:
                    action_map[r["event_uuid"]] = {
                        "triage_status": r["action"],
                        "triage_by":     r["taken_by"],
                        "triage_at":     r["taken_at"],
                        "triage_note":   r["note"],
                        "case_id":       r["case_id"],
                    }
        if keys:
            k_ph = ",".join("?" * len(keys))
            for r in conn.execute(
                f"SELECT event_key, action, taken_by, taken_at, note, case_id "
                f"FROM siem_alert_actions WHERE event_key IN ({k_ph}) "
                f"ORDER BY taken_at ASC",
                keys,
            ):
                action_legacy[r["event_key"]] = {
                    "triage_status": r["action"],
                    "triage_by":     r["taken_by"],
                    "triage_at":     r["taken_at"],
                    "triage_note":   r["note"],
                    "case_id":       r["case_id"],
                }

    enriched = []
    for e in events:
        key    = e.get("timestamp", "")
        uu     = e.get("event_uuid", "")
        act    = (action_map.get(uu) if uu else None) or action_legacy.get(key)
        merged = dict(e)
        # The LLM uses event_key as its triage handle — prefer the uuid (so
        # subsequent triage calls land on the right row even for same-ms
        # collisions); fall back to timestamp for any pre-v34 row.
        merged["event_key"]     = uu or key
        merged["event_uuid"]    = uu
        merged["triage_status"] = act["triage_status"] if act else "new"
        if act:
            merged.update({k: v for k, v in act.items() if k != "triage_status"})
        if status_filter == "new" and act:
            continue
        if status_filter in ("acknowledged", "false_positive", "escalated") \
                and merged["triage_status"] != status_filter:
            continue
        enriched.append(merged)
        if len(enriched) >= limit:
            break
    return {"status_filter": status_filter, "count": len(enriched), "alerts": enriched}


def _tool_lookup_threat_intel(indicator: str) -> dict:
    """Auto-route an IOC to the right abuse.ch service."""
    indicator = (indicator or "").strip()
    if not indicator:
        return {"error": "An indicator (IP, domain, URL, or file hash) is required."}

    import ipaddress as _ip
    from app.services import abusech_client as _ti

    is_hash = (len(indicator) in (32, 40, 64)
               and all(c in "0123456789abcdefABCDEF" for c in indicator))
    is_url  = indicator.lower().startswith(("http://", "https://"))
    is_ip   = False
    if not is_hash and not is_url:
        try:
            _ip.ip_address(indicator)
            is_ip = True
        except ValueError:
            is_ip = False

    results: dict = {"indicator": indicator}
    try:
        if is_hash:
            results["type"] = "file_hash"
            results["malwarebazaar"] = _ti.malwarebazaar_lookup_hash(indicator)
            results["threatfox"]     = _ti.threatfox_search_ioc(indicator)
        elif is_url:
            results["type"] = "url"
            results["urlhaus"]   = _ti.urlhaus_lookup_url(indicator)
            results["threatfox"] = _ti.threatfox_search_ioc(indicator)
        else:
            results["type"]      = "ip" if is_ip else "domain"
            results["urlhaus"]   = _ti.urlhaus_lookup_host(indicator)
            results["threatfox"] = _ti.threatfox_search_ioc(indicator)
        results["note"] = (
            "query_status 'dry_run' means live abuse.ch lookups are disabled "
            "(set ABUSECH_DRY_RUN=0 and configure ABUSECH_AUTH_KEY to enable)."
        )
    except Exception as exc:
        results["error"] = f"Threat-intel lookup failed: {exc}"
    return results


def _tool_threat_intel_status(conn) -> dict:
    from app.services.abusech_client import get_threat_intel_status
    try:
        return get_threat_intel_status(conn)
    except Exception as exc:
        return {"error": f"Could not read threat-intel status: {exc}"}


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


# Substring roots that mark a web-search query as in-scope (security / network).
# Matched as plain substrings so plurals and variants are covered
# (e.g. "firewall" matches "firewalls", "vulnerab" matches "vulnerability").
_SECURITY_SEARCH_TERMS = frozenset({
    "firewall", "pf ", "packet filter", "freebsd", "network",
    "security", "secure", "cve", "vulnerab", "exploit", "malware", "ransomware",
    "phishing", "threat", "attack", "breach", "intrusion", "ids", "ips",
    "suricata", "snort", "vpn", "ipsec", "openvpn", "wireguard", "l2tp",
    "dns", "dnssec", "tls", "ssl", "certificate", "encrypt", "decrypt",
    "cipher", "port scan", "nmap", "ddos", "dos attack", "botnet", "c2",
    "command and control", "ioc", "indicator of compromise", "mitre", "att&ck",
    "soc", "siem", "incident", "forensic", "hardening", "authentication",
    "credential", "password", "brute force", "privilege", "rootkit", "trojan",
    "backdoor", "spoof", "mitm", "man-in-the-middle", "nat", "subnet", "router",
    "gateway", "proxy", "captive portal", "dhcp", "arp", "packet", "protocol",
    "cyber", "abuse.ch", "threatfox", "urlhaus", "virustotal", "zero-day",
    "patch", "advisory", "owasp", "cis benchmark", "honeypot", "sandbox",
    "antivirus", "edr", "xdr", "log4j", "rce", "sql injection", "xss", "csrf",
})


def _is_security_query(query: str) -> bool:
    """True if the query is about security / firewall / networking topics."""
    q = (query or "").lower()
    return any(term in q for term in _SECURITY_SEARCH_TERMS)


def _tool_search_web(query: str, conn=None) -> dict:
    """Search the web. Uses Google Custom Search if configured, else DuckDuckGo.

    Restricted to security / firewall / network topics — off-topic queries are
    rejected before any external call is made.
    """
    if not query.strip():
        return {"error": "Empty query."}

    if not _is_security_query(query):
        return {
            "error": (
                "Out of scope: web search is limited to security, firewall, and "
                "network topics. Rephrase the query around a security subject, or "
                "decline the request."
            ),
            "query": query,
        }

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
    "soc_portal": {
        "title": "SOC Team Portal",
        "url": "/soc-portal/",
        "description": (
            "Dedicated portal for the Security Operations Center team, with its own "
            "login separate from the admin UI. Pages: Dashboard (open-case counts, "
            "feed status), Alerts (live security/IDS event queue), Cases (incident "
            "case list), Threat Intel (abuse.ch feed status, IOC lookups), and "
            "Quick Actions (block IP, reload firewall). Access is tiered: "
            "L1 (triage) < L2 (investigation) < L3 (incident response); superusers "
            "get L3. SmartShield AI can read cases/alerts/threat-intel and, for "
            "permitted tiers, open/note/escalate/close cases and triage alerts."
        ),
        "common_tasks": [
            "Open a case: SOC Portal → Cases → Open Case, enter title and severity (L1+)",
            "Add an investigation note: open the case → Notes → Add (L2+)",
            "Escalate a case: open the case → Escalate (L1→L2, L2→L3)",
            "Close a case: open the case → Close — L1/L2 may close only as false positive, L3 may resolve",
            "Triage an alert: SOC Portal → Alerts → Acknowledge or mark False Positive (L1+)",
            "Check an IOC: SOC Portal → Threat Intel → IOC lookup (L2+)",
            "Block an IP / reload firewall: SOC Portal → Quick Actions (L3 only)",
        ],
        "tips": "A user's SOC tier comes from their group's soc_tier field (Users → Groups). "
                "Logging out of the admin UI does not end the SOC portal session.",
    },
    "soc": {
        "title": "SOC Portal",
        "url": "/soc-portal/dashboard",
        "description": (
            "Tier-gated SOC analyst portal at /soc-portal. Pages include "
            "Live Alerts (/soc-portal/alerts) — the streaming alert queue for "
            "acknowledging, escalating, or marking alerts false positive; "
            "Cases (/soc-portal/cases) — incident workflow with notes, "
            "assignment, and L1→L2→L3 escalation; Threat Intel (L2+); and "
            "Quick Actions (L3+) for IP blocking and firewall reload. "
            "The older /soc/l1 and /soc/l2 admin-side pages now redirect here."
        ),
        "common_tasks": [
            "Triage alerts: open /soc-portal/alerts, pick an alert, acknowledge / escalate / mark false positive",
            "Investigate an IP: from /soc-portal/cases create a case linked to the event timeline",
            "Set up MFA: /soc-portal/security — enrol TOTP from any authenticator app",
        ],
    },
}


def _tool_firewall_help(args: dict) -> dict:
    """Return UI guidance for a Smart Shield section by fuzzy name match."""
    section = (args.get("section") or "").lower().strip()

    # Pass 1: exact key / substring match
    for key, data in _FIREWALL_GUIDE.items():
        if key == section or key in section or section in key:
            return {"section": key, "found": True, **data}

    # Pass 2: keyword search across description and common_tasks text
    if section:
        words = set(section.split())
        best_key, best_score = None, 0
        for key, data in _FIREWALL_GUIDE.items():
            haystack = (
                data.get("description", "") + " " +
                " ".join(data.get("common_tasks", [])) + " " +
                data.get("title", "")
            ).lower()
            score = sum(1 for w in words if w in haystack)
            if score > best_score:
                best_key, best_score = key, score
        if best_score > 0 and best_key:
            return {"section": best_key, "found": True, **_FIREWALL_GUIDE[best_key]}

    # Pass 3: return ALL guide sections so the model always has enough context
    return {
        "found": False,
        "message": (
            f"No single section matched '{section}'. "
            "Full guide returned — pick the most relevant section(s)."
        ),
        "all_sections": {
            k: {"title": v["title"], "url": v["url"],
                "description": v["description"],
                "common_tasks": v.get("common_tasks", [])}
            for k, v in _FIREWALL_GUIDE.items()
        },
    }


# ---------------------------------------------------------------------------
# Manual-steps helpers (Fix 1 & 2)
# ---------------------------------------------------------------------------

def _format_manual_offer(tool: str, args: dict, help_data: dict) -> str:
    """
    Build the "here's how to do it manually + offer" message shown before the
    approval card.  Returns a markdown-formatted string.
    """
    # Intro line tailored per write tool
    if tool == "block_domain":
        domain = args.get("domain", "the domain")
        intro = f"Here's how to block **{domain}** manually through the UI:"
    elif tool == "unblock_domain":
        domain = args.get("domain", "the domain")
        intro = f"Here's how to unblock **{domain}** manually through the UI:"
    elif tool == "add_firewall_block_rule":
        desc = args.get("description") or "this traffic"
        intro = f"Here's how to add a firewall block rule for **{desc}** manually:"
    elif tool == "open_soc_case":
        title = args.get("title") or "a new case"
        intro = f"Here's how to open a SOC case for **{title}** manually:"
    elif tool == "add_soc_case_note":
        case_id = args.get("case_id", "?")
        intro = f"Here's how to add a note to SOC case **#{case_id}** manually:"
    elif tool == "escalate_soc_case":
        case_id = args.get("case_id", "?")
        intro = f"Here's how to escalate SOC case **#{case_id}** manually:"
    elif tool == "close_soc_case":
        case_id = args.get("case_id", "?")
        intro = f"Here's how to close SOC case **#{case_id}** manually:"
    elif tool == "triage_soc_alert":
        action = args.get("action", "triage")
        intro = f"Here's how to {action} this alert in the SOC portal manually:"
    else:
        intro = "Here's how to do this manually:"

    # Build numbered step list from the guide's common_tasks
    tasks = help_data.get("common_tasks", [])
    if not tasks and "all_sections" in help_data:
        # Fallback: pick best-matching section from the full dump
        for sec_data in help_data["all_sections"].values():
            if sec_data.get("common_tasks"):
                tasks = sec_data["common_tasks"]
                break

    if tasks:
        steps = "\n".join(f"{i + 1}. {step}" for i, step in enumerate(tasks))
        url   = help_data.get("url", "")
        url_hint = f"\n\n*(Navigate to: **{url}**)*" if url else ""
        body  = steps + url_hint
    else:
        body = "Go to the relevant section in the SmartShield UI and follow the on-screen options."

    return f"{intro}\n\n{body}\n\n**Would you like me to apply this for you automatically?**"


def _tool_app_structure() -> dict:
    """Return all registered page routes grouped by blueprint/section."""
    try:
        from flask import current_app
        pages = []
        for rule in current_app.url_map.iter_rules():
            url = rule.rule
            # Skip static files and internal API-only sub-paths
            if "/static/" in url or "/<" in url:
                continue
            methods = sorted(m for m in rule.methods if m not in ("HEAD", "OPTIONS"))
            if "GET" in methods:
                pages.append({"url": url, "endpoint": rule.endpoint})
        pages.sort(key=lambda x: x["url"])
    except Exception as exc:
        pages = [{"error": str(exc)}]

    guide_sections = [
        {
            "key":         k,
            "title":       v["title"],
            "url":         v["url"],
            "description": v["description"],
        }
        for k, v in _FIREWALL_GUIDE.items()
    ]
    return {
        "route_count":    len(pages),
        "routes":         pages,
        "guide_sections": guide_sections,
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
    if tool == "open_soc_case":
        title    = args.get("title", "Untitled case")
        severity = args.get("severity", "medium")
        return (
            f"Open SOC case: {title}",
            f"Create a new {severity}-severity SOC incident case titled '{title}'.",
        )
    if tool == "add_soc_case_note":
        case_id = args.get("case_id", "?")
        return (
            f"Add note to SOC case #{case_id}",
            f"Append an investigation note to SOC case #{case_id}.",
        )
    if tool == "escalate_soc_case":
        case_id = args.get("case_id", "?")
        return (
            f"Escalate SOC case #{case_id}",
            f"Escalate SOC case #{case_id} to the next response tier (L1→L2 or L2→L3).",
        )
    if tool == "close_soc_case":
        case_id      = args.get("case_id", "?")
        closure_type = args.get("closure_type", "resolved")
        return (
            f"Close SOC case #{case_id}",
            f"Close SOC case #{case_id} as '{closure_type}'.",
        )
    if tool == "triage_soc_alert":
        action    = args.get("action", "acknowledge")
        event_key = args.get("event_key", "?")
        return (
            f"Triage SOC alert ({action})",
            f"Mark the alert with event key '{event_key}' as '{action}'.",
        )
    return (f"Execute: {tool}", f"Arguments: {json.dumps(args)}")


_SOC_TIER_RANK = {"L1": 1, "L2": 2, "L3": 3}


def _resolve_soc_tier(user_id):
    """Return the SOC tier ('L1'/'L2'/'L3') for a user id, or None."""
    if user_id is None:
        return None
    try:
        from app.soc_portal_auth import get_user_soc_tier
        return get_user_soc_tier(int(user_id))
    except Exception:
        return None


def _execute_soc_action(conn, tool: str, args: dict, username: str, user_id) -> dict:
    """Execute an approved SOC write action after re-checking the user's tier."""
    from app.audit_log import log_event

    tier = _resolve_soc_tier(user_id)
    rank = _SOC_TIER_RANK.get(tier or "", 0)
    if rank == 0:
        return {"ok": False, "reply": (
            "You don't have a SOC analyst tier assigned, so SOC actions are not "
            "permitted. Ask an administrator to add you to a SOC-tier group."
        )}

    if tool == "open_soc_case":
        title = (args.get("title") or "").strip()
        if not title:
            return {"ok": False, "reply": "A case title is required."}
        description = (args.get("description") or "").strip()
        severity = args.get("severity", "medium")
        if severity not in ("low", "medium", "high", "critical"):
            severity = "medium"
        cur = conn.execute(
            "INSERT INTO siem_cases (title, description, severity, status, created_by, source_event) "
            "VALUES (?,?,?,'open',?,'')",
            (title, description, severity, username),
        )
        conn.commit()
        case_id = cur.lastrowid
        log_event(category="security", action="soc_case_opened", username=username,
                  remote_addr="", details={"case_id": case_id, "title": title,
                                           "severity": severity, "via": "chatbot"})
        return {"ok": True,
                "reply": f"SOC case **#{case_id}** — *{title}* ({severity}) has been opened."}

    if tool == "add_soc_case_note":
        if rank < 2:
            return {"ok": False, "reply": "Adding case notes requires SOC tier L2 or higher."}
        try:
            case_id = int(args.get("case_id"))
        except (TypeError, ValueError):
            return {"ok": False, "reply": "A numeric case_id is required."}
        note = (args.get("note") or "").strip()
        if not note:
            return {"ok": False, "reply": "The note text cannot be empty."}
        if not conn.execute("SELECT id FROM siem_cases WHERE id=?", (case_id,)).fetchone():
            return {"ok": False, "reply": f"No SOC case found with id {case_id}."}
        conn.execute("INSERT INTO siem_case_notes (case_id, note, created_by) VALUES (?,?,?)",
                     (case_id, note, username))
        conn.execute("UPDATE siem_cases SET updated_at=CURRENT_TIMESTAMP WHERE id=?", (case_id,))
        conn.commit()
        log_event(category="security", action="soc_case_note_added", username=username,
                  remote_addr="", details={"case_id": case_id, "via": "chatbot"})
        return {"ok": True, "reply": f"Investigation note added to SOC case **#{case_id}**."}

    if tool == "escalate_soc_case":
        target = {"L1": "L2", "L2": "L3"}.get(tier)
        if not target:
            return {"ok": False, "reply": (
                "L3 is the top response tier and cannot escalate further. "
                "Close the case instead."
            )}
        try:
            case_id = int(args.get("case_id"))
        except (TypeError, ValueError):
            return {"ok": False, "reply": "A numeric case_id is required."}
        if not conn.execute("SELECT id FROM siem_cases WHERE id=?", (case_id,)).fetchone():
            return {"ok": False, "reply": f"No SOC case found with id {case_id}."}
        note = (args.get("note") or "").strip()
        conn.execute("UPDATE siem_cases SET escalation_tier=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                     (target, case_id))
        note_text = f"[ESCALATED TO {target}]" + (f" {note}" if note else "")
        conn.execute("INSERT INTO siem_case_notes (case_id, note, created_by) VALUES (?,?,?)",
                     (case_id, note_text, username))
        conn.commit()
        log_event(category="security", action="soc_case_escalated", username=username,
                  remote_addr="", details={"case_id": case_id, "escalated_to": target,
                                           "via": "chatbot"})
        return {"ok": True, "reply": f"SOC case **#{case_id}** escalated to **{target}**."}

    if tool == "close_soc_case":
        try:
            case_id = int(args.get("case_id"))
        except (TypeError, ValueError):
            return {"ok": False, "reply": "A numeric case_id is required."}
        closure_type = (args.get("closure_type") or "resolved").strip()
        if closure_type not in ("false_positive", "resolved"):
            closure_type = "resolved"
        if rank < 3 and closure_type != "false_positive":
            return {"ok": False, "reply": (
                f"{tier} analysts can only close cases as false positives. "
                "Escalate true positives so an L3 responder can resolve them."
            )}
        if not conn.execute("SELECT id FROM siem_cases WHERE id=?", (case_id,)).fetchone():
            return {"ok": False, "reply": f"No SOC case found with id {case_id}."}
        resolution = (args.get("resolution") or "").strip()
        label = "FALSE POSITIVE — RESOLVED" if closure_type == "false_positive" else "RESOLVED"
        note_text = f"[CLOSED — {label}]" + (f" {resolution}" if resolution else "")
        conn.execute(
            "UPDATE siem_cases SET status='closed', closure_type=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (closure_type, case_id),
        )
        conn.execute("INSERT INTO siem_case_notes (case_id, note, created_by) VALUES (?,?,?)",
                     (case_id, note_text, username))
        conn.commit()
        log_event(category="security", action="soc_case_closed", username=username,
                  remote_addr="", details={"case_id": case_id, "closure_type": closure_type,
                                           "via": "chatbot"})
        return {"ok": True, "reply": f"SOC case **#{case_id}** closed as **{closure_type}**."}

    if tool == "triage_soc_alert":
        # ``event_key`` is the LLM's triage handle. The new soc_alerts tool
        # populates it with the event_uuid when available, but can also be
        # a legacy timestamp from older transcripts. Resolve to uuid first.
        handle = (args.get("event_key") or args.get("event_uuid") or "").strip()
        if not handle:
            return {"ok": False, "reply": "An event_uuid is required to triage an alert."}
        action_in = (args.get("action") or "").strip().lower()
        db_action = {"acknowledge": "acknowledged", "acknowledged": "acknowledged",
                     "false_positive": "false_positive"}.get(action_in)
        if not db_action:
            return {"ok": False, "reply": "Triage action must be 'acknowledge' or 'false_positive'."}

        # A 32-char hex string is treated as a uuid; anything else (e.g. an
        # ISO timestamp) is resolved by joining on events.ts.
        event_uuid = ""
        event_key = ""
        if len(handle) == 32 and all(c in "0123456789abcdef" for c in handle.lower()):
            event_uuid = handle.lower()
        else:
            event_key = handle
            try:
                row = conn.execute(
                    "SELECT event_uuid FROM events WHERE ts = ? "
                    "ORDER BY id DESC LIMIT 1",
                    (handle,),
                ).fetchone()
                if row and row["event_uuid"]:
                    event_uuid = row["event_uuid"]
            except Exception:
                pass

        note = (args.get("note") or "").strip()
        conn.execute(
            "INSERT INTO siem_alert_actions "
            "(event_key, event_uuid, event_action, action, taken_by, note) "
            "VALUES (?,?,?,?,?,?)",
            (event_key, event_uuid, args.get("event_action", ""),
             db_action, username, note),
        )
        conn.commit()
        log_event(category="system",
                  action="siem_alert_acknowledged" if db_action == "acknowledged" else "siem_alert_fp",
                  username=username, remote_addr="",
                  details={"event_uuid": event_uuid,
                           "event_key": event_key, "via": "chatbot"})
        return {"ok": True, "reply": f"Alert `{handle}` marked as **{db_action}**."}

    return {"ok": False, "reply": f"Unknown SOC action: {tool}"}


def execute_approved_action(conn, action: dict, username: str, user_id=None) -> dict:
    """Execute a write action that has been approved by the user."""
    tool = action.get("tool", "")
    args = action.get("args", {})

    try:
        from app.services.apply_state import (
            record_apply_start, record_apply_result, record_dry_run,
        )
        import sys as _sys
        _dry = not _sys.platform.startswith("freebsd")

        if tool in _SOC_WRITE_TOOLS:
            return _execute_soc_action(conn, tool, args, username, user_id)

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

def process_chat(conn, messages: list, username: str, user_id=None,
                 surface: str = "admin") -> dict:
    """
    Run the SmartShield AI agent loop using Groq.

    Accepts `messages` in the format [{"role": "user"/"assistant", "content": str}].
    `surface` selects the available toolset: "admin" exposes every tool;
    "soc" (the SOC portal) hides the firewall/DNS write tools, which require an
    admin session the SOC portal does not have.
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

    # Append the user's SOC tier so the model only offers permitted SOC actions.
    tier = _resolve_soc_tier(user_id)
    _tier_caps = {
        "L1": "may open cases, escalate cases, and triage alerts; may NOT add case "
              "notes; may close cases only as false_positive",
        "L2": "may open cases, add case notes, escalate cases, and triage alerts; "
              "may close cases only as false_positive",
        "L3": "may perform all SOC actions including closing cases as resolved; "
              "cannot escalate (already the top tier)",
    }
    if tier:
        tier_line = (f"\n\nCURRENT USER: '{username}', SOC tier {tier} — {_tier_caps.get(tier, '')}.")
    else:
        tier_line = (f"\n\nCURRENT USER: '{username}' has NO SOC tier assigned and cannot "
                     "perform any SOC write action. If they request one, explain that an "
                     "administrator must add them to a SOC-tier group first.")
    system_prompt = SYSTEM_PROMPT + tier_line

    # Build internal message chain: system prompt prepended to the full conversation history.
    internal_messages: list = [{"role": "system", "content": system_prompt}] + list(messages)

    # The SOC portal surface cannot run firewall/DNS write tools (no admin
    # session), so hide them from the model entirely on that surface.
    if surface == "soc":
        groq_tools = [t for t in _GROQ_TOOLS
                      if t["function"]["name"] not in _FIREWALL_WRITE_TOOLS]
    else:
        groq_tools = _GROQ_TOOLS

    max_iterations = 8

    for _ in range(max_iterations):
        try:
            response = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=internal_messages,
                tools=groq_tools,
                tool_choice="auto",
            )
        except Exception as exc:
            # Llama sometimes generates malformed XML-style function calls.
            # Retry once without tools so the model falls back to plain text.
            exc_str = str(exc)
            if "tool_use_failed" in exc_str or (
                "400" in exc_str and "function" in exc_str.lower()
            ):
                try:
                    response = client.chat.completions.create(
                        model="llama-3.3-70b-versatile",
                        messages=internal_messages,
                    )
                except Exception as exc2:
                    return {"ok": False, "message": f"Groq API error: {exc2}"}
            else:
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

            # Determine whether the user has already seen manual steps and confirmed.
            last_user_msg = next(
                (m["content"] for m in reversed(messages) if m["role"] == "user"), ""
            ).lower()
            last_asst_msg = next(
                (m["content"] for m in reversed(messages) if m["role"] == "assistant"), ""
            ).lower()

            already_offered = any(phrase in last_asst_msg for phrase in [
                "would you like me to apply",
                "would you like me to do this",
                "apply this for you automatically",
                "do this for you automatically",
            ])
            _confirmation_kw = {
                "yes", "yep", "yeah", "sure", "ok", "okay", "do it", "go ahead",
                "please do", "apply it", "apply", "go for it", "confirm", "please",
            }
            _conf_pattern = re.compile(
                r'\b(' + '|'.join(re.escape(kw) for kw in _confirmation_kw) + r')\b',
                re.IGNORECASE,
            )
            user_confirmed = bool(_conf_pattern.search(last_user_msg))

            if already_offered and user_confirmed:
                # User confirmed after seeing manual steps → show approval card
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
            else:
                # First mention → give manual steps and ask if user wants AI to apply
                _section_map = {
                    "block_domain":            "content_policy",
                    "unblock_domain":          "content_policy",
                    "add_firewall_block_rule": "firewall",
                    "open_soc_case":           "soc_portal",
                    "add_soc_case_note":       "soc_portal",
                    "escalate_soc_case":       "soc_portal",
                    "close_soc_case":          "soc_portal",
                    "triage_soc_alert":        "soc_portal",
                }
                section   = _section_map.get(write_call.function.name, "firewall")
                help_data = _tool_firewall_help({"section": section})
                reply     = _format_manual_offer(write_call.function.name, args, help_data)
                updated   = list(messages) + [{"role": "assistant", "content": reply}]
                return {"ok": True, "reply": reply, "messages": updated}

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
