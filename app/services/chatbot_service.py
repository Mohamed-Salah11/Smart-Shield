"""
chatbot_service.py
------------------
SmartShield AI agent powered by Groq LLM with tool-use.

The agent can query live system data (firewall rules, logs, service health,
DHCP leases, IDS alerts, content policy, VPN status) and search the web for
security topics. It uses an agentic loop so Claude can call multiple tools
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
# Tool definitions (OpenAI/Groq function-calling format)
# ---------------------------------------------------------------------------

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "get_system_health",
            "description": (
                "Get the current running status of all Smart Shield services "
                "(PF firewall, DHCP, Unbound/DNS, OpenVPN, IPSec, IDS/Suricata, etc.) "
                "and basic system resource usage."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
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
    },
    {
        "type": "function",
        "function": {
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
    },
    {
        "type": "function",
        "function": {
            "name": "get_network_config",
            "description": (
                "Get the current network configuration: LAN IP/subnet, WAN type and IP, "
                "interface port assignments, and DHCP pool settings."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_dhcp_leases",
            "description": (
                "Get the current active DHCP leases — shows all devices that have received "
                "IP addresses from this Smart Shield appliance."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
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
    },
    {
        "type": "function",
        "function": {
            "name": "get_content_policy",
            "description": (
                "Get the current content policy rules: DNS filter rules (blocked/allowed domains), "
                "web filter rules, and application filter rules."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_vpn_status",
            "description": (
                "Get the current VPN configuration and connection status for "
                "OpenVPN servers/clients, IPSec tunnels, and L2TP."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
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
    },
]


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
        if name == "get_ids_alerts":
            return _tool_ids_alerts(conn, args)
        if name == "get_content_policy":
            return _tool_content_policy(conn)
        if name == "get_vpn_status":
            return _tool_vpn_status(conn)
        if name == "search_web":
            return _tool_search_web(args.get("query", ""))
        return {"error": f"Unknown tool: {name}"}
    except Exception as exc:
        return {"error": str(exc)}


def _tool_health(conn) -> dict:
    from app.services.service_manager import get_all_service_health
    try:
        health = get_all_service_health()
    except Exception:
        health = {}
    # Also add basic counts
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
    events   = tail_events(limit=limit, category=category, search=search)
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


def _tool_ids_alerts(conn, args: dict) -> dict:
    limit = min(int(args.get("limit") or 20), 100)
    try:
        from app.services.ids_service import get_recent_alerts
        alerts = get_recent_alerts(limit=limit)
    except Exception:
        # Fallback: check if IDS is configured
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
    return {
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


def _tool_search_web(query: str) -> dict:
    """Search DuckDuckGo instant answers API (no key required)."""
    if not query.strip():
        return {"error": "Empty query."}
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
            results.append({"source": data.get("AbstractURL", ""), "snippet": data["AbstractText"]})
        for r in data.get("RelatedTopics", [])[:5]:
            if isinstance(r, dict) and r.get("Text"):
                results.append({"source": r.get("FirstURL", ""), "snippet": r["Text"]})
        return {"query": query, "results": results or [{"snippet": "No instant answer found. Try a more specific query."}]}
    except Exception as exc:
        return {"error": f"Web search failed: {exc}"}


# ---------------------------------------------------------------------------
# Agentic chat loop
# ---------------------------------------------------------------------------

def process_chat(conn, messages: list, username: str) -> dict:
    """
    Run the SmartShield AI agent loop.

    Accepts `messages` in OpenAI format ([{"role": "user"/"assistant"/"tool", "content": ...}]).
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
    full_messages = [{"role": "system", "content": SYSTEM_PROMPT}] + list(messages)

    max_iterations = 8  # prevent infinite loops
    for _ in range(max_iterations):
        try:
            resp = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                max_tokens=4096,
                tools=TOOLS,
                tool_choice="auto",
                messages=full_messages,
            )
        except Exception as exc:
            return {"ok": False, "message": f"Groq API error: {exc}"}

        choice = resp.choices[0]

        if choice.finish_reason == "stop":
            reply = choice.message.content or ""
            messages = messages + [{"role": "assistant", "content": reply}]
            return {"ok": True, "reply": reply, "messages": messages}

        if choice.finish_reason == "tool_calls":
            tool_calls = choice.message.tool_calls or []
            # Build the assistant message dict for history
            asst_msg = {
                "role": "assistant",
                "content": choice.message.content or "",
                "tool_calls": [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {"name": tc.function.name, "arguments": tc.function.arguments},
                    }
                    for tc in tool_calls
                ],
            }
            full_messages.append(asst_msg)
            messages = messages + [asst_msg]

            for tc in tool_calls:
                try:
                    tool_args = json.loads(tc.function.arguments or "{}")
                except json.JSONDecodeError:
                    tool_args = {}
                result = _execute_tool(conn, tc.function.name, tool_args)
                tool_msg = {
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": json.dumps(result, default=str),
                }
                full_messages.append(tool_msg)
                messages = messages + [tool_msg]
            continue

        # Unexpected finish reason
        break

    return {"ok": False, "message": "Agent loop ended without a final response. Please try again."}
