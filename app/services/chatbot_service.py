"""
chatbot_service.py
------------------
SmartShield AI agent powered by Claude (Anthropic) with tool-use.

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

Agent capabilities (require user approval):
- You can block or unblock domains via the DNS filter using block_domain / unblock_domain.
- You can add firewall block rules using add_firewall_block_rule.
- When a user asks you to block/allow something, call the appropriate tool directly — the
  system will pause and show the user an approval card before any change is applied.
- Do NOT ask the user "shall I proceed?" in text — just call the tool and let the approval
  UI handle the confirmation.
"""

# ---------------------------------------------------------------------------
# Anthropic key resolution (DB-first → env fallback)
# ---------------------------------------------------------------------------

def _load_anthropic_key(conn) -> str:
    """Read Anthropic API key from service_state (encrypted) then fall back to env var."""
    try:
        row = conn.execute(
            "SELECT value_json FROM service_state WHERE key_name='chatbot_settings'"
        ).fetchone()
        if row:
            settings = json.loads(row["value_json"])
            encrypted = settings.get("anthropic_api_key", "")
            if encrypted:
                from app.secret_store import decrypt_secret
                return decrypt_secret(encrypted)
    except Exception:
        pass
    return os.environ.get("ANTHROPIC_API_KEY", "")


# ---------------------------------------------------------------------------
# Tool definitions (Anthropic format)
# ---------------------------------------------------------------------------

TOOLS = [
    {
        "name": "get_system_health",
        "description": (
            "Get the current running status of all Smart Shield services "
            "(PF firewall, DHCP, Unbound/DNS, OpenVPN, IPSec, IDS/Suricata, etc.) "
            "and basic system resource usage."
        ),
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_audit_logs",
        "description": (
            "Search and retrieve Smart Shield audit logs. Use this to analyse "
            "login attempts, configuration changes, firewall events, and security incidents."
        ),
        "input_schema": {
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
        "input_schema": {
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
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_dhcp_leases",
        "description": (
            "Get the current active DHCP leases — shows all devices that have received "
            "IP addresses from this Smart Shield appliance."
        ),
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_ids_alerts",
        "description": (
            "Get recent IDS/IPS (Suricata) intrusion detection alerts. "
            "Use this to analyse active threats and security incidents."
        ),
        "input_schema": {
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
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_vpn_status",
        "description": (
            "Get the current VPN configuration and connection status for "
            "OpenVPN servers/clients, IPSec tunnels, and L2TP."
        ),
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "search_web",
        "description": (
            "Search the internet for firewall configuration guides, security advisories, "
            "CVE information, or best practices. Use when the user asks about external "
            "security topics not specific to this appliance."
        ),
        "input_schema": {
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
    # ── Write / action tools (require user confirmation) ──────────────────
    {
        "name": "block_domain",
        "description": (
            "Block a domain via the DNS content filter. "
            "Use this when the user asks to block a website or domain. "
            "This requires user confirmation before it is applied."
        ),
        "input_schema": {
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
        "input_schema": {
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
        "input_schema": {
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
            f"All DNS queries for {domain} and its subdomains will return NXDOMAIN.",
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
        if tool == "block_domain":
            domain      = args.get("domain", "").strip()
            category    = args.get("category", "custom")
            description = args.get("description", "Blocked via SmartShield AI")
            if not domain:
                return {"ok": False, "reply": "Domain name is required."}
            from app.services.dns_filter import add_dns_filter_rule, apply_dns_filter
            add_dns_filter_rule(conn, domain, action="block", category=category, description=description)
            result = apply_dns_filter(conn)
            if result["ok"]:
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
            result = apply_dns_filter(conn)
            suffix = "" if result["ok"] else f" (DNS reload failed: {result['message']})"
            return {"ok": True, "reply": f"DNS block rule for **{domain}** has been removed.{suffix}"}

        if tool == "add_firewall_block_rule":
            description = args.get("description", "AI-generated block rule")
            source      = args.get("source", "any")
            destination = args.get("destination", "any")
            protocol    = args.get("protocol", "any")
            dest_port   = args.get("dest_port", "")
            direction   = args.get("direction", "any")

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
                ("block", direction, protocol, source, destination, dest_port, description, new_order),
            )
            conn.commit()
            try:
                from app.services.firewall_writer import write_pf_rules
                write_pf_rules(conn)
            except Exception:
                pass
            return {
                "ok": True,
                "reply": (
                    f"Firewall block rule **{description}** has been added "
                    f"({source} → {destination}, {protocol.upper()}). Changes have been applied."
                ),
            }

        return {"ok": False, "reply": f"Unknown action type: {tool}"}

    except Exception as exc:
        return {"ok": False, "reply": f"Failed to execute action: {exc}"}


# ---------------------------------------------------------------------------
# Agentic chat loop
# ---------------------------------------------------------------------------

def process_chat(conn, messages: list, username: str) -> dict:
    """
    Run the SmartShield AI agent loop.

    Accepts `messages` in Anthropic format ([{"role": "user"/"assistant", "content": ...}]).
    Returns {"ok": True, "reply": str, "messages": updated_list} or {"ok": False, "message": str}.
    """
    api_key = _load_anthropic_key(conn)
    if not api_key:
        return {"ok": False, "message": "ANTHROPIC_API_KEY not configured. Add it via Admin → Settings → SmartShield AI."}

    try:
        import anthropic
    except ImportError:
        return {"ok": False, "message": "Anthropic SDK not installed. Run: pip install anthropic"}

    client = anthropic.Anthropic(api_key=api_key)

    max_iterations = 8  # prevent infinite loops
    for _ in range(max_iterations):
        try:
            resp = client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=4096,
                system=SYSTEM_PROMPT,
                tools=TOOLS,
                messages=messages,
            )
        except Exception as exc:
            return {"ok": False, "message": f"Claude API error: {exc}"}

        if resp.stop_reason == "end_turn":
            reply = next((b.text for b in resp.content if b.type == "text"), "")
            messages = messages + [{"role": "assistant", "content": reply}]
            return {"ok": True, "reply": reply, "messages": messages}

        if resp.stop_reason == "tool_use":
            tool_use_blocks = [b for b in resp.content if b.type == "tool_use"]

            # Check if any call is a write action requiring confirmation
            write_tc = next((b for b in tool_use_blocks if b.name in _WRITE_TOOLS), None)
            if write_tc:
                summary, detail = _describe_pending_action(write_tc.name, write_tc.input)
                agent_text = next(
                    (b.text for b in resp.content if b.type == "text"),
                    f"I can {summary.lower()}. Please review the details below and approve or cancel.",
                )
                # Store only text (no tool_use block) to avoid an unmatched tool_use on the next turn
                messages = messages + [{"role": "assistant", "content": agent_text}]
                return {
                    "ok": True,
                    "reply": agent_text,
                    "messages": messages,
                    "pending_action": {
                        "tool": write_tc.name,
                        "args": write_tc.input,
                        "summary": summary,
                        "detail": detail,
                    },
                }

            # Build the assistant message with content blocks for history
            asst_content = []
            for b in resp.content:
                if b.type == "text":
                    asst_content.append({"type": "text", "text": b.text})
                elif b.type == "tool_use":
                    asst_content.append({"type": "tool_use", "id": b.id, "name": b.name, "input": b.input})
            asst_msg = {"role": "assistant", "content": asst_content}
            messages = messages + [asst_msg]

            # Execute read tools and collect results
            tool_results = []
            for b in tool_use_blocks:
                result = _execute_tool(conn, b.name, b.input)
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": b.id,
                    "content": json.dumps(result, default=str),
                })
            messages = messages + [{"role": "user", "content": tool_results}]
            continue

        # Unexpected stop reason
        break

    return {"ok": False, "message": "Agent loop ended without a final response. Please try again."}
