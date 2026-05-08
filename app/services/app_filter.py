"""
app_filter.py
-------------
Application-layer filtering.  Blocks applications by two complementary methods:

  1. DNS blocking  — adds Unbound local-zone entries for the app's known domains,
                     so clients cannot resolve them.  Effective for domain-pinned
                     apps (Facebook, YouTube, etc.).

  2. Port blocking — injects pf(4) block rules for the app's known ports/protocols.
                     Effective for protocol-identified apps (BitTorrent, etc.)
                     that don't rely solely on well-known domain names.

Built-in signature library covers 18 popular applications across 6 categories.
New signatures can be added at any time through the web UI.

Public API
----------
APP_SIGNATURES                              dict  — built-in library
get_app_filter_rules(conn)                  -> List[dict]
add_app_filter_rule(conn, ...)              -> int
add_app_from_signature(conn, sig_key, ...)  -> int
toggle_app_filter_rule(conn, id, bool)      -> None
delete_app_filter_rule(conn, id)            -> None
generate_app_filter_dns_zones(conn)         -> List[str]   # for dns_writer
generate_app_filter_pf_rules(conn)          -> str          # for pf_generator
apply_app_filter(conn)                      -> dict
"""

import sys

from app.services.content_policy import get_block_page_ip


# ---------------------------------------------------------------------------
# Built-in application signature library
# ---------------------------------------------------------------------------

APP_SIGNATURES = {
    # ── Social Media ──────────────────────────────────────────────────────────
    "facebook": {
        "name": "Facebook",
        "category": "social",
        "domains": "facebook.com,fbcdn.net,fb.com,facebook.net,fbsbx.com",
        "ports": "",
        "protocol": "tcp+udp",
    },
    "instagram": {
        "name": "Instagram",
        "category": "social",
        "domains": "instagram.com,cdninstagram.com",
        "ports": "",
        "protocol": "tcp+udp",
    },
    "twitter": {
        "name": "Twitter / X",
        "category": "social",
        "domains": "twitter.com,t.co,x.com,twimg.com,abs.twimg.com",
        "ports": "",
        "protocol": "tcp+udp",
    },
    "tiktok": {
        "name": "TikTok",
        "category": "social",
        "domains": "tiktok.com,tiktokcdn.com,musical.ly,bytedance.com,tiktokv.com",
        "ports": "",
        "protocol": "tcp+udp",
    },
    "snapchat": {
        "name": "Snapchat",
        "category": "social",
        "domains": "snapchat.com,snap.com,snapchatads.com,sc-cdn.net",
        "ports": "",
        "protocol": "tcp+udp",
    },
    # ── Streaming ─────────────────────────────────────────────────────────────
    "youtube": {
        "name": "YouTube",
        "category": "streaming",
        "domains": "youtube.com,youtu.be,ytimg.com,googlevideo.com,yt3.ggpht.com",
        "ports": "",
        "protocol": "tcp+udp",
    },
    "netflix": {
        "name": "Netflix",
        "category": "streaming",
        "domains": "netflix.com,nflxvideo.net,nflximg.net,nflxso.net,nflxext.com",
        "ports": "",
        "protocol": "tcp+udp",
    },
    "spotify": {
        "name": "Spotify",
        "category": "streaming",
        "domains": "spotify.com,scdn.co,spotifycdn.com,audio-ak.spotify.com",
        "ports": "4070",
        "protocol": "tcp+udp",
    },
    "twitch": {
        "name": "Twitch",
        "category": "streaming",
        "domains": "twitch.tv,twitchapps.com,jtvnw.net,twitchsvc.net",
        "ports": "",
        "protocol": "tcp+udp",
    },
    # ── Messaging ─────────────────────────────────────────────────────────────
    "whatsapp": {
        "name": "WhatsApp",
        "category": "messaging",
        "domains": "whatsapp.com,whatsapp.net,whatsapp.org",
        "ports": "5222,5228,4244",
        "protocol": "tcp+udp",
    },
    "telegram": {
        "name": "Telegram",
        "category": "messaging",
        "domains": "telegram.org,t.me,telegram.me,core.telegram.org",
        "ports": "",
        "protocol": "tcp+udp",
    },
    "discord": {
        "name": "Discord",
        "category": "messaging",
        "domains": "discord.com,discordapp.com,discord.gg,discord.media",
        "ports": "",
        "protocol": "tcp+udp",
    },
    "signal": {
        "name": "Signal",
        "category": "messaging",
        "domains": "signal.org,signalapp.com,cdn2.signal.org",
        "ports": "",
        "protocol": "tcp+udp",
    },
    # ── VoIP / Conferencing ───────────────────────────────────────────────────
    "zoom": {
        "name": "Zoom",
        "category": "voip",
        "domains": "zoom.us,zoom.com,zoomgov.com,zmtg.com",
        "ports": "8801-8802,3478,3479",
        "protocol": "tcp+udp",
    },
    "teams": {
        "name": "Microsoft Teams",
        "category": "voip",
        "domains": "teams.microsoft.com,teams.live.com,skype.com",
        "ports": "3478-3481",
        "protocol": "tcp+udp",
    },
    # ── Gaming ────────────────────────────────────────────────────────────────
    "steam": {
        "name": "Steam",
        "category": "gaming",
        "domains": "steampowered.com,steamcommunity.com,steamgames.com,steamstatic.com",
        "ports": "27015-27030,27036-27037",
        "protocol": "tcp+udp",
    },
    # ── P2P / File Sharing ────────────────────────────────────────────────────
    "bittorrent": {
        "name": "BitTorrent / P2P",
        "category": "p2p",
        "domains": "",
        "ports": "6881-6889,6969,51413",
        "protocol": "tcp+udp",
    },
    "emule": {
        "name": "eMule",
        "category": "p2p",
        "domains": "",
        "ports": "4662,4672",
        "protocol": "tcp+udp",
    },
}

APP_CATEGORIES = sorted({v["category"] for v in APP_SIGNATURES.values()}) + ["custom"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rows(conn, sql, params=()):
    cur = conn.cursor()
    cur.execute(sql, params)
    return [dict(r) for r in cur.fetchall()]


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

def get_app_filter_rules(conn) -> list:
    return _rows(conn, "SELECT * FROM filter_app_rules ORDER BY id DESC")


def add_app_filter_rule(
    conn,
    app_name: str,
    action: str = "block",
    block_dns: bool = True,
    block_ports: bool = True,
    ports: str = "",
    protocol: str = "tcp+udp",
    domains: str = "",
    category: str = "custom",
    description: str = "",
) -> int:
    if not app_name.strip():
        raise ValueError("Application name must not be empty.")
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO filter_app_rules
            (app_name, action, block_dns, block_ports,
             ports, protocol, domains, category, description)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            app_name.strip(),
            action,
            1 if block_dns else 0,
            1 if block_ports else 0,
            ports,
            protocol,
            domains,
            category,
            description,
        ),
    )
    conn.commit()
    return cur.lastrowid


def add_app_from_signature(conn, sig_key: str, action: str = "block") -> int:
    """Add a rule from the built-in signature library by key."""
    sig = APP_SIGNATURES.get(sig_key)
    if not sig:
        raise ValueError(f"Unknown application signature: '{sig_key}'")
    return add_app_filter_rule(
        conn,
        app_name=sig["name"],
        action=action,
        block_dns=bool(sig["domains"]),
        block_ports=bool(sig["ports"]),
        ports=sig["ports"],
        protocol=sig["protocol"],
        domains=sig["domains"],
        category=sig["category"],
        description="Added from built-in signature library.",
    )


def toggle_app_filter_rule(conn, rule_id: int, enabled: bool) -> None:
    conn.execute(
        "UPDATE filter_app_rules SET enabled = ? WHERE id = ?",
        (1 if enabled else 0, rule_id),
    )
    conn.commit()


def delete_app_filter_rule(conn, rule_id: int) -> None:
    conn.execute("DELETE FROM filter_app_rules WHERE id = ?", (rule_id,))
    conn.commit()


# ---------------------------------------------------------------------------
# Config generators
# ---------------------------------------------------------------------------

def generate_app_filter_dns_zones(conn) -> list:
    """
    Return Unbound server-block lines for app filter DNS blocking.
    Consumed by dns_writer.generate_unbound_conf().

    Redirects blocked app domains to Smart Shield's LAN IP so the browser hits
    the /portal/block page. Falls back to always_nxdomain if no LAN IP is set.
    """
    block_ip = get_block_page_ip(conn)

    rules = _rows(conn, """
        SELECT domains, action
        FROM filter_app_rules
        WHERE enabled = 1 AND block_dns = 1
        ORDER BY id
    """)
    lines = []
    for rule in rules:
        if (rule.get("action") or "block").lower() != "block":
            continue
        for raw in (rule.get("domains") or "").split(","):
            domain = raw.strip().lower().lstrip("*.").strip(".")
            if not domain:
                continue
            fqdn = domain + "."
            if block_ip:
                lines.append(f'    local-zone: "{fqdn}" redirect')
                lines.append(f'    local-data: "{fqdn} A {block_ip}"')
            else:
                lines.append(f'    local-zone: "{fqdn}" always_nxdomain')
    return lines


def generate_app_filter_pf_rules(conn) -> str:
    """
    Return PF block rules for app filter port-based blocking.
    Consumed by pf_generator.generate_pf_conf().
    """
    rules = _rows(conn, """
        SELECT app_name, ports, protocol, action
        FROM filter_app_rules
        WHERE enabled = 1 AND block_ports = 1
        ORDER BY id
    """)
    lines = []
    for rule in rules:
        if (rule.get("action") or "block").lower() != "block":
            continue
        ports_raw = (rule.get("ports") or "").strip()
        if not ports_raw:
            continue
        app_name = rule.get("app_name", "")
        protocol = (rule.get("protocol") or "tcp+udp").lower()

        # Convert "6881-6889,6969" → pf port list "{ 6881:6889 6969 }"
        parts = []
        for token in ports_raw.split(","):
            token = token.strip()
            if "-" in token:
                lo, hi = token.split("-", 1)
                parts.append(f"{lo.strip()}:{hi.strip()}")
            elif token:
                parts.append(token)
        if not parts:
            continue
        port_list = "{ " + " ".join(parts) + " }"
        lines.append(f"# {app_name}")
        if protocol == "tcp+udp":
            lines.append(f"block quick proto tcp from !<authenticated_clients> to any port {port_list}")
            lines.append(f"block quick proto udp from !<authenticated_clients> to any port {port_list}")
        else:
            lines.append(f"block quick proto {protocol} from !<authenticated_clients> to any port {port_list}")

    if not lines:
        return ""
    return "\n".join(["# ── Application Filter ──"] + lines + [""])


# ---------------------------------------------------------------------------
# Apply (DNS + PF)
# ---------------------------------------------------------------------------

def apply_app_filter(conn) -> dict:
    """Regenerate unbound.conf (DNS blocking) and pf.conf (port blocking), then reload both."""
    results = []
    try:
        from app.services.dns_writer import write_unbound_conf
        dns_result = write_unbound_conf(conn)
        results.append(f"DNS: {dns_result['message']}")
        if sys.platform.startswith("freebsd") and dns_result["ok"]:
            from app.services.service_manager import service_action
            r = service_action("unbound", "reload")
            results.append(f"Unbound reload: {r['message']}")
    except Exception as exc:
        results.append(f"DNS apply error: {exc}")

    try:
        from app.services.pf_generator import reload_pf_rules
        pf_result = reload_pf_rules(conn)
        results.append(f"PF: {pf_result['message']}")
    except Exception as exc:
        results.append(f"PF apply error: {exc}")

    return {"ok": True, "message": " | ".join(results)}
