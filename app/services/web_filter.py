"""
web_filter.py
-------------
Domain-level web content filtering via Unbound.

Full URL-path filtering (blocking /path on a domain while allowing the root)
requires an HTTP proxy (Squid/SquidGuard) and is out of scope here.  This
module implements domain-level blocking — the same mechanism used by DNS
filter but organised around URL/category concepts familiar to web-filter UIs.

Public API
----------
generate_web_filter_zones(conn)             -> List[str]
get_web_filter_rules(conn)                  -> List[dict]
add_web_filter_rule(conn, url_pattern, ...) -> int
toggle_web_filter_rule(conn, id, bool)      -> None
delete_web_filter_rule(conn, id)            -> None
apply_web_filter(conn)                      -> dict
"""

import re
import sys

from app.services.content_policy import get_block_page_ip


WEB_CATEGORIES = [
    ("adult",     "Adult / Explicit Content"),
    ("social",    "Social Media"),
    ("streaming", "Video Streaming"),
    ("gaming",    "Gaming"),
    ("gambling",  "Gambling"),
    ("violence",  "Violence / Weapons"),
    ("malware",   "Malware / Phishing"),
    ("ads",       "Advertising / Trackers"),
    ("p2p",       "P2P / File Sharing"),
    ("custom",    "Custom"),
]


def _rows(conn, sql, params=()):
    cur = conn.cursor()
    cur.execute(sql, params)
    return [dict(r) for r in cur.fetchall()]


def _extract_domain(url_pattern: str) -> str:
    """Extract bare domain from a URL or domain pattern."""
    d = re.sub(r'^https?://', '', url_pattern.strip().lower())
    d = d.split('/')[0].strip()
    d = d.lstrip('*.').strip('.')
    return d


# ---------------------------------------------------------------------------
# Unbound config lines (consumed by dns_writer.py)
# ---------------------------------------------------------------------------

def generate_web_filter_zones(conn) -> list:
    """
    Return Unbound server-block lines for all enabled web filter rules.
    Merged with DNS filter rules inside dns_writer.generate_unbound_conf().

    Block rules redirect to Smart Shield's LAN IP so the browser hits the
    /portal/block page. Falls back to always_nxdomain if no LAN IP is set.
    """
    block_ip = get_block_page_ip(conn)

    rules = _rows(conn, """
        SELECT url_pattern, action
        FROM filter_web_rules
        WHERE enabled = 1
        ORDER BY id
    """)
    lines = []
    for rule in rules:
        domain = _extract_domain(rule.get("url_pattern") or "")
        action = (rule.get("action") or "block").lower()
        if not domain:
            continue
        fqdn = domain + "."
        if action == "block":
            if block_ip:
                lines.append(f'    local-zone: "{fqdn}" redirect')
                lines.append(f'    local-data: "{fqdn} A {block_ip}"')
            else:
                lines.append(f'    local-zone: "{fqdn}" always_nxdomain')
        elif action == "allow":
            lines.append(f'    local-zone: "{fqdn}" transparent')
    return lines


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

def get_web_filter_rules(conn) -> list:
    return _rows(conn, "SELECT * FROM filter_web_rules ORDER BY id DESC")


def add_web_filter_rule(
    conn,
    url_pattern: str,
    action: str = "block",
    category: str = "custom",
    description: str = "",
) -> int:
    domain = _extract_domain(url_pattern)
    if not domain:
        raise ValueError("Could not extract a domain from the supplied URL/pattern.")
    cur = conn.cursor()
    cur.execute(
        """
        INSERT OR IGNORE INTO filter_web_rules
            (url_pattern, action, category, description)
        VALUES (?, ?, ?, ?)
        """,
        (domain, action, category, description),
    )
    conn.commit()
    return cur.lastrowid


def toggle_web_filter_rule(conn, rule_id: int, enabled: bool) -> None:
    conn.execute(
        "UPDATE filter_web_rules SET enabled = ? WHERE id = ?",
        (1 if enabled else 0, rule_id),
    )
    conn.commit()


def delete_web_filter_rule(conn, rule_id: int) -> None:
    conn.execute("DELETE FROM filter_web_rules WHERE id = ?", (rule_id,))
    conn.commit()


# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------

def apply_web_filter(conn) -> dict:
    """Regenerate unbound.conf with the current web filter rules and reload."""
    try:
        from app.services.dns_writer import write_unbound_conf
        result = write_unbound_conf(conn)
        if not result["ok"]:
            return result
        if sys.platform.startswith("freebsd"):
            from app.services.service_manager import service_action
            r = service_action("unbound", "reload")
            if not r["ok"]:
                return {"ok": False, "message": f"Config written but Unbound reload failed: {r['message']}"}
        return {"ok": True, "message": "Web filter applied and Unbound reloaded."}
    except Exception as exc:
        return {"ok": False, "message": str(exc)}
