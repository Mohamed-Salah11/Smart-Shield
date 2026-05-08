"""
dns_filter.py
-------------
DNS-level content filtering via Unbound local-zone directives.

Blocking a zone with always_nxdomain causes Unbound to return NXDOMAIN for
the zone apex and every subdomain, requiring no knowledge of individual
subdomains.  Redirect mode returns a specific IP (e.g. a block-page server).

Public API
----------
generate_dns_filter_zones(conn)              -> List[str]   # unbound config lines
get_dns_filter_rules(conn)                   -> List[dict]
add_dns_filter_rule(conn, domain, ...)       -> int         # new row id
toggle_dns_filter_rule(conn, rule_id, bool)  -> None
delete_dns_filter_rule(conn, rule_id)        -> None
apply_dns_filter(conn)                       -> dict        # {"ok", "message"}
"""

import re
import sys

from app.services.content_policy import get_block_page_ip


def _rows(conn, sql, params=()):
    cur = conn.cursor()
    cur.execute(sql, params)
    return [dict(r) for r in cur.fetchall()]


def _sanitize_domain(raw: str) -> str:
    """Strip protocol, path, wildcards, and trailing dots from a domain string."""
    d = re.sub(r'^https?://', '', raw.strip().lower())
    d = d.split('/')[0].strip()
    d = d.lstrip('*.').strip('.')
    return d


# ---------------------------------------------------------------------------
# Unbound config line generator (consumed by dns_writer.py)
# ---------------------------------------------------------------------------


def generate_dns_filter_zones(conn) -> list:
    """
    Return a list of Unbound server-block lines for all enabled DNS filter rules.
    These are injected into unbound.conf by dns_writer.generate_unbound_conf().

    For "block" rules: redirect to Smart Shield's LAN IP so the browser hits the
    /portal/block page instead of getting a raw NXDOMAIN.  Falls back to
    always_nxdomain when no LAN IP is configured.
    """
    block_ip = get_block_page_ip(conn)

    rules = _rows(conn, """
        SELECT domain, action, redirect_ip
        FROM filter_dns_rules
        WHERE enabled = 1
        ORDER BY id
    """)
    lines = []
    for rule in rules:
        domain = _sanitize_domain(rule.get("domain") or "")
        action = (rule.get("action") or "block").lower()
        redirect_ip = (rule.get("redirect_ip") or "").strip()
        if not domain:
            continue
        fqdn = domain + "."
        if action == "block":
            if block_ip:
                # Redirect to Smart Shield so the block/login page is served
                lines.append(f'    local-zone: "{fqdn}" redirect')
                lines.append(f'    local-data: "{fqdn} A {block_ip}"')
            else:
                lines.append(f'    local-zone: "{fqdn}" always_nxdomain')
        elif action == "redirect" and redirect_ip:
            lines.append(f'    local-zone: "{fqdn}" redirect')
            lines.append(f'    local-data: "{fqdn} A {redirect_ip}"')
        elif action == "allow":
            lines.append(f'    local-zone: "{fqdn}" transparent')
    return lines


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

def get_dns_filter_rules(conn) -> list:
    return _rows(conn, "SELECT * FROM filter_dns_rules ORDER BY id DESC")


def add_dns_filter_rule(
    conn,
    domain: str,
    action: str = "block",
    redirect_ip: str = "",
    category: str = "custom",
    description: str = "",
) -> int:
    domain = _sanitize_domain(domain)
    if not domain:
        raise ValueError("Domain must not be empty.")
    cur = conn.cursor()
    cur.execute(
        """
        INSERT OR IGNORE INTO filter_dns_rules
            (domain, action, redirect_ip, category, description)
        VALUES (?, ?, ?, ?, ?)
        """,
        (domain, action, redirect_ip, category, description),
    )
    conn.commit()
    return cur.lastrowid


def update_dns_filter_rule(
    conn,
    rule_id: int,
    domain: str,
    action: str = "block",
    redirect_ip: str = "",
    category: str = "custom",
    description: str = "",
) -> None:
    domain = _sanitize_domain(domain)
    if not domain:
        raise ValueError("Domain must not be empty.")
    if action not in ("block", "allow"):
        raise ValueError("Action must be 'block' or 'allow'.")
    conn.execute(
        """
        UPDATE filter_dns_rules
           SET domain=?, action=?, redirect_ip=?, category=?, description=?
         WHERE id=?
        """,
        (domain, action, redirect_ip, category, description, rule_id),
    )
    conn.commit()


def hot_apply_dns_rule(conn, rule_id: int) -> None:
    """Instantly inject or remove a single DNS rule via unbound-control (no service restart)."""
    import sys
    if not sys.platform.startswith("freebsd"):
        return
    try:
        from app.services.priv_helper import run_privileged
        row = conn.execute(
            "SELECT domain, action, redirect_ip, enabled FROM filter_dns_rules WHERE id=?",
            (rule_id,),
        ).fetchone()
        if not row:
            return
        domain = row["domain"]
        if row["enabled"]:
            if row["action"] == "redirect" and row["redirect_ip"]:
                run_privileged("unbound.local_zone", domain=domain, zone_type="redirect")
                run_privileged("unbound.local_data_a", domain=domain, ip=row["redirect_ip"])
            else:
                zone_type = "transparent" if row["action"] == "allow" else "always_refuse"
                run_privileged("unbound.local_zone", domain=domain, zone_type=zone_type)
        else:
            try:
                run_privileged("unbound.local_zone_remove", domain=domain)
            except Exception:
                pass
            try:
                run_privileged("unbound.local_data_remove", domain=domain)
            except Exception:
                pass
    except Exception:
        pass


def toggle_dns_filter_rule(conn, rule_id: int, enabled: bool) -> None:
    conn.execute(
        "UPDATE filter_dns_rules SET enabled = ? WHERE id = ?",
        (1 if enabled else 0, rule_id),
    )
    conn.commit()
    hot_apply_dns_rule(conn, rule_id)


def delete_dns_filter_rule(conn, rule_id: int) -> None:
    conn.execute("DELETE FROM filter_dns_rules WHERE id = ?", (rule_id,))
    conn.commit()


# ---------------------------------------------------------------------------
# Apply (write + reload Unbound)
# ---------------------------------------------------------------------------

def apply_dns_filter(conn) -> dict:
    """Regenerate unbound.conf (including filter rules) and reload Unbound."""
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
        return {"ok": True, "message": "DNS filter applied and Unbound reloaded."}
    except Exception as exc:
        return {"ok": False, "message": str(exc)}
