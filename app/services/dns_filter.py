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

import logging
import re
import sys

from app.services.content_policy import get_block_page_ip, normalize_action, normalize_domain

_log = logging.getLogger(__name__)


def _rows(conn, sql, params=()):
    cur = conn.cursor()
    cur.execute(sql, params)
    return [dict(r) for r in cur.fetchall()]


def _sanitize_domain(raw: str) -> str:
    """Validate and lowercase a domain. Returns "" for invalid input.

    Delegates to ``content_policy.normalize_domain`` so DNS / Web / App filters
    all apply the same domain rules (no schemes, no paths, no wildcards, no
    single-label names).
    """
    return normalize_domain(raw or "")


def _doh_blocking_enabled(conn) -> bool:
    """True when the admin has not explicitly disabled DoH-provider blocking.

    Default: ON whenever ANY content/DNS/web/app rule is active. Admin can
    flip ``service_state.content_policy_settings.block_known_doh`` to False
    to opt out (e.g., if their network legitimately uses Cloudflare DoH).
    """
    try:
        import json as _json
        row = conn.execute(
            "SELECT value_json FROM service_state WHERE key_name='content_policy_settings'"
        ).fetchone()
        if not row:
            return True
        cfg = _json.loads(row["value_json"]) or {}
        # Missing key defaults to True (block by default).
        return bool(cfg.get("block_known_doh", True))
    except Exception:
        return True


def generate_doh_block_zones(conn) -> list:
    """Return Unbound local-zone lines that NXDOMAIN every known DoH endpoint.

    Emits only when content filtering is active AND the block_known_doh flag
    is on. Always NXDOMAIN (never redirect to the block page) — DoH clients
    don't render HTML so a redirect would just confuse them.
    """
    try:
        from app.services.content_policy import (
            has_active_content_policy, DOH_PROVIDER_DOMAINS,
        )
        if not has_active_content_policy(conn):
            return []
    except Exception:
        return []

    if not _doh_blocking_enabled(conn):
        return []

    lines: list = []
    for domain in DOH_PROVIDER_DOMAINS:
        fqdn = domain + "."
        lines.append(f'    local-zone: "{fqdn}" always_nxdomain')
    return lines


# ---------------------------------------------------------------------------
# Unbound config line generator (consumed by dns_writer.py)
# ---------------------------------------------------------------------------


def generate_dns_filter_zones(conn) -> list:
    """
    Return Unbound server-block lines for all enabled DNS filter rules.

    DEPRECATED for the apply path — ``dns_writer.generate_unbound_conf`` calls
    ``content_policy.emit_unbound_policy_zones`` directly so duplicate domains
    across DNS / Web / App filters collapse into a single ``local-zone``.
    This function is kept only for ``filter_conflicts.get_filter_preview`` so
    the UI can show per-filter previews. Do not call from apply paths.
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
        action = normalize_action(rule.get("action"))
        redirect_ip = (rule.get("redirect_ip") or "").strip()
        if not domain:
            continue
        fqdn = domain + "."
        # block_all and allow_whitelist_only both default-deny; the
        # whitelist_view re-allows whitelisted clients out-of-band.
        # TTL=5 s on the block redirect so the browser DNS cache expires
        # quickly after the user authenticates and PF switches them to the
        # upstream resolver.
        if action in ("block_all", "allow_whitelist_only"):
            if block_ip:
                lines.append(f'    local-zone: "{fqdn}" redirect')
                lines.append(f'    local-data: "{fqdn} 5 A {block_ip}"')
            else:
                lines.append(f'    local-zone: "{fqdn}" always_nxdomain')
        elif action == "redirect" and redirect_ip:
            lines.append(f'    local-zone: "{fqdn}" redirect')
            lines.append(f'    local-data: "{fqdn} 5 A {redirect_ip}"')
    return lines


def generate_dns_whitelist_overrides(conn) -> list:
    """
    Return local-zone transparent overrides for 'allow whitelist only' DNS rules.
    Injected into the Unbound whitelist_view so whitelisted devices bypass the block.
    """
    # Match either the legacy "allow" string or the canonical
    # "allow_whitelist_only" — see content_policy.normalize_action.
    rules = _rows(
        conn,
        "SELECT domain FROM filter_dns_rules "
        "WHERE LOWER(COALESCE(action,'')) IN ('allow', 'allow_whitelist_only') "
        "AND enabled=1",
    )
    lines = []
    for rule in rules:
        domain = _sanitize_domain(rule.get("domain") or "")
        if not domain:
            continue
        lines.append(f'    local-zone: "{domain}." transparent')
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
    if action not in ("block", "allow", "redirect"):
        raise ValueError("Action must be 'block', 'allow', or 'redirect'.")
    if action == "redirect" and not redirect_ip:
        raise ValueError("A redirect IP is required for 'redirect' action.")
    cur = conn.cursor()
    cur.execute(
        """
        INSERT OR IGNORE INTO filter_dns_rules
            (domain, action, redirect_ip, category, description)
        VALUES (?, ?, ?, ?, ?)
        """,
        (domain, action, redirect_ip, category, description),
    )
    if cur.rowcount == 0:
        raise ValueError(f"A DNS block rule for '{domain}' already exists.")
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
    if action not in ("block", "allow", "redirect"):
        raise ValueError("Action must be 'block', 'allow', or 'redirect'.")
    if action == "redirect" and not redirect_ip:
        raise ValueError("redirect_ip is required when action is 'redirect'.")
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
            elif row["action"] == "block":
                block_ip = get_block_page_ip(conn)
                if block_ip:
                    run_privileged("unbound.local_zone", domain=domain, zone_type="redirect")
                    run_privileged("unbound.local_data_a", domain=domain, ip=block_ip)
                else:
                    run_privileged("unbound.local_zone", domain=domain, zone_type="always_nxdomain")
            else:  # allow
                run_privileged("unbound.local_zone", domain=domain, zone_type="transparent")
        else:
            try:
                run_privileged("unbound.local_zone_remove", domain=domain)
            except Exception as exc:
                _log.warning("dns_filter: local_zone_remove failed for %r: %s", domain, exc)
            try:
                run_privileged("unbound.local_data_remove", domain=domain)
            except Exception as exc:
                _log.warning("dns_filter: local_data_remove failed for %r: %s", domain, exc)
    except Exception as exc:
        _log.warning("dns_filter: hot_apply_dns_rule failed for rule %s: %s", rule_id, exc)


def toggle_dns_filter_rule(conn, rule_id: int, enabled: bool) -> None:
    conn.execute(
        "UPDATE filter_dns_rules SET enabled = ? WHERE id = ?",
        (1 if enabled else 0, rule_id),
    )
    conn.commit()
    hot_apply_dns_rule(conn, rule_id)


def _hot_remove_domain(domain: str) -> None:
    """Remove a single domain zone from live Unbound (FreeBSD only, best-effort)."""
    if not sys.platform.startswith("freebsd"):
        return
    try:
        from app.services.priv_helper import run_privileged
        run_privileged("unbound.local_zone_remove", domain=domain)
    except Exception as exc:
        _log.warning("dns_filter: hot-remove local_zone failed for %r: %s", domain, exc)
    try:
        from app.services.priv_helper import run_privileged
        run_privileged("unbound.local_data_remove", domain=domain)
    except Exception as exc:
        _log.warning("dns_filter: hot-remove local_data failed for %r: %s", domain, exc)


def delete_dns_filter_rule(conn, rule_id: int) -> None:
    row = conn.execute(
        "SELECT domain FROM filter_dns_rules WHERE id=?", (rule_id,)
    ).fetchone()
    if row:
        _hot_remove_domain(row["domain"])
    conn.execute("DELETE FROM filter_dns_rules WHERE id = ?", (rule_id,))
    conn.commit()


# ---------------------------------------------------------------------------
# Apply (write + reload Unbound)
# ---------------------------------------------------------------------------

def apply_dns_filter(conn) -> dict:
    """Regenerate unbound.conf (including filter rules) and reload Unbound.

    Routes through ``apply_unbound`` so the change goes through the
    validate → backup → atomic write → reload → rollback pipeline rather
    than the legacy raw-write path. A malformed rule cannot replace a
    working unbound.conf this way.
    """
    try:
        from app.services.dns_writer import apply_unbound
        return apply_unbound(conn)
    except Exception as exc:
        return {"ok": False, "message": str(exc)}
