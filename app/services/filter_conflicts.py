"""
filter_conflicts.py
-------------------
Detects conflicts across DNS filter, web filter, and application filter rules
before they are merged into unbound.conf and pf.conf.

Public API
----------
detect_conflicts(conn)          -> dict  {"errors": [...], "warnings": [...]}
get_filter_preview(conn)        -> dict  {"dns_zones": [...], "pf_rules": str, "conflicts": [...]}
import_filter_list(conn, text, filter_type, action, category) -> dict
export_filter_list(conn, filter_type) -> str  (newline-separated domains/patterns)
"""

import re


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rows(conn, sql, params=()):
    cur = conn.cursor()
    cur.execute(sql, params)
    return [dict(r) for r in cur.fetchall()]


def _sanitize_domain(raw: str) -> str:
    d = re.sub(r'^https?://', '', (raw or "").strip().lower())
    d = d.split('/')[0].strip()
    d = d.lstrip('*.').strip('.')
    return d


# ---------------------------------------------------------------------------
# Conflict detection
# ---------------------------------------------------------------------------

def detect_conflicts(conn) -> dict:
    """
    Analyse all enabled filter rules for conflicts:

    - Duplicate domain: the same domain appears in more than one filter category
      (DNS filter, web filter, app filter DNS) with the same action.  Usually
      harmless but wastes config space.

    - Allow/Block conflict: a domain is explicitly allowed in one filter but
      blocked in another.  The "allow" Unbound directive (transparent) cannot
      override an "always_nxdomain" in the same zone block — the block wins.

    - Invalid redirect IP: a DNS filter redirect rule with a non-routable or
      empty redirect IP.

    Returns ``{"errors": [...], "warnings": [...]}``.
    """
    errors   = []
    warnings = []

    # Collect all (domain, action) pairs per source
    dns_rules = _rows(conn, "SELECT domain, action, redirect_ip FROM filter_dns_rules WHERE enabled=1")
    web_rules = _rows(conn, "SELECT url_pattern, action FROM filter_web_rules WHERE enabled=1")
    app_rules = _rows(conn, "SELECT domains, action, app_name FROM filter_app_rules WHERE enabled=1 AND block_dns=1")

    # Build domain → {source: action} map
    domain_map: dict[str, list[tuple[str, str]]] = {}

    for r in dns_rules:
        d = _sanitize_domain(r.get("domain") or "")
        action = (r.get("action") or "block").lower()
        redirect_ip = (r.get("redirect_ip") or "").strip()

        if not d:
            continue

        # Check redirect IP validity
        if action == "redirect":
            if not redirect_ip:
                errors.append(f"DNS filter: domain {d!r} has action=redirect but no redirect IP set.")
            else:
                import ipaddress
                try:
                    ipaddress.ip_address(redirect_ip)
                except ValueError:
                    errors.append(f"DNS filter: redirect IP {redirect_ip!r} for {d!r} is invalid.")

        domain_map.setdefault(d, []).append(("dns_filter", action))

    for r in web_rules:
        d = _sanitize_domain(r.get("url_pattern") or "")
        action = (r.get("action") or "block").lower()
        if d:
            domain_map.setdefault(d, []).append(("web_filter", action))

    for r in app_rules:
        raw_domains = (r.get("domains") or "").strip()
        app_action  = (r.get("action") or "block").lower()
        app_name    = r.get("app_name", "")
        for raw in raw_domains.split(","):
            d = _sanitize_domain(raw)
            if d:
                domain_map.setdefault(d, []).append((f"app_filter({app_name})", app_action))

    # Detect conflicts
    for domain, sources in domain_map.items():
        actions = set(a for _, a in sources)

        # Duplicates within same action (warning)
        if len(sources) > 1 and len(actions) == 1:
            src_names = [s for s, _ in sources]
            warnings.append(
                f"Duplicate rule: {domain!r} is blocked by multiple filters: {src_names}. "
                "Only one is needed."
            )

        # Allow/Block conflict (error)
        has_block = any(a in ("block", "redirect") for a in actions)
        has_allow = "allow" in actions
        if has_block and has_allow:
            block_src = [s for s, a in sources if a in ("block", "redirect")]
            allow_src = [s for s, a in sources if a == "allow"]
            errors.append(
                f"Conflict on {domain!r}: blocked by {block_src} but allowed by {allow_src}. "
                "Block takes precedence in Unbound."
            )

    return {"errors": errors, "warnings": warnings}


# ---------------------------------------------------------------------------
# Combined filter preview
# ---------------------------------------------------------------------------

def get_filter_preview(conn) -> dict:
    """
    Return the DNS zone lines and PF rules that would be generated from
    all filter modules, plus any detected conflicts.
    """
    from app.services.dns_filter import generate_dns_filter_zones
    from app.services.web_filter import generate_web_filter_zones
    from app.services.app_filter import generate_app_filter_dns_zones, generate_app_filter_pf_rules

    dns_zones = []
    try:
        dns_zones += generate_dns_filter_zones(conn)
    except Exception as exc:
        dns_zones.append(f"# DNS filter error: {exc}")

    try:
        dns_zones += generate_web_filter_zones(conn)
    except Exception as exc:
        dns_zones.append(f"# Web filter error: {exc}")

    try:
        dns_zones += generate_app_filter_dns_zones(conn)
    except Exception as exc:
        dns_zones.append(f"# App filter DNS error: {exc}")

    pf_rules = ""
    try:
        pf_rules = generate_app_filter_pf_rules(conn)
    except Exception as exc:
        pf_rules = f"# App filter PF error: {exc}"

    conflicts = detect_conflicts(conn)

    return {
        "dns_zones":     dns_zones,
        "pf_rules":      pf_rules,
        "conflicts":     conflicts,
        "dns_zone_count": len([z for z in dns_zones if z.strip() and not z.strip().startswith("#")]),
    }


# ---------------------------------------------------------------------------
# Import / Export
# ---------------------------------------------------------------------------

def import_filter_list(
    conn,
    text: str,
    filter_type: str,
    action: str = "block",
    category: str = "custom",
) -> dict:
    """
    Bulk-import a newline-separated list of domains/URLs into the specified filter.

    filter_type: "dns" | "web" | "app"
    Returns ``{"ok": bool, "imported": int, "skipped": int, "errors": [...]}``.
    """
    if filter_type not in ("dns", "web", "app"):
        return {"ok": False, "imported": 0, "skipped": 0,
                "errors": [f"Unknown filter_type: {filter_type!r}"]}

    lines  = [l.strip() for l in text.splitlines() if l.strip() and not l.startswith("#")]
    imported = skipped = 0
    errs = []

    for line in lines:
        try:
            if filter_type == "dns":
                from app.services.dns_filter import add_dns_filter_rule
                add_dns_filter_rule(conn, line, action=action, category=category)
                imported += 1
            elif filter_type == "web":
                from app.services.web_filter import add_web_filter_rule
                add_web_filter_rule(conn, line, action=action, category=category)
                imported += 1
            elif filter_type == "app":
                from app.services.app_filter import add_app_filter_rule
                add_app_filter_rule(conn, app_name=line, action=action,
                                    block_dns=True, block_ports=False,
                                    domains=line, category=category)
                imported += 1
        except Exception as exc:
            errs.append(f"{line!r}: {exc}")
            skipped += 1

    return {
        "ok": skipped == 0,
        "imported": imported,
        "skipped": skipped,
        "errors": errs,
    }


def export_filter_list(conn, filter_type: str) -> str:
    """
    Export all enabled rules for the given filter as a newline-separated list.
    filter_type: "dns" | "web" | "app"
    """
    if filter_type == "dns":
        rows = _rows(conn, "SELECT domain FROM filter_dns_rules WHERE enabled=1 ORDER BY domain")
        return "\n".join(r["domain"] for r in rows)
    elif filter_type == "web":
        rows = _rows(conn, "SELECT url_pattern FROM filter_web_rules WHERE enabled=1 ORDER BY url_pattern")
        return "\n".join(r["url_pattern"] for r in rows)
    elif filter_type == "app":
        rows = _rows(conn, "SELECT app_name FROM filter_app_rules WHERE enabled=1 ORDER BY app_name")
        return "\n".join(r["app_name"] for r in rows)
    return ""
