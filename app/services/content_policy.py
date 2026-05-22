"""
content_policy.py
-----------------
Helpers for deciding whether an inbound HTTP request is the result of an
active Smart Shield content-policy DNS redirect.

Also exposes a unified domain-policy model used by ``dns_writer`` to emit
exactly one Unbound ``local-zone`` / ``local-data`` pair per blocked domain
even when the same domain is named by multiple filters (DNS Guard / Web
Guard / App Guard). Without dedup, overlapping rules generate duplicate
``local-zone`` entries which ``unbound-checkconf`` rejects.
"""

import json
import re
import time
from dataclasses import dataclass


# Canonical content-policy actions. The DB column still stores the legacy
# "block" / "allow" / "redirect" strings; this enum makes new code unambiguous.
CONTENT_POLICY_ACTIONS = (
    "block_all",
    "allow_all",
    "allow_whitelist_only",
    "redirect",
)


def normalize_action(raw: str) -> str:
    """Map UI/DB action strings to the canonical CONTENT_POLICY_ACTIONS values.

    Legacy values from existing DB rows:
        "block"  → block_all
        "allow"  → allow_whitelist_only   (this is what the old code actually does)
        "redirect" → redirect
    """
    val = (raw or "").strip().lower()
    if val in ("block", "block_all", ""):
        return "block_all"
    if val == "allow_all":
        return "allow_all"
    if val in ("allow", "allow_whitelist_only"):
        return "allow_whitelist_only"
    if val == "redirect":
        return "redirect"
    raise ValueError(f"Unknown content-policy action: {raw!r}")


# Allowed values for service_state['content_policy_settings']['mode'].
#   dns_nxdomain_only        — blocked domains return NXDOMAIN, no portal.
#   dns_redirect_block_page  — default; redirect to LAN IP + Flask block page.
#   captive_auth_required    — like above but the block page demands portal login.
#   whitelist_only           — only whitelisted devices bypass; everyone else blocked.
CONTENT_POLICY_MODES = (
    "dns_nxdomain_only",
    "dns_redirect_block_page",
    "captive_auth_required",
    "whitelist_only",
)


def get_content_policy_mode(conn) -> str:
    """Return the current content policy mode, defaulting to the safe block-page mode."""
    try:
        row = conn.execute(
            "SELECT value_json FROM service_state WHERE key_name='content_policy_settings'"
        ).fetchone()
        if not row:
            return "dns_redirect_block_page"
        cfg = json.loads(row["value_json"]) or {}
        mode = (cfg.get("mode") or "").strip().lower()
        if mode in CONTENT_POLICY_MODES:
            return mode
    except Exception:
        pass
    return "dns_redirect_block_page"


_DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def normalize_domain(raw: str) -> str:
    """Return a bare lowercase domain, or an empty string if it is invalid."""
    domain = (raw or "").strip().lower()
    if not domain:
        return ""

    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    domain = domain.split(":", 1)[0]
    domain = domain.lstrip("*.").strip(".")
    if not domain or "." not in domain:
        return ""

    labels = domain.split(".")
    if any(not _DOMAIN_LABEL_RE.match(label) for label in labels):
        return ""
    return domain


def domain_matches(host: str, policy_domain: str) -> bool:
    """True when host is the policy domain or one of its subdomains."""
    host = normalize_domain(host)
    policy_domain = normalize_domain(policy_domain)
    if not host or not policy_domain:
        return False
    return host == policy_domain or host.endswith("." + policy_domain)


def _rows(conn, sql, params=()):
    cur = conn.cursor()
    cur.execute(sql, params)
    return [dict(row) for row in cur.fetchall()]


# Canonical actions that count as "policy is enforcing on this domain" — used
# by has_active_content_policy / is_blocked_domain. `allow_all` does not count
# (it's an explicit allow, not enforcement); `allow_whitelist_only` does count
# because it implicitly blocks every other domain.
_ENFORCING_ACTIONS = frozenset({"block_all", "allow_whitelist_only", "redirect"})


def _is_enforcing(raw_action: str) -> bool:
    """True when the stored action string maps to a policy-enforcing canonical."""
    try:
        return normalize_action(raw_action) in _ENFORCING_ACTIONS
    except ValueError:
        return False


def has_active_content_policy(conn) -> bool:
    """Return True when any enforcing content policy rule is enabled.

    Honours canonical action values (`block_all`, `allow_whitelist_only`,
    `redirect`) alongside the legacy strings (`block`, `allow`, `redirect`).
    A rule stored with the canonical name used to be invisible to this check;
    callers now see it correctly.
    """
    for row in conn.execute(
        "SELECT action FROM filter_dns_rules WHERE enabled=1"
    ).fetchall():
        if _is_enforcing(row["action"] if "action" in row.keys() else ""):
            return True

    for row in conn.execute(
        "SELECT action FROM filter_web_rules WHERE enabled=1"
    ).fetchall():
        if _is_enforcing(row["action"] if "action" in row.keys() else ""):
            return True

    for row in conn.execute(
        "SELECT action, block_dns, block_ports FROM filter_app_rules WHERE enabled=1"
    ).fetchall():
        if not (row["block_dns"] or row["block_ports"]):
            continue
        if _is_enforcing(row["action"] if "action" in row.keys() else ""):
            return True

    return False


def is_blocked_domain(conn, host: str) -> bool:
    """Return True when host matches an active DNS/web/app enforcing rule.

    Defers to the unified domain-policy map so a rule stored with the
    canonical `block_all` / `allow_whitelist_only` / `redirect` action is
    treated identically to the legacy `block` / `allow` / `redirect` strings.
    """
    host = normalize_domain(host)
    if not host:
        return False

    try:
        policies = build_domain_policy_map(conn)
    except Exception:
        policies = {}

    for policy_domain, policy in policies.items():
        if policy.action not in _ENFORCING_ACTIONS:
            continue
        if domain_matches(host, policy_domain):
            return True
    return False


def resolve_domain_policy(conn, host: str):
    """Return the effective ``DomainPolicy`` for *host*, or ``None``.

    Performs subdomain fallback: ``m.youtube.com`` resolves via a rule on
    ``youtube.com``. The longest matching parent wins so a more-specific
    sub-rule overrides a broader one. Returned object exposes the canonical
    action, source, and (when applicable) redirect_ip.
    """
    host = normalize_domain(host)
    if not host:
        return None

    try:
        policies = build_domain_policy_map(conn)
    except Exception:
        return None

    best = None
    best_len = -1
    for policy_domain, policy in policies.items():
        if not domain_matches(host, policy_domain):
            continue
        if len(policy_domain) > best_len:
            best = policy
            best_len = len(policy_domain)
    return best


def has_active_captive_session(conn, ip: str, now: int | None = None) -> bool:
    """Return True when ip has a current captive portal bypass session."""
    ip = (ip or "").strip()
    if not ip:
        return False
    now = int(time.time()) if now is None else int(now)
    row = conn.execute(
        """
        SELECT 1
        FROM captive_sessions
        WHERE ip_address=?
          AND logged_out=0
          AND expires_at > ?
        LIMIT 1
        """,
        (ip, now),
    ).fetchone()
    return row is not None


def is_admin_bypass_session(conn, ip: str, now: int | None = None) -> bool:
    """Return True when ip belongs to an active admin (superuser) portal session."""
    ip = (ip or "").strip()
    if not ip:
        return False
    now = int(time.time()) if now is None else int(now)
    row = conn.execute(
        """
        SELECT 1
        FROM captive_sessions
        WHERE ip_address=?
          AND is_superuser=1
          AND logged_out=0
          AND expires_at > ?
        LIMIT 1
        """,
        (ip, now),
    ).fetchone()
    return row is not None


def is_device_whitelisted(conn, ip: str) -> bool:
    """Return True when this IP is in the device whitelist (tracked_hosts.is_whitelisted=1).

    Semantics (Phase 3.2): is_whitelisted == "captive portal bypass only".
    Content/DNS/app policy still applies. Use is_policy_exempt() for clients
    that should also bypass DNS-based filtering.
    """
    ip = (ip or "").strip()
    if not ip:
        return False
    row = conn.execute(
        "SELECT 1 FROM tracked_hosts WHERE ip_address=? AND is_whitelisted=1 LIMIT 1",
        (ip,),
    ).fetchone()
    return row is not None


def is_policy_exempt(conn, ip: str) -> bool:
    """Return True when this IP is exempt from content policy (tracked_hosts.is_policy_exempt=1).

    Policy exemption is enforced at the DNS layer via Unbound's
    policy_exemption_view — the client gets normal recursive answers instead
    of NXDOMAIN / redirect-to-block-page. Captive portal bypass is a separate
    flag (is_whitelisted / is_device_whitelisted).
    """
    ip = (ip or "").strip()
    if not ip:
        return False
    try:
        row = conn.execute(
            "SELECT 1 FROM tracked_hosts WHERE ip_address=? AND is_policy_exempt=1 LIMIT 1",
            (ip,),
        ).fetchone()
    except Exception:
        # Column may not exist on freshly-imported legacy DBs; treat as not exempt.
        return False
    return row is not None


# ---------------------------------------------------------------------------
# Unified domain-policy map
# ---------------------------------------------------------------------------

# Higher precedence value wins when the same domain appears in multiple
# filters. SOC emergency blocks would beat App/Web/DNS, but the current
# SOC blocklist is IP-based (PF table) so domains never collide there.
_SOURCE_PRECEDENCE = {
    "allow_whitelist_only": 100,  # whitelist override always wins
    "soc":    80,
    "app":    60,
    "web":    40,
    "dns":    20,
}


@dataclass(frozen=True)
class DomainPolicy:
    """Resolved decision for a single normalized domain.

    ``action`` is always one of the canonical CONTENT_POLICY_ACTIONS values
    (``block_all``, ``allow_whitelist_only``, ``redirect``, ``allow_all``) —
    callers should *not* compare against the legacy ``block``/``allow`` strings.
    """

    domain: str
    action: str            # canonical CONTENT_POLICY_ACTIONS value
    source: str            # "dns" | "web" | "app" | "soc" (lower-case)
    redirect_ip: str = ""  # only meaningful when action == "redirect"

    @property
    def precedence(self) -> int:
        if self.action == "allow_whitelist_only":
            return _SOURCE_PRECEDENCE["allow_whitelist_only"]
        return _SOURCE_PRECEDENCE.get(self.source, 0)


def _consider(policies: dict, candidate: DomainPolicy) -> None:
    """Insert candidate into the map, preferring the higher precedence."""
    existing = policies.get(candidate.domain)
    if existing is None or candidate.precedence > existing.precedence:
        policies[candidate.domain] = candidate


def build_domain_policy_map(conn) -> dict:
    """Return ``{normalized_domain: DomainPolicy}`` over every enabled
    domain-blocking rule in the DB. Duplicate domains across DNS / Web /
    App filters are collapsed to a single entry; precedence is:

        allow (whitelist-only) > SOC > App > Web > DNS
    """
    policies: dict = {}

    try:
        for row in conn.execute(
            "SELECT domain, action, redirect_ip FROM filter_dns_rules "
            "WHERE enabled = 1"
        ).fetchall():
            d = normalize_domain(row["domain"] or "")
            if not d:
                continue
            action = normalize_action(row["action"])
            _consider(policies, DomainPolicy(
                domain=d, action=action, source="dns",
                redirect_ip=(row["redirect_ip"] or "").strip(),
            ))
    except Exception:
        pass

    try:
        for row in conn.execute(
            "SELECT url_pattern, action FROM filter_web_rules WHERE enabled = 1"
        ).fetchall():
            d = normalize_domain(row["url_pattern"] or "")
            if not d:
                continue
            action = normalize_action(row["action"])
            _consider(policies, DomainPolicy(
                domain=d, action=action, source="web",
            ))
    except Exception:
        pass

    try:
        for row in conn.execute(
            "SELECT domains, action FROM filter_app_rules "
            "WHERE enabled = 1 AND block_dns = 1"
        ).fetchall():
            action = normalize_action(row["action"])
            for raw in (row["domains"] or "").split(","):
                d = normalize_domain(raw)
                if not d:
                    continue
                _consider(policies, DomainPolicy(
                    domain=d, action=action, source="app",
                ))
    except Exception:
        pass

    return policies


# Phase 4.2 — known DNS-over-HTTPS provider endpoints. Kept in content_policy
# (not dns_filter) so other modules (policy_exemption_view, future feature flags)
# can reference it without creating import cycles.
#
# DoH lets a client tunnel DNS queries inside HTTPS to a public resolver,
# bypassing Smart Shield's Unbound and any DNS-based content filtering.
# We can't generically detect DoH (it's just HTTPS to port 443) but we CAN
# refuse to resolve the well-known provider hostnames. That stops the most
# common case where browsers and OSes use a public DoH resolver by default.
#
# Limitations:
#   * If the client hardcodes the resolver's IP, this won't help.
#   * New providers not in this list will still resolve.
# The content_policy_settings.block_known_doh feature flag controls emission.
DOH_PROVIDER_DOMAINS = (
    "dns.google",
    "dns.google.com",
    "cloudflare-dns.com",
    "mozilla.cloudflare-dns.com",
    "one.one.one.one",
    "dns.quad9.net",
    "dns.nextdns.io",
    "doh.opendns.com",
    "doh.cleanbrowsing.org",
)


def emit_policy_exemption_overrides(conn) -> list:
    """Render `local-zone "<domain>." transparent` lines for every domain that
    has ANY block (or "allow whitelist-only") rule in the unified policy map.

    Injected into the Unbound `policy_exemption_view` so clients in
    tracked_hosts.is_policy_exempt receive normal recursive answers instead
    of the global server-scope NXDOMAIN / redirect-to-block-page.

    Why "transparent" (not "deny" or "always_transparent"): the view inherits
    behaviour from the server scope unless a same-named local-zone is declared
    in the view. `transparent` tells Unbound: do not synthesize an answer
    locally — forward the query upstream. This is the same pattern used by
    `whitelist_view`, just applied to every blocked domain rather than the
    narrower "allow whitelist-only" subset.
    """
    try:
        policies = build_domain_policy_map(conn)
    except Exception:
        policies = {}

    overrides: set = set()
    for domain, policy in policies.items():
        # Whitelist-only rows aren't a block, so no exemption override needed.
        if policy.action == "allow_whitelist_only":
            continue
        overrides.add(domain)

    # Policy-exempt clients also bypass the DoH-provider block, so they can use
    # public DoH resolvers if they want. (The block is a global content-policy
    # backstop; exemption opts that client out of it.)
    for domain in DOH_PROVIDER_DOMAINS:
        overrides.add(domain)

    return [f'    local-zone: "{d}." transparent' for d in sorted(overrides)]


def emit_unbound_policy_zones(conn, block_page_ip: str) -> list:
    """Render the deduplicated domain policy map to Unbound config lines.

    Emits exactly one ``local-zone`` + (when applicable) one ``local-data``
    record per domain. Output is sorted to keep generated configs stable
    diff-by-diff, which is important for the apply/rollback story.

    Mode handling (see ``get_content_policy_mode``):
        dns_nxdomain_only       — always emit ``always_nxdomain``, ignore block_page_ip.
        dns_redirect_block_page — default; redirect to block_page_ip when set.
        captive_auth_required   — same emit shape as block_page; the portal flow
                                  handles authentication on top.
        whitelist_only          — same emit shape as block_page so non-whitelisted
                                  clients see the block page.
    """
    mode = get_content_policy_mode(conn)
    force_nxdomain = (mode == "dns_nxdomain_only")

    policies = build_domain_policy_map(conn)
    lines: list = []
    for domain in sorted(policies):
        policy = policies[domain]
        fqdn = domain + "."
        if policy.action == "redirect" and policy.redirect_ip and not force_nxdomain:
            lines.append(f'    local-zone: "{fqdn}" redirect')
            lines.append(f'    local-data: "{fqdn} 5 A {policy.redirect_ip}"')
            continue
        # Both "block" and "allow whitelist-only" produce the same
        # default-deny zone. "Allow" rules get a transparent override in
        # the whitelist_view (still generated by the per-filter helpers).
        if not force_nxdomain and block_page_ip:
            lines.append(f'    local-zone: "{fqdn}" redirect')
            lines.append(f'    local-data: "{fqdn} 5 A {block_page_ip}"')
        else:
            lines.append(f'    local-zone: "{fqdn}" always_nxdomain')
    return lines


def explain_domain_policy(conn, host: str) -> dict:
    """
    Resolve which filter rule blocks (or allows) ``host`` and return enough
    detail for SOC analysts and audit logs. Returns ``{}`` when no rule matches.

    Result fields:
        domain     — normalized parent domain of the matched rule
        source     — "dns" | "web" | "app"
        rule_id    — primary key of the matching row
        action     — canonical CONTENT_POLICY_ACTIONS value
                     ("block_all" / "allow_whitelist_only" / "redirect" / "allow_all")
        category   — best-effort category string (may be empty)
    """
    host = normalize_domain(host)
    if not host:
        return {}

    # Walk in the same precedence as build_domain_policy_map: app > web > dns,
    # but unlike the writer we also look at "allow" rules so the explanation
    # surfaces whitelist hits when present.
    sources = [
        (
            "app",
            "SELECT id, domains AS pattern, action, category "
            "FROM filter_app_rules WHERE enabled=1 AND block_dns=1",
        ),
        (
            "web",
            "SELECT id, url_pattern AS pattern, action, category "
            "FROM filter_web_rules WHERE enabled=1",
        ),
        (
            "dns",
            "SELECT id, domain AS pattern, action, category "
            "FROM filter_dns_rules WHERE enabled=1",
        ),
    ]

    best: dict = {}
    best_precedence = -1
    for src, sql in sources:
        try:
            rows = conn.execute(sql).fetchall()
        except Exception:
            continue
        for row in rows:
            patterns = (row["pattern"] or "").split(",") if src == "app" else [row["pattern"] or ""]
            action = normalize_action(row["action"])
            for raw in patterns:
                d = normalize_domain(raw)
                if not d or not domain_matches(host, d):
                    continue
                precedence = (_SOURCE_PRECEDENCE["allow_whitelist_only"]
                              if action == "allow_whitelist_only"
                              else _SOURCE_PRECEDENCE.get(src, 0))
                if precedence > best_precedence:
                    best_precedence = precedence
                    best = {
                        "domain":   d,
                        "source":   src,
                        "rule_id":  row["id"],
                        "action":   action,
                        "category": (row["category"] or "") if "category" in row.keys() else "",
                    }
    return best


def get_block_page_ip(conn) -> str:
    """
    Return the LAN IP for Unbound local-data A records (block page redirect target).
    Always uses the LAN interface IP from lan_config — never localhost or a URL.
    Returns '' if LAN IP is not configured (Unbound falls back to NXDOMAIN).
    """
    try:
        row = conn.execute("SELECT ipv4_address FROM lan_config WHERE id=1").fetchone()
        raw = ((row["ipv4_address"] if row else "") or "").strip()
        ip = raw.split("/")[0].strip()  # strip CIDR prefix, e.g. "192.168.1.1/24" → "192.168.1.1"
        if ip and not ip.startswith("127."):
            return ip
    except Exception:
        pass
    return ""
