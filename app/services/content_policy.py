"""
content_policy.py
-----------------
Helpers for deciding whether an inbound HTTP request is the result of an
active Smart Shield content-policy DNS redirect.
"""

import re
import time


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


def has_active_content_policy(conn) -> bool:
    """Return True when any content policy block rule is enabled."""
    checks = (
        """
        SELECT 1
        FROM filter_dns_rules
        WHERE enabled=1 AND LOWER(COALESCE(action, 'block'))='block'
        LIMIT 1
        """,
        """
        SELECT 1
        FROM filter_web_rules
        WHERE enabled=1 AND LOWER(COALESCE(action, 'block'))='block'
        LIMIT 1
        """,
        """
        SELECT 1
        FROM filter_app_rules
        WHERE enabled=1
          AND LOWER(COALESCE(action, 'block'))='block'
          AND (block_dns=1 OR block_ports=1)
        LIMIT 1
        """,
    )
    for sql in checks:
        if conn.execute(sql).fetchone():
            return True
    return False


def is_blocked_domain(conn, host: str) -> bool:
    """Return True when host matches an active DNS/web/app domain block rule."""
    host = normalize_domain(host)
    if not host:
        return False

    dns_rules = _rows(
        conn,
        """
        SELECT domain
        FROM filter_dns_rules
        WHERE enabled=1 AND LOWER(COALESCE(action, 'block'))='block'
        """,
    )
    for rule in dns_rules:
        if domain_matches(host, rule.get("domain") or ""):
            return True

    web_rules = _rows(
        conn,
        """
        SELECT url_pattern
        FROM filter_web_rules
        WHERE enabled=1 AND LOWER(COALESCE(action, 'block'))='block'
        """,
    )
    for rule in web_rules:
        if domain_matches(host, rule.get("url_pattern") or ""):
            return True

    app_rules = _rows(
        conn,
        """
        SELECT domains
        FROM filter_app_rules
        WHERE enabled=1
          AND block_dns=1
          AND LOWER(COALESCE(action, 'block'))='block'
        """,
    )
    for rule in app_rules:
        for domain in (rule.get("domains") or "").split(","):
            if domain_matches(host, domain):
                return True

    return False


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
