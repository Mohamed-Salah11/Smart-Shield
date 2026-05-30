"""
bypass_policy.py
----------------
Single source of truth for which PF address tables bypass each filtering layer.

The captive portal, DNS content policy, web filter, application filter, and
firewall rule generators all need to agree on *who* gets to skip enforcement.
Before this module existed, each generator hard-coded its own list of tables —
which meant a client could be exempted from one layer but still blocked by
another. The matrix below resolves that.

Layer semantics
---------------
``captive_portal_http`` — clients whose HTTP traffic skips the portal redirect.
``captive_portal_dns``  — clients whose DNS queries reach upstream directly
                          (skipping Unbound). Kept conservative so authenticated
                          and whitelisted clients still resolve through Unbound
                          and remain under content-policy enforcement; only the
                          opt-in ``admin_bypass_clients`` table is allowed here.
``dns_policy``          — clients exempted from DNS block/redirect zones.
``web_filter``          — clients exempted from web-filter DNS zones.
``app_filter``          — clients exempted from app-filter DNS + PF rules.

Table reference
---------------
``admin_bypass_clients``  appliance administrators and emergency-bypass entries
``authenticated_clients`` captive-portal users with a valid session
``device_whitelist``      devices marked bypass-portal in tracked_hosts
``access_whitelist``      access-policy-allowed clients
``policy_exemption``      clients marked policy-exempt in tracked_hosts

Adding a new layer
------------------
1. Add the layer name and its tuple of table names to ``BYPASS_MATRIX``.
2. Update the generator (pf_generator / dns_writer / captive_portal / etc.) to
   call ``bypass_tables_for(layer)`` instead of hard-coding the list.
3. Document the trade-off in the layer's docstring so future readers know what
   "bypass" means for that particular enforcement layer.
"""

from typing import Iterable


# Ordered tuples so emitted `no rdr` / `pass quick` rules have a stable order
# from one apply to the next — important for diff-based audit review.
BYPASS_MATRIX: dict[str, tuple[str, ...]] = {
    "captive_portal_http": (
        "admin_bypass_clients",
        "authenticated_clients",
        "device_whitelist",
        "access_whitelist",
    ),
    "captive_portal_dns": (
        # Conservative: only admin bypass clients reach upstream DNS directly.
        # Authenticated and whitelisted clients still go through Unbound so
        # content policy remains effective.
        #
        # P.2 note: captive_auth_required mode grants a per-client DNS bypass on
        # login via tracked_hosts.is_policy_exempt (which pulls the /32 into
        # Unbound's policy_exemption_view), NOT via this PF table. That keeps the
        # exemption mode-scoped and auto-revoked on logout/expiry, so this matrix
        # intentionally stays limited to admin_bypass_clients.
        "admin_bypass_clients",
    ),
    "dns_policy": (
        "admin_bypass_clients",
        "policy_exemption",
    ),
    "web_filter": (
        "admin_bypass_clients",
        "policy_exemption",
    ),
    "app_filter": (
        "admin_bypass_clients",
        "policy_exemption",
    ),
}


def bypass_tables_for(layer: str) -> tuple[str, ...]:
    """Return the ordered tuple of PF table names that bypass *layer*.

    Returns an empty tuple for unknown layers — callers should treat that as
    "no bypass" rather than crashing. Spelling errors will silently disable
    bypass; pair with the unit-test list ``ALL_LAYERS`` below to guard against
    drift.
    """
    return BYPASS_MATRIX.get(layer, ())


ALL_LAYERS: tuple[str, ...] = tuple(BYPASS_MATRIX.keys())


def iter_bypass_pairs() -> Iterable[tuple[str, tuple[str, ...]]]:
    """Yield ``(layer, tables)`` pairs in declaration order."""
    return BYPASS_MATRIX.items()
