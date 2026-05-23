"""
pf_static_validator.py
----------------------
Lightweight static checker for PF rule ordering that catches section-order
bugs *before* ``pfctl -nf`` validation runs (or instead of it, on
Windows/Linux dev machines where ``pfctl`` is unavailable).

PF requires rules to appear in a specific order inside any single ruleset
(top-level pf.conf OR anchor body):

    1. Macros / table definitions
    2. Options (set ...)
    3. Normalization (scrub ...)
    4. Queueing (altq, queue ...)
    5. Translation (rdr, nat, binat, rdr-anchor, nat-anchor)
    6. Packet filtering (antispoof, pass, block, match, anchor)

If any rule appears in an earlier-numbered section *after* a later-numbered
one, pfctl rejects the file with "syntax error". This module detects every
such transition deterministically.

Public API
----------
``validate_section_order(text)``
    Raises ``PfRuleOrderError`` for any backward section transition.
``validate_anchor_order(text, *, captive_portal_before_lan_allow=True)``
    Lightweight semantic check: catches the case where the captive-portal
    filter anchor (or DNS intercept) is placed AFTER a broad LAN pass rule
    that would short-circuit it. Best-effort — does not replace ``pfctl -nf``.
"""

from __future__ import annotations

import re


class PfRuleOrderError(ValueError):
    """Raised when a PF rule appears in the wrong section order."""


# Match the first whitespace-delimited token on a non-comment line.
_TOKEN_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9-]*)\b")

# Section index — higher means later. A token belonging to a lower index after
# a token belonging to a higher index is a section-order violation.
#
# Tables and macros are skipped (they can appear anywhere syntactically, even
# though convention puts them near the top). Comments are ignored.
_SECTION_BY_TOKEN: dict[str, int] = {
    # options
    "set": 2,
    # normalization
    "scrub": 3,
    # queueing
    "altq": 4, "queue": 4,
    # translation
    "rdr":         5, "nat":         5, "binat":       5,
    "rdr-anchor":  5, "nat-anchor":  5,
    # filtering
    "antispoof": 6, "pass": 6, "block": 6, "match": 6,
    "anchor": 6, "load": 6,
}

_SECTION_NAMES = {
    2: "options",
    3: "normalization (scrub)",
    4: "queueing",
    5: "translation (rdr/nat/binat)",
    6: "filtering (pass/block/antispoof)",
}

# Legacy aliases retained so other modules importing them keep working.
_TRANSLATION_KEYWORDS = frozenset({"rdr", "nat", "binat", "rdr-anchor", "nat-anchor"})
_FILTER_KEYWORDS      = frozenset({"pass", "block", "antispoof", "match"})


def _first_token(line: str) -> str | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    m = _TOKEN_RE.match(stripped)
    return m.group(1).lower() if m else None


def validate_section_order(text: str) -> None:
    """
    Scan *text* line-by-line and raise ``PfRuleOrderError`` on the first
    backward section transition.

    Reports both the offending line and the earlier line whose section it
    violates so the operator can see the conflicting pair at a glance.
    """
    highest_seen: int = 0
    highest_seen_line: tuple[int, str, int] | None = None  # (idx, text, section)

    for idx, raw in enumerate(text.splitlines(), start=1):
        tok = _first_token(raw)
        if not tok:
            continue
        section = _SECTION_BY_TOKEN.get(tok)
        if section is None:
            # Tables, macros, custom keywords — not a PF section transition.
            continue

        if section >= highest_seen:
            highest_seen = section
            highest_seen_line = (idx, raw.strip(), section)
            continue

        # section < highest_seen → backward transition
        assert highest_seen_line is not None
        h_idx, h_text, h_sec = highest_seen_line
        raise PfRuleOrderError(
            f"PF section-order violation: line {idx} keyword {tok!r} "
            f"({_SECTION_NAMES[section]}) follows line {h_idx} "
            f"({_SECTION_NAMES[h_sec]} — {h_text!r}). "
            f"PF requires sections to appear in order: "
            f"macros/tables → options → scrub → queueing → translation → filtering.\n"
            f"Offending line: {raw.strip()!r}"
        )


def validate_anchor_order(
    text: str,
    *,
    captive_portal_before_lan_allow: bool = True,
    dns_intercept_before_lan_allow: bool = True,
) -> None:
    """Catch a small class of semantic order bugs missed by section ordering.

    These are the worst-case captive-portal/policy bypasses we have seen in
    review:

    * The ``captive_portal_filter`` anchor placed *after* a broad
      ``pass in quick on $lan_iface from $lan_net to any`` rule — the captive
      portal anchor never sees unauthenticated traffic.
    * The DNS-intercept rdr (53/udp → portal IP) placed after a broad LAN
      DNS pass rule — clients reach upstream resolvers and bypass Unbound.

    The function inspects only the first 320 chars of each rule line, so it
    is cheap and avoids false positives from long ``match`` keyword chains.
    """
    cp_anchor_idx: int | None = None
    dns_intercept_idx: int | None = None
    broad_lan_allow_idx: tuple[int, str] | None = None

    for idx, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # captive portal filter anchor — generated by pf_generator with the
        # name `captive_portal_filter` (see generate_pf_anchor()).
        if "captive_portal_filter" in stripped and stripped.startswith(("anchor", "load anchor")):
            cp_anchor_idx = idx

        # DNS intercept (LAN → Smart Shield) — emitted in pf_generator as a
        # rdr line with port 53. First-line catch is good enough.
        if (stripped.startswith("rdr") and " port 53" in stripped[:320]):
            dns_intercept_idx = idx

        # A broad LAN allow is the dangerous "from $lan_net to any" form.
        # We only flag it when it doesn't restrict ports — restricted forms
        # (admin GUI 443, portal 53) are intentional.
        low = stripped.lower()
        if (low.startswith("pass") and " on " in low and " from " in low and
            (" to any" in low) and " port " not in low and broad_lan_allow_idx is None):
            broad_lan_allow_idx = (idx, stripped)

    if (captive_portal_before_lan_allow
            and broad_lan_allow_idx is not None
            and cp_anchor_idx is not None
            and broad_lan_allow_idx[0] < cp_anchor_idx):
        raise PfRuleOrderError(
            f"PF anchor-order violation: broad LAN pass on line "
            f"{broad_lan_allow_idx[0]} ({broad_lan_allow_idx[1]!r}) appears "
            f"before the captive_portal_filter anchor on line {cp_anchor_idx}. "
            f"Unauthenticated clients would bypass the portal."
        )

    if (dns_intercept_before_lan_allow
            and broad_lan_allow_idx is not None
            and dns_intercept_idx is not None
            and broad_lan_allow_idx[0] < dns_intercept_idx):
        raise PfRuleOrderError(
            f"PF anchor-order violation: broad LAN pass on line "
            f"{broad_lan_allow_idx[0]} ({broad_lan_allow_idx[1]!r}) appears "
            f"before the DNS intercept rdr on line {dns_intercept_idx}. "
            f"LAN clients could reach upstream DNS directly and bypass "
            f"content policy."
        )
