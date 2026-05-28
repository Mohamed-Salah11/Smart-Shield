"""
tests/test_pf_static_validator.py
---------------------------------
Phase 3.4 — fast regression tests for ``app/services/pf_static_validator.py``.

The static validator catches two classes of PF mistake before ``pfctl -nf``
ever runs (which is essential on Windows/Linux dev boxes, where pfctl is
unavailable, and also as a defence-in-depth gate on FreeBSD):

  1. ``validate_section_order`` — backward section transitions (e.g. a
     ``pass`` filter rule appearing before a ``nat`` translation rule).
  2. ``validate_anchor_order`` — semantic mistakes where a broad
     ``pass in quick on $lan from $lan_net to any`` short-circuits a
     captive-portal filter anchor or a DNS-intercept rdr.

These three tests pin the *anchor* class against the exact scenarios that
have escaped into a release before — the captive-portal anchor or the
DNS-intercept rdr landing AFTER a broad LAN allow.
"""
import pytest

from app.services.pf_static_validator import (
    PfRuleOrderError,
    validate_anchor_order,
    validate_section_order,
)


# A fully clean ruleset: macros → options → scrub → translation → filtering,
# with the captive-portal anchor and DNS-intercept rdr emitted BEFORE the
# only broad LAN pass (the one that says "to em1:network", not "to any").
CLEAN_RULESET = """
# Macros & tables
ext_if = "em0"
lan_iface = "em1"
table <authenticated_clients> persist

# Options
set block-policy drop
set skip on lo

# Normalisation
scrub in all

# Translation
nat on em0 from em1:network to any -> (em0)
rdr on em1 proto udp from em1:network to !em1 port 53 -> 192.168.1.1 port 53
rdr-anchor "captive_portal_rdr"

# Filtering
anchor "captive_portal_filter"
block log all
pass out quick keep state
pass in quick on em1 from em1:network to em1:network
"""


# Mis-generated ruleset: the captive-portal filter anchor lands AFTER a
# broad LAN allow, so unauthenticated clients sail straight through the
# portal.
CAPTIVE_PORTAL_ANCHOR_AFTER_LAN_PASS = """
# Macros
lan_iface = "em1"

# Filtering
block log all
pass out quick keep state
# Broad LAN allow that defeats the portal:
pass in quick on em1 from em1:network to any
# Captive portal filter anchor — placed AFTER the broad pass, ineffective:
anchor "captive_portal_filter"
"""


# Mis-generated ruleset: the DNS-intercept rdr lands AFTER a broad LAN
# allow, so LAN clients reach upstream resolvers before pf rewrites the
# destination to Unbound.
DNS_INTERCEPT_AFTER_LAN_PASS = """
# Macros
lan_iface = "em1"

# Translation hook header
rdr-anchor "captive_portal_rdr"

# Filtering
block log all
pass out quick keep state
# Broad LAN allow — DNS clients reach upstream before being intercepted:
pass in quick on em1 from em1:network to any
# DNS intercept rdr — placed AFTER the broad pass, useless:
rdr on em1 proto udp from em1:network to !em1 port 53 -> 192.168.1.1 port 53
"""


# ---------------------------------------------------------------------------
# The three regression tests called out by the audit prompt
# ---------------------------------------------------------------------------

def test_captive_portal_anchor_after_broad_lan_pass_raises():
    with pytest.raises(PfRuleOrderError) as excinfo:
        validate_anchor_order(CAPTIVE_PORTAL_ANCHOR_AFTER_LAN_PASS)
    msg = str(excinfo.value)
    assert "captive_portal_filter" in msg
    assert "bypass the portal" in msg


def test_dns_intercept_after_broad_lan_pass_raises():
    with pytest.raises(PfRuleOrderError) as excinfo:
        validate_anchor_order(DNS_INTERCEPT_AFTER_LAN_PASS)
    msg = str(excinfo.value)
    assert "DNS intercept" in msg
    assert "content policy" in msg


def test_clean_ruleset_passes():
    # Both checks must succeed against the clean ruleset — sanity that we
    # didn't write a fixture that is *only* clean because the validator
    # is broken.
    validate_anchor_order(CLEAN_RULESET)
    validate_section_order(CLEAN_RULESET)


# ---------------------------------------------------------------------------
# Additional regression coverage — the negative space around each check
# ---------------------------------------------------------------------------

class TestAnchorOrderEdgeCases:

    def test_broad_lan_pass_with_port_does_not_trigger(self):
        # A port-restricted LAN allow (e.g. the admin GUI on 443) is
        # intentional and must NOT be flagged.
        ruleset = """
        block log all
        pass in quick on em1 from em1:network to any port 443
        anchor "captive_portal_filter"
        """
        validate_anchor_order(ruleset)

    def test_anchor_before_broad_lan_pass_does_not_trigger(self):
        # The correct order: anchor first, broad allow second.
        ruleset = """
        block log all
        anchor "captive_portal_filter"
        pass in quick on em1 from em1:network to any
        """
        validate_anchor_order(ruleset)

    def test_dns_intercept_before_broad_lan_pass_does_not_trigger(self):
        ruleset = """
        rdr on em1 proto udp from em1:network to !em1 port 53 -> 192.168.1.1 port 53
        block log all
        pass in quick on em1 from em1:network to any
        """
        validate_anchor_order(ruleset)

    def test_only_first_broad_lan_pass_counts(self):
        # If the first broad-pass is before the anchor, that's the
        # violation. A later broad-pass after the anchor is irrelevant.
        ruleset = """
        block log all
        pass in quick on em1 from em1:network to any
        anchor "captive_portal_filter"
        pass in quick on em1 from em1:network to any
        """
        with pytest.raises(PfRuleOrderError, match="captive_portal_filter"):
            validate_anchor_order(ruleset)


# ---------------------------------------------------------------------------
# section_order — sanity coverage so the file pins both public functions
# ---------------------------------------------------------------------------

class TestSectionOrder:

    def test_filtering_before_translation_raises(self):
        # `pass` (section 6) before `nat` (section 5) is a backward
        # transition — exactly the bug section_order is designed to catch.
        ruleset = """
        pass in quick on em1
        nat on em0 from em1:network to any -> (em0)
        """
        with pytest.raises(PfRuleOrderError, match="section-order"):
            validate_section_order(ruleset)

    def test_scrub_after_filter_raises(self):
        ruleset = """
        block log all
        scrub in all
        """
        with pytest.raises(PfRuleOrderError, match="section-order"):
            validate_section_order(ruleset)

    def test_comments_and_blank_lines_dont_confuse_validator(self):
        ruleset = """
        # macros
        ext_if = "em0"


        set block-policy drop
        # filtering
        block log all
        """
        validate_section_order(ruleset)
