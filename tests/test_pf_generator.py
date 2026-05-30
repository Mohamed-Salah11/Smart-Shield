"""
tests/test_pf_generator.py
--------------------------
Unit tests for app/services/pf_generator.py.
No FreeBSD required — all system calls are either skipped or mocked.
"""

import os
import sys
import pytest

# Ensure test env vars are set before importing the app
os.environ.setdefault("SMARTSHIELD_DB_PATH", "file:pftest?mode=memory&cache=shared")
os.environ.setdefault("SECRET_KEY", "test-pf-key")
os.environ.setdefault("SMARTSHIELD_MASTER_KEY",
    __import__("base64").b64encode(__import__("secrets").token_bytes(32)).decode())


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def conn():
    """In-memory SQLite with the Smart Shield schema and minimal seed data."""
    from app.database import get_db, init_db
    init_db()
    db = get_db()

    # Seed LAN / WAN config
    db.execute(
        "UPDATE lan_config SET assigned_port='em1', ipv4_address='192.168.1.1/24' WHERE id=1"
    )
    db.execute(
        "UPDATE wan_config SET assigned_port='em0', ipv4_config_type='static', "
        "ipv4_address='203.0.113.1/24' WHERE id=1"
    )
    db.commit()
    yield db
    db.close()


@pytest.fixture()
def fresh_conn():
    """Per-test clean in-memory DB."""
    os.environ["SMARTSHIELD_DB_PATH"] = "file:pftest2?mode=memory&cache=shared"
    from app.database import get_db, init_db
    init_db()
    db = get_db()
    db.execute(
        "UPDATE lan_config SET assigned_port='em1', ipv4_address='192.168.1.1/24' WHERE id=1"
    )
    db.execute(
        "UPDATE wan_config SET assigned_port='em0', ipv4_config_type='static', "
        "ipv4_address='203.0.113.1/24' WHERE id=1"
    )
    db.commit()
    yield db
    db.close()
    os.environ["SMARTSHIELD_DB_PATH"] = "file:pftest?mode=memory&cache=shared"


# ---------------------------------------------------------------------------
# Config generation
# ---------------------------------------------------------------------------

class TestGeneratePfConf:

    def test_contains_wan_lan_macros(self, conn):
        from app.services.pf_generator import generate_pf_conf
        conf = generate_pf_conf(conn)
        assert 'WAN     = "em0"' in conf
        assert 'LAN     = "em1"' in conf

    def test_contains_lan_net(self, conn):
        from app.services.pf_generator import generate_pf_conf
        conf = generate_pf_conf(conn)
        assert "LAN_NET" in conf
        assert "192.168.1.0/24" in conf

    def test_default_block_policy(self, conn):
        from app.services.pf_generator import generate_pf_conf
        conf = generate_pf_conf(conn)
        assert "set block-policy drop" in conf

    def test_ids_block_table_and_rule_present(self, conn):
        # The IDS block-on-alert table (populated live by ids_blocker) and its
        # drop rule must always be in the ruleset so members are dropped the
        # instant they are added to the table.
        from app.services.pf_generator import generate_pf_conf
        conf = generate_pf_conf(conn)
        assert "table <ss_ids_blocks> persist" in conf
        assert "from <ss_ids_blocks>" in conf

    def test_scrub_max_mss_emitted_when_set(self, fresh_conn):
        # A per-interface MSS clamp on wan_config.mss must be emitted as a
        # `scrub on $WAN all max-mss <N>` rule, ahead of the global scrub so
        # pf's first-match scrub picks it on the WAN link (PMTUD black-hole
        # fix for PPPoE/low-MTU uplinks).
        from app.services.pf_generator import generate_pf_conf
        fresh_conn.execute("UPDATE wan_config SET mss='1452' WHERE id=1")
        fresh_conn.commit()
        conf = generate_pf_conf(fresh_conn)
        assert "scrub on $WAN all max-mss 1452" in conf
        # Per-interface clamp must precede the global `scrub in all`.
        assert conf.index("scrub on $WAN all max-mss 1452") < conf.index("scrub in all")

    def test_default_masquerade_when_no_outbound_nat(self, conn):
        from app.services.pf_generator import generate_pf_conf
        conf = generate_pf_conf(conn)
        assert "nat on $WAN from $LAN_NET to any -> ($WAN)" in conf

    def test_default_masquerade_always_present_even_with_explicit_outbound(self, fresh_conn):
        # The default masquerade must always be emitted as a safety net.
        # Explicit outbound rules are written below it and still take
        # precedence via PF's last-match-wins semantics, so LAN clients
        # never lose internet just because an admin added a NAT rule.
        from app.services.pf_generator import generate_pf_conf
        fresh_conn.execute(
            "INSERT INTO nat_outbound (disabled, interface, src_address, dst_address, nat_address)"
            " VALUES (0, 'em0', '192.168.1.0/24', 'any', '')"
        )
        fresh_conn.commit()
        conf = generate_pf_conf(fresh_conn)
        assert "nat on $WAN from $LAN_NET to any -> ($WAN)" in conf
        # Explicit user rule must still appear (and PF last-match means it wins)
        default_idx  = conf.index("nat on $WAN from $LAN_NET")
        explicit_idx = conf.index("nat on em0 from 192.168.1.0/24")
        assert explicit_idx > default_idx, "explicit outbound rule must come AFTER the default for last-match override"

    def test_outbound_nat_translates_symbolic_wan_interface(self, fresh_conn):
        # The NAT UI stores interface as the symbolic 'WAN'/'LAN'. PF only
        # accepts real interface names — the generator must translate.
        from app.services.pf_generator import generate_pf_conf
        fresh_conn.execute(
            "INSERT INTO nat_outbound (disabled, interface, src_address, dst_address, nat_address)"
            " VALUES (0, 'WAN', '192.168.1.0/24', 'any', '')"
        )
        fresh_conn.commit()
        conf = generate_pf_conf(fresh_conn)
        assert "nat on em0 from 192.168.1.0/24 to any -> (em0)" in conf
        # The raw symbol must not leak into pf.conf — pfctl would reject it.
        assert "nat on WAN from" not in conf

    def test_pppoe_wan_uses_tun0(self, fresh_conn):
        from app.services.pf_generator import generate_pf_conf
        fresh_conn.execute(
            "UPDATE wan_config SET ipv4_config_type='pppoe' WHERE id=1"
        )
        fresh_conn.commit()
        conf = generate_pf_conf(fresh_conn)
        assert 'WAN     = "tun0"' in conf

    def test_wan_rules_generated(self, fresh_conn):
        from app.services.pf_generator import generate_pf_conf
        fresh_conn.execute(
            "INSERT INTO firewall_rules_wan (action, disabled, protocol, source, destination)"
            " VALUES ('pass', 0, 'tcp', 'any', 'any')"
        )
        fresh_conn.commit()
        conf = generate_pf_conf(fresh_conn)
        assert "pass in on em0" in conf

    def test_lan_rules_generated(self, fresh_conn):
        from app.services.pf_generator import generate_pf_conf
        fresh_conn.execute(
            "INSERT INTO firewall_rules_lan (disabled, protocol, source, destination)"
            " VALUES (0, 'any', 'any', 'any')"
        )
        fresh_conn.commit()
        conf = generate_pf_conf(fresh_conn)
        assert "pass in on em1" in conf

    def test_disabled_rules_excluded(self, fresh_conn):
        from app.services.pf_generator import generate_pf_conf
        fresh_conn.execute(
            "INSERT INTO firewall_rules_wan (action, disabled, protocol, source, destination, description)"
            " VALUES ('block', 1, 'tcp', '10.0.0.1', 'any', 'DISABLED_TEST')"
        )
        fresh_conn.commit()
        conf = generate_pf_conf(fresh_conn)
        assert "DISABLED_TEST" not in conf

    def test_nat_port_forward_generated(self, fresh_conn):
        from app.services.pf_generator import generate_pf_conf
        fresh_conn.execute(
            "INSERT INTO nat_pf (disabled, interface, protocol, src_address, dst_address, redirect_ip)"
            " VALUES (0, 'em0', 'tcp', 'any', 'any', '192.168.1.100')"
        )
        fresh_conn.commit()
        conf = generate_pf_conf(fresh_conn)
        assert "rdr on em0 proto tcp" in conf
        assert "192.168.1.100" in conf

    def test_nat_port_forward_without_redirect_skipped(self, fresh_conn):
        from app.services.pf_generator import generate_pf_conf
        fresh_conn.execute(
            "INSERT INTO nat_pf (disabled, interface, protocol, src_address, dst_address, redirect_ip)"
            " VALUES (0, 'em0', 'tcp', 'any', 'any', '')"
        )
        fresh_conn.commit()
        conf = generate_pf_conf(fresh_conn)
        # Rule with empty redirect_ip must be skipped
        lines = [l for l in conf.splitlines() if "rdr on em0" in l]
        # Only rules with a real redirect_ip should appear
        for line in lines:
            assert "any" not in line.split("->")[-1].strip()

    def test_alias_table_generated(self, fresh_conn):
        from app.services.pf_generator import generate_pf_conf
        import json
        fresh_conn.execute(
            "INSERT INTO firewall_aliases (name, type, alias_values)"
            " VALUES ('BADGUYS', 'host', ?)",
            (json.dumps(["1.2.3.4", "5.6.7.8"]),),
        )
        fresh_conn.commit()
        conf = generate_pf_conf(fresh_conn)
        assert "table <BADGUYS>" in conf
        assert "1.2.3.4" in conf

    def test_floating_rule_generated(self, fresh_conn):
        from app.services.pf_generator import generate_pf_conf
        fresh_conn.execute(
            "INSERT INTO firewall_rules_floating (disabled, protocol, source, destination, description)"
            " VALUES (0, 'icmp', 'any', 'any', 'Allow ICMP')"
        )
        fresh_conn.commit()
        conf = generate_pf_conf(fresh_conn)
        assert "pass quick" in conf
        assert "proto icmp" in conf

    def test_outbound_nat_generated(self, fresh_conn):
        from app.services.pf_generator import generate_pf_conf
        fresh_conn.execute(
            "INSERT INTO nat_outbound (disabled, interface, src_address, dst_address)"
            " VALUES (0, 'em0', '10.0.0.0/8', 'any')"
        )
        fresh_conn.commit()
        conf = generate_pf_conf(fresh_conn)
        assert "nat on em0 from 10.0.0.0/8 to any" in conf

    def test_1to1_nat_generated(self, fresh_conn):
        from app.services.pf_generator import generate_pf_conf
        fresh_conn.execute(
            "INSERT INTO nat_1to1 (disabled, interface, external_address, internal_address)"
            " VALUES (0, 'em0', '203.0.113.10', '192.168.1.10')"
        )
        fresh_conn.commit()
        conf = generate_pf_conf(fresh_conn)
        assert "binat on em0 from 192.168.1.10 to any -> 203.0.113.10" in conf

    def test_scrub_present(self, conn):
        from app.services.pf_generator import generate_pf_conf
        conf = generate_pf_conf(conn)
        assert "scrub in all" in conf

    def test_pf_sections_are_ordered_for_pfctl(self, fresh_conn):
        from app.services.pf_generator import generate_pf_conf
        import json

        fresh_conn.execute("DELETE FROM firewall_aliases WHERE name='ORDERTEST'")
        fresh_conn.execute("DELETE FROM nat_outbound")
        fresh_conn.execute("DELETE FROM nat_pf")
        fresh_conn.execute(
            "INSERT INTO firewall_aliases (name, type, alias_values)"
            " VALUES ('ORDERTEST', 'host', ?)",
            (json.dumps(["1.2.3.4"]),),
        )
        fresh_conn.execute(
            "INSERT INTO nat_pf (disabled, interface, protocol, src_address, dst_address, redirect_ip)"
            " VALUES (0, 'em0', 'tcp', 'any', 'any', '192.168.1.100')"
        )
        fresh_conn.commit()

        conf = generate_pf_conf(fresh_conn)
        table_pos = conf.index("table <authenticated_clients>")
        alias_pos = conf.index("table <ORDERTEST>")
        options_pos = conf.index("set block-policy drop")
        scrub_pos = conf.index("scrub in all")
        nat_pos = conf.index("nat on $WAN")
        rdr_pos = conf.index("rdr on em0 proto tcp")
        rdr_anchor_pos = conf.index('rdr-anchor "captive_portal_rdr"')
        filter_anchor_pos = conf.index('anchor "captive_portal_filter"')

        assert table_pos < alias_pos < options_pos < scrub_pos
        assert scrub_pos < nat_pos < rdr_pos < rdr_anchor_pos < filter_anchor_pos


# ---------------------------------------------------------------------------
# Validation (pfctl is mocked — only tests non-FreeBSD path)
# ---------------------------------------------------------------------------

class TestValidatePfConf:

    def test_non_freebsd_always_passes(self):
        from app.services.pf_generator import validate_pf_conf
        ok, msg = validate_pf_conf("anything here")
        assert ok is True
        assert "skipped" in msg

    def test_empty_string_passes_on_non_freebsd(self):
        from app.services.pf_generator import validate_pf_conf
        ok, _ = validate_pf_conf("")
        assert ok is True


# ---------------------------------------------------------------------------
# Status (non-FreeBSD path)
# ---------------------------------------------------------------------------

class TestGetPfStatus:

    def test_non_freebsd_returns_dry_run(self):
        from app.services.pf_generator import get_pf_status
        status = get_pf_status()
        assert status["state"] == "dry-run"
        assert status["running"] is False


# ---------------------------------------------------------------------------
# Rollback (non-FreeBSD path)
# ---------------------------------------------------------------------------

class TestRollbackPf:

    def test_rollback_fails_gracefully_on_non_freebsd(self):
        from app.services.pf_generator import rollback_pf
        result = rollback_pf()
        assert result["ok"] is False
        assert "FreeBSD" in result["message"] or "Non" in result["message"]


# ---------------------------------------------------------------------------
# reload_pf_rules (dry-run)
# ---------------------------------------------------------------------------

class TestReloadPfRules:

    def test_non_freebsd_returns_ok_with_conf(self, conn):
        from app.services.pf_generator import reload_pf_rules
        result = reload_pf_rules(conn)
        assert result["ok"] is True
        assert "conf" in result
        assert "WAN" in result["conf"]
        assert "Non-FreeBSD" in result["message"]


# ---------------------------------------------------------------------------
# FreeBSD PF correctness — ensures generated config is valid pfctl syntax
# ---------------------------------------------------------------------------

class TestPfFreeBSDCorrectness:
    """
    These tests verify that pf_generator produces syntactically correct PF
    output that pfctl -nf would accept on FreeBSD.  No FreeBSD required to
    run; we inspect the generated text directly.
    """

    # ── Protocol rendering ────────────────────────────────────────────────────

    def test_proto_tcp_udp_renders_braces(self, fresh_conn):
        from app.services.pf_generator import generate_pf_conf
        fresh_conn.execute(
            "INSERT INTO firewall_rules_wan (action, disabled, protocol, source, destination)"
            " VALUES ('pass', 0, 'tcp+udp', 'any', 'any')"
        )
        fresh_conn.commit()
        conf = generate_pf_conf(fresh_conn)
        assert "proto { tcp udp }" in conf
        assert "proto tcp+udp" not in conf

    def test_proto_tcp_slash_udp_also_renders_braces(self, fresh_conn):
        from app.services.pf_generator import generate_pf_conf
        fresh_conn.execute(
            "INSERT INTO firewall_rules_wan (action, disabled, protocol, source, destination)"
            " VALUES ('pass', 0, 'tcp/udp', 'any', 'any')"
        )
        fresh_conn.commit()
        conf = generate_pf_conf(fresh_conn)
        assert "proto { tcp udp }" in conf
        assert "proto tcp/udp" not in conf

    def test_proto_icmpv6_renders_icmp6(self, fresh_conn):
        from app.services.pf_generator import generate_pf_conf
        fresh_conn.execute(
            "INSERT INTO firewall_rules_floating (disabled, protocol, source, destination)"
            " VALUES (0, 'icmpv6', 'any', 'any')"
        )
        fresh_conn.commit()
        conf = generate_pf_conf(fresh_conn)
        assert "proto icmp6" in conf
        assert "proto icmpv6" not in conf

    # ── Port expression rendering ─────────────────────────────────────────────

    def test_port_list_renders_braces(self, fresh_conn):
        from app.services.pf_generator import generate_pf_conf
        fresh_conn.execute(
            "INSERT INTO firewall_rules_wan (action, disabled, protocol, source, destination, dest_port)"
            " VALUES ('pass', 0, 'tcp', 'any', 'any', '80,443')"
        )
        fresh_conn.commit()
        conf = generate_pf_conf(fresh_conn)
        assert "port { 80 443 }" in conf
        assert "port 80,443" not in conf

    def test_port_range_renders_colon(self, fresh_conn):
        from app.services.pf_generator import generate_pf_conf
        fresh_conn.execute(
            "INSERT INTO firewall_rules_wan (action, disabled, protocol, source, destination, dest_port)"
            " VALUES ('pass', 0, 'tcp', 'any', 'any', '8080-8090')"
        )
        fresh_conn.commit()
        conf = generate_pf_conf(fresh_conn)
        assert "port 8080:8090" in conf
        assert "port 8080-8090" not in conf

    def test_single_port_renders_without_braces(self, fresh_conn):
        from app.services.pf_generator import generate_pf_conf
        fresh_conn.execute(
            "INSERT INTO firewall_rules_wan (action, disabled, protocol, source, destination, dest_port)"
            " VALUES ('pass', 0, 'tcp', 'any', 'any', '443')"
        )
        fresh_conn.commit()
        conf = generate_pf_conf(fresh_conn)
        assert "port 443 " in conf

    # ── ICMP echoreq / ping-block ordering ────────────────────────────────────

    def test_hardening_does_not_quick_pass_inbound_echoreq(self, conn):
        """The hardening section must NOT emit 'pass in quick ... echoreq'.
        If it did, user block-ping rules would be unreachable."""
        from app.services.pf_generator import generate_pf_conf
        conf = generate_pf_conf(conn)
        for line in conf.splitlines():
            stripped = line.strip()
            if "echoreq" in stripped and stripped.startswith("pass in") and "quick" in stripped:
                raise AssertionError(
                    f"Hardening emits 'pass in quick' with echoreq — user block-ping rules "
                    f"will never be reached.\nOffending line: {line!r}"
                )

    def test_user_block_ping_rule_is_present_in_output(self, fresh_conn):
        """A user-created 'block in on WAN proto icmp' rule must appear in the
        generated conf and must not be shadowed by an earlier quick-pass."""
        from app.services.pf_generator import generate_pf_conf
        fresh_conn.execute(
            "INSERT INTO firewall_rules_wan (action, disabled, protocol, source, destination, description)"
            " VALUES ('block', 0, 'icmp', 'any', 'any', 'BlockPingTest')"
        )
        fresh_conn.commit()
        conf = generate_pf_conf(fresh_conn)
        assert "BlockPingTest" in conf
        # Ensure the block rule is present
        block_lines = [l for l in conf.splitlines() if "BlockPingTest" in l or
                       ("block in on" in l and "proto icmp" in l)]
        assert block_lines, "User block-icmp rule not found in generated conf"

    # ── NAT port-forward dst_type ─────────────────────────────────────────────

    def test_nat_dst_type_wan_address_renders_iface(self, fresh_conn):
        """dst_type=wan_address must produce 'to (em0)', not 'to any'.
        Uses a unique redirect IP (192.168.1.201) to avoid collision with other
        tests that also insert into nat_pf on the shared pftest2 DB."""
        from app.services.pf_generator import generate_pf_conf
        fresh_conn.execute(
            "INSERT INTO nat_pf (disabled, interface, protocol, src_address,"
            " dst_address, dst_type, redirect_ip, redirect_port)"
            " VALUES (0, 'em0', 'tcp', 'any', 'any', 'wan_address', '192.168.1.201', '8443')"
        )
        fresh_conn.commit()
        conf = generate_pf_conf(fresh_conn)
        rdr_lines = [l for l in conf.splitlines() if "rdr on em0" in l and "192.168.1.201" in l]
        assert rdr_lines, "Port-forward rule for 192.168.1.201 not found in generated conf"
        for line in rdr_lines:
            assert "to (em0)" in line, (
                f"Expected 'to (em0)' for wan_address dst_type, got: {line!r}"
            )
            assert "to any" not in line, (
                f"dst_type=wan_address must not render as 'to any': {line!r}"
            )

    def test_nat_dst_type_any_renders_any(self, fresh_conn):
        """dst_type=any (or unset) must produce 'to any'."""
        from app.services.pf_generator import generate_pf_conf
        fresh_conn.execute(
            "INSERT INTO nat_pf (disabled, interface, protocol, src_address,"
            " dst_address, dst_type, redirect_ip)"
            " VALUES (0, 'em0', 'tcp', 'any', 'any', 'any', '10.0.0.5')"
        )
        fresh_conn.commit()
        conf = generate_pf_conf(fresh_conn)
        rdr_lines = [l for l in conf.splitlines() if "rdr on em0" in l and "10.0.0.5" in l]
        assert rdr_lines, "Port-forward rule not found"
        assert any("to any" in l for l in rdr_lines)


# ---------------------------------------------------------------------------
# Content-policy DNS funnel — fail-open when Unbound isn't serving the LAN
# ---------------------------------------------------------------------------

class TestContentPolicyDnsFailOpen:
    """When content filtering is active, PF normally force-redirects all LAN
    :53 to Unbound and blocks LAN→WAN DNS. That must FAIL OPEN when Unbound
    isn't actually serving the LAN — otherwise a dead resolver black-holes all
    LAN name resolution (ping works, nothing browses)."""

    def _activate_policy(self, db):
        db.execute("DELETE FROM filter_dns_rules")
        db.execute(
            "INSERT INTO filter_dns_rules (domain, action, enabled) "
            "VALUES ('ads.example.com', 'block', 1)"
        )
        db.commit()

    def test_funnel_present_when_unbound_serving(self, fresh_conn, monkeypatch):
        import app.services.pf_generator as pf
        monkeypatch.setattr(pf, "_unbound_lan_ready", lambda conn: True)
        self._activate_policy(fresh_conn)
        try:
            conf = pf.generate_pf_conf(fresh_conn)
            assert "port 53 -> 192.168.1.1 port 53" in conf          # rdr funnel
            assert "Block LAN→WAN DNS" in conf                        # egress block
        finally:
            fresh_conn.execute("DELETE FROM filter_dns_rules")
            fresh_conn.commit()

    def test_funnel_suppressed_when_unbound_not_serving(self, fresh_conn, monkeypatch):
        import app.services.pf_generator as pf
        monkeypatch.setattr(pf, "_unbound_lan_ready", lambda conn: False)
        self._activate_policy(fresh_conn)
        try:
            conf = pf.generate_pf_conf(fresh_conn)
            assert "port 53 -> 192.168.1.1 port 53" not in conf       # rdr suppressed
            assert "fail-open" in conf                                # explanatory comment
            assert "Block LAN→WAN DNS" not in conf                    # egress block suppressed
        finally:
            fresh_conn.execute("DELETE FROM filter_dns_rules")
            fresh_conn.commit()

    # ── P.3: DNS-force is independent of the captive portal; DoT is blocked ────

    def test_content_policy_only_forces_dns_to_unbound(self, fresh_conn, monkeypatch):
        # Captive portal explicitly OFF, content policy ON → the port-53 rdr to
        # Unbound (lan_ip) must still be present in the MAIN ruleset.
        import app.services.pf_generator as pf
        monkeypatch.setattr(pf, "_unbound_lan_ready", lambda conn: True)
        self._activate_policy(fresh_conn)
        import json
        fresh_conn.execute(
            "INSERT OR REPLACE INTO service_state (key_name, value_json) VALUES "
            "('captive_portal_settings', ?)",
            (json.dumps({"enabled": False}),),
        )
        fresh_conn.commit()
        try:
            conf = pf.generate_pf_conf(fresh_conn)
            assert "rdr on em1 proto udp from 192.168.1.0/24 to ! 192.168.1.1 port 53 -> 192.168.1.1 port 53" in conf
        finally:
            fresh_conn.execute("DELETE FROM filter_dns_rules")
            fresh_conn.execute("DELETE FROM service_state WHERE key_name='captive_portal_settings'")
            fresh_conn.commit()

    def test_dot_block_emitted_when_enabled(self, fresh_conn, monkeypatch):
        # block_dot defaults to block_known_doh (block by default) → DoT/DoQ 853
        # egress block present, with the dns_policy exemptions ahead of it.
        import app.services.pf_generator as pf
        monkeypatch.setattr(pf, "_unbound_lan_ready", lambda conn: True)
        self._activate_policy(fresh_conn)
        try:
            conf = pf.generate_pf_conf(fresh_conn)
            assert "smartshield:content_policy:dot_block" in conf
            assert "port 853" in conf
            # exemption pass must precede the block (PF 'quick' ordering)
            assert conf.index("dot_exempt") < conf.index("dot_block")
        finally:
            fresh_conn.execute("DELETE FROM filter_dns_rules")
            fresh_conn.commit()

    def test_dot_block_absent_when_disabled(self, fresh_conn, monkeypatch):
        import app.services.pf_generator as pf
        import json
        monkeypatch.setattr(pf, "_unbound_lan_ready", lambda conn: True)
        self._activate_policy(fresh_conn)
        fresh_conn.execute(
            "INSERT OR REPLACE INTO service_state (key_name, value_json) VALUES "
            "('content_policy_settings', ?)",
            (json.dumps({"block_dot": False}),),
        )
        fresh_conn.commit()
        try:
            conf = pf.generate_pf_conf(fresh_conn)
            assert "dot_block" not in conf
            assert "port 853" not in conf
            # the plain port-53 funnel is unaffected
            assert "port 53 -> 192.168.1.1 port 53" in conf
        finally:
            fresh_conn.execute("DELETE FROM filter_dns_rules")
            fresh_conn.execute("DELETE FROM service_state WHERE key_name='content_policy_settings'")
            fresh_conn.commit()
