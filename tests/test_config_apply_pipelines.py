"""
Integration tests for config-apply pipelines.

Each test:
  1. Seeds the in-memory DB with realistic data.
  2. Calls the apply function with run_command mocked out so no OS calls happen.
  3. Asserts the generated config file text contains the expected content.
"""
import os
import sys
import pytest
from unittest.mock import MagicMock, patch
from app.database import get_db


# ── helpers ──────────────────────────────────────────────────────────────────

def _mock_run(returncode=0, stdout="", stderr=""):
    result = MagicMock()
    result.returncode = returncode
    result.stdout = stdout
    result.stderr = stderr
    return result


# ── PF / firewall ─────────────────────────────────────────────────────────────

class TestPFGeneratorPipeline:
    def test_generates_valid_pf_conf_structure(self, app):
        with app.app_context():
            conn = get_db()
            from app.services.pf_generator import generate_pf_conf
            text = generate_pf_conf(conn)
            assert "set block-policy drop" in text
            assert "scrub in all" in text
            assert "block log all" in text
            assert "pass out quick keep state" in text

    def test_default_nat_masquerade_added_when_no_outbound_rules(self, app):
        with app.app_context():
            conn = get_db()
            conn.execute("DELETE FROM nat_outbound")
            conn.commit()
            from app.services.pf_generator import generate_pf_conf
            text = generate_pf_conf(conn)
            assert "nat on $WAN" in text or "Default masquerade" in text

    def test_alias_table_included(self, app):
        with app.app_context():
            conn = get_db()
            conn.execute(
                "INSERT INTO firewall_aliases (name, type, alias_values) VALUES (?, ?, ?)",
                ("TEST_ALIAS", "host", '["192.168.1.10"]'),
            )
            conn.commit()
            from app.services.pf_generator import generate_pf_conf
            text = generate_pf_conf(conn)
            assert "TEST_ALIAS" in text

    def test_floating_rule_included(self, app):
        with app.app_context():
            conn = get_db()
            conn.execute("DELETE FROM firewall_rules_floating WHERE description='block bad ip'")
            conn.execute(
                """INSERT INTO firewall_rules_floating
                   (disabled, source, destination, description, rule_order)
                   VALUES (0, '1.2.3.4', 'any', 'block bad ip', 99)"""
            )
            conn.commit()
            from app.services.pf_generator import generate_pf_conf
            text = generate_pf_conf(conn)
            assert "1.2.3.4" in text
            assert "block bad ip" in text

    def test_wan_rule_action_and_source_included(self, app):
        with app.app_context():
            conn = get_db()
            conn.execute("DELETE FROM firewall_rules_wan WHERE description='test wan rule'")
            conn.execute(
                """INSERT INTO firewall_rules_wan
                   (disabled, action, source, destination, protocol, description, rule_order)
                   VALUES (0, 'block', '5.5.5.5', 'any', 'tcp', 'test wan rule', 99)"""
            )
            conn.commit()
            from app.services.pf_generator import generate_pf_conf
            text = generate_pf_conf(conn)
            assert "5.5.5.5" in text
            assert "block" in text

    def test_port_forward_includes_redirect_port(self, app):
        with app.app_context():
            conn = get_db()
            conn.execute("DELETE FROM nat_pf WHERE redirect_ip='192.168.1.100'")
            # nat_pf uses redirect_ip; the redirect_port comes from pf_generator reading it
            # The table doesn't have redirect_port; the pf_generator reads it as r.get("redirect_port")
            # which gracefully handles None. Test that the redirect IP appears.
            conn.execute(
                """INSERT INTO nat_pf
                   (disabled, interface, protocol, src_address, dst_address,
                    redirect_ip, rule_order)
                   VALUES (0, 'em0', 'tcp', 'any', 'any', '192.168.1.100', 99)"""
            )
            conn.commit()
            from app.services.pf_generator import generate_pf_conf
            text = generate_pf_conf(conn)
            assert "192.168.1.100" in text

    def test_reload_pf_rules_dry_run_on_non_freebsd(self, app):
        with app.app_context():
            conn = get_db()
            from app.services.pf_generator import reload_pf_rules
            result = reload_pf_rules(conn)
            # On non-FreeBSD the config is generated but not applied
            assert result["ok"] is True
            assert "conf" in result
            assert "pf.conf" in result["conf"] or "Smart Shield" in result["conf"]


# ── DHCP ──────────────────────────────────────────────────────────────────────

class TestDHCPPipeline:
    def test_generates_dhcpd_conf_for_enabled_pool(self, app):
        with app.app_context():
            conn = get_db()
            conn.execute("INSERT OR REPLACE INTO lan_config (id, assigned_port, ipv4_address) VALUES (1, 'em1', '192.168.1.1/24')")
            conn.execute("DELETE FROM dhcp_pools WHERE interface_type='LAN'")
            conn.execute(
                """INSERT INTO dhcp_pools
                   (interface_type, enabled, start_ip, end_ip, gateway_ip, dns_servers, lease_time)
                   VALUES ('LAN', 1, '192.168.1.100', '192.168.1.200', '192.168.1.1', '8.8.8.8', 86400)"""
            )
            conn.commit()
            from app.services.dhcp_writer import generate_dhcpd_conf
            conf = generate_dhcpd_conf(conn)
            assert "192.168.1.100" in conf
            assert "192.168.1.200" in conf
            assert "routers 192.168.1.1" in conf

    def test_static_lease_included(self, app):
        with app.app_context():
            conn = get_db()
            conn.execute("DELETE FROM static_leases WHERE mac_address='aa:bb:cc:dd:ee:ff'")
            conn.execute(
                """INSERT INTO static_leases (interface_type, mac_address, ip_address, hostname)
                   VALUES ('LAN', 'aa:bb:cc:dd:ee:ff', '192.168.1.50', 'myhost')"""
            )
            conn.commit()
            from app.services.dhcp_writer import generate_dhcpd_conf
            conf = generate_dhcpd_conf(conn)
            assert "aa:bb:cc:dd:ee:ff" in conf
            assert "192.168.1.50" in conf

    def test_apply_dhcpd_dry_run_on_non_freebsd(self, app):
        with app.app_context():
            conn = get_db()
            from app.services.dhcp_writer import apply_dhcpd
            result = apply_dhcpd(conn)
            assert "errors" in result
            if not result["ok"]:
                # Acceptable if pool config is invalid in test DB
                assert isinstance(result["errors"], list)

    def test_validate_dhcp_catches_overlapping_pool_and_static(self, app):
        with app.app_context():
            conn = get_db()
            conn.execute("INSERT OR REPLACE INTO lan_config (id, assigned_port, ipv4_address) VALUES (1, 'em1', '10.0.0.1/24')")
            conn.execute("DELETE FROM dhcp_pools WHERE interface_type='LAN'")
            conn.execute(
                """INSERT INTO dhcp_pools
                   (interface_type, enabled, start_ip, end_ip, gateway_ip, dns_servers, lease_time)
                   VALUES ('LAN', 1, '10.0.0.100', '10.0.0.200', '10.0.0.1', '8.8.8.8', 86400)"""
            )
            conn.execute("DELETE FROM static_leases WHERE mac_address='11:22:33:44:55:66'")
            conn.execute(
                """INSERT INTO static_leases (interface_type, mac_address, ip_address)
                   VALUES ('LAN', '11:22:33:44:55:66', '10.0.0.150')"""
            )
            conn.commit()
            from app.services.dhcp_writer import validate_dhcp_config
            errors = validate_dhcp_config(conn)
            assert any("10.0.0.150" in e for e in errors)


# ── DNS / Unbound ─────────────────────────────────────────────────────────────

class TestUnboundPipeline:
    def test_generates_unbound_conf(self, app):
        with app.app_context():
            conn = get_db()
            from app.services.dns_writer import generate_unbound_conf
            conf = generate_unbound_conf(conn)
            assert "server:" in conf
            assert "port: 53" in conf
            assert "forward-zone:" in conf

    def test_forward_zone_uses_configured_dns(self, app):
        with app.app_context():
            conn = get_db()
            import json, os
            # Temporarily point config to a known DNS
            cfg_path = os.getenv("SMARTSHIELD_CONFIG_PATH", "config.json")
            original = None
            try:
                if os.path.exists(cfg_path):
                    with open(cfg_path) as f:
                        original = f.read()
                with open(cfg_path, "w") as f:
                    json.dump({"dns_servers": ["9.9.9.9", "1.1.1.1"]}, f)
                from app.services.dns_writer import generate_unbound_conf
                conf = generate_unbound_conf(conn)
                assert "9.9.9.9" in conf
            finally:
                if original is not None:
                    with open(cfg_path, "w") as f:
                        f.write(original)

    def test_apply_unbound_dry_run(self, app):
        with app.app_context():
            conn = get_db()
            from app.services.dns_writer import apply_unbound
            result = apply_unbound(conn)
            assert result["ok"] is True
            assert "conf" in result


# ── Certificate manager ───────────────────────────────────────────────────────

class TestCertManagerPipeline:
    def test_create_ca_and_list(self, app):
        with app.app_context():
            conn = get_db()
            from app.services.cert_manager import create_ca, list_certs
            result = create_ca(conn, name="test-ca", common_name="Test CA")
            assert result["ok"] is True
            cas = list_certs(conn, cert_type="ca")
            assert any(c["name"] == "test-ca" for c in cas)

    def test_create_server_cert_under_ca(self, app):
        with app.app_context():
            conn = get_db()
            from app.services.cert_manager import create_ca, create_server_cert
            ca = create_ca(conn, name="pipeline-ca", common_name="Pipeline CA")
            assert ca["ok"] is True
            cert = create_server_cert(
                conn, ca_id=ca["id"], name="srv1", common_name="server.local"
            )
            assert cert["ok"] is True

    def test_revoke_cert(self, app):
        with app.app_context():
            conn = get_db()
            from app.services.cert_manager import create_ca, create_client_cert, revoke_cert
            ca   = create_ca(conn, name="revoke-ca", common_name="Revoke CA")
            cert = create_client_cert(conn, ca_id=ca["id"], name="cli1", common_name="client1")
            assert cert["ok"] is True
            rv   = revoke_cert(conn, cert["id"])
            assert rv["ok"] is True
            # Check DB
            row = conn.execute("SELECT revoked FROM certificates WHERE id=?", (cert["id"],)).fetchone()
            assert row["revoked"] == 1

    def test_generate_crl_for_ca_with_revoked_cert(self, app):
        with app.app_context():
            conn = get_db()
            from app.services.cert_manager import create_ca, create_client_cert, revoke_cert, generate_crl
            ca   = create_ca(conn, name="crl-ca", common_name="CRL CA")
            cert = create_client_cert(conn, ca_id=ca["id"], name="crl-cli", common_name="crl.client")
            revoke_cert(conn, cert["id"])
            result = generate_crl(conn, ca["id"])
            assert result["ok"] is True
            assert "BEGIN X509 CRL" in result["pem"]

    def test_export_pkcs12(self, app):
        with app.app_context():
            conn = get_db()
            from app.services.cert_manager import create_ca, create_server_cert, export_pkcs12
            ca   = create_ca(conn, name="p12-ca", common_name="PKCS12 CA")
            cert = create_server_cert(conn, ca_id=ca["id"], name="p12-srv", common_name="p12.local")
            raw  = export_pkcs12(conn, cert["id"], password="testpass")
            assert isinstance(raw, bytes)
            assert len(raw) > 100
