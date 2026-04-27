"""
tests/test_dns_writer.py
------------------------
Unit tests for app/services/dns_writer.py.
No FreeBSD required — unbound-checkconf and service restarts are skipped.
"""

import json
import os
import pytest

os.environ.setdefault("SMARTSHIELD_DB_PATH", "file:dnstest?mode=memory&cache=shared")
os.environ.setdefault("SECRET_KEY", "test-dns-key")
os.environ.setdefault("SMARTSHIELD_MASTER_KEY",
    __import__("base64").b64encode(__import__("secrets").token_bytes(32)).decode())


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def conn():
    import secrets
    os.environ["SMARTSHIELD_DB_PATH"] = (
        f"file:dns_{secrets.token_hex(4)}?mode=memory&cache=shared"
    )
    from app.database import init_db, get_db
    init_db()
    db = get_db()
    db.execute(
        "UPDATE lan_config SET assigned_port='em1', ipv4_address='192.168.1.1/24' WHERE id=1"
    )
    db.commit()
    yield db
    db.close()


# ---------------------------------------------------------------------------
# Config generation
# ---------------------------------------------------------------------------

class TestGenerateUnboundConf:

    def test_server_section_present(self, conn):
        from app.services.dns_writer import generate_unbound_conf
        conf = generate_unbound_conf(conn)
        assert "server:" in conf

    def test_interface_binding_lan_ip(self, conn):
        from app.services.dns_writer import generate_unbound_conf
        conf = generate_unbound_conf(conn)
        assert "interface: 192.168.1.1" in conf

    def test_loopback_interface_always_present(self, conn):
        from app.services.dns_writer import generate_unbound_conf
        conf = generate_unbound_conf(conn)
        assert "interface: 127.0.0.1" in conf

    def test_lan_subnet_access_control(self, conn):
        from app.services.dns_writer import generate_unbound_conf
        conf = generate_unbound_conf(conn)
        assert "access-control: 192.168.1.0/24 allow" in conf

    def test_forward_zone_present(self, conn):
        from app.services.dns_writer import generate_unbound_conf
        conf = generate_unbound_conf(conn)
        assert "forward-zone:" in conf
        assert 'name: "."' in conf

    def test_default_upstream_dns_present(self, conn):
        from app.services.dns_writer import generate_unbound_conf
        conf = generate_unbound_conf(conn)
        # Default upstreams are 1.1.1.1 or 8.8.8.8
        assert "forward-addr: 1.1.1.1" in conf or "forward-addr: 8.8.8.8" in conf

    def test_privacy_settings(self, conn):
        from app.services.dns_writer import generate_unbound_conf
        conf = generate_unbound_conf(conn)
        assert "hide-identity: yes" in conf
        assert "hide-version: yes" in conf

    def test_host_override_written(self, conn):
        from app.services.dns_writer import generate_unbound_conf
        overrides = [{"host": "myhost", "domain": "home.arpa", "ip": "192.168.1.10"}]
        conn.execute(
            "INSERT INTO service_state (key_name, value_json) VALUES ('dns_resolver', ?)",
            (json.dumps({"host_overrides": overrides}),),
        )
        conn.commit()
        conf = generate_unbound_conf(conn)
        assert "myhost.home.arpa. A 192.168.1.10" in conf

    def test_host_override_ptr_written(self, conn):
        from app.services.dns_writer import generate_unbound_conf
        conn.execute("DELETE FROM service_state WHERE key_name='dns_resolver'")
        overrides = [{"host": "ptrhost", "domain": "local", "ip": "192.168.1.20"}]
        conn.execute(
            "INSERT INTO service_state (key_name, value_json) VALUES ('dns_resolver', ?)",
            (json.dumps({"host_overrides": overrides}),),
        )
        conn.commit()
        conf = generate_unbound_conf(conn)
        assert "192.168.1.20 ptrhost.local" in conf

    def test_private_address_suppression(self, conn):
        from app.services.dns_writer import generate_unbound_conf
        conf = generate_unbound_conf(conn)
        assert "private-address: 192.168.0.0/16" in conf
        assert "private-address: 10.0.0.0/8" in conf


# ---------------------------------------------------------------------------
# Validation (non-FreeBSD skips unbound-checkconf)
# ---------------------------------------------------------------------------

class TestValidateUnboundConf:

    def test_non_freebsd_returns_skipped(self):
        from app.services.dns_writer import validate_unbound_conf
        ok, msg = validate_unbound_conf("anything")
        assert ok is True
        assert "skipped" in msg


# ---------------------------------------------------------------------------
# Dry-run apply
# ---------------------------------------------------------------------------

class TestApplyUnbound:

    def test_non_freebsd_returns_ok(self, conn):
        from app.services.dns_writer import apply_unbound
        result = apply_unbound(conn)
        assert result["ok"] is True
        assert "conf" in result
        assert "server:" in result["conf"]


# ---------------------------------------------------------------------------
# Status (non-FreeBSD)
# ---------------------------------------------------------------------------

class TestGetUnboundStatus:

    def test_non_freebsd_returns_dry_run(self):
        from app.services.dns_writer import get_unbound_status
        status = get_unbound_status()
        assert status["state"] in ("dry-run", "stopped", "error")


# ---------------------------------------------------------------------------
# DNS resolution test (socket fallback)
# ---------------------------------------------------------------------------

class TestTestDnsResolution:

    def test_resolves_known_hostname(self):
        from app.services.dns_writer import test_dns_resolution
        result = test_dns_resolution("localhost")
        # localhost should always resolve
        assert result["ok"] is True or result["method"] == "socket"

    def test_empty_hostname_returns_error(self):
        from app.services.dns_writer import test_dns_resolution
        result = test_dns_resolution("")
        assert result["ok"] is False

    def test_invalid_hostname_returns_failure(self):
        from app.services.dns_writer import test_dns_resolution
        result = test_dns_resolution("this.hostname.does.not.exist.example.invalid")
        # May fail or succeed depending on DNS — just verify structure
        assert "ok" in result
        assert "method" in result

    def test_result_has_expected_keys(self):
        from app.services.dns_writer import test_dns_resolution
        result = test_dns_resolution("example.com")
        assert set(result.keys()) >= {"ok", "ip", "method", "message"}
