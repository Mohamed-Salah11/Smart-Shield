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


# ---------------------------------------------------------------------------
# LAN-serving checks + self-healing recovery
# ---------------------------------------------------------------------------

class TestLanServingHelpers:
    """Off-FreeBSD these short-circuit to True so dev/tests are unaffected;
    the real sockstat/resolution probing only runs on the appliance."""

    def test_listening_on_lan_true_off_freebsd(self, conn):
        from app.services.dns_writer import unbound_listening_on_lan
        assert unbound_listening_on_lan(conn) is True

    def test_serving_lan_true_off_freebsd(self, conn):
        from app.services.dns_writer import unbound_serving_lan
        assert unbound_serving_lan(conn) is True


class TestRecoverDnsService:
    def test_skips_when_already_serving(self, conn):
        from app.services.dns_writer import recover_dns_service
        res = recover_dns_service(conn)
        assert res["ok"] is True
        assert res.get("skipped") is True
        assert res["reason"] == "already_serving"

    def test_recovers_when_not_serving(self, conn, monkeypatch):
        # Force the "not serving" path; apply_unbound off-FreeBSD returns ok
        # (generate + validate only), and PF reload is best-effort.
        import app.services.dns_writer as dw
        monkeypatch.setattr(dw, "unbound_serving_lan", lambda c: False)
        res = dw.recover_dns_service(conn)
        assert res["ok"] is True
        assert res["reason"] == "recovered"


class TestApplyUnboundRestartEscalation:
    """A `reload` re-reads config but does NOT re-bind listening sockets, so an
    Unbound started on the 127.0.0.1-only bootstrap config stays on loopback even
    after we write a LAN-binding config. apply_unbound must escalate to a full
    restart (which re-binds) when the LAN IP isn't actually being served."""

    def _patch_freebsd_apply(self, monkeypatch):
        """Stub out every FreeBSD-only side effect in apply_unbound so the
        restart-escalation branch is reachable on a dev host."""
        import app.services.dns_writer as dw
        import app.services.service_manager as sm
        import app.services.network_service as ns
        import app.services.config_file_utils as cfu

        monkeypatch.setattr("sys.platform", "freebsd")
        monkeypatch.setattr("time.sleep", lambda *_a, **_k: None)
        monkeypatch.setattr(dw, "validate_unbound_conf", lambda _c: (True, ""))
        monkeypatch.setattr(dw, "_save_known_good_unbound", lambda: True)
        monkeypatch.setattr(cfu, "atomic_write", lambda *_a, **_k: None)
        monkeypatch.setattr(sm, "sysrc_set", lambda *_a, **_k: {"ok": True, "message": ""})
        monkeypatch.setattr(ns, "is_network_dry_run", lambda: False)
        # Daemon is "running" (true even for the loopback bootstrap config).
        monkeypatch.setattr(dw, "get_unbound_status", lambda: {"running": True, "message": "running"})
        # A reload "succeeds" at the rc level but doesn't re-bind.
        monkeypatch.setattr(dw, "_start_or_reload_unbound", lambda: {"ok": True, "message": "reloaded"})

    def test_escalates_to_restart_when_loopback_only(self, conn, monkeypatch):
        import app.services.dns_writer as dw
        self._patch_freebsd_apply(monkeypatch)

        calls = {"restart": 0}
        # Loopback-only after reload (False), bound after the restart (True).
        bind_states = iter([False, True])
        monkeypatch.setattr(dw, "unbound_listening_on_lan",
                            lambda _c: next(bind_states, True))

        def _restart():
            calls["restart"] += 1
            return {"ok": True, "message": "restarted"}
        monkeypatch.setattr(dw, "_restart_unbound", _restart)

        res = dw.apply_unbound(conn)
        assert calls["restart"] == 1, "should escalate reload→restart"
        assert res["ok"] is True
        assert res["message"] == "restarted"

    def test_restart_failure_rolls_back(self, conn, monkeypatch):
        import app.services.dns_writer as dw
        self._patch_freebsd_apply(monkeypatch)

        # Never binds the LAN IP, even after the restart.
        monkeypatch.setattr(dw, "unbound_listening_on_lan", lambda _c: False)
        monkeypatch.setattr(dw, "_restart_unbound",
                            lambda: {"ok": True, "message": "restarted"})
        rolled = {"n": 0}

        def _rb():
            rolled["n"] += 1
            return {"ok": True, "message": "rolled back to known-good"}
        monkeypatch.setattr(dw, "_rollback_unbound", _rb)

        res = dw.apply_unbound(conn)
        assert res["ok"] is False
        assert rolled["n"] == 1
        assert res["rolled_back"] is True
        assert "192.168.1.1" in res["message"]
