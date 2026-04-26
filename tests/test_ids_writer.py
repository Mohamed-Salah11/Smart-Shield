"""
tests/test_ids_writer.py
------------------------
Unit tests for app/services/ids_writer.py.
No FreeBSD required.
"""
import os
import pytest

os.environ.setdefault("SMARTSHIELD_DB_PATH", "file:idstest?mode=memory&cache=shared")
os.environ.setdefault("SECRET_KEY", "test-ids-key")
os.environ.setdefault("SMARTSHIELD_MASTER_KEY",
    __import__("base64").b64encode(__import__("secrets").token_bytes(32)).decode())


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def conn():
    import secrets
    os.environ["SMARTSHIELD_DB_PATH"] = f"file:ids_{secrets.token_hex(4)}?mode=memory&cache=shared"
    from app.database import init_db, get_db
    init_db()
    db = get_db()
    yield db
    db.close()


# ---------------------------------------------------------------------------
# YAML generation
# ---------------------------------------------------------------------------

class TestGenerateSuricataYaml:

    def test_yaml_header(self, conn):
        from app.services.ids_writer import generate_suricata_yaml
        yaml = generate_suricata_yaml(conn)
        assert "%YAML 1.1" in yaml

    def test_ids_mode_uses_pcap(self, conn):
        from app.services.ids_writer import generate_suricata_yaml
        conn.execute("UPDATE ids_config SET mode='ids' WHERE id=1")
        conn.commit()
        yaml = generate_suricata_yaml(conn)
        assert "pcap:" in yaml

    def test_ips_mode_uses_netmap(self, conn):
        from app.services.ids_writer import generate_suricata_yaml
        conn.execute("UPDATE ids_config SET mode='ips', interface='em0' WHERE id=1")
        conn.commit()
        yaml = generate_suricata_yaml(conn)
        assert "netmap:" in yaml

    def test_home_net_in_yaml(self, conn):
        from app.services.ids_writer import generate_suricata_yaml
        conn.execute("UPDATE ids_config SET home_net='10.0.0.0/8' WHERE id=1")
        conn.commit()
        yaml = generate_suricata_yaml(conn)
        assert "10.0.0.0/8" in yaml

    def test_eve_log_present_when_enabled(self, conn):
        from app.services.ids_writer import generate_suricata_yaml
        conn.execute("UPDATE ids_config SET eve_json_enabled=1 WHERE id=1")
        conn.commit()
        yaml = generate_suricata_yaml(conn)
        assert "eve-log" in yaml

    def test_eve_log_absent_when_disabled(self, conn):
        from app.services.ids_writer import generate_suricata_yaml
        conn.execute("UPDATE ids_config SET eve_json_enabled=0 WHERE id=1")
        conn.commit()
        yaml = generate_suricata_yaml(conn)
        assert "eve-log" not in yaml

    def test_fast_log_present_when_enabled(self, conn):
        from app.services.ids_writer import generate_suricata_yaml
        conn.execute("UPDATE ids_config SET fast_log_enabled=1 WHERE id=1")
        conn.commit()
        yaml = generate_suricata_yaml(conn)
        assert "fast.log" in yaml

    def test_default_ruleset_when_none_active(self, conn):
        from app.services.ids_writer import generate_suricata_yaml
        conn.execute("UPDATE ids_rulesets SET enabled=0")
        conn.commit()
        yaml = generate_suricata_yaml(conn)
        assert "emerging-threats.rules" in yaml

    def test_active_ruleset_appears(self, conn):
        from app.services.ids_writer import generate_suricata_yaml
        yaml = generate_suricata_yaml(conn)
        # Default DB seeds "Emerging Threats Open" ruleset as enabled
        assert "rule-files:" in yaml

    def test_max_pending_packets(self, conn):
        from app.services.ids_writer import generate_suricata_yaml
        conn.execute("UPDATE ids_config SET max_pending_packets=2048 WHERE id=1")
        conn.commit()
        yaml = generate_suricata_yaml(conn)
        assert "max-pending-packets: 2048" in yaml

    def test_inline_stream_in_ips_mode(self, conn):
        from app.services.ids_writer import generate_suricata_yaml
        conn.execute("UPDATE ids_config SET mode='ips' WHERE id=1")
        conn.commit()
        yaml = generate_suricata_yaml(conn)
        assert "inline: true" in yaml

    def test_inline_stream_false_in_ids_mode(self, conn):
        from app.services.ids_writer import generate_suricata_yaml
        conn.execute("UPDATE ids_config SET mode='ids' WHERE id=1")
        conn.commit()
        yaml = generate_suricata_yaml(conn)
        assert "inline: false" in yaml


# ---------------------------------------------------------------------------
# YAML validation (non-FreeBSD path)
# ---------------------------------------------------------------------------

class TestValidateSuricataYaml:

    def test_non_freebsd_always_skipped(self):
        from app.services.ids_writer import validate_suricata_yaml
        ok, msg = validate_suricata_yaml("anything")
        assert ok is True
        assert "skipped" in msg


# ---------------------------------------------------------------------------
# IPS safety check
# ---------------------------------------------------------------------------

class TestValidateIpsSafety:

    def test_no_interface_produces_error(self, conn):
        from app.services.ids_writer import validate_ips_safety
        conn.execute("UPDATE ids_config SET interface='' WHERE id=1")
        conn.commit()
        warnings = validate_ips_safety(conn)
        assert any("requires" in w.lower() for w in warnings)

    def test_interface_set_produces_only_informational_warning(self, conn):
        from app.services.ids_writer import validate_ips_safety
        conn.execute("UPDATE ids_config SET interface='em0' WHERE id=1")
        conn.commit()
        warnings = validate_ips_safety(conn)
        # Should produce only the netmap informational warning (not a hard "requires" error)
        hard = [w for w in warnings if "requires" in w.lower()]
        assert len(hard) == 0


# ---------------------------------------------------------------------------
# Status / toggle (non-FreeBSD)
# ---------------------------------------------------------------------------

class TestGetIdsStatus:

    def test_non_freebsd_returns_not_running(self):
        from app.services.ids_writer import get_ids_status
        status = get_ids_status()
        assert status["running"] is False
        assert status["ok"] is True


class TestToggleIds:

    def test_enable_non_freebsd(self, conn):
        from app.services.ids_writer import toggle_ids
        result = toggle_ids(conn, True)
        assert result["ok"] is True
        assert "non-FreeBSD" in result["message"] or "enabled" in result["message"]

    def test_disable_non_freebsd(self, conn):
        from app.services.ids_writer import toggle_ids
        result = toggle_ids(conn, False)
        assert result["ok"] is True

    def test_ips_mode_without_interface_blocked(self, conn):
        from app.services.ids_writer import toggle_ids
        conn.execute("UPDATE ids_config SET mode='ips', interface='' WHERE id=1")
        conn.commit()
        result = toggle_ids(conn, True)
        assert result["ok"] is False
        assert "interface" in result["message"].lower() or "requires" in result["message"].lower()


# ---------------------------------------------------------------------------
# write (dry-run)
# ---------------------------------------------------------------------------

class TestWriteSuricataConfig:

    def test_non_freebsd_returns_ok(self, conn):
        from app.services.ids_writer import write_suricata_config
        result = write_suricata_config(conn)
        assert result["ok"] is True
        assert "suricata.yaml" in result["conf"] or "YAML" in result["conf"]
