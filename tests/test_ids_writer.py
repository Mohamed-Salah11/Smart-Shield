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
        import os
        from app.services.ids_writer import generate_suricata_yaml, _SURICATA_UPDATE_RULES
        conn.execute("UPDATE ids_rulesets SET enabled=0")
        conn.commit()
        yaml = generate_suricata_yaml(conn)
        # When no rulesets are active, the writer falls back to the suricata-update
        # managed combined rule file. Rule files are emitted RELATIVE to
        # default-rule-path (see test_yaml_uses_default_rule_path), so assert the
        # bare basename appears under that path — not the absolute path.
        rules_dir  = os.path.dirname(_SURICATA_UPDATE_RULES)
        rules_base = os.path.basename(_SURICATA_UPDATE_RULES)
        assert f"default-rule-path: {rules_dir}" in yaml
        assert f"- {rules_base}" in yaml

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
        safety = validate_ips_safety(conn)
        # Missing interface is a hard error → not safe to proceed.
        assert safety["ok"] is False
        assert any("interface" in e.lower() for e in safety["errors"])

    def test_interface_set_produces_only_informational_warning(self, conn):
        from app.services.ids_writer import validate_ips_safety
        conn.execute("UPDATE ids_config SET interface='em0' WHERE id=1")
        conn.commit()
        safety = validate_ips_safety(conn)
        # On non-FreeBSD with an interface set: no hard errors, just an
        # informational netmap warning.
        assert safety["ok"] is True
        assert safety["errors"] == []
        assert len(safety["warnings"]) >= 1


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


# ---------------------------------------------------------------------------
# Rule path layout — default-rule-path + relative rule files
# ---------------------------------------------------------------------------

class TestRulePathLayout:

    def test_yaml_uses_default_rule_path(self, conn):
        from app.services.ids_writer import generate_suricata_yaml
        yaml = generate_suricata_yaml(conn)
        assert "default-rule-path: /var/lib/suricata/rules" in yaml
        # Merged file should appear as a bare name, not the absolute path.
        assert "- suricata.rules" in yaml
        assert "- /var/lib/suricata/rules/suricata.rules" not in yaml


# ---------------------------------------------------------------------------
# LAN interface fallback inside generate_suricata_yaml
# The IDS monitors the LAN side by default: explicit ids_config.interface wins,
# else the configured LAN port (lan_config.assigned_port), else "em1".
# ---------------------------------------------------------------------------

class TestLanInterfaceFallback:

    def test_explicit_interface_wins(self, conn):
        from app.services.ids_writer import generate_suricata_yaml
        conn.execute("UPDATE ids_config SET interface='em3' WHERE id=1")
        conn.execute("UPDATE lan_config SET assigned_port='em2' WHERE id=1")
        conn.commit()
        yaml = generate_suricata_yaml(conn)
        assert "interface: em3" in yaml

    def test_lan_fallback_when_interface_blank(self, conn):
        from app.services.ids_writer import generate_suricata_yaml
        conn.execute("UPDATE ids_config SET interface='' WHERE id=1")
        conn.execute("INSERT OR IGNORE INTO lan_config (id) VALUES (1)")
        # Use a non-default port so this verifies the lan_config lookup, not the
        # hardcoded "em1" last-resort default.
        conn.execute("UPDATE lan_config SET assigned_port='em2' WHERE id=1")
        conn.commit()
        yaml = generate_suricata_yaml(conn)
        assert "interface: em2" in yaml

    def test_em1_default_when_nothing_set(self, conn):
        from app.services.ids_writer import generate_suricata_yaml
        conn.execute("UPDATE ids_config SET interface='' WHERE id=1")
        # No usable LAN port → fall back to the LAN default "em1".
        conn.execute("INSERT OR IGNORE INTO lan_config (id) VALUES (1)")
        conn.execute("UPDATE lan_config SET assigned_port='' WHERE id=1")
        conn.commit()
        yaml = generate_suricata_yaml(conn)
        assert "interface: em1" in yaml


# ---------------------------------------------------------------------------
# HOME_NET derivation from the LAN subnet
# ---------------------------------------------------------------------------

class TestHomeNetDerivation:

    def test_derives_from_lan_subnet_when_unset(self, conn):
        from app.services.ids_writer import generate_suricata_yaml
        conn.execute("UPDATE ids_config SET home_net='' WHERE id=1")
        conn.execute("UPDATE lan_config SET ipv4_address='192.168.50.1/24' WHERE id=1")
        conn.commit()
        yaml = generate_suricata_yaml(conn)
        assert "192.168.50.0/24" in yaml

    def test_explicit_home_net_wins(self, conn):
        from app.services.ids_writer import generate_suricata_yaml
        conn.execute("UPDATE ids_config SET home_net='10.0.0.0/8' WHERE id=1")
        conn.execute("UPDATE lan_config SET ipv4_address='192.168.50.1/24' WHERE id=1")
        conn.commit()
        yaml = generate_suricata_yaml(conn)
        assert "10.0.0.0/8" in yaml
        assert "192.168.50.0/24" not in yaml

    def test_falls_back_to_broad_range_when_no_lan_address(self, conn):
        from app.services.ids_writer import generate_suricata_yaml
        conn.execute("UPDATE ids_config SET home_net='' WHERE id=1")
        conn.execute("UPDATE lan_config SET ipv4_address='' WHERE id=1")
        conn.commit()
        yaml = generate_suricata_yaml(conn)
        assert "192.168.0.0/16" in yaml


# ---------------------------------------------------------------------------
# update_rules — --output flag, timeouts, post-check, placeholder restore
# ---------------------------------------------------------------------------

class _RunCommandRecorder:
    """Captures every run_command call so tests can assert argv + timeouts."""
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.calls = []
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr

    def __call__(self, cmd, check=True, timeout_seconds=20, _audit=True):
        self.calls.append({"cmd": list(cmd), "timeout_seconds": timeout_seconds})
        class _R:
            pass
        r = _R()
        r.returncode = self.returncode
        r.stdout = self.stdout
        r.stderr = self.stderr
        return r


def _force_freebsd(monkeypatch):
    """Make sys.platform.startswith('freebsd') true for the writer module."""
    import app.services.ids_writer as iw
    monkeypatch.setattr(iw.sys, "platform", "freebsd13", raising=False)


class TestUpdateRules:

    def test_uses_output_flag_and_300s_timeout(self, conn, monkeypatch, tmp_path):
        import app.services.ids_writer as iw
        _force_freebsd(monkeypatch)
        rules_path = tmp_path / "rules" / "suricata.rules"
        rules_path.parent.mkdir(parents=True, exist_ok=True)
        rules_path.write_text("alert ip any any -> any any (sid:1;)\n")
        monkeypatch.setattr(iw, "_SURICATA_UPDATE_RULES", str(rules_path))
        monkeypatch.setattr(iw, "_find_suricata_update", lambda: "/fake/suricata-update")
        rec = _RunCommandRecorder(returncode=0)
        monkeypatch.setattr(iw, "run_command", rec)
        # ensure_rules_file is a no-op since the tmp path already exists.

        result = iw.update_rules(conn)

        # Main run must include --output <dir> and use the 300s ceiling.
        main = [c for c in rec.calls if "--output" in c["cmd"]]
        assert main, f"--output not passed; calls: {rec.calls}"
        assert main[0]["cmd"][1] == "--output"
        assert main[0]["cmd"][2] == str(rules_path.parent)
        assert main[0]["timeout_seconds"] == 300
        assert result["ok"] is True
        assert result["rules_path"] == str(rules_path)
        assert result["rules_size"] > 0

    def test_update_sources_uses_180s_timeout(self, conn, monkeypatch, tmp_path):
        import app.services.ids_writer as iw
        _force_freebsd(monkeypatch)
        rules_path = tmp_path / "rules" / "suricata.rules"
        rules_path.parent.mkdir(parents=True, exist_ok=True)
        rules_path.touch()
        monkeypatch.setattr(iw, "_SURICATA_UPDATE_RULES", str(rules_path))
        monkeypatch.setattr(iw, "_find_suricata_update", lambda: "/fake/suricata-update")
        rec = _RunCommandRecorder(returncode=0)
        monkeypatch.setattr(iw, "run_command", rec)

        iw.update_rules(conn)

        srcs = [c for c in rec.calls if "update-sources" in c["cmd"]]
        assert srcs, f"update-sources not invoked; calls: {rec.calls}"
        assert srcs[0]["timeout_seconds"] == 180

    def test_restores_placeholder_after_failure(self, conn, monkeypatch, tmp_path):
        import app.services.ids_writer as iw
        _force_freebsd(monkeypatch)
        rules_path = tmp_path / "rules" / "suricata.rules"
        rules_path.parent.mkdir(parents=True, exist_ok=True)
        # Start with no file — simulates a failed prior run.
        assert not rules_path.exists()
        monkeypatch.setattr(iw, "_SURICATA_UPDATE_RULES", str(rules_path))
        monkeypatch.setattr(iw, "_find_suricata_update", lambda: "/fake/suricata-update")
        rec = _RunCommandRecorder(returncode=1, stderr="boom")
        monkeypatch.setattr(iw, "run_command", rec)

        result = iw.update_rules(conn)

        assert result["ok"] is False
        # ensure_rules_file() must have re-created the empty placeholder.
        assert rules_path.exists()


# ---------------------------------------------------------------------------
# apply_ids — same ordering as the GUI enable path
# ---------------------------------------------------------------------------

class TestApplyIds:

    def test_skipped_when_disabled(self, conn, monkeypatch):
        import app.services.ids_writer as iw
        conn.execute("UPDATE ids_config SET enabled=0 WHERE id=1")
        conn.commit()
        called = {"restart": False}
        def _no_restart(*_a, **_k):
            called["restart"] = True
            return {"ok": True, "message": ""}
        monkeypatch.setattr(iw, "service_action", _no_restart)

        result = iw.apply_ids(conn)

        assert result["ok"] is True
        assert "disabled" in result["message"].lower() or "skipped" in result["message"].lower()
        assert called["restart"] is False

    def test_runs_rules_then_write_then_restart_when_enabled(self, conn, monkeypatch):
        import app.services.ids_writer as iw
        conn.execute("UPDATE ids_config SET enabled=1 WHERE id=1")
        conn.commit()
        order = []
        monkeypatch.setattr(iw, "ensure_rules_present",
                            lambda _c: (order.append("rules"),
                                        {"ok": True, "message": ""})[1])
        monkeypatch.setattr(iw, "write_suricata_config",
                            lambda _c: (order.append("write"),
                                        {"ok": True, "message": "", "conf": ""})[1])
        monkeypatch.setattr(iw, "service_action",
                            lambda *_a, **_k: (order.append("restart"),
                                               {"ok": True, "message": "ok"})[1])

        result = iw.apply_ids(conn)

        assert order == ["rules", "write", "restart"]
        assert result["ok"] is True

    def test_bails_when_rule_bootstrap_fails(self, conn, monkeypatch):
        import app.services.ids_writer as iw
        conn.execute("UPDATE ids_config SET enabled=1 WHERE id=1")
        conn.commit()
        monkeypatch.setattr(iw, "ensure_rules_present",
                            lambda _c: {"ok": False, "message": "cannot create"})
        called = {"write": False, "restart": False}
        monkeypatch.setattr(iw, "write_suricata_config",
                            lambda _c: called.__setitem__("write", True) or {"ok": True, "message": "", "conf": ""})
        monkeypatch.setattr(iw, "service_action",
                            lambda *_a, **_k: called.__setitem__("restart", True) or {"ok": True, "message": ""})

        result = iw.apply_ids(conn)

        assert result["ok"] is False
        assert called["write"] is False
        assert called["restart"] is False


# ---------------------------------------------------------------------------
# Phase tracker
# ---------------------------------------------------------------------------

class TestPhaseTracker:

    def test_set_phase_updates_snapshot(self):
        from app.services.ids_writer import _set_phase, get_ids_phase
        _set_phase("STOPPED")
        _set_phase("UPDATING_RULES")
        snap = get_ids_phase()
        assert snap["phase"] == "UPDATING_RULES"
        assert snap["error"] is None

    def test_set_phase_records_error(self):
        from app.services.ids_writer import _set_phase, get_ids_phase
        _set_phase("ERROR", "boom")
        snap = get_ids_phase()
        assert snap["phase"] == "ERROR"
        assert snap["error"] == "boom"

    def test_set_phase_rejects_unknown(self):
        from app.services.ids_writer import _set_phase, get_ids_phase
        _set_phase("RUNNING")
        before = get_ids_phase()["phase"]
        _set_phase("BOGUS_PHASE")
        assert get_ids_phase()["phase"] == before  # unchanged

    def test_toggle_emits_phase_in_response(self, conn):
        from app.services.ids_writer import toggle_ids
        result = toggle_ids(conn, True)
        # Non-FreeBSD short-circuit: phase should still be present in result.
        assert "phase" in result
        assert result["phase"] in ("RUNNING", "STOPPED")

    def test_toggle_ips_failure_sets_error_phase(self, conn):
        """An IPS toggle that can't find an interface drives phase=ERROR."""
        from app.services.ids_writer import toggle_ids, get_ids_phase, _set_phase
        _set_phase("STOPPED")  # reset
        conn.execute("UPDATE ids_config SET mode='ips', interface='' WHERE id=1")
        conn.commit()
        result = toggle_ids(conn, True)
        assert result["ok"] is False
        assert result["phase"] == "ERROR"
        assert get_ids_phase()["phase"] == "ERROR"
        assert get_ids_phase()["error"]  # non-empty


# ---------------------------------------------------------------------------
# Netmap auto-load on IPS Enable (the screenshot bug fix)
# ---------------------------------------------------------------------------

class _FakeResult:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class TestEnsureNetmapLoaded:

    def test_short_circuits_when_already_loaded(self, monkeypatch):
        """If kldstat already reports netmap loaded, don't call kldload."""
        import app.services.ids_writer as iw
        # Force the FreeBSD branch even on dev hosts so we exercise the path.
        monkeypatch.setattr(iw.sys, "platform", "freebsd14")
        monkeypatch.setattr(iw, "_kldstat_netmap_loaded", lambda: True)
        called = {"kldload": False, "persist": False}

        def _no_kldload(*a, **k):
            called["kldload"] = True
            raise AssertionError("kldload should not be called when already loaded")

        def _persist_stub():
            called["persist"] = True
            return {"ok": True, "warning": ""}

        # Patch the priv_helper import in the helper.
        import app.services.priv_helper as ph
        monkeypatch.setattr(ph, "run_privileged", _no_kldload)
        monkeypatch.setattr(iw, "_persist_netmap_load_yes", _persist_stub)

        result = iw._ensure_netmap_loaded(None)
        assert result["ok"] is True
        assert called["kldload"] is False
        assert called["persist"] is True

    def test_auto_loads_when_missing(self, monkeypatch):
        """kldstat reports missing first, then loaded after kldload — ok=True."""
        import app.services.ids_writer as iw
        monkeypatch.setattr(iw.sys, "platform", "freebsd14")
        loaded_calls = iter([False, True])  # before kldload, after kldload
        monkeypatch.setattr(iw, "_kldstat_netmap_loaded",
                            lambda: next(loaded_calls))
        kldload_args = {}

        def _fake_run_priv(name, **kw):
            kldload_args["name"] = name
            kldload_args["kw"] = kw
            return _FakeResult(returncode=0, stdout="")

        import app.services.priv_helper as ph
        monkeypatch.setattr(ph, "run_privileged", _fake_run_priv)
        monkeypatch.setattr(iw, "_persist_netmap_load_yes",
                            lambda: {"ok": True, "warning": ""})

        result = iw._ensure_netmap_loaded(None)
        assert result["ok"] is True
        assert kldload_args["name"] == "kldload"
        assert kldload_args["kw"] == {"module": "netmap"}

    def test_hard_fails_when_kldload_still_misses(self, monkeypatch):
        """If kldstat STILL reports missing after kldload, return ok=False."""
        import app.services.ids_writer as iw
        monkeypatch.setattr(iw.sys, "platform", "freebsd14")
        monkeypatch.setattr(iw, "_kldstat_netmap_loaded", lambda: False)

        import app.services.priv_helper as ph
        monkeypatch.setattr(ph, "run_privileged",
                            lambda *a, **kw: _FakeResult(0, "", "no error but no load either"))
        monkeypatch.setattr(iw, "_persist_netmap_load_yes",
                            lambda: {"ok": True, "warning": ""})

        result = iw._ensure_netmap_loaded(None)
        assert result["ok"] is False
        assert "netmap" in result["message"].lower()

    def test_propagates_priv_helper_exception(self, monkeypatch):
        """A PrivilegedActionError surfaces as ok=False with the error text."""
        import app.services.ids_writer as iw
        monkeypatch.setattr(iw.sys, "platform", "freebsd14")
        monkeypatch.setattr(iw, "_kldstat_netmap_loaded", lambda: False)

        import app.services.priv_helper as ph

        def _boom(*a, **kw):
            raise ph.PrivilegedActionError("kldload not in allowlist (test)")

        monkeypatch.setattr(ph, "run_privileged", _boom)
        result = iw._ensure_netmap_loaded(None)
        assert result["ok"] is False
        assert "kldload" in result["message"].lower() or "load" in result["message"].lower()

    def test_persist_warning_passes_through(self, monkeypatch):
        """Live-load works but loader.conf persist fails → ok=True with warning."""
        import app.services.ids_writer as iw
        monkeypatch.setattr(iw.sys, "platform", "freebsd14")
        loaded_calls = iter([False, True])
        monkeypatch.setattr(iw, "_kldstat_netmap_loaded",
                            lambda: next(loaded_calls))
        import app.services.priv_helper as ph
        monkeypatch.setattr(ph, "run_privileged",
                            lambda *a, **kw: _FakeResult(0, "", ""))
        monkeypatch.setattr(iw, "_persist_netmap_load_yes",
                            lambda: {"ok": False, "warning": "sysrc dropped on the floor"})

        result = iw._ensure_netmap_loaded(None)
        assert result["ok"] is True
        assert "sysrc dropped on the floor" in result["warning"]


class TestValidateIpsSafetyAutoLoad:

    def test_passes_when_ensure_netmap_succeeds(self, conn, monkeypatch):
        """validate_ips_safety uses _ensure_netmap_loaded — when it returns
        ok=True, no error rises even on FreeBSD."""
        import app.services.ids_writer as iw
        monkeypatch.setattr(iw.sys, "platform", "freebsd14")
        conn.execute("UPDATE ids_config SET mode='ips', interface='em0' WHERE id=1")
        conn.commit()
        monkeypatch.setattr(iw, "_ensure_netmap_loaded",
                            lambda _c: {"ok": True, "warning": "", "message": "ok"})

        safety = iw.validate_ips_safety(conn)
        assert safety["ok"] is True
        assert safety["errors"] == []

    def test_fails_when_ensure_netmap_errors(self, conn, monkeypatch):
        import app.services.ids_writer as iw
        monkeypatch.setattr(iw.sys, "platform", "freebsd14")
        conn.execute("UPDATE ids_config SET mode='ips', interface='em0' WHERE id=1")
        conn.commit()
        monkeypatch.setattr(iw, "_ensure_netmap_loaded",
                            lambda _c: {"ok": False, "warning": "",
                                        "message": "netmap.ko could not be loaded; IPS mode is unavailable."})

        safety = iw.validate_ips_safety(conn)
        assert safety["ok"] is False
        assert any("netmap" in e.lower() for e in safety["errors"])

    def test_persist_warning_is_warning_not_error(self, conn, monkeypatch):
        import app.services.ids_writer as iw
        monkeypatch.setattr(iw.sys, "platform", "freebsd14")
        conn.execute("UPDATE ids_config SET mode='ips', interface='em0' WHERE id=1")
        conn.commit()
        monkeypatch.setattr(iw, "_ensure_netmap_loaded",
                            lambda _c: {"ok": True,
                                        "warning": "loader.conf persist failed",
                                        "message": "ok"})

        safety = iw.validate_ips_safety(conn)
        assert safety["ok"] is True
        assert safety["errors"] == []
        assert any("loader.conf" in w for w in safety["warnings"])


# ---------------------------------------------------------------------------
# Signature counter
# ---------------------------------------------------------------------------

class TestCountSignatures:

    def test_counts_only_rule_actions(self, tmp_path, monkeypatch):
        import app.services.ids_writer as iw
        rules = tmp_path / "suricata.rules"
        rules.write_text(
            "# comment line — must be ignored\n"
            "alert tcp any any -> any any (msg:\"a\"; sid:1;)\n"
            "drop tcp any any -> any any (msg:\"b\"; sid:2;)\n"
            "reject tcp any any -> any any (msg:\"c\"; sid:3;)\n"
            "pass tcp any any -> any any (msg:\"d\"; sid:4;)\n"
            "include other.rules\n"            # non-action prefix → ignored
            "\n"                               # blank → ignored
            "alert tcp 2.3.4.5 any -> any any (msg:\"e\"; sid:5;)\n"
        )
        monkeypatch.setattr(iw, "_SURICATA_UPDATE_RULES", str(rules))
        assert iw._count_signatures() == 5

    def test_zero_when_file_missing(self, tmp_path, monkeypatch):
        import app.services.ids_writer as iw
        monkeypatch.setattr(iw, "_SURICATA_UPDATE_RULES",
                            str(tmp_path / "does-not-exist.rules"))
        assert iw._count_signatures() == 0


# ---------------------------------------------------------------------------
# Diagnostics snapshot
# ---------------------------------------------------------------------------

class TestGetDiagnostics:

    REQUIRED_KEYS = {
        "ok", "phase", "error", "last_phase_at", "last_success_at",
        "mode", "interface", "cfg_enabled", "running", "rc_enabled",
        "signatures_loaded", "rules_file", "rules_size",
        "config_path", "config_exists", "netmap_loaded", "log_tail",
    }

    def test_returns_stable_shape(self, conn):
        from app.services.ids_writer import get_diagnostics
        d = get_diagnostics(conn)
        assert set(d.keys()) >= self.REQUIRED_KEYS
        assert d["ok"] is True
        assert isinstance(d["log_tail"], list)
        assert d["mode"] in ("ids", "ips")

    def test_reflects_db_mode(self, conn):
        from app.services.ids_writer import get_diagnostics
        conn.execute("UPDATE ids_config SET mode='ips', interface='em7' WHERE id=1")
        conn.commit()
        d = get_diagnostics(conn)
        assert d["mode"] == "ips"
        assert d["interface"] == "em7"

    def test_signature_count_uses_helper(self, conn, tmp_path, monkeypatch):
        import app.services.ids_writer as iw
        rules = tmp_path / "suricata.rules"
        rules.write_text("alert tcp any any -> any any (sid:1;)\n")
        monkeypatch.setattr(iw, "_SURICATA_UPDATE_RULES", str(rules))
        d = iw.get_diagnostics(conn)
        assert d["signatures_loaded"] == 1
        assert d["rules_size"] > 0

    def test_no_conn_does_not_raise(self):
        from app.services.ids_writer import get_diagnostics
        d = get_diagnostics(None)
        assert d["ok"] is True
        # No conn means default mode reading falls through to "ids".
        assert d["mode"] == "ids"
