"""
tests/test_runtime_mode.py
--------------------------
Tests for ``app/services/runtime_mode.py``.

Phase 2.4 hardening: a world-readable smartshield.env is fatal in 'live'
mode (the file holds SECRET_KEY + SMARTSHIELD_MASTER_KEY) but only a warning
on dev / dry-run / degraded — those modes don't run on a hardened appliance.
"""
import os
import stat

import pytest

os.environ.setdefault("SMARTSHIELD_DB_PATH", "file:rmtest?mode=memory&cache=shared")
os.environ.setdefault("SECRET_KEY", "test-rm-key")
os.environ.setdefault("SMARTSHIELD_MASTER_KEY",
    __import__("base64").b64encode(__import__("secrets").token_bytes(32)).decode())


class _FakeStat:
    """Minimal stand-in for os.stat_result with just the bit we read."""
    def __init__(self, mode):
        self.st_mode = mode


class TestEnvFileWorldReadable:

    def test_returns_path_when_world_readable_on_freebsd(self, monkeypatch, tmp_path):
        import app.services.runtime_mode as rm
        env_path = str(tmp_path / "smartshield.env")
        with open(env_path, "w", encoding="utf-8") as fh:
            fh.write("SECRET_KEY=x\n")
        # Pretend we're on FreeBSD and the env dir resolves to tmp_path.
        monkeypatch.setattr(rm.sys, "platform", "freebsd14")
        monkeypatch.setattr("app.config._ss_dir",
                            lambda base: str(tmp_path))
        # The file actually exists; just lie about its mode so the test works
        # on Windows (where chmod is a no-op).
        monkeypatch.setattr(rm.os, "stat",
                            lambda p: _FakeStat(0o644))  # world-readable
        assert rm.env_file_world_readable() == env_path

    def test_returns_empty_when_mode_is_safe(self, monkeypatch, tmp_path):
        import app.services.runtime_mode as rm
        env_path = str(tmp_path / "smartshield.env")
        with open(env_path, "w", encoding="utf-8") as fh:
            fh.write("SECRET_KEY=x\n")
        monkeypatch.setattr(rm.sys, "platform", "freebsd14")
        monkeypatch.setattr("app.config._ss_dir",
                            lambda base: str(tmp_path))
        monkeypatch.setattr(rm.os, "stat",
                            lambda p: _FakeStat(0o600))  # owner-only
        assert rm.env_file_world_readable() == ""

    def test_off_freebsd_always_returns_empty(self, monkeypatch, tmp_path):
        # Dev machines run as the developer's user — the file may legitimately
        # be 0644 there. Never abort dev boots over this.
        import app.services.runtime_mode as rm
        monkeypatch.setattr(rm.sys, "platform", "win32")
        assert rm.env_file_world_readable() == ""


class TestAssertEnvFileSafe:

    def test_live_mode_with_world_readable_env_raises_systemexit(self, monkeypatch):
        import app.services.runtime_mode as rm
        monkeypatch.setattr(rm, "current_mode", lambda: "live")
        monkeypatch.setattr(rm, "env_file_world_readable",
                            lambda: "/usr/local/etc/smartshield/smartshield.env")
        with pytest.raises(SystemExit) as excinfo:
            rm.assert_env_file_safe()
        assert excinfo.value.code == 78  # EX_CONFIG

    def test_dry_run_mode_with_world_readable_env_does_not_abort(self, monkeypatch):
        import app.services.runtime_mode as rm
        monkeypatch.setattr(rm, "current_mode", lambda: "dry-run")
        monkeypatch.setattr(rm, "env_file_world_readable",
                            lambda: "/usr/local/etc/smartshield/smartshield.env")
        # Must not raise — dev/dry-run keep booting with a warning only.
        rm.assert_env_file_safe()

    def test_development_mode_does_not_abort(self, monkeypatch):
        import app.services.runtime_mode as rm
        monkeypatch.setattr(rm, "current_mode", lambda: "development")
        monkeypatch.setattr(rm, "env_file_world_readable",
                            lambda: "/some/path")
        rm.assert_env_file_safe()

    def test_degraded_mode_does_not_abort(self, monkeypatch):
        import app.services.runtime_mode as rm
        monkeypatch.setattr(rm, "current_mode", lambda: "degraded")
        monkeypatch.setattr(rm, "env_file_world_readable",
                            lambda: "/some/path")
        rm.assert_env_file_safe()

    def test_live_mode_with_safe_perms_does_not_abort(self, monkeypatch):
        import app.services.runtime_mode as rm
        monkeypatch.setattr(rm, "current_mode", lambda: "live")
        monkeypatch.setattr(rm, "env_file_world_readable", lambda: "")
        rm.assert_env_file_safe()
