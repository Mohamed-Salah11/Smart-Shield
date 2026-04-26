"""
tests/test_phase5.py
--------------------
Unit tests for Phase 5: Production appliance hardening.

Covers:
- app.services.priv_helper     (allowlist + validation)
- app.services.config_history  (versioning + rollback)
- app.migrations               (formal migration runner)
- app.services.health_monitor  (disk/CPU/memory + service checks)
- app.app_log                  (structured operational logging)
- app.services.network_service (secret redaction)
- tools.build_release          (artifact checks helper)
"""

import hashlib
import json
import os
import sqlite3
import sys
import tempfile
from secrets import token_hex
from unittest.mock import patch

import pytest

# ── DB fixture ────────────────────────────────────────────────────────────────

@pytest.fixture
def db():
    """In-memory SQLite connection with the full Phase 5 schema."""
    token  = token_hex(4)
    uri    = f"file:p5_{token}?mode=memory&cache=shared"
    os.environ["SMARTSHIELD_DB_PATH"] = uri
    os.environ["SMARTSHIELD_NETWORK_DRY_RUN"] = "1"

    # Bootstrap the DB
    import importlib
    import app.database as dbmod
    importlib.reload(dbmod)
    conn = dbmod.get_db()
    dbmod.init_db()

    # Re-open after init
    conn2 = sqlite3.connect(uri, uri=True)
    conn2.execute("PRAGMA foreign_keys = ON")
    conn2.row_factory = sqlite3.Row
    yield conn2
    conn2.close()


# =============================================================================
# 1. Secret redaction in network_service
# =============================================================================

class TestSecretRedaction:
    def test_password_flag_redacted(self):
        from app.services.network_service import redact_command
        result = redact_command(["/usr/sbin/mpd5", "-p", "hunter2", "-f", "/etc/mpd.conf"])
        assert result[2] == "***"
        assert result[4] == "/etc/mpd.conf"

    def test_password_equals_form_redacted(self):
        from app.services.network_service import redact_command
        result = redact_command(["somebin", "--password=secret123"])
        assert "secret123" not in result[1]
        assert "***" in result[1]

    def test_non_secret_flag_not_redacted(self):
        from app.services.network_service import redact_command
        cmd = ["pfctl", "-f", "/etc/pf.conf"]
        assert redact_command(cmd) == cmd

    def test_empty_command(self):
        from app.services.network_service import redact_command
        assert redact_command([]) == []

    def test_key_flag_redacted(self):
        from app.services.network_service import redact_command
        result = redact_command(["wg", "set", "wg0", "--key", "SECRETKEY=="])
        assert result[4] == "***"

    def test_no_mutation_of_original(self):
        from app.services.network_service import redact_command
        original = ["cmd", "--password=abc"]
        _ = redact_command(original)
        assert original[1] == "--password=abc"


# =============================================================================
# 2. Privileged helper — allowlist and validation
# =============================================================================

class TestPrivHelper:
    def setup_method(self):
        os.environ["SMARTSHIELD_NETWORK_DRY_RUN"] = "1"

    def test_list_allowed_actions_nonempty(self):
        from app.services.priv_helper import list_allowed_actions
        actions = list_allowed_actions()
        assert len(actions) > 5
        assert "pf.reload" in actions
        assert "service.action" in actions

    def test_unknown_action_raises(self):
        from app.services.priv_helper import run_privileged, PrivilegedActionError
        with pytest.raises(PrivilegedActionError, match="not in the privileged allowlist"):
            run_privileged("rm.everything", config_path="/etc/pf.conf")

    def test_missing_param_raises(self):
        from app.services.priv_helper import run_privileged, PrivilegedActionError
        with pytest.raises(PrivilegedActionError, match="Missing required param"):
            run_privileged("pf.reload")  # config_path is required

    def test_bad_config_path_raises(self):
        from app.services.priv_helper import run_privileged, PrivilegedActionError
        with pytest.raises(PrivilegedActionError, match="Unsafe config path"):
            run_privileged("pf.reload", config_path="/tmp/evil; rm -rf /")

    def test_path_not_in_allowed_dirs_raises(self):
        from app.services.priv_helper import run_privileged, PrivilegedActionError
        with pytest.raises(PrivilegedActionError, match="not in allowed dirs"):
            run_privileged("pf.reload", config_path="/home/user/pf.conf")

    def test_valid_pf_reload_dry_run(self):
        from app.services.priv_helper import run_privileged
        result = run_privileged("pf.reload", config_path="/etc/pf.conf")
        assert result.returncode == 0

    def test_extra_params_rejected(self):
        from app.services.priv_helper import run_privileged, PrivilegedActionError
        with pytest.raises(PrivilegedActionError, match="Unexpected params"):
            run_privileged("pf.enable", evil_extra="boom")

    def test_invalid_service_name_raises(self):
        from app.services.priv_helper import run_privileged, PrivilegedActionError
        with pytest.raises(PrivilegedActionError, match="Unknown service name"):
            run_privileged("service.action", service_name="bash", action="start")

    def test_invalid_service_action_raises(self):
        from app.services.priv_helper import run_privileged, PrivilegedActionError
        with pytest.raises(PrivilegedActionError, match="Unknown service action"):
            run_privileged("service.action", service_name="unbound", action="--kill-all")

    def test_valid_service_action_dry_run(self):
        from app.services.priv_helper import run_privileged
        result = run_privileged("service.action", service_name="unbound", action="restart")
        assert result.returncode == 0

    def test_invalid_ip_for_table_add_raises(self):
        from app.services.priv_helper import run_privileged, PrivilegedActionError
        with pytest.raises(PrivilegedActionError, match="Invalid IP"):
            run_privileged("pf.table_add", table="authenticated_clients", ip="not-an-ip")

    def test_valid_table_add_dry_run(self):
        from app.services.priv_helper import run_privileged
        result = run_privileged(
            "pf.table_add", table="authenticated_clients", ip="192.168.1.50"
        )
        assert result.returncode == 0

    def test_sysrc_set_valid_dry_run(self):
        from app.services.priv_helper import run_privileged
        result = run_privileged("sysrc.set", key="ntpd_enable", value="YES")
        assert result.returncode == 0

    def test_sysrc_set_unsafe_value_raises(self):
        from app.services.priv_helper import run_privileged, PrivilegedActionError
        with pytest.raises(PrivilegedActionError):
            run_privileged("sysrc.set", key="ntpd_enable", value="YES; rm -rf /")


# =============================================================================
# 3. Config history
# =============================================================================

class TestConfigHistory:
    def test_save_and_list(self, db):
        from app.services.config_history import save_config_version, list_config_versions
        vid = save_config_version(
            db, "pf", "pass all\n",
            applied_by="admin", file_path="/etc/pf.conf",
            validation_ok=True, apply_ok=True,
        )
        assert isinstance(vid, int) and vid > 0
        versions = list_config_versions(db, "pf")
        assert len(versions) == 1
        assert versions[0]["id"] == vid
        assert "content" not in versions[0]  # content excluded from list

    def test_version_numbers_increment(self, db):
        from app.services.config_history import save_config_version, list_config_versions
        save_config_version(db, "pf", "v1 content", applied_by="a")
        save_config_version(db, "pf", "v2 content", applied_by="a")
        save_config_version(db, "pf", "v3 content", applied_by="a")
        versions = list_config_versions(db, "pf")
        nums = [v["version_num"] for v in versions]
        assert nums == [3, 2, 1]

    def test_get_version_includes_content(self, db):
        from app.services.config_history import save_config_version, get_config_version
        vid = save_config_version(db, "unbound", "server:\n  verbosity: 1\n", applied_by="sys")
        ver = get_config_version(db, vid)
        assert ver is not None
        assert ver["content"] == "server:\n  verbosity: 1\n"
        assert ver["service"] == "unbound"

    def test_get_missing_version_returns_none(self, db):
        from app.services.config_history import get_config_version
        assert get_config_version(db, 999999) is None

    def test_content_hash_stored(self, db):
        from app.services.config_history import save_config_version, get_config_version
        content = "pass all\nblock in\n"
        vid = save_config_version(db, "pf", content)
        ver = get_config_version(db, vid)
        expected = hashlib.sha256(content.encode()).hexdigest()
        assert ver["content_hash"] == expected

    def test_rollback_non_freebsd_returns_ok(self, db):
        from app.services.config_history import save_config_version, rollback_to_config_version
        vid = save_config_version(
            db, "pf", "pass all\n",
            file_path="/etc/pf.conf",
        )
        result = rollback_to_config_version(db, vid)
        assert result["ok"] is True
        assert result["version_id"] == vid

    def test_rollback_missing_version(self, db):
        from app.services.config_history import rollback_to_config_version
        result = rollback_to_config_version(db, 999999)
        assert result["ok"] is False

    def test_prune_keeps_recent(self, db):
        from app.services.config_history import save_config_version, prune_config_versions, list_config_versions
        for i in range(5):
            save_config_version(db, "dhcpd", f"config v{i}", applied_by="sys")
        deleted = prune_config_versions(db, "dhcpd", keep=3)
        assert deleted == 2
        remaining = list_config_versions(db, "dhcpd")
        assert len(remaining) == 3

    def test_list_all_services(self, db):
        from app.services.config_history import save_config_version, list_all_services_with_history
        save_config_version(db, "pf", "pf content")
        save_config_version(db, "unbound", "unbound content")
        svcs = list_all_services_with_history(db)
        names = {s["service"] for s in svcs}
        assert "pf" in names
        assert "unbound" in names


# =============================================================================
# 4. Migrations
# =============================================================================

class TestMigrations:
    def _fresh_conn(self):
        uri  = f"file:mig_{token_hex(4)}?mode=memory&cache=shared"
        conn = sqlite3.connect(uri, uri=True)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        # Create the schema_version table that init_db would normally create
        conn.execute("""
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()
        return conn

    def test_migrations_run_on_empty_db(self):
        from app.migrations import run_migrations, CURRENT_SCHEMA_VERSION
        conn    = self._fresh_conn()
        applied = run_migrations(conn)
        assert CURRENT_SCHEMA_VERSION in applied

    def test_migrations_idempotent(self):
        from app.migrations import run_migrations
        conn = self._fresh_conn()
        run_migrations(conn)
        applied2 = run_migrations(conn)
        assert applied2 == []  # no-op on second call

    def test_schema_version_newer_raises(self):
        from app.migrations import run_migrations, CURRENT_SCHEMA_VERSION, SchemaVersionError
        conn = self._fresh_conn()
        conn.execute(
            "INSERT INTO schema_version (version) VALUES (?)",
            (CURRENT_SCHEMA_VERSION + 10,),
        )
        conn.commit()
        with pytest.raises(SchemaVersionError):
            run_migrations(conn)

    def test_config_versions_table_created(self):
        from app.migrations import run_migrations
        conn = self._fresh_conn()
        run_migrations(conn)
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
        assert "config_versions" in tables
        assert "health_snapshots" in tables

    def test_current_version_constant(self):
        from app.migrations import CURRENT_SCHEMA_VERSION
        assert CURRENT_SCHEMA_VERSION >= 5


# =============================================================================
# 5. Health monitor
# =============================================================================

class TestHealthMonitor:
    def test_check_disk_usage_returns_list(self):
        from app.services.health_monitor import check_disk_usage
        result = check_disk_usage()
        assert "disks" in result
        # At least one disk (root or cwd) should be accessible
        # (may be empty on unusual CI environments)
        assert isinstance(result["disks"], list)

    def test_check_memory_cpu(self):
        from app.services.health_monitor import check_memory_cpu
        result = check_memory_cpu()
        assert "cpu_load_1" in result
        assert isinstance(result["cpu_load_1"], float)
        assert "memory_ok" in result

    def test_full_health_check_structure(self, db):
        from app.services.health_monitor import full_health_check
        snapshot = full_health_check(db)
        assert "timestamp" in snapshot
        assert "services" in snapshot
        assert "disk" in snapshot
        assert "system" in snapshot
        assert "overall_ok" in snapshot

    def test_store_and_retrieve_snapshot(self, db):
        from app.services.health_monitor import (
            full_health_check, store_health_snapshot,
            get_health_history, get_latest_health,
        )
        snapshot = full_health_check(db)
        sid      = store_health_snapshot(db, snapshot)
        assert isinstance(sid, int) and sid > 0

        history = get_health_history(db, limit=5)
        assert len(history) >= 1
        assert history[0]["id"] == sid

        latest = get_latest_health(db)
        assert latest["id"] == sid

    def test_prune_health_history(self, db):
        from app.services.health_monitor import (
            full_health_check, store_health_snapshot,
            get_health_history, prune_health_history,
        )
        snap = full_health_check(db)
        for _ in range(5):
            store_health_snapshot(db, snap)
        deleted = prune_health_history(db, keep=3)
        assert deleted == 2
        assert len(get_health_history(db)) == 3

    def test_check_all_services_has_pf(self, db):
        from app.services.health_monitor import check_all_services
        health = check_all_services(db)
        assert "pf" in health

    def test_config_drift_returns_dict(self, db):
        from app.services.health_monitor import check_all_services
        health = check_all_services(db)
        assert "config_drift" in health
        assert isinstance(health["config_drift"], dict)


# =============================================================================
# 6. App log
# =============================================================================

class TestAppLog:
    @pytest.fixture(autouse=True)
    def _tmp_log(self, tmp_path, monkeypatch):
        log_path = str(tmp_path / "app.log")
        monkeypatch.setenv("SMARTSHIELD_APP_LOG_PATH", log_path)
        # Reload module so it picks up the new env var
        import importlib, app.app_log as m
        importlib.reload(m)
        self._path = log_path
        yield

    def test_log_info_writes_entry(self):
        from app.app_log import log_info, tail_app_events
        log_info("test_comp", "hello world", {"x": 1})
        events = tail_app_events(limit=10)
        assert len(events) == 1
        assert events[0]["level"] == "INFO"
        assert events[0]["component"] == "test_comp"
        assert events[0]["message"] == "hello world"

    def test_log_warning(self):
        from app.app_log import log_warning, tail_app_events
        log_warning("test_comp", "careful!", {})
        events = tail_app_events()
        assert events[0]["level"] == "WARNING"

    def test_log_error(self):
        from app.app_log import log_error, tail_app_events
        log_error("test_comp", "oops", {})
        events = tail_app_events()
        assert events[0]["level"] == "ERROR"

    def test_secret_redaction(self):
        from app.app_log import log_info, tail_app_events
        log_info("auth", "Login attempt", {"username": "alice", "password": "s3cret"})
        events = tail_app_events()
        assert events[0]["details"]["password"] == "***"
        assert events[0]["details"]["username"] == "alice"

    def test_level_filter(self):
        from app.app_log import log_info, log_error, tail_app_events
        log_info("c", "info msg")
        log_error("c", "err msg")
        errors = tail_app_events(level="ERROR")
        assert all(e["level"] == "ERROR" for e in errors)
        assert len(errors) == 1

    def test_component_filter(self):
        from app.app_log import log_info, tail_app_events
        log_info("network_service", "msg1")
        log_info("pf_generator", "msg2")
        net_events = tail_app_events(component="network")
        assert all(e["component"].startswith("network") for e in net_events)

    def test_search_filter(self):
        from app.app_log import log_info, tail_app_events
        log_info("c", "pfctl reload failed")
        log_info("c", "unbound restarted")
        results = tail_app_events(search="pfctl")
        assert len(results) == 1

    def test_stats(self):
        from app.app_log import log_info, log_error, app_log_stats
        log_info("c", "x")
        log_error("c", "y")
        stats = app_log_stats()
        assert stats.get("INFO", 0) >= 1
        assert stats.get("ERROR", 0) >= 1

    def test_no_log_file_returns_empty(self):
        import importlib, app.app_log as m
        import os
        os.environ["SMARTSHIELD_APP_LOG_PATH"] = "/nonexistent/path/app.log"
        importlib.reload(m)
        events = m.tail_app_events()
        assert events == []


# =============================================================================
# 7. Build release (artifact check helper)
# =============================================================================

class TestBuildRelease:
    def test_excluded_patterns_match_env(self):
        import sys
        sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent / "tools"))
        from build_release import _is_excluded
        assert _is_excluded(".env")
        assert _is_excluded("data.db")
        assert _is_excluded("backups/old.tar.gz")
        assert _is_excluded("app/__pycache__/foo.cpython-311.pyc")
        assert _is_excluded(".venv/lib/python3.11/site-packages/flask/__init__.py")
        assert _is_excluded(".git/HEAD")
        assert _is_excluded("audit.log")

    def test_non_excluded_pass(self):
        import sys
        sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent / "tools"))
        from build_release import _is_excluded
        assert not _is_excluded("app/database.py")
        assert not _is_excluded("routes/status.py")
        assert not _is_excluded("README.md")
        assert not _is_excluded("requirements.txt")

    def test_build_creates_archive(self, tmp_path):
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))
        from build_release import build_release

        project_root = Path(__file__).parent.parent
        output_dir   = tmp_path / "dist"
        rc = build_release("test-1.0.0", project_root, output_dir)
        assert rc == 0
        archives = list(output_dir.glob("*.tar.gz"))
        assert len(archives) == 1
        sha256s = list(output_dir.glob("*.sha256"))
        assert len(sha256s) == 1

    def test_archive_contains_version_json(self, tmp_path):
        import sys, tarfile
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))
        from build_release import build_release

        project_root = Path(__file__).parent.parent
        output_dir   = tmp_path / "dist"
        build_release("test-0.0.1", project_root, output_dir)
        archive = list(output_dir.glob("*.tar.gz"))[0]
        with tarfile.open(archive, "r:gz") as tar:
            names = tar.getnames()
        assert any("version.json" in n for n in names)

    def test_archive_excludes_env(self, tmp_path):
        import sys, tarfile
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))
        from build_release import build_release

        project_root = Path(__file__).parent.parent
        output_dir   = tmp_path / "dist"
        build_release("test-0.0.2", project_root, output_dir)
        archive = list(output_dir.glob("*.tar.gz"))[0]
        with tarfile.open(archive, "r:gz") as tar:
            names = tar.getnames()
        for name in names:
            assert ".env" not in name or "example" in name
            assert "data.db" not in name
            assert "__pycache__" not in name
