"""
tests/integration/test_apply_state_pipeline.py
-----------------------------------------------
Integration tests for Phases 37/38: apply-state tracking and
config transaction manager pipeline.
"""

import os
import sqlite3
import sys
import pytest

os.environ.setdefault("SMARTSHIELD_DB_PATH", "file:inttest_apply?mode=memory&cache=shared")
os.environ.setdefault("SECRET_KEY", "apply-state-test-secret")
os.environ.setdefault("SMARTSHIELD_NETWORK_DRY_RUN", "1")


@pytest.fixture()
def db():
    """Isolated in-memory DB with the exact schema apply_state.py expects."""
    import secrets
    token = secrets.token_hex(4)
    conn = sqlite3.connect(
        f"file:as_{token}?mode=memory&cache=shared", uri=True
    )
    conn.row_factory = sqlite3.Row
    conn.executescript("""
        CREATE TABLE config_apply_jobs (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            feature_key  TEXT NOT NULL,
            state        TEXT NOT NULL DEFAULT 'saved',
            config_hash  TEXT DEFAULT '',
            applied_by   TEXT DEFAULT 'system',
            notes        TEXT DEFAULT '',
            message      TEXT DEFAULT '',
            created_at   REAL,
            updated_at   REAL
        );
        CREATE TABLE feature_applied_state (
            feature_key  TEXT PRIMARY KEY,
            state        TEXT NOT NULL DEFAULT 'unknown',
            message      TEXT DEFAULT '',
            last_job_id  INTEGER,
            updated_at   REAL
        );
    """)
    conn.commit()
    yield conn
    conn.close()


# ---------------------------------------------------------------------------
# apply_state module
# ---------------------------------------------------------------------------

class TestApplyStateLifecycle:
    def test_record_save_sets_status_saved(self, db):
        from app.services.apply_state import record_save, get_feature_state
        record_save(db, "pf_firewall", applied_by="admin")
        state = get_feature_state(db, "pf_firewall")
        assert state is not None
        assert state["state"] == "saved"
        assert state["color"] == "blue"

    def test_record_apply_success_sets_applied(self, db):
        from app.services.apply_state import (
            record_apply_start, record_apply_result, get_feature_state,
        )
        job_id = record_apply_start(db, "dns_resolver", applied_by="system")
        assert isinstance(job_id, int) and job_id > 0
        record_apply_result(db, job_id, ok=True, message="OK")
        state = get_feature_state(db, "dns_resolver")
        assert state["state"] == "applied"
        assert state["color"] == "green"

    def test_record_apply_failure_sets_failed(self, db):
        from app.services.apply_state import (
            record_apply_start, record_apply_result, get_feature_state,
        )
        job_id = record_apply_start(db, "dhcpv4", applied_by="admin")
        record_apply_result(db, job_id, ok=False, message="dhcpd syntax error")
        state = get_feature_state(db, "dhcpv4")
        assert state["state"] == "failed"
        assert state["color"] == "red"

    def test_record_dry_run_sets_dry_run(self, db):
        from app.services.apply_state import record_dry_run, get_feature_state
        record_dry_run(db, "openvpn", applied_by="system")
        state = get_feature_state(db, "openvpn")
        assert state["state"] == "dry-run"
        assert state["color"] == "gray"

    def test_has_pending_changes_after_save(self, db):
        from app.services.apply_state import record_save, has_pending_changes
        record_save(db, "pf_firewall", applied_by="admin")
        assert has_pending_changes(db, "pf_firewall") is True

    def test_no_pending_changes_after_apply(self, db):
        from app.services.apply_state import (
            record_save, record_apply_start, record_apply_result, has_pending_changes,
        )
        record_save(db, "suricata_ids", applied_by="admin")
        job_id = record_apply_start(db, "suricata_ids", applied_by="admin")
        record_apply_result(db, job_id, ok=True, message="OK")
        assert has_pending_changes(db, "suricata_ids") is False

    def test_get_all_feature_states_returns_dict(self, db):
        from app.services.apply_state import record_save, get_all_feature_states
        record_save(db, "ntp", applied_by="system")
        record_save(db, "ddns", applied_by="system")
        states = get_all_feature_states(db)
        assert isinstance(states, dict)
        assert "ntp" in states
        assert "ddns" in states

    def test_get_recent_jobs(self, db):
        from app.services.apply_state import (
            record_apply_start, record_apply_result, get_recent_jobs,
        )
        job_id = record_apply_start(db, "snmp", applied_by="admin")
        record_apply_result(db, job_id, ok=True, message="done")
        jobs = get_recent_jobs(db, feature_key="snmp", limit=10)
        assert len(jobs) >= 1
        assert jobs[0]["feature_key"] == "snmp"

    def test_record_unsupported(self, db):
        from app.services.apply_state import record_unsupported, get_feature_state
        record_unsupported(db, "mrtg", reason="not available")
        state = get_feature_state(db, "mrtg")
        assert state["state"] == "unsupported"

    def test_get_pending_features(self, db):
        from app.services.apply_state import record_save, get_pending_features
        record_save(db, "igmp_proxy", applied_by="system")
        pending = get_pending_features(db)
        assert "igmp_proxy" in pending

    def test_rollback_sets_rolled_back(self, db):
        from app.services.apply_state import (
            record_apply_start, record_apply_result, get_feature_state,
        )
        job_id = record_apply_start(db, "ipsec", applied_by="admin")
        record_apply_result(db, job_id, ok=False, message="failed", rollback_ok=True)
        state = get_feature_state(db, "ipsec")
        assert state["state"] == "rolled_back"
        assert state["color"] == "orange"


# ---------------------------------------------------------------------------
# ConfigTransaction
# ---------------------------------------------------------------------------

class TestConfigTransaction:
    def test_dry_run_on_non_freebsd(self, db):
        from app.services.config_transaction import ConfigTransaction
        called = []
        with ConfigTransaction(db, "test_txn", applied_by="test") as txn:
            result = txn.apply("pf_firewall", lambda: called.append(1) or {"ok": True, "message": "ok"})
        if not sys.platform.startswith("freebsd"):
            assert txn.dry_run is True
            assert called == []

    def test_transaction_success_no_errors(self, db):
        from app.services.config_transaction import ConfigTransaction
        with ConfigTransaction(db, "txn_ok", dry_run=True) as txn:
            txn.apply("pf_firewall", lambda: {"ok": True, "message": "ok"})
            txn.apply("dns_resolver", lambda: {"ok": True, "message": "ok"})
        assert txn.success is True
        assert txn.errors == []

    def test_transaction_rollback_on_failure(self, db, monkeypatch):
        """Rollback only fires when functions are actually called (live/freebsd mode).
        Simulate live mode by patching _ON_FREEBSD so apply() calls the functions."""
        import app.services.config_transaction as ct_mod
        monkeypatch.setattr(ct_mod, "_ON_FREEBSD", True)

        from app.services.config_transaction import ConfigTransaction, TransactionError
        rollback_log = []

        def _step1():
            return {"ok": True, "message": "step1 ok"}

        def _rollback1():
            rollback_log.append("rolled_back_step1")

        def _step2():
            raise RuntimeError("step2 failed intentionally")

        with pytest.raises(TransactionError):
            with ConfigTransaction(db, "txn_fail", dry_run=False) as txn:
                txn.apply("pf_firewall", _step1, rollback_fn=_rollback1)
                txn.apply("dns_resolver", _step2)

        assert "rolled_back_step1" in rollback_log

    def test_transaction_summary_structure(self, db):
        from app.services.config_transaction import ConfigTransaction
        with ConfigTransaction(db, "txn_summary", dry_run=True) as txn:
            txn.apply("ntp", lambda: {"ok": True, "message": "ok"})
        s = txn.summary()
        assert "transaction_id" in s
        assert "ok" in s
        assert "dry_run" in s
        assert s["dry_run"] is True

    def test_transaction_errors_accumulate(self, db, monkeypatch):
        """Errors accumulate in live mode when apply_fn returns ok=False."""
        import app.services.config_transaction as ct_mod
        monkeypatch.setattr(ct_mod, "_ON_FREEBSD", True)
        from app.services.config_transaction import ConfigTransaction, TransactionError
        with pytest.raises(TransactionError):
            with ConfigTransaction(db, "txn_err", dry_run=False) as txn:
                txn.apply("bad_feature", lambda: {"ok": False, "message": "oops"})
        assert len(txn.errors) > 0

    def test_conn_none_dry_run_works(self):
        """ConfigTransaction should not crash when conn=None (test/no-DB scenario)."""
        from app.services.config_transaction import ConfigTransaction
        with ConfigTransaction(None, "no_conn", dry_run=True) as txn:
            r = txn.apply("pf_firewall", lambda: {"ok": True, "message": "ok"})
        assert r["ok"] is True
