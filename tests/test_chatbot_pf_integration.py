"""
tests/test_chatbot_pf_integration.py
------------------------------------
Phase 3.2 — regression test for the
``chatbot writes block rule → pf_generator.reload_pf_rules`` flow.

This is the exact code path that was broken in TODO_FULL_LIVE_APPLIANCE.md
("Known Critical Bug — chatbot reload"). Three things have to stay wired
together for it to keep working:

  1. ``chatbot_service.execute_approved_action`` inserts a row into
     ``firewall_rules_floating`` with ``action='block'``.
  2. It records an apply job via
     ``apply_state.record_apply_start`` / ``record_apply_result`` so the
     dashboard can show "AI-applied: pf_firewall — applied" with a job id.
  3. It calls ``pf_generator.reload_pf_rules`` exactly once.

On failure (``reload_pf_rules`` returns ``ok=False``) the floating row must
still be persisted, but the apply-state row must transition to ``failed``
so the operator sees the divergence rather than the chatbot silently
"applying" a rule PF rejected.

The chatbot decides between live-apply and dry-run by reading
``sys.platform``; these tests monkeypatch it to ``freebsd14`` so the live
branch executes deterministically on the Windows dev box and on FreeBSD CI.
"""
import os
import sys

import pytest

os.environ.setdefault("SMARTSHIELD_DB_PATH", "file:cbpf?mode=memory&cache=shared")
os.environ.setdefault("SECRET_KEY", "test-cbpf-key")
os.environ.setdefault("SMARTSHIELD_MASTER_KEY",
    __import__("base64").b64encode(__import__("secrets").token_bytes(32)).decode())


@pytest.fixture()
def conn(monkeypatch):
    """Per-test in-memory DB seeded with LAN/WAN, plus the live-apply
    code path forced on by faking ``sys.platform``."""
    import secrets as _s
    os.environ["SMARTSHIELD_DB_PATH"] = (
        f"file:cbpf_{_s.token_hex(4)}?mode=memory&cache=shared"
    )
    from app.database import get_db, init_db
    init_db()
    db = get_db()
    # The chatbot's block-rule branch chooses dry-run when sys.platform isn't
    # FreeBSD — patch that so the test exercises the real apply path the
    # operator sees in production.
    monkeypatch.setattr(sys, "platform", "freebsd14")
    yield db
    db.close()


# ---------------------------------------------------------------------------
# Happy path — pf_generator.reload_pf_rules reports ok
# ---------------------------------------------------------------------------

class TestSuccessfulBlockRuleApply:

    def test_rule_persisted_and_apply_state_recorded(self, conn, monkeypatch):
        from app.services import chatbot_service
        import app.services.pf_generator as pf

        # Mock pf_generator.reload_pf_rules — execute_approved_action does
        # ``from app.services.pf_generator import reload_pf_rules`` inside the
        # function, so we patch on the source module (where the lookup happens).
        calls = {"n": 0}
        def _fake_reload(conn_arg):
            calls["n"] += 1
            return {"ok": True, "message": "ok"}
        monkeypatch.setattr(pf, "reload_pf_rules", _fake_reload)

        result = chatbot_service.execute_approved_action(
            conn,
            {"tool": "add_firewall_block_rule",
             "args": {"description": "test", "source": "1.2.3.4"}},
            "tester",
        )

        # (top-level result)
        assert result["ok"] is True, result
        assert "test" in result["reply"]
        assert "applied" in result["reply"].lower()

        # (a) firewall_rules_floating row was written with action='block'
        rule_rows = conn.execute(
            "SELECT action, source, description FROM firewall_rules_floating "
            "WHERE description = ?",
            ("test",),
        ).fetchall()
        assert len(rule_rows) == 1
        assert rule_rows[0]["action"] == "block"
        assert rule_rows[0]["source"] == "1.2.3.4"

        # (b) reload_pf_rules was called exactly once
        assert calls["n"] == 1, (
            f"reload_pf_rules must be called exactly once, was called {calls['n']} times"
        )

        # (c) apply-state job row was recorded via record_apply_start +
        #     record_apply_result. State must be 'applied'; feature_key
        #     'pf_firewall'; notes carry the chatbot trace marker.
        job_rows = conn.execute(
            "SELECT feature_key, state, applied_by, notes FROM config_apply_jobs "
            "WHERE notes = ?",
            ("chatbot:add_firewall_block_rule",),
        ).fetchall()
        assert len(job_rows) == 1
        job = job_rows[0]
        assert job["feature_key"] == "pf_firewall"
        assert job["state"] == "applied"
        assert job["applied_by"] == "tester"


# ---------------------------------------------------------------------------
# Failure path — reload_pf_rules reports ok=False
# ---------------------------------------------------------------------------

class TestFailedReloadPersistsRuleAndFailsJob:

    def test_rule_still_persisted_but_job_state_is_failed(self, conn, monkeypatch):
        from app.services import chatbot_service
        import app.services.pf_generator as pf

        monkeypatch.setattr(
            pf, "reload_pf_rules",
            lambda c: {"ok": False, "message": "pfctl: rule rejected"},
        )

        result = chatbot_service.execute_approved_action(
            conn,
            {"tool": "add_firewall_block_rule",
             "args": {"description": "bad-rule", "source": "1.2.3.5"}},
            "tester",
        )

        # The chatbot still reports ok=True at the API level — the rule was
        # saved, only PF reload failed — but the reply tells the operator
        # they need to fix it.
        assert result["ok"] is True
        assert "saved" in result["reply"].lower() or "failed" in result["reply"].lower()

        # The floating-rule row IS still there — losing the rule on a PF
        # reload failure would silently drop the operator's intent.
        rule_rows = conn.execute(
            "SELECT action, source FROM firewall_rules_floating WHERE description = ?",
            ("bad-rule",),
        ).fetchall()
        assert len(rule_rows) == 1
        assert rule_rows[0]["action"] == "block"
        assert rule_rows[0]["source"] == "1.2.3.5"

        # The apply-state job, on the other hand, transitions to 'failed'
        # so the dashboard surfaces the divergence (rule on disk ≠ rule in
        # kernel).
        job = conn.execute(
            "SELECT state, message FROM config_apply_jobs WHERE notes = ?",
            ("chatbot:add_firewall_block_rule",),
        ).fetchone()
        assert job is not None
        assert job["state"] == "failed"
        assert "pfctl" in (job["message"] or "")


# ---------------------------------------------------------------------------
# Defence-in-depth — exception in reload also marks the job failed
# ---------------------------------------------------------------------------

class TestReloadException:

    def test_reload_raising_marks_job_failed_without_losing_rule(self, conn, monkeypatch):
        # The chatbot wraps reload_pf_rules in a try/except so the operator
        # gets a job row regardless of why pf failed.
        from app.services import chatbot_service
        import app.services.pf_generator as pf

        def _boom(c):
            raise RuntimeError("pfctl exploded")
        monkeypatch.setattr(pf, "reload_pf_rules", _boom)

        result = chatbot_service.execute_approved_action(
            conn,
            {"tool": "add_firewall_block_rule",
             "args": {"description": "boom-rule", "source": "1.2.3.6"}},
            "tester",
        )
        assert result["ok"] is True

        rule = conn.execute(
            "SELECT action FROM firewall_rules_floating WHERE description = ?",
            ("boom-rule",),
        ).fetchone()
        assert rule is not None
        assert rule["action"] == "block"

        job = conn.execute(
            "SELECT state, message FROM config_apply_jobs WHERE notes = ?",
            ("chatbot:add_firewall_block_rule",),
        ).fetchone()
        assert job is not None
        assert job["state"] == "failed"
        assert "pfctl exploded" in (job["message"] or "")
