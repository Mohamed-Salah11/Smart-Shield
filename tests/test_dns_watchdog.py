"""
tests/test_dns_watchdog.py
--------------------------
Tests for the DNS self-healing watchdog (app/services/dns_watchdog.py).

The watchdog must:
  * skip when Unbound is already serving the LAN,
  * skip when disabled via dns_resolver.watchdog_enabled,
  * delegate to dns_writer.recover_dns_service when not serving,
  * honour the cool-down so it can't hammer the host.

All recovery work is mocked — these tests exercise only the watchdog's
skip/attempt/rate-limit policy, never a real daemon.
"""

import json
import os

import pytest

os.environ.setdefault("SMARTSHIELD_DB_PATH", "file:dnswdtest?mode=memory&cache=shared")
os.environ.setdefault("SECRET_KEY", "test-dns-watchdog-key")
os.environ.setdefault(
    "SMARTSHIELD_MASTER_KEY",
    __import__("base64").b64encode(__import__("secrets").token_bytes(32)).decode(),
)


@pytest.fixture()
def wd_db():
    """Per-test isolated in-memory DB (unique shared-cache URI, restored on
    teardown) — mirrors the writer test fixtures so it can't contaminate the
    session DB other test modules use."""
    import secrets
    _prev = os.environ.get("SMARTSHIELD_DB_PATH")
    os.environ["SMARTSHIELD_DB_PATH"] = (
        f"file:dnswd_{secrets.token_hex(4)}?mode=memory&cache=shared"
    )
    from app.database import init_db, get_db
    init_db()
    db = get_db()
    yield db
    db.close()
    if _prev is None:
        os.environ.pop("SMARTSHIELD_DB_PATH", None)
    else:
        os.environ["SMARTSHIELD_DB_PATH"] = _prev


def test_skips_when_serving(wd_db, monkeypatch):
    import app.services.dns_writer as dw
    import app.services.dns_watchdog as wd
    monkeypatch.setattr(dw, "unbound_serving_lan", lambda conn: True)
    res = wd.attempt_recovery()
    assert res["skipped"] is True
    assert res["reason"] == "already_serving"


def test_skips_when_watchdog_disabled(wd_db, monkeypatch):
    import app.services.dns_writer as dw
    import app.services.dns_watchdog as wd
    wd_db.execute(
        "INSERT INTO service_state (key_name, value_json) VALUES ('dns_resolver', ?)",
        (json.dumps({"watchdog_enabled": False}),),
    )
    wd_db.commit()
    # Would attempt if enabled — prove the disable flag short-circuits first.
    monkeypatch.setattr(dw, "unbound_serving_lan", lambda conn: False)
    res = wd.attempt_recovery()
    assert res["skipped"] is True
    assert res["reason"] == "watchdog_disabled"


def test_attempts_and_recovers_when_not_serving(wd_db, monkeypatch):
    import app.services.dns_writer as dw
    import app.services.dns_watchdog as wd
    calls = {}
    monkeypatch.setattr(dw, "unbound_serving_lan", lambda conn: False)

    def _fake_recover(conn, actor="watchdog"):
        calls["actor"] = actor
        return {"ok": True, "reason": "recovered", "message": "ok",
                "service_message": "started"}

    monkeypatch.setattr(dw, "recover_dns_service", _fake_recover)
    res = wd.attempt_recovery()
    assert res["ok"] is True
    assert not res.get("skipped")
    assert calls.get("actor") == "watchdog"
    assert res.get("attempts_this_hour") == 1


def test_rate_limited_after_attempt(wd_db, monkeypatch):
    import app.services.dns_writer as dw
    import app.services.dns_watchdog as wd
    monkeypatch.setattr(dw, "unbound_serving_lan", lambda conn: False)
    monkeypatch.setattr(
        dw, "recover_dns_service",
        lambda conn, actor="watchdog": {"ok": True, "reason": "recovered", "message": "ok"},
    )
    first = wd.attempt_recovery()
    assert first["ok"] is True and not first.get("skipped")
    # Second call within the cool-down must be refused.
    second = wd.attempt_recovery()
    assert second.get("skipped") is True
    assert second["reason"] == "rate_limited"
