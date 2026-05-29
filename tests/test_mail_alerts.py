"""
tests/test_mail_alerts.py
-------------------------
Tests for Phase 2.2 — per-source cooldown + alert-digest aggregation in
``app/services/mail_alerts.py``.

Both behaviors operate on ``notify_event`` directly and are observable
through ``_QUEUE`` (immediate sends) vs ``_DIGEST_BUFFER`` (digest mode), so
the SMTP delivery path is never reached — we never actually send mail in
these tests.
"""
import os

import pytest

os.environ.setdefault("SMARTSHIELD_DB_PATH", "file:mailtest?mode=memory&cache=shared")
os.environ.setdefault("SECRET_KEY", "test-mail-key")
os.environ.setdefault("SMARTSHIELD_MASTER_KEY",
    __import__("base64").b64encode(__import__("secrets").token_bytes(32)).decode())


@pytest.fixture()
def conn():
    import secrets as _s
    os.environ["SMARTSHIELD_DB_PATH"] = (
        f"file:mail_{_s.token_hex(4)}?mode=memory&cache=shared"
    )
    from app.database import init_db, get_db
    init_db()
    db = get_db()
    yield db
    db.close()


@pytest.fixture(autouse=True)
def _reset_mail_state(monkeypatch):
    """Isolate mail-alerts module state per test. The sender thread is a
    process-wide daemon (started by anything that calls ``log_event`` once),
    so it may already be consuming ``_QUEUE`` by the time these tests run.
    We swap in a fresh, test-local Queue so the worker can't drain our
    assertions; we also clear every cooldown ring + the digest buffer and
    stub ``start_mail_alert_worker`` so no NEW workers spin up."""
    import queue as _queue
    import app.services.mail_alerts as ma
    monkeypatch.setattr(ma, "_QUEUE", _queue.Queue(maxsize=200))
    ma._FIRED.clear()
    ma._PER_SOURCE_FIRED.clear()
    with ma._DIGEST_LOCK:
        ma._DIGEST_BUFFER.clear()
        ma._DIGEST_LAST_FLUSH[0] = 0
    ma.invalidate_config_cache()
    monkeypatch.setattr(ma, "start_mail_alert_worker", lambda: None)


def _drain_queue(ma) -> list:
    items = []
    while not ma._QUEUE.empty():
        try:
            items.append(ma._QUEUE.get_nowait())
            ma._QUEUE.task_done()
        except Exception:
            break
    return items


def _high_event(src_ip="1.2.3.4", action="ids_alert", signature="ET SCAN test"):
    return {
        "category":    "ids",
        "action":      action,
        "severity":    "high",
        "remote_addr": src_ip,
        "details":     {"src_ip": src_ip, "signature": signature},
    }


# ---------------------------------------------------------------------------
# Per-source cooldown
# ---------------------------------------------------------------------------

def test_per_source_cooldown_suppresses_duplicate_within_window(conn, monkeypatch):
    # Enable the feature, disable the global (category, action, remote_addr)
    # cooldown so it can't mask the per-source check we're testing.
    conn.execute(
        "UPDATE mail_alerts_config SET enabled=1, min_severity='high', "
        "cooldown_minutes=0, max_per_hour=0, per_source_cooldown_minutes=10, "
        "digest_window_minutes=0 WHERE id=1"
    )
    conn.commit()

    import app.services.mail_alerts as ma
    ma.invalidate_config_cache()

    # First high-severity alert from src 1.2.3.4 → queued.
    ma.notify_event(_high_event(src_ip="1.2.3.4", action="a1"))
    queued = _drain_queue(ma)
    assert len(queued) == 1
    assert queued[0]["event"]["details"]["src_ip"] == "1.2.3.4"

    # Second alert from SAME src within the window → suppressed (still empty).
    ma.notify_event(_high_event(src_ip="1.2.3.4", action="a2"))
    assert _drain_queue(ma) == [], "noisy src_ip must be suppressed within window"

    # Different src → not suppressed.
    ma.notify_event(_high_event(src_ip="5.6.7.8", action="a3"))
    queued = _drain_queue(ma)
    assert len(queued) == 1
    assert queued[0]["event"]["details"]["src_ip"] == "5.6.7.8"


# ---------------------------------------------------------------------------
# Digest aggregation
# ---------------------------------------------------------------------------

def test_digest_aggregates_and_sends_after_window(conn, monkeypatch):
    # Digest mode on, per-source cooldown disabled so it can't suppress the
    # second/third events out from under the buffer.
    conn.execute(
        "UPDATE mail_alerts_config SET enabled=1, min_severity='high', "
        "cooldown_minutes=0, max_per_hour=0, per_source_cooldown_minutes=0, "
        "digest_window_minutes=60 WHERE id=1"
    )
    conn.commit()

    import app.services.mail_alerts as ma
    ma.invalidate_config_cache()

    # Three high-severity events feed the digest buffer, NOT _QUEUE.
    ma.notify_event(_high_event(src_ip="1.1.1.1", action="a1"))
    ma.notify_event(_high_event(src_ip="2.2.2.2", action="a2"))
    ma.notify_event(_high_event(src_ip="3.3.3.3", action="a3"))

    assert _drain_queue(ma) == [], (
        "digest mode must not enqueue events immediately — they go to the buffer"
    )
    with ma._DIGEST_LOCK:
        assert len(ma._DIGEST_BUFFER) == 3

    # Forcing a flush should drain the buffer and enqueue ONE digest job
    # covering all three events. (The digest ticker normally does this; we
    # call _flush_digest directly so the test isn't time-dependent.)
    flushed = ma._flush_digest()
    assert flushed == 3
    with ma._DIGEST_LOCK:
        assert ma._DIGEST_BUFFER == []
    queued = _drain_queue(ma)
    assert len(queued) == 1, "exactly one digest mail must be enqueued"
    job = queued[0]
    assert job["kind"] == "digest"
    assert len(job["events"]) == 3
    assert {e["details"]["src_ip"] for e in job["events"]} == {
        "1.1.1.1", "2.2.2.2", "3.3.3.3"
    }


def test_digest_disabled_falls_back_to_immediate_enqueue(conn, monkeypatch):
    """Sanity check: with ``digest_window_minutes`` = 0, notify_event must keep
    its pre-Phase-2.2 behavior — each event enqueued individually."""
    conn.execute(
        "UPDATE mail_alerts_config SET enabled=1, min_severity='high', "
        "cooldown_minutes=0, max_per_hour=0, per_source_cooldown_minutes=0, "
        "digest_window_minutes=0 WHERE id=1"
    )
    conn.commit()

    import app.services.mail_alerts as ma
    ma.invalidate_config_cache()

    ma.notify_event(_high_event(src_ip="10.0.0.1", action="a1"))
    ma.notify_event(_high_event(src_ip="10.0.0.2", action="a2"))

    with ma._DIGEST_LOCK:
        assert ma._DIGEST_BUFFER == []
    queued = _drain_queue(ma)
    assert len(queued) == 2
    assert all(j["kind"] == "alert" for j in queued)
