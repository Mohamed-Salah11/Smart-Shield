"""
tests/test_collector_health.py
------------------------------
Phase 2.5: every SIEM collector loop must call
``collector_health.heartbeat(name, restart=True, last_error=…)`` when its
``try`` block catches an exception, so the operator sees "DNS collector
restarted 12 times in the last hour" on the collector-health page.

These tests drive the loop exactly once by patching ``time.sleep`` to raise,
then verify the ``collector_state`` row carries the bumped ``restart_count``
plus the stored error message.
"""
import os

import pytest

os.environ.setdefault("SMARTSHIELD_DB_PATH", "file:colhealth?mode=memory&cache=shared")
os.environ.setdefault("SECRET_KEY", "test-colhealth-key")
os.environ.setdefault("SMARTSHIELD_MASTER_KEY",
    __import__("base64").b64encode(__import__("secrets").token_bytes(32)).decode())


@pytest.fixture()
def conn():
    import secrets as _s
    os.environ["SMARTSHIELD_DB_PATH"] = (
        f"file:colhealth_{_s.token_hex(4)}?mode=memory&cache=shared"
    )
    from app.database import init_db, get_db
    init_db()
    db = get_db()
    yield db
    db.close()


class _StopLoop(Exception):
    """Raised by the patched ``time.sleep`` to break out of an otherwise
    infinite ``while True`` collector loop after one iteration."""


def _row(conn, source_name):
    return conn.execute(
        "SELECT * FROM collector_state WHERE source_name = ?", (source_name,)
    ).fetchone()


# Each entry: (siem_collector attribute exposing the loop, the inner collect
# function to patch, the expected source_name written by heartbeat()).
_COLLECTORS = [
    ("_run_ids_collector",     "_collect_ids_alerts",      "siem-ids"),
    ("_run_dhcp_collector",    "_collect_dhcp_events",     "siem-dhcp"),
    ("_run_pf_collector",      "_collect_pf_connections",  "siem-pf"),
    ("_run_syslog_collector",  "_collect_syslog_events",   "siem-syslog"),
    ("_run_system_collector",  "_collect_system_events",   "siem-system"),
    ("_run_vpn_collector",     "_collect_vpn_sessions",    "siem-vpn"),
    ("_run_health_collector",  "_collect_health",          "siem-health"),
]


@pytest.mark.parametrize("loop_attr,collect_attr,source_name", _COLLECTORS)
def test_collector_loop_bumps_restart_count_on_exception(
    conn, monkeypatch, loop_attr, collect_attr, source_name
):
    import app.services.siem_collector as sc

    monkeypatch.setattr(sc, collect_attr,
                        lambda state: (_ for _ in ()).throw(RuntimeError("kaboom")))
    monkeypatch.setattr(sc.time, "sleep",
                        lambda _seconds: (_ for _ in ()).throw(_StopLoop()))

    with pytest.raises(_StopLoop):
        getattr(sc, loop_attr)({})

    row = _row(conn, source_name)
    assert row is not None, f"{source_name} heartbeat row missing"
    assert row["restart_count"] >= 1
    assert "kaboom" in (row["last_error"] or "")


def test_vpn_log_tailer_records_restart_on_exception(conn, monkeypatch):
    # _run_vpn_log_tailer wraps two sub-collectors; force one to throw.
    import app.services.siem_collector as sc
    monkeypatch.setattr(sc, "_collect_strongswan_lines",
                        lambda state: (_ for _ in ()).throw(RuntimeError("vpn-boom")))
    monkeypatch.setattr(sc, "_collect_mpd5_lines", lambda state: None)
    monkeypatch.setattr(sc.time, "sleep",
                        lambda _s: (_ for _ in ()).throw(_StopLoop()))
    with pytest.raises(_StopLoop):
        sc._run_vpn_log_tailer({})
    row = _row(conn, "siem-vpn-log")
    assert row is not None
    assert row["restart_count"] >= 1
    assert "vpn-boom" in (row["last_error"] or "")


def test_anomaly_detector_records_restart_on_exception(conn, monkeypatch):
    # _run_anomaly_detector imports correlation_engine.evaluate at runtime —
    # patch the module so the import resolves to our exploding callable.
    import sys, types
    fake = types.ModuleType("app.services.correlation_engine")
    fake.evaluate = lambda: (_ for _ in ()).throw(RuntimeError("anomaly-boom"))
    monkeypatch.setitem(sys.modules, "app.services.correlation_engine", fake)

    import app.services.siem_collector as sc
    monkeypatch.setattr(sc.time, "sleep",
                        lambda _s: (_ for _ in ()).throw(_StopLoop()))
    with pytest.raises(_StopLoop):
        sc._run_anomaly_detector({})
    row = _row(conn, "siem-anomaly")
    assert row is not None
    assert row["restart_count"] >= 1
    assert "anomaly-boom" in (row["last_error"] or "")


def test_restart_count_accumulates_across_iterations(conn, monkeypatch):
    # Drive _run_ids_collector through two failed iterations; restart_count
    # must reach 2 (i.e. heartbeat increments, not just sets).
    import app.services.siem_collector as sc
    monkeypatch.setattr(sc, "_collect_ids_alerts",
                        lambda state: (_ for _ in ()).throw(RuntimeError("e1")))
    calls = {"n": 0}
    def _sleep(_):
        calls["n"] += 1
        if calls["n"] >= 2:
            raise _StopLoop()
    monkeypatch.setattr(sc.time, "sleep", _sleep)
    with pytest.raises(_StopLoop):
        sc._run_ids_collector({})
    row = _row(conn, "siem-ids")
    assert row["restart_count"] == 2
