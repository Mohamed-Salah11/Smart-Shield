"""
tests/test_health_monitor.py
----------------------------
Phase 2.6: ``health_monitor.check_daemon_processes`` must cross-check both
``pgrep -x <exe>`` and ``service <rc> status``, treating the daemon as
running if EITHER reports OK. Each row also exposes ``pgrep`` + ``rc_state``
so the dashboard can flag divergence (e.g. strongSwan launched by a wrapper).
"""
import os
import sys
import types

import pytest

os.environ.setdefault("SMARTSHIELD_DB_PATH", "file:hmtest?mode=memory&cache=shared")
os.environ.setdefault("SECRET_KEY", "test-hm-key")
os.environ.setdefault("SMARTSHIELD_MASTER_KEY",
    __import__("base64").b64encode(__import__("secrets").token_bytes(32)).decode())


class _Result:
    """Minimal stand-in for ``subprocess.CompletedProcess``."""
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _patch_freebsd(monkeypatch):
    """Pretend we are on FreeBSD so check_daemon_processes does real work."""
    import app.services.health_monitor as hm
    monkeypatch.setattr(hm.sys, "platform", "freebsd14")


def _install_run_command(monkeypatch, fn):
    """Replace ``network_service.run_command`` (the only thing
    ``check_daemon_processes`` calls into for pgrep)."""
    import app.services.network_service as ns
    monkeypatch.setattr(ns, "run_command", fn)


def _install_service_status(monkeypatch, fn):
    """Replace ``service_manager.service_status`` (the rc.d signal)."""
    import app.services.service_manager as sm
    monkeypatch.setattr(sm, "service_status", fn)


# ---------------------------------------------------------------------------
# Cross-platform short-circuit
# ---------------------------------------------------------------------------

class TestNonFreeBSDShortCircuit:

    def test_non_freebsd_returns_reason_for_every_entry(self, monkeypatch):
        import app.services.health_monitor as hm
        monkeypatch.setattr(hm.sys, "platform", "win32")
        result = hm.check_daemon_processes()
        # Every configured daemon must appear with the documented reason.
        assert set(result.keys()) == {k for k, _p, _r in hm._DAEMON_CHECKS}
        for key, row in result.items():
            assert row == {"running": False, "reason": "non-FreeBSD"}


# ---------------------------------------------------------------------------
# pgrep ∨ rc.d truth table
# ---------------------------------------------------------------------------

class TestPgrepAndRcCrossCheck:

    def test_pgrep_and_rc_both_running_reports_running(self, monkeypatch):
        _patch_freebsd(monkeypatch)
        _install_run_command(monkeypatch, lambda *a, **k: _Result(returncode=0))
        _install_service_status(monkeypatch,
            lambda name: {"ok": True, "running": True, "message": "running"})
        result = __import__("app.services.health_monitor",
                            fromlist=["check_daemon_processes"]).check_daemon_processes()
        for row in result.values():
            assert row["running"] is True
            assert row["pgrep"] is True
            assert row["rc_state"] == "running"

    def test_pgrep_alone_reports_running(self, monkeypatch):
        # rc.d says stopped, but pgrep finds the process — daemon is running.
        _patch_freebsd(monkeypatch)
        _install_run_command(monkeypatch, lambda *a, **k: _Result(returncode=0))
        _install_service_status(monkeypatch,
            lambda name: {"ok": True, "running": False, "message": "not running"})
        result = __import__("app.services.health_monitor",
                            fromlist=["check_daemon_processes"]).check_daemon_processes()
        for row in result.values():
            assert row["running"] is True
            assert row["pgrep"] is True
            assert row["rc_state"] == "stopped"

    def test_rc_alone_reports_running(self, monkeypatch):
        # pgrep misses (wrapper case — strongSwan/charon on pkg builds),
        # but service rc says running. Treat as running.
        _patch_freebsd(monkeypatch)
        _install_run_command(monkeypatch, lambda *a, **k: _Result(returncode=1))
        _install_service_status(monkeypatch,
            lambda name: {"ok": True, "running": True, "message": "running"})
        result = __import__("app.services.health_monitor",
                            fromlist=["check_daemon_processes"]).check_daemon_processes()
        for row in result.values():
            assert row["running"] is True
            assert row["pgrep"] is False
            assert row["rc_state"] == "running"

    def test_neither_signal_reports_stopped(self, monkeypatch):
        _patch_freebsd(monkeypatch)
        _install_run_command(monkeypatch, lambda *a, **k: _Result(returncode=1))
        _install_service_status(monkeypatch,
            lambda name: {"ok": True, "running": False, "message": "not running"})
        result = __import__("app.services.health_monitor",
                            fromlist=["check_daemon_processes"]).check_daemon_processes()
        for row in result.values():
            assert row["running"] is False
            assert row["pgrep"] is False
            assert row["rc_state"] == "stopped"


# ---------------------------------------------------------------------------
# rc.d ↔ pgrep mapping is correct (no longer 1:1)
# ---------------------------------------------------------------------------

class TestProcessAndRcMapping:

    def test_charon_dispatched_via_strongswan_rc_name(self, monkeypatch):
        # The whole point of this prompt: charon comes up under
        # ``service strongswan start`` even when pgrep -x charon misses.
        _patch_freebsd(monkeypatch)

        rc_calls = []
        def _fake_rc(name):
            rc_calls.append(name)
            # Only "strongswan" reports running; everything else reports stopped.
            return {"ok": True, "running": name == "strongswan", "message": ""}
        _install_service_status(monkeypatch, _fake_rc)
        _install_run_command(monkeypatch, lambda *a, **k: _Result(returncode=1))

        result = __import__("app.services.health_monitor",
                            fromlist=["check_daemon_processes"]).check_daemon_processes()
        assert "strongswan" in rc_calls, \
            "check_daemon_processes must hit `service strongswan status` for charon"
        assert result["charon"]["running"] is True
        assert result["charon"]["pgrep"] is False
        assert result["charon"]["rc_state"] == "running"

    def test_dhcpd_uses_isc_dhcpd_rc_name(self, monkeypatch):
        # FreeBSD's rc service name for dhcpd is `isc-dhcpd`, not `dhcpd`.
        _patch_freebsd(monkeypatch)
        rc_calls = []
        def _fake_rc(name):
            rc_calls.append(name)
            return {"ok": True, "running": name == "isc-dhcpd", "message": ""}
        _install_service_status(monkeypatch, _fake_rc)
        _install_run_command(monkeypatch, lambda *a, **k: _Result(returncode=1))

        result = __import__("app.services.health_monitor",
                            fromlist=["check_daemon_processes"]).check_daemon_processes()
        assert "isc-dhcpd" in rc_calls
        assert result["dhcpd"]["running"] is True
        assert result["dhcpd"]["rc_state"] == "running"

    def test_pgrep_invoked_with_exe_name_not_rc_name(self, monkeypatch):
        # pgrep -x must still receive the executable name, not the rc.d name.
        _patch_freebsd(monkeypatch)
        captured = []
        def _fake_rc(name):
            return {"ok": True, "running": False, "message": ""}
        def _fake_run(cmd, **kw):
            captured.append(list(cmd))
            return _Result(returncode=1)
        _install_service_status(monkeypatch, _fake_rc)
        _install_run_command(monkeypatch, _fake_run)

        __import__("app.services.health_monitor",
                   fromlist=["check_daemon_processes"]).check_daemon_processes()
        # Find the pgrep invocation for the charon row.
        charon_calls = [c for c in captured if c[:2] == ["pgrep", "-x"] and c[2] == "charon"]
        assert charon_calls, "charon must still be queried by exe name via pgrep -x charon"
        # And confirm dhcpd was queried by the exe name `dhcpd`, not `isc-dhcpd`.
        dhcpd_calls = [c for c in captured if c[:2] == ["pgrep", "-x"] and c[2] == "dhcpd"]
        assert dhcpd_calls
        assert not [c for c in captured if c[:2] == ["pgrep", "-x"] and c[2] == "isc-dhcpd"]


# ---------------------------------------------------------------------------
# Failure isolation — one signal blowing up must not kill the row
# ---------------------------------------------------------------------------

class TestSignalFailureIsolation:

    def test_pgrep_exception_falls_back_to_rc_state(self, monkeypatch):
        _patch_freebsd(monkeypatch)
        def _boom(*a, **k):
            raise OSError("pgrep not on PATH")
        _install_run_command(monkeypatch, _boom)
        _install_service_status(monkeypatch,
            lambda name: {"ok": True, "running": True, "message": "running"})
        result = __import__("app.services.health_monitor",
                            fromlist=["check_daemon_processes"]).check_daemon_processes()
        for row in result.values():
            # pgrep blew up → pgrep stays False, but rc_state still up,
            # so the row reports running.
            assert row["pgrep"] is False
            assert row["rc_state"] == "running"
            assert row["running"] is True

    def test_service_status_exception_falls_back_to_pgrep(self, monkeypatch):
        _patch_freebsd(monkeypatch)
        _install_run_command(monkeypatch, lambda *a, **k: _Result(returncode=0))
        def _boom(name):
            raise RuntimeError("rc.d unreachable")
        _install_service_status(monkeypatch, _boom)
        result = __import__("app.services.health_monitor",
                            fromlist=["check_daemon_processes"]).check_daemon_processes()
        for row in result.values():
            assert row["pgrep"] is True
            assert row["rc_state"] == "unknown"
            assert row["running"] is True

    def test_both_signals_explode_row_still_present(self, monkeypatch):
        _patch_freebsd(monkeypatch)
        _install_run_command(monkeypatch,
            lambda *a, **k: (_ for _ in ()).throw(OSError("nope")))
        _install_service_status(monkeypatch,
            lambda name: (_ for _ in ()).throw(RuntimeError("nope")))
        result = __import__("app.services.health_monitor",
                            fromlist=["check_daemon_processes"]).check_daemon_processes()
        # Every configured daemon must STILL be present in the result —
        # operators must never see a daemon silently vanish from the page.
        assert set(result.keys()) == {k for k, _p, _r in __import__(
            "app.services.health_monitor",
            fromlist=["_DAEMON_CHECKS"])._DAEMON_CHECKS}
        for row in result.values():
            assert row["running"] is False
            assert row["pgrep"] is False
            assert row["rc_state"] == "unknown"
