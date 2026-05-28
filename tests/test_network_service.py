"""
tests/test_network_service.py
-----------------------------
Unit tests for app/services/network_service.py live-apply helpers.

``apply_interface_with_rollback`` early-returns off FreeBSD, so these tests
fake ``sys.platform`` and stub ``run_command`` plus the state helpers to assert
the ifconfig argv that would be issued — no real interfaces are touched.
"""
import os

import pytest

os.environ.setdefault("SMARTSHIELD_DB_PATH", "file:nstest?mode=memory&cache=shared")
os.environ.setdefault("SECRET_KEY", "test-ns-key")
os.environ.setdefault("SMARTSHIELD_MASTER_KEY",
    __import__("base64").b64encode(__import__("secrets").token_bytes(32)).decode())


class _FakeResult:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class TestApplyInterfaceSetsMtu:

    def _patch(self, monkeypatch, calls):
        import app.services.network_service as ns
        monkeypatch.setattr(ns.sys, "platform", "freebsd14")
        monkeypatch.setattr(ns, "run_command",
                            lambda cmd, **kw: (calls.append(list(cmd)), _FakeResult(0))[1])
        # No previous address/gateway → nothing to roll back; no verify ping.
        monkeypatch.setattr(ns, "get_interface_state", lambda _i: {"cidr": "", "inet": ""})
        monkeypatch.setattr(ns, "get_default_gateway", lambda: "")
        return ns

    def test_apply_interface_sets_mtu(self, monkeypatch):
        calls = []
        ns = self._patch(monkeypatch, calls)
        res = ns.apply_interface_with_rollback("em1", "192.168.5.1/24", mtu="1492")
        assert res["ok"] is True
        assert res["rolled_back"] is False
        assert ["ifconfig", "em1", "mtu", "1492"] in calls

    def test_no_mtu_command_when_mtu_blank(self, monkeypatch):
        calls = []
        ns = self._patch(monkeypatch, calls)
        res = ns.apply_interface_with_rollback("em1", "192.168.5.1/24")
        assert res["ok"] is True
        assert not any(c[:2] == ["ifconfig", "em1"] and "mtu" in c for c in calls)
