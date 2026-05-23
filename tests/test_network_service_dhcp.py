"""Regression tests for the DHCP-client kick in network_service.

The setup wizard's Step 4 Apply hits `_kick_dhcp_client(iface)` to bring the
WAN online. FreeBSD's dhclient refuses to start when a pidfile exists ("rc=1
dhclient already running, pid: X, exiting"), which strands a wizard apply
because install.sh + boot already started dhclient on the WAN. We pre-empt
that by running `<dhcp_bin> -x iface` first, and reinterpret a residual
"already running" error as success when the iface actually has a lease + a
default route.
"""
import os

import pytest


os.environ.setdefault("SMARTSHIELD_DB_PATH", "file:nsdhcp?mode=memory&cache=shared")
os.environ.setdefault("SECRET_KEY", "test-ns-key")
os.environ.setdefault("SMARTSHIELD_MASTER_KEY",
    __import__("base64").b64encode(__import__("secrets").token_bytes(32)).decode())


class _FakeResult:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class TestKickDhcpClientStopsExisting:

    def _patch_freebsd(self, monkeypatch):
        import app.services.network_service as ns
        monkeypatch.setattr(ns.sys, "platform", "freebsd14")
        import shutil
        monkeypatch.setattr(shutil, "which",
                            lambda b: "/sbin/dhclient" if b == "dhclient" else None)
        return ns

    def test_pre_emptive_stop_runs_before_start(self, monkeypatch):
        """A `dhclient -x <iface>` must be invoked before `dhclient <iface>`."""
        ns = self._patch_freebsd(monkeypatch)
        calls = []

        def _fake_run(cmd, **kw):
            calls.append(list(cmd))
            return _FakeResult(returncode=0, stdout="")

        monkeypatch.setattr(ns, "run_command", _fake_run)
        monkeypatch.setattr(ns, "_verify_default_route", lambda: True)

        result = ns._kick_dhcp_client("em0")
        assert result["ok"] is True

        argvs = [tuple(c) for c in calls]
        # The pre-emptive stop must happen.
        assert ("/sbin/dhclient", "-x", "em0") in argvs
        # And it must run BEFORE the fresh start.
        stop_idx  = argvs.index(("/sbin/dhclient", "-x", "em0"))
        start_idx = argvs.index(("/sbin/dhclient", "em0"))
        assert stop_idx < start_idx

    def test_already_running_with_valid_lease_is_success(self, monkeypatch):
        """If dhclient still says "already running" but the iface has a lease
        AND a default route, we treat it as success (existing client is fine).
        """
        ns = self._patch_freebsd(monkeypatch)

        def _fake_run(cmd, **kw):
            # ifconfig up + dhclient -x → benign noise
            if cmd[0] == "/sbin/ifconfig" and len(cmd) >= 3 and cmd[2] == "up":
                return _FakeResult(0, "", "")
            if cmd[:3] == ["/sbin/dhclient", "-x", "em0"]:
                return _FakeResult(1, "", "no process found")
            if cmd[:2] == ["/sbin/dhclient", "em0"]:
                return _FakeResult(1, "", "dhclient already running, pid: 489. exiting.")
            return _FakeResult(0, "", "")

        monkeypatch.setattr(ns, "run_command", _fake_run)
        monkeypatch.setattr(ns, "_iface_has_ipv4_lease", lambda _i: True)
        monkeypatch.setattr(ns, "_verify_default_route", lambda: True)

        result = ns._kick_dhcp_client("em0")
        assert result["ok"] is True
        assert "already running" in result["message"].lower()

    def test_already_running_without_lease_is_error(self, monkeypatch):
        """If the residual collision happens but there's no working lease yet,
        it still must be reported as an error so the wizard surfaces it.
        """
        ns = self._patch_freebsd(monkeypatch)

        def _fake_run(cmd, **kw):
            if cmd[:3] == ["/sbin/dhclient", "-x", "em0"]:
                return _FakeResult(1, "", "no process found")
            if cmd[:2] == ["/sbin/dhclient", "em0"]:
                return _FakeResult(1, "", "dhclient already running, pid: 489. exiting.")
            return _FakeResult(0, "", "")

        monkeypatch.setattr(ns, "run_command", _fake_run)
        monkeypatch.setattr(ns, "_iface_has_ipv4_lease", lambda _i: False)
        monkeypatch.setattr(ns, "_verify_default_route", lambda: False)

        result = ns._kick_dhcp_client("em0")
        assert result["ok"] is False
        assert "rc=1" in result["message"]

    def test_dhcpcd_path_also_pre_stops(self, monkeypatch):
        """dhcpcd hosts (FreeBSD 14 default) must get the same -x pre-stop."""
        import app.services.network_service as ns
        monkeypatch.setattr(ns.sys, "platform", "freebsd14")
        import shutil
        # which("dhclient") → None, which("dhcpcd") → /usr/local/sbin/dhcpcd
        monkeypatch.setattr(
            shutil, "which",
            lambda b: "/usr/local/sbin/dhcpcd" if b == "dhcpcd" else None,
        )
        argvs = []

        def _fake_run(cmd, **kw):
            argvs.append(tuple(cmd))
            return _FakeResult(0, "", "")

        monkeypatch.setattr(ns, "run_command", _fake_run)
        monkeypatch.setattr(ns, "_verify_default_route", lambda: True)

        result = ns._kick_dhcp_client("em0")
        assert result["ok"] is True
        assert ("/usr/local/sbin/dhcpcd", "-x", "em0") in argvs


class TestIfaceHasIpv4Lease:

    def test_returns_true_for_real_address(self, monkeypatch):
        import app.services.network_service as ns
        monkeypatch.setattr(
            ns, "run_command",
            lambda cmd, **kw: _FakeResult(0,
                "em0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n"
                "\tinet 192.0.2.5 netmask 0xffffff00 broadcast 192.0.2.255\n"
                "\tether aa:bb:cc:dd:ee:ff\n", ""))
        assert ns._iface_has_ipv4_lease("em0") is True

    def test_returns_false_for_link_local_only(self, monkeypatch):
        """APIPA (169.254.x.x) is a self-assigned non-lease and must not
        count — otherwise we'd green-light a wizard apply that never actually
        got a DHCP response."""
        import app.services.network_service as ns
        monkeypatch.setattr(
            ns, "run_command",
            lambda cmd, **kw: _FakeResult(0,
                "em0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n"
                "\tinet 169.254.10.20 netmask 0xffff0000 broadcast 169.254.255.255\n", ""))
        assert ns._iface_has_ipv4_lease("em0") is False

    def test_returns_false_when_ifconfig_fails(self, monkeypatch):
        import app.services.network_service as ns
        monkeypatch.setattr(
            ns, "run_command",
            lambda cmd, **kw: _FakeResult(1, "", "ifconfig: interface em9 does not exist"))
        assert ns._iface_has_ipv4_lease("em9") is False
