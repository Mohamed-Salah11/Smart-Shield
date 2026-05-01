"""
tests/test_freebsd_integration.py
----------------------------------
FreeBSD integration test plan for Smart Shield.

HOW TO USE
----------
These tests are SKIPPED automatically on non-FreeBSD platforms.
To run them on a FreeBSD VM or jail:

    1. Install Smart Shield (bsd/install.sh).
    2. Set SMARTSHIELD_ENABLE_NETWORK_APPLY=1 in the env file.
    3. Run pytest from the project root:

           pytest tests/test_freebsd_integration.py -v

Some tests require root or sudo access; those tests are marked
``@pytest.mark.sudo_required`` and will be skipped if the current
user is not root.

Environment variables that control behaviour
--------------------------------------------
SMARTSHIELD_INTEGRATION_IFACE : FreeBSD interface to use (default: em0)
SMARTSHIELD_INTEGRATION_LAN_IP: LAN IP/CIDR (default: 192.168.1.1/24)
SMARTSHIELD_INTEGRATION_GW    : Default gateway (default: 192.168.1.254)
"""

import os
import shutil
import subprocess
import sys
import sqlite3

import pytest

# All tests in this file are FreeBSD-only
pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("freebsd"),
    reason="FreeBSD integration tests — skipped on non-FreeBSD",
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

IFACE  = os.getenv("SMARTSHIELD_INTEGRATION_IFACE", "em0")
LAN_IP = os.getenv("SMARTSHIELD_INTEGRATION_LAN_IP", "192.168.1.1/24")
GW     = os.getenv("SMARTSHIELD_INTEGRATION_GW", "192.168.1.254")

APP_ROOT = os.getenv("SMARTSHIELD_APP_ROOT", "/usr/local/share/smart-shield")
ENV_FILE = os.getenv("SMARTSHIELD_ENV_FILE", "/usr/local/etc/smart-shield/smart-shield.env")
DB_PATH  = os.getenv("SMARTSHIELD_DB_PATH",  "/var/db/smart-shield/data.db")


def _run(cmd, timeout=10):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _is_root():
    if not hasattr(os, "geteuid"):
        return False
    return os.geteuid() == 0


sudo_required = pytest.mark.skipif(
    not _is_root(),
    reason="Requires root or sudo",
)


# ---------------------------------------------------------------------------
# Install + rc.d
# ---------------------------------------------------------------------------

class TestInstallation:
    def test_app_root_exists(self):
        assert os.path.isdir(APP_ROOT), f"App root not found: {APP_ROOT}"

    def test_env_file_exists(self):
        assert os.path.isfile(ENV_FILE), f"Env file not found: {ENV_FILE}"

    def test_env_file_permissions(self):
        stat = os.stat(ENV_FILE)
        perm = oct(stat.st_mode)[-3:]
        assert perm == "600", f"Env file permissions should be 600, got {perm}"

    def test_db_file_exists(self):
        assert os.path.isfile(DB_PATH), f"DB not found: {DB_PATH}"

    def test_db_schema_version(self):
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        row  = conn.execute("SELECT MAX(version) AS v FROM schema_version").fetchone()
        conn.close()
        assert row and row["v"] >= 5, f"Schema version too old: {row}"

    def test_smartshieldctl_installed(self):
        assert shutil.which("smartshieldctl"), "smartshieldctl not found in PATH"

    def test_smartshieldctl_status(self):
        r = _run(["smartshieldctl", "status"])
        assert r.returncode in (0, 1), f"Unexpected exit code: {r.returncode}"

    def test_rc_d_script_exists(self):
        assert os.path.isfile("/usr/local/etc/rc.d/smart_shield"), \
            "rc.d script not found"

    def test_rc_d_script_permissions(self):
        stat = os.stat("/usr/local/etc/rc.d/smart_shield")
        perm = oct(stat.st_mode)[-3:]
        assert perm in ("555", "755"), f"rc.d script permissions: {perm}"

    def test_sudoers_file_exists(self):
        assert os.path.isfile("/usr/local/etc/sudoers.d/smartshield"), \
            "sudoers file not found"

    def test_sudoers_file_permissions(self):
        stat = os.stat("/usr/local/etc/sudoers.d/smartshield")
        perm = oct(stat.st_mode)[-3:]
        assert perm == "440", f"sudoers file should be 440, got {perm}"

    def test_sudoers_syntax_valid(self):
        r = _run(["visudo", "-c", "-f", "/usr/local/etc/sudoers.d/smartshield"])
        assert r.returncode == 0, f"visudo check failed: {r.stdout}{r.stderr}"


# ---------------------------------------------------------------------------
# PF / Firewall
# ---------------------------------------------------------------------------

class TestPFIntegration:
    @sudo_required
    def test_pf_enabled(self):
        r = _run(["pfctl", "-si"])
        assert "Status: Enabled" in r.stdout, "PF is not enabled"

    @sudo_required
    def test_pfctl_validate_conf(self):
        """Validate the currently applied pf.conf without reloading."""
        conf_path = "/etc/pf.conf"
        if not os.path.isfile(conf_path):
            pytest.skip(f"{conf_path} not found")
        r = _run(["pfctl", "-n", "-f", conf_path])
        assert r.returncode == 0, f"pfctl validation failed:\n{r.stderr}"

    def test_pf_conf_no_shell_injection(self):
        """Verify pf.conf does not contain shell metacharacters."""
        conf_path = "/etc/pf.conf"
        if not os.path.isfile(conf_path):
            pytest.skip(f"{conf_path} not found")
        with open(conf_path) as f:
            content = f.read()
        for bad in ("`", "$(", ";", "&&", "||"):
            assert bad not in content, f"Suspicious character {bad!r} found in pf.conf"

    @sudo_required
    def test_pf_tables_exist(self):
        r = _run(["pfctl", "-t", "authenticated_clients", "-T", "show"])
        # exit code 1 is acceptable (empty table); 2+ is an error
        assert r.returncode in (0, 1), f"PF table check failed: {r.stderr}"


# ---------------------------------------------------------------------------
# DHCP
# ---------------------------------------------------------------------------

class TestDHCPIntegration:
    def test_dhcpd_conf_parseable(self):
        conf = "/usr/local/etc/dhcpd.conf"
        if not os.path.isfile(conf):
            pytest.skip(f"{conf} not found")
        r = _run(["dhcpd", "-t", "-cf", conf])
        assert r.returncode == 0, f"dhcpd config test failed:\n{r.stderr}"

    @sudo_required
    def test_dhcpd_service_can_status(self):
        r = _run(["service", "isc-dhcpd", "status"])
        assert r.returncode in (0, 1)


# ---------------------------------------------------------------------------
# DNS / Unbound
# ---------------------------------------------------------------------------

class TestDNSIntegration:
    def test_unbound_conf_parseable(self):
        conf = "/usr/local/etc/unbound/unbound.conf"
        if not os.path.isfile(conf):
            pytest.skip(f"{conf} not found")
        if not shutil.which("unbound-checkconf"):
            pytest.skip("unbound-checkconf not found")
        r = _run(["unbound-checkconf", conf])
        assert r.returncode == 0, f"unbound-checkconf failed:\n{r.stderr}"

    def test_dns_resolves_localhost(self):
        """Unbound should resolve localhost without errors."""
        r = _run(["drill", "-p", "53", "@127.0.0.1", "localhost", "A"])
        if r.returncode != 0:
            # drill may not be installed — try dig
            r = _run(["dig", "@127.0.0.1", "+short", "localhost", "A"])
        assert r.returncode == 0 or "127.0.0.1" in r.stdout


# ---------------------------------------------------------------------------
# VPN — OpenVPN
# ---------------------------------------------------------------------------

class TestOpenVPNIntegration:
    def test_openvpn_conf_parseable(self):
        import glob
        confs = glob.glob("/usr/local/etc/openvpn/*.conf")
        if not confs:
            pytest.skip("No OpenVPN configs found")
        for conf in confs:
            r = _run(["openvpn", "--config", conf, "--verb", "0", "--mode", "server",
                      "--verify-config"])
            assert r.returncode == 0, f"OpenVPN config {conf} failed:\n{r.stderr}"


# ---------------------------------------------------------------------------
# IDS — Suricata
# ---------------------------------------------------------------------------

class TestSuricataIntegration:
    def test_suricata_conf_parseable(self):
        conf = "/usr/local/etc/suricata/suricata.yaml"
        if not os.path.isfile(conf):
            pytest.skip(f"{conf} not found")
        if not shutil.which("suricata"):
            pytest.skip("suricata not installed")
        r = _run(["suricata", "-T", "-c", conf], timeout=30)
        assert r.returncode == 0, f"Suricata config test failed:\n{r.stderr}"


# ---------------------------------------------------------------------------
# Privileged helper (sudo allowlist)
# ---------------------------------------------------------------------------

class TestPrivHelperIntegration:
    def test_sudo_pfctl_n_allowed(self):
        """Verify the smartshield user can run pfctl -n via sudo."""
        conf = "/etc/pf.conf"
        if not os.path.isfile(conf):
            pytest.skip(f"{conf} not found")
        r = _run(["sudo", "-n", "/sbin/pfctl", "-n", "-f", conf])
        assert r.returncode == 0, \
            f"sudo pfctl -n returned {r.returncode}: {r.stderr}"

    def test_sudo_service_unbound_status_allowed(self):
        r = _run(["sudo", "-n", "/usr/sbin/service", "unbound", "status"])
        assert r.returncode in (0, 1), \
            f"sudo service unbound status returned {r.returncode}: {r.stderr}"

    def test_sudo_shell_not_allowed(self):
        """The smartshield user must NOT be able to sudo a shell."""
        r = _run(["sudo", "-n", "/bin/sh", "-c", "id"])
        assert r.returncode != 0, "sudo /bin/sh should be denied"


# ---------------------------------------------------------------------------
# smartshieldctl CLI
# ---------------------------------------------------------------------------

class TestSmartshieldCtl:
    def test_help_output(self):
        r = _run(["smartshieldctl", "help"])
        assert r.returncode == 0

    def test_preflight_command(self):
        r = _run(["smartshieldctl", "preflight"], timeout=30)
        assert r.returncode in (0, 1), f"Unexpected exit: {r.returncode}\n{r.stdout}"

    @sudo_required
    def test_service_status(self):
        r = _run(["smartshieldctl", "status"])
        assert r.returncode in (0, 1)


# ---------------------------------------------------------------------------
# Config history persistence
# ---------------------------------------------------------------------------

class TestConfigHistoryIntegration:
    def test_save_and_read_from_real_db(self):
        from app.services.config_history import save_config_version, get_config_version
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        vid = save_config_version(
            conn, "integration_test", "test content\n",
            applied_by="pytest", file_path="",
            validation_ok=True, apply_ok=True,
        )
        ver = get_config_version(conn, vid)
        conn.close()
        assert ver is not None
        assert ver["service"] == "integration_test"
