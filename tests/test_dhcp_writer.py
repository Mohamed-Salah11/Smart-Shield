"""
tests/test_dhcp_writer.py
-------------------------
Unit tests for app/services/dhcp_writer.py.
No FreeBSD required — service restart calls are skipped on non-FreeBSD.
"""

import os
import pytest

os.environ.setdefault("SMARTSHIELD_DB_PATH", "file:dhcptest?mode=memory&cache=shared")
os.environ.setdefault("SECRET_KEY", "test-dhcp-key")
os.environ.setdefault("SMARTSHIELD_MASTER_KEY",
    __import__("base64").b64encode(__import__("secrets").token_bytes(32)).decode())


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def conn():
    """Per-test clean in-memory DB with seed data."""
    import secrets, base64
    _prev = os.environ.get("SMARTSHIELD_DB_PATH")
    os.environ["SMARTSHIELD_DB_PATH"] = (
        f"file:dhcp_{secrets.token_hex(4)}?mode=memory&cache=shared"
    )
    from app.database import init_db, get_db
    init_db()
    db = get_db()
    db.execute(
        "UPDATE lan_config SET assigned_port='em1', ipv4_address='192.168.1.1/24' WHERE id=1"
    )
    db.execute(
        "UPDATE wan_config SET assigned_port='em0', ipv4_address='10.0.0.1/24' WHERE id=1"
    )
    # Enable LAN pool with valid settings
    db.execute(
        "UPDATE dhcp_pools SET enabled=1, start_ip='192.168.1.100', end_ip='192.168.1.200',"
        " gateway_ip='192.168.1.1', dns_servers='1.1.1.1,8.8.8.8', lease_time=86400"
        " WHERE interface_type='LAN'"
    )
    db.commit()
    yield db
    db.close()
    if _prev is None:
        os.environ.pop("SMARTSHIELD_DB_PATH", None)
    else:
        os.environ["SMARTSHIELD_DB_PATH"] = _prev


# ---------------------------------------------------------------------------
# Config generation
# ---------------------------------------------------------------------------

class TestGenerateDhcpdConf:

    def test_contains_authoritative(self, conn):
        from app.services.dhcp_writer import generate_dhcpd_conf
        conf = generate_dhcpd_conf(conn)
        assert "authoritative;" in conf

    def test_pool_range_present(self, conn):
        from app.services.dhcp_writer import generate_dhcpd_conf
        conf = generate_dhcpd_conf(conn)
        assert "range 192.168.1.100 192.168.1.200;" in conf

    def test_subnet_derived_from_interface(self, conn):
        from app.services.dhcp_writer import generate_dhcpd_conf
        conf = generate_dhcpd_conf(conn)
        assert "subnet 192.168.1.0 netmask 255.255.255.0" in conf

    def test_gateway_option(self, conn):
        from app.services.dhcp_writer import generate_dhcpd_conf
        conf = generate_dhcpd_conf(conn)
        assert "option routers 192.168.1.1;" in conf

    def test_dns_option(self, conn):
        from app.services.dhcp_writer import generate_dhcpd_conf
        conf = generate_dhcpd_conf(conn)
        assert "domain-name-servers" in conf
        assert "1.1.1.1" in conf

    def test_disabled_pool_excluded(self, conn):
        from app.services.dhcp_writer import generate_dhcpd_conf
        conn.execute("UPDATE dhcp_pools SET enabled=0 WHERE interface_type='LAN'")
        conn.commit()
        conf = generate_dhcpd_conf(conn)
        assert "range 192.168.1.100" not in conf

    def test_static_lease_block(self, conn):
        from app.services.dhcp_writer import generate_dhcpd_conf
        conn.execute(
            "INSERT INTO static_leases (interface_type, hostname, mac_address, ip_address)"
            " VALUES ('LAN', 'mypc', 'aa:bb:cc:dd:ee:ff', '192.168.1.50')"
        )
        conn.commit()
        conf = generate_dhcpd_conf(conn)
        assert "hardware ethernet aa:bb:cc:dd:ee:ff;" in conf
        assert "fixed-address 192.168.1.50;" in conf
        assert 'option host-name "mypc"' in conf

    def test_static_lease_without_hostname(self, conn):
        from app.services.dhcp_writer import generate_dhcpd_conf
        conn.execute(
            "INSERT INTO static_leases (interface_type, hostname, mac_address, ip_address)"
            " VALUES ('LAN', '', 'aa:11:22:33:44:55', '192.168.1.51')"
        )
        conn.commit()
        conf = generate_dhcpd_conf(conn)
        assert "hardware ethernet aa:11:22:33:44:55;" in conf

    def test_no_pool_no_subnet_block(self, conn):
        from app.services.dhcp_writer import generate_dhcpd_conf
        conn.execute("DELETE FROM dhcp_pools")
        conn.commit()
        conf = generate_dhcpd_conf(conn)
        assert "subnet " not in conf


# ---------------------------------------------------------------------------
# dhcpd_ifaces (interface binding) — keep dhcpd off the WAN
# ---------------------------------------------------------------------------

class TestDhcpIfaces:

    def test_lan_pool_binds_lan_iface_only(self, conn):
        # Seed fixture enables a LAN pool on em1 (WAN em0 has no pool), so dhcpd
        # must bind em1 only — never the WAN, which is what caused the boot-log
        # "No subnet declaration for em0 / Ignoring requests on em0".
        from app.services.dhcp_writer import _dhcp_ifaces
        assert _dhcp_ifaces(conn) == "em1"

    def test_no_enabled_pool_returns_empty(self, conn):
        from app.services.dhcp_writer import _dhcp_ifaces
        conn.execute("UPDATE dhcp_pools SET enabled=0")
        conn.commit()
        assert _dhcp_ifaces(conn) == ""

    def test_rc_conf_block_persists_dhcpd_ifaces(self, conn):
        # The boot-time rcvar must match the live value apply_dhcpd sets.
        from app.services.rc_conf_writer import generate_rc_conf_block
        block = generate_rc_conf_block(conn)
        assert 'dhcpd_enable="YES"' in block
        assert 'dhcpd_ifaces="em1"' in block


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

class TestValidateDhcpConfig:

    def test_valid_config_no_errors(self, conn):
        from app.services.dhcp_writer import validate_dhcp_config
        errors = validate_dhcp_config(conn)
        assert errors == []

    def test_invalid_start_ip(self, conn):
        from app.services.dhcp_writer import validate_dhcp_config
        conn.execute(
            "UPDATE dhcp_pools SET start_ip='not-an-ip' WHERE interface_type='LAN'"
        )
        conn.commit()
        errors = validate_dhcp_config(conn)
        assert any("start IP" in e for e in errors)

    def test_invalid_end_ip(self, conn):
        from app.services.dhcp_writer import validate_dhcp_config
        conn.execute(
            "UPDATE dhcp_pools SET end_ip='999.999.999.999' WHERE interface_type='LAN'"
        )
        conn.commit()
        errors = validate_dhcp_config(conn)
        assert any("end IP" in e for e in errors)

    def test_start_greater_than_end(self, conn):
        from app.services.dhcp_writer import validate_dhcp_config
        conn.execute(
            "UPDATE dhcp_pools SET start_ip='192.168.1.200', end_ip='192.168.1.100'"
            " WHERE interface_type='LAN'"
        )
        conn.commit()
        errors = validate_dhcp_config(conn)
        assert any("start" in e.lower() and "end" in e.lower() for e in errors)

    def test_pool_outside_subnet(self, conn):
        from app.services.dhcp_writer import validate_dhcp_config
        conn.execute(
            "UPDATE dhcp_pools SET start_ip='10.10.10.10', end_ip='10.10.10.20'"
            " WHERE interface_type='LAN'"
        )
        conn.commit()
        errors = validate_dhcp_config(conn)
        assert any("subnet" in e.lower() for e in errors)

    def test_short_lease_time_error(self, conn):
        from app.services.dhcp_writer import validate_dhcp_config
        conn.execute(
            "UPDATE dhcp_pools SET lease_time=30 WHERE interface_type='LAN'"
        )
        conn.commit()
        errors = validate_dhcp_config(conn)
        assert any("lease time" in e.lower() for e in errors)

    def test_invalid_dns_server(self, conn):
        from app.services.dhcp_writer import validate_dhcp_config
        conn.execute(
            "UPDATE dhcp_pools SET dns_servers='bad-dns' WHERE interface_type='LAN'"
        )
        conn.commit()
        errors = validate_dhcp_config(conn)
        assert any("DNS" in e for e in errors)

    def test_duplicate_mac_prevented_by_db_constraint(self, conn):
        """
        The DB enforces UNIQUE on mac_address, so duplicate MACs are rejected
        at INSERT time rather than at validation time.  Verify the constraint
        is present and raises IntegrityError.
        """
        import sqlite3
        mac = "bb:bb:bb:bb:bb:bb"
        conn.execute(
            "INSERT INTO static_leases (interface_type, mac_address, ip_address)"
            " VALUES ('LAN', ?, '192.168.1.51')", (mac,)
        )
        conn.commit()
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO static_leases (interface_type, mac_address, ip_address)"
                " VALUES ('LAN', ?, '192.168.1.52')", (mac,)
            )
            conn.commit()

    def test_duplicate_ip_error(self, conn):
        from app.services.dhcp_writer import validate_dhcp_config
        conn.execute(
            "INSERT INTO static_leases (interface_type, mac_address, ip_address)"
            " VALUES ('LAN', '11:22:33:44:55:66', '192.168.1.55')"
        )
        conn.execute(
            "INSERT INTO static_leases (interface_type, mac_address, ip_address)"
            " VALUES ('LAN', 'aa:bb:cc:dd:ee:01', '192.168.1.55')"
        )
        conn.commit()
        errors = validate_dhcp_config(conn)
        assert any("Duplicate" in e and "IP" in e for e in errors)

    def test_static_ip_inside_pool_warns(self, conn):
        from app.services.dhcp_writer import validate_dhcp_config
        # Insert static lease whose IP is inside the enabled pool range
        conn.execute(
            "INSERT INTO static_leases (interface_type, mac_address, ip_address)"
            " VALUES ('LAN', 'ff:ee:dd:cc:bb:aa', '192.168.1.150')"
        )
        conn.commit()
        errors = validate_dhcp_config(conn)
        assert any("falls inside" in e.lower() for e in errors)


# ---------------------------------------------------------------------------
# Dry-run apply
# ---------------------------------------------------------------------------

class TestApplyDhcpd:

    def test_apply_returns_ok_on_non_freebsd_with_valid_config(self, conn):
        from app.services.dhcp_writer import apply_dhcpd
        result = apply_dhcpd(conn)
        assert result["ok"] is True
        assert "conf" in result
        assert result["errors"] == []

    def test_apply_fails_with_validation_errors(self, conn):
        from app.services.dhcp_writer import apply_dhcpd
        conn.execute(
            "UPDATE dhcp_pools SET start_ip='BADIP' WHERE interface_type='LAN'"
        )
        conn.commit()
        result = apply_dhcpd(conn)
        assert result["ok"] is False
        assert result["errors"]


# ---------------------------------------------------------------------------
# Status (non-FreeBSD)
# ---------------------------------------------------------------------------

class TestGetDhcpStatus:

    def test_non_freebsd_returns_dry_run(self):
        from app.services.dhcp_writer import get_dhcp_status
        status = get_dhcp_status()
        assert status["state"] in ("dry-run", "stopped", "error")


# ---------------------------------------------------------------------------
# Live leases (non-FreeBSD)
# ---------------------------------------------------------------------------

class TestGetLiveLeases:

    def test_non_freebsd_returns_empty_list(self):
        from app.services.dhcp_writer import get_live_leases
        leases = get_live_leases()
        assert isinstance(leases, list)
        assert leases == []
