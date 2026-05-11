"""
tests/test_phase4_writers.py
----------------------------
Unit tests for all Phase 4 service writers.
No FreeBSD required — all system calls are skipped/mocked.
"""

import os
import pytest

# Set up env before any imports
os.environ.setdefault("SMARTSHIELD_DB_PATH", "file:p4test?mode=memory&cache=shared")
os.environ.setdefault("SECRET_KEY", "test-phase4")
os.environ.setdefault("SMARTSHIELD_MASTER_KEY",
    __import__("base64").b64encode(__import__("secrets").token_bytes(32)).decode())


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def conn():
    import secrets as _s
    os.environ["SMARTSHIELD_DB_PATH"] = f"file:p4_{_s.token_hex(4)}?mode=memory&cache=shared"
    from app.database import init_db, get_db
    init_db()
    db = get_db()
    yield db
    db.close()


# ===========================================================================
# NTP Writer
# ===========================================================================

class TestNtpWriter:

    def test_generate_contains_servers(self):
        from app.services.ntp_writer import generate_ntp_conf
        settings = {"servers": ["pool.ntp.org", "time.google.com"]}
        conf = generate_ntp_conf(settings)
        assert "server pool.ntp.org iburst" in conf
        assert "server time.google.com iburst" in conf

    def test_generate_drift_file(self):
        from app.services.ntp_writer import generate_ntp_conf
        conf = generate_ntp_conf({})
        assert "driftfile" in conf

    def test_generate_local_clock(self):
        from app.services.ntp_writer import generate_ntp_conf
        conf = generate_ntp_conf({"serve_local": True})
        assert "127.127.1.0" in conf

    def test_generate_no_local_clock(self):
        from app.services.ntp_writer import generate_ntp_conf
        conf = generate_ntp_conf({"serve_local": False})
        assert "127.127.1.0" not in conf

    def test_generate_restrict_default(self):
        from app.services.ntp_writer import generate_ntp_conf
        conf = generate_ntp_conf({"restrict_default": True})
        assert "restrict default" in conf

    def test_validate_no_servers_error(self):
        from app.services.ntp_writer import validate_ntp
        errors = validate_ntp({"servers": []})
        assert errors

    def test_validate_valid(self):
        from app.services.ntp_writer import validate_ntp
        errors = validate_ntp({"servers": ["0.pool.ntp.org"]})
        assert errors == []

    def test_validate_bad_network(self):
        from app.services.ntp_writer import validate_ntp
        errors = validate_ntp({"servers": ["0.pool.ntp.org"], "allowed_networks": ["not-a-net"]})
        assert errors

    def test_apply_dry_run(self, conn):
        from app.services.ntp_writer import apply_ntp, DEFAULT_SETTINGS
        import json
        conn.execute(
            "INSERT INTO service_state (key_name, value_json) VALUES ('ntp_settings', ?)",
            (json.dumps(DEFAULT_SETTINGS),)
        )
        conn.commit()
        result = apply_ntp(conn)
        assert result["ok"] is True
        assert "Non-FreeBSD" in result["message"]

    def test_status_dry_run(self):
        from app.services.ntp_writer import get_ntp_status
        status = get_ntp_status()
        assert status["state"] == "dry-run"

    def test_sync_status_dry_run(self):
        from app.services.ntp_writer import get_ntp_sync_status
        status = get_ntp_sync_status()
        assert "peers" in status


# ===========================================================================
# DHCPv6 Writer
# ===========================================================================

class TestDhcpv6Writer:

    def test_generate_kea_json(self, conn):
        from app.services.dhcpv6_writer import generate_kea_dhcp6_conf
        conn.execute(
            "UPDATE dhcpv6_pools SET enabled=1, prefix='2001:db8::/64',"
            " start_address='2001:db8::100', end_address='2001:db8::200'"
            " WHERE interface_type='LAN'"
        )
        conn.commit()
        conf = generate_kea_dhcp6_conf(conn)
        import json
        text = conf[conf.index("{"):]  # skip comment header
        data = json.loads(text)
        assert "Dhcp6" in data
        assert data["Dhcp6"]["subnet6"][0]["subnet"] == "2001:db8::/64"

    def test_generate_empty_no_subnets(self, conn):
        from app.services.dhcpv6_writer import generate_kea_dhcp6_conf
        conf = generate_kea_dhcp6_conf(conn)
        import json
        text = conf[conf.index("{"):]
        data = json.loads(text)
        assert data["Dhcp6"]["subnet6"] == []

    def test_validate_valid(self, conn):
        from app.services.dhcpv6_writer import validate_dhcpv6
        assert validate_dhcpv6(conn) == []

    def test_validate_bad_start_address(self, conn):
        from app.services.dhcpv6_writer import validate_dhcpv6
        conn.execute(
            "UPDATE dhcpv6_pools SET enabled=1, start_address='not-ipv6' WHERE interface_type='LAN'"
        )
        conn.commit()
        errors = validate_dhcpv6(conn)
        assert errors

    def test_validate_ipv4_address_rejected(self, conn):
        from app.services.dhcpv6_writer import validate_dhcpv6
        conn.execute(
            "UPDATE dhcpv6_pools SET enabled=1, start_address='192.168.1.1'"
            " WHERE interface_type='LAN'"
        )
        conn.commit()
        errors = validate_dhcpv6(conn)
        assert any("not an IPv6" in e for e in errors)

    def test_validate_short_lifetime(self, conn):
        from app.services.dhcpv6_writer import validate_dhcpv6
        conn.execute(
            "UPDATE dhcpv6_pools SET enabled=1, valid_lifetime=30 WHERE interface_type='LAN'"
        )
        conn.commit()
        errors = validate_dhcpv6(conn)
        assert any("lifetime" in e.lower() for e in errors)

    def test_apply_dry_run(self, conn):
        from app.services.dhcpv6_writer import apply_dhcpv6
        result = apply_dhcpv6(conn)
        assert result["ok"] is True
        assert "Non-FreeBSD" in result["message"]

    def test_status_dry_run(self):
        from app.services.dhcpv6_writer import get_dhcpv6_status
        assert get_dhcpv6_status()["state"] == "dry-run"

    def test_leases_empty_non_freebsd(self):
        from app.services.dhcpv6_writer import get_dhcpv6_leases
        assert get_dhcpv6_leases() == []


# ===========================================================================
# rtadvd Writer
# ===========================================================================

class TestRtadvdWriter:

    def test_generate_empty(self, conn):
        from app.services.rtadvd_writer import generate_rtadvd_conf
        conf = generate_rtadvd_conf(conn)
        assert "rtadvd" in conf.lower() or "Smart Shield" in conf

    def test_generate_with_iface(self, conn):
        from app.services.rtadvd_writer import generate_rtadvd_conf
        conn.execute(
            "INSERT INTO ra_settings (interface_name, enabled, prefix, autonomous_flag)"
            " VALUES ('em1', 1, '2001:db8::/64', 1)"
        )
        conn.commit()
        conf = generate_rtadvd_conf(conn)
        assert "em1:\\" in conf
        assert "2001:db8::" in conf

    def test_validate_no_ifaces(self, conn):
        from app.services.rtadvd_writer import validate_rtadvd
        assert validate_rtadvd(conn) == []

    def test_validate_ipv4_prefix_rejected(self, conn):
        from app.services.rtadvd_writer import validate_rtadvd
        conn.execute(
            "INSERT INTO ra_settings (interface_name, enabled, prefix)"
            " VALUES ('em0', 1, '192.168.1.0/24')"
        )
        conn.commit()
        errors = validate_rtadvd(conn)
        assert errors

    def test_apply_dry_run(self, conn):
        from app.services.rtadvd_writer import apply_rtadvd
        result = apply_rtadvd(conn)
        assert result["ok"] is True

    def test_status_dry_run(self):
        from app.services.rtadvd_writer import get_rtadvd_status
        assert get_rtadvd_status()["state"] == "dry-run"


# ===========================================================================
# DDNS Writer
# ===========================================================================

class TestDdnsWriter:

    def test_generate_empty(self, conn):
        from app.services.ddns_writer import generate_ddclient_conf
        conf = generate_ddclient_conf(conn)
        assert "ddclient" in conf.lower() or "Smart Shield" in conf

    def test_generate_with_client(self, conn):
        import json
        from app.secret_store import encrypt_secret
        from app.services.ddns_writer import generate_ddclient_conf
        clients = [{
            "disabled": False,
            "service_type": "cloudflare",
            "hostname": "home.example.com",
            "username": "user@example.com",
            "password": encrypt_secret("supersecret"),
            "interface": "em0",
        }]
        conn.execute(
            "INSERT INTO service_state (key_name, value_json) VALUES ('dynamic_dns_clients', ?)",
            (json.dumps(clients),)
        )
        conn.commit()
        conf = generate_ddclient_conf(conn)
        assert "cloudflare" in conf
        assert "home.example.com" in conf
        assert "supersecret" in conf  # decrypted for conf file

    def test_validate_no_clients_ok(self):
        from app.services.ddns_writer import validate_ddns
        assert validate_ddns([]) == []

    def test_validate_missing_hostname(self):
        from app.services.ddns_writer import validate_ddns
        errors = validate_ddns([{"service_type": "cloudflare", "username": "u"}])
        assert any("hostname" in e.lower() for e in errors)

    def test_validate_unknown_service(self):
        from app.services.ddns_writer import validate_ddns
        errors = validate_ddns([{"hostname": "h.com", "service_type": "unknownsvc", "username": "u"}])
        assert errors

    def test_validate_rfc2136_valid(self):
        from app.services.ddns_writer import validate_rfc2136
        from app.secret_store import encrypt_secret
        errors = validate_rfc2136({
            "hostname": "host.example.com",
            "zone": "example.com",
            "server": "192.168.1.1",
            "key_name": "mykey",
            "key": encrypt_secret("base64secret"),
            "key_algorithm": "hmac-sha256",
        })
        assert errors == []

    def test_validate_rfc2136_missing_zone(self):
        from app.services.ddns_writer import validate_rfc2136
        errors = validate_rfc2136({"hostname": "h.com", "zone": "", "server": "1.2.3.4",
                                    "key_name": "k", "key": "enc:abc"})
        assert any("Zone" in e for e in errors)

    def test_validate_rfc2136_legacy_hash_error(self):
        from app.services.ddns_writer import validate_rfc2136
        errors = validate_rfc2136({"hostname": "h.com", "zone": "z.com", "server": "1.2.3.4",
                                    "key_name": "k", "key": "hash:pbkdf2:...",
                                    "key_algorithm": "hmac-sha256"})
        assert any("one-way hash" in e or "cannot be used" in e for e in errors)

    def test_nsupdate_script_contains_update(self):
        from app.services.ddns_writer import generate_nsupdate_script
        from app.secret_store import encrypt_secret
        script = generate_nsupdate_script({
            "hostname": "test.example.com",
            "zone": "example.com",
            "server": "192.168.1.1",
            "key_name": "testkey",
            "key": encrypt_secret("secretkey"),
            "key_algorithm": "hmac-sha256",
            "record_type": "A",
            "ttl": "300",
            "current_ip": "1.2.3.4",
        })
        assert "server 192.168.1.1" in script
        assert "zone example.com" in script
        assert "update add test.example.com." in script
        assert "1.2.3.4" in script

    def test_status_dry_run(self):
        from app.services.ddns_writer import get_ddns_status
        status = get_ddns_status()
        assert "state" in status


# ===========================================================================
# SNMP Writer
# ===========================================================================

class TestSnmpWriter:

    def test_generate_contains_community(self):
        from app.services.snmp_writer import generate_snmpd_config
        conf = generate_snmpd_config({"community": "mytestcommunity"})
        assert "mytestcommunity" in conf

    def test_generate_has_location(self):
        from app.services.snmp_writer import generate_snmpd_config
        conf = generate_snmpd_config({"community": "x", "location": "Server Room"})
        assert "Server Room" in conf

    def test_generate_has_contact(self):
        from app.services.snmp_writer import generate_snmpd_config
        conf = generate_snmpd_config({"community": "x", "contact": "admin@corp.com"})
        assert "admin@corp.com" in conf

    def test_validate_no_community_error(self):
        from app.services.snmp_writer import validate_snmp
        errors = validate_snmp({"community": ""})
        assert errors

    def test_validate_public_community_warning(self):
        from app.services.snmp_writer import validate_snmp
        errors = validate_snmp({"community": "public"})
        assert any("public" in e.lower() or "well-known" in e.lower() for e in errors)

    def test_validate_private_community_warning(self):
        from app.services.snmp_writer import validate_snmp
        errors = validate_snmp({"community": "private"})
        assert errors

    def test_validate_invalid_port(self):
        from app.services.snmp_writer import validate_snmp
        errors = validate_snmp({"community": "strongcommunity", "port": 99999})
        assert errors

    def test_validate_valid(self):
        from app.services.snmp_writer import validate_snmp
        errors = validate_snmp({"community": "strongcommunity", "port": 161})
        assert errors == []

    def test_mask_hides_community(self):
        from app.services.snmp_writer import mask_snmp_settings
        safe = mask_snmp_settings({"community": "secret123", "port": 161})
        assert safe["community"] == "••••••••"
        assert safe["port"] == 161

    def test_status_dry_run(self):
        from app.services.snmp_writer import get_snmp_status
        assert get_snmp_status()["state"] == "dry-run"


# ===========================================================================
# UPnP Writer
# ===========================================================================

class TestUpnpWriter:

    def test_generate_contains_wan(self):
        from app.services.upnp_writer import generate_miniupnpd_conf
        conf = generate_miniupnpd_conf({"wan_interface": "em0", "lan_interface": "em1"})
        assert "ext_ifname=em0" in conf

    def test_generate_secure_mode_default(self):
        from app.services.upnp_writer import generate_miniupnpd_conf
        conf = generate_miniupnpd_conf({"wan_interface": "em0", "lan_interface": "em1"})
        assert "secure_mode=yes" in conf

    def test_generate_insecure_mode(self):
        from app.services.upnp_writer import generate_miniupnpd_conf
        conf = generate_miniupnpd_conf({
            "wan_interface": "em0", "lan_interface": "em1", "secure_mode": False
        })
        assert "secure_mode=no" in conf

    def test_generate_allowed_subnet_deny_all(self):
        from app.services.upnp_writer import generate_miniupnpd_conf
        conf = generate_miniupnpd_conf({
            "wan_interface": "em0", "lan_interface": "em1",
            "allowed_subnets": ["192.168.1.0/24"],
        })
        assert "deny 0-65535" in conf

    def test_validate_no_wan_error(self):
        from app.services.upnp_writer import validate_upnp
        errors = validate_upnp({"lan_interface": "em1"})
        assert any("WAN" in e for e in errors)

    def test_validate_no_lan_error(self):
        from app.services.upnp_writer import validate_upnp
        errors = validate_upnp({"wan_interface": "em0"})
        assert any("LAN" in e for e in errors)

    def test_validate_invalid_subnet(self):
        from app.services.upnp_writer import validate_upnp
        errors = validate_upnp({
            "wan_interface": "em0", "lan_interface": "em1",
            "allowed_subnets": ["not-a-subnet"],
        })
        assert errors

    def test_validate_port_range_reversed(self):
        from app.services.upnp_writer import validate_upnp
        errors = validate_upnp({
            "wan_interface": "em0", "lan_interface": "em1",
            "ext_port_start": 8000, "ext_port_end": 1000,
        })
        assert errors

    def test_validate_valid(self):
        from app.services.upnp_writer import validate_upnp
        errors = validate_upnp({"wan_interface": "em0", "lan_interface": "em1"})
        assert errors == []

    def test_status_dry_run(self):
        from app.services.upnp_writer import get_upnp_status
        assert get_upnp_status()["state"] == "dry-run"

    def test_mappings_empty_non_freebsd(self):
        from app.services.upnp_writer import get_active_mappings
        assert get_active_mappings() == []


# ===========================================================================
# IGMP Writer
# ===========================================================================

class TestIgmpWriter:

    def test_generate_upstream_downstream(self):
        from app.services.igmp_writer import generate_igmpproxy_conf
        settings = {
            "upstream_interfaces": [{"interface": "em0", "threshold": 1}],
            "downstream_interfaces": [{"interface": "em1", "threshold": 1}],
        }
        conf = generate_igmpproxy_conf(settings)
        assert "phyint em0 upstream" in conf
        assert "phyint em1 downstream" in conf

    def test_generate_quick_leave(self):
        from app.services.igmp_writer import generate_igmpproxy_conf
        settings = {"upstream_interfaces": [], "downstream_interfaces": [], "quick_leave": True}
        conf = generate_igmpproxy_conf(settings)
        assert "quickleave" in conf

    def test_generate_alt_subnet(self):
        from app.services.igmp_writer import generate_igmpproxy_conf
        settings = {
            "upstream_interfaces": [{"interface": "em0", "alt_subnet": ["239.0.0.0/8"]}],
            "downstream_interfaces": [{"interface": "em1"}],
        }
        conf = generate_igmpproxy_conf(settings)
        assert "239.0.0.0/8" in conf

    def test_validate_no_upstream_error(self):
        from app.services.igmp_writer import validate_igmp
        errors = validate_igmp({"downstream_interfaces": [{"interface": "em1"}]})
        assert any("upstream" in e.lower() for e in errors)

    def test_validate_no_downstream_error(self):
        from app.services.igmp_writer import validate_igmp
        errors = validate_igmp({"upstream_interfaces": [{"interface": "em0"}]})
        assert any("downstream" in e.lower() for e in errors)

    def test_validate_valid(self):
        from app.services.igmp_writer import validate_igmp
        errors = validate_igmp({
            "upstream_interfaces": [{"interface": "em0"}],
            "downstream_interfaces": [{"interface": "em1"}],
        })
        assert errors == []

    def test_status_dry_run(self):
        from app.services.igmp_writer import get_igmp_status
        assert get_igmp_status()["state"] == "dry-run"


# ===========================================================================
# Wake-on-LAN
# ===========================================================================

class TestWolSender:

    def test_send_valid_mac_loopback(self):
        from app.services.wol_sender import send_wol
        result = send_wol("aa:bb:cc:dd:ee:ff", "lo0", "127.0.0.1")
        # May fail due to permissions but should not crash
        assert "mac" in result

    def test_validate_valid_mac(self):
        from app.services.wol_sender import validate_wol
        assert validate_wol("aa:bb:cc:dd:ee:ff", "em0") == []

    def test_validate_invalid_mac(self):
        from app.services.wol_sender import validate_wol
        errors = validate_wol("NOTAMAC", "em0")
        assert errors

    def test_validate_empty_mac(self):
        from app.services.wol_sender import validate_wol
        errors = validate_wol("", "em0")
        assert errors

    def test_validate_no_interface(self):
        from app.services.wol_sender import validate_wol
        errors = validate_wol("aa:bb:cc:dd:ee:ff", "")
        assert errors

    def test_validate_hyphen_mac(self):
        from app.services.wol_sender import validate_wol
        assert validate_wol("AA-BB-CC-DD-EE-FF", "em0") == []

    def test_magic_packet_length(self):
        from app.services.wol_sender import _build_magic_packet
        pkt = _build_magic_packet("aa:bb:cc:dd:ee:ff")
        assert len(pkt) == 102  # 6 + 16*6

    def test_magic_packet_starts_with_ff(self):
        from app.services.wol_sender import _build_magic_packet
        pkt = _build_magic_packet("aa:bb:cc:dd:ee:ff")
        assert pkt[:6] == b"\xff\xff\xff\xff\xff\xff"

    def test_magic_packet_invalid_mac_raises(self):
        from app.services.wol_sender import _build_magic_packet
        with pytest.raises(ValueError):
            _build_magic_packet("invalid")


# ===========================================================================
# Captive Portal
# ===========================================================================

class TestCaptivePortal:

    def test_authenticate_creates_session(self, conn):
        from app.services.captive_portal import authenticate_session, get_active_sessions
        result = authenticate_session(conn, "aa:bb:cc:dd:ee:ff", "192.168.1.50",
                                       "testuser", duration_minutes=30)
        assert result["ok"] is True
        sessions = get_active_sessions(conn)
        assert len(sessions) == 1
        assert sessions[0]["ip_address"] == "192.168.1.50"

    def test_logout_removes_session(self, conn):
        from app.services.captive_portal import authenticate_session, logout_session, get_active_sessions
        authenticate_session(conn, "bb:cc:dd:ee:ff:00", "192.168.1.51", duration_minutes=60)
        sessions = get_active_sessions(conn)
        logout_session(conn, sessions[0]["id"])
        assert get_active_sessions(conn) == []

    def test_expire_sessions(self, conn):
        from app.services.captive_portal import expire_sessions
        # Insert an already-expired session
        conn.execute(
            "INSERT INTO captive_sessions (mac_address, ip_address, expires_at)"
            " VALUES ('cc:dd:ee:ff:00:11', '192.168.1.52', 1)"
        )
        conn.commit()
        count = expire_sessions(conn)
        assert count >= 1

    def test_generate_voucher(self, conn):
        from app.services.captive_portal import generate_voucher
        result = generate_voucher(conn, duration_minutes=120, bandwidth_kbps=1000)
        assert result["ok"] is True
        assert len(result["code"]) == 8

    def test_redeem_voucher(self, conn):
        from app.services.captive_portal import generate_voucher, redeem_voucher
        v = generate_voucher(conn, duration_minutes=30)
        result = redeem_voucher(conn, v["code"], "dd:ee:ff:00:11:22", "192.168.1.53")
        assert result["ok"] is True

    def test_redeem_twice_fails(self, conn):
        from app.services.captive_portal import generate_voucher, redeem_voucher
        v = generate_voucher(conn, duration_minutes=30)
        redeem_voucher(conn, v["code"], "ee:ff:00:11:22:33", "192.168.1.54")
        result = redeem_voucher(conn, v["code"], "ff:00:11:22:33:44", "192.168.1.55")
        assert result["ok"] is False

    def test_generate_pf_anchor_contains_rules(self, conn):
        from app.services.captive_portal import generate_pf_anchor
        anchor = generate_pf_anchor(conn)
        assert "authenticated_clients" in anchor
        assert "rdr on" in anchor

    def test_generate_pf_anchor_redirects_http_only(self, conn):
        from app.services.captive_portal import generate_pf_anchor
        anchor = generate_pf_anchor(conn)
        assert "port 80" in anchor
        assert "port 443" not in anchor

    def test_generate_pf_anchor_defaults_to_lan_ip(self, conn):
        from app.services.captive_portal import generate_pf_anchor
        conn.execute("UPDATE lan_config SET ipv4_address='192.168.50.1/24' WHERE id=1")
        conn.commit()
        anchor = generate_pf_anchor(conn)
        assert "-> 192.168.50.1 port 5000" in anchor

    def test_apply_dry_run(self, conn):
        from app.services.captive_portal import apply_captive_portal
        result = apply_captive_portal(conn)
        assert result["ok"] is True

    def test_status_returns_dict(self, conn):
        from app.services.captive_portal import get_captive_status
        status = get_captive_status(conn)
        assert "active_sessions" in status
        assert "state" in status
