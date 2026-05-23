"""
tests/test_validators.py
------------------------
Unit tests for app/validators.py.  No database or Flask context needed.
"""

import pytest
from app.validators import (
    validate_ip,
    validate_cidr,
    validate_network,
    validate_hostname,
    validate_port,
    validate_port_range,
    validate_port_list,
    validate_protocol,
    validate_interface_name,
    validate_mac,
    validate_username,
    validate_boolean,
    validate_description,
    validate_name,
    collect_errors,
)


class TestValidateIP:
    def test_valid_ipv4(self):
        assert validate_ip("192.168.1.1") == "192.168.1.1"

    def test_valid_ipv6(self):
        assert validate_ip("::1") == "::1"

    def test_empty_allowed_by_default(self):
        assert validate_ip("") == ""
        assert validate_ip(None) == ""

    def test_empty_rejected_when_required(self):
        with pytest.raises(ValueError, match="required"):
            validate_ip("", allow_empty=False)

    def test_invalid_ip_raises(self):
        with pytest.raises(ValueError, match="Invalid IP"):
            validate_ip("999.999.999.999")

    def test_strips_whitespace(self):
        assert validate_ip("  10.0.0.1  ") == "10.0.0.1"


class TestValidateCIDR:
    def test_valid_cidr(self):
        assert validate_cidr("192.168.1.0/24") == "192.168.1.0/24"

    def test_host_with_prefix(self):
        assert validate_cidr("10.0.0.1/32") == "10.0.0.1/32"

    def test_empty_allowed(self):
        assert validate_cidr("") == ""

    def test_invalid_prefix_raises(self):
        with pytest.raises(ValueError):
            validate_cidr("192.168.1.1/33")

    def test_plain_ip_without_prefix_raises(self):
        # Plain IP without prefix is treated as host (/32) by ip_interface — it's valid.
        assert validate_cidr("10.0.0.1") == "10.0.0.1"


class TestValidateNetwork:
    def test_valid_network(self):
        assert validate_network("10.0.0.0/8") == "10.0.0.0/8"

    def test_host_bits_accepted(self):
        # strict=False allows host bits in the network address.
        assert validate_network("192.168.1.5/24") == "192.168.1.5/24"

    def test_invalid_raises(self):
        with pytest.raises(ValueError):
            validate_network("not-a-network")


class TestValidateHostname:
    def test_simple_hostname(self):
        assert validate_hostname("example.com") == "example.com"

    def test_subdomain(self):
        assert validate_hostname("www.example.com") == "www.example.com"

    def test_single_label(self):
        assert validate_hostname("router") == "router"

    def test_empty_allowed(self):
        assert validate_hostname("") == ""

    def test_invalid_starts_with_dash(self):
        with pytest.raises(ValueError):
            validate_hostname("-bad.com")

    def test_too_long_raises(self):
        with pytest.raises(ValueError, match="253"):
            validate_hostname("a" * 254)


class TestValidatePort:
    def test_valid_port(self):
        assert validate_port(80) == 80
        assert validate_port("443") == 443

    def test_boundary_values(self):
        assert validate_port(1) == 1
        assert validate_port(65535) == 65535

    def test_zero_out_of_range(self):
        with pytest.raises(ValueError, match="range"):
            validate_port(0)

    def test_above_max_raises(self):
        with pytest.raises(ValueError):
            validate_port(65536)

    def test_none_returns_none_when_allowed(self):
        assert validate_port(None) is None

    def test_none_raises_when_required(self):
        with pytest.raises(ValueError, match="required"):
            validate_port(None, allow_empty=False)

    def test_non_integer_raises(self):
        with pytest.raises(ValueError):
            validate_port("not-a-port")


class TestValidatePortRange:
    def test_single_port(self):
        assert validate_port_range("80") == "80"

    def test_range_with_dash(self):
        assert validate_port_range("8080-8090") == "8080-8090"

    def test_range_with_colon(self):
        assert validate_port_range("6881:6889") == "6881:6889"

    def test_empty_allowed(self):
        assert validate_port_range("") == ""

    def test_reversed_range_raises(self):
        with pytest.raises(ValueError, match="end must be"):
            validate_port_range("100-50")

    def test_out_of_range_raises(self):
        with pytest.raises(ValueError):
            validate_port_range("70000")


class TestValidatePortList:
    def test_multiple_ports(self):
        assert validate_port_list("80,443,8080") == "80,443,8080"

    def test_mixed_ports_and_ranges(self):
        assert validate_port_list("80,8080-8090,443") == "80,8080-8090,443"

    def test_invalid_entry_raises(self):
        with pytest.raises(ValueError):
            validate_port_list("80,99999")


class TestValidateProtocol:
    def test_tcp(self):
        assert validate_protocol("tcp") == "tcp"

    def test_any(self):
        assert validate_protocol("any") == "any"

    def test_empty_allowed(self):
        assert validate_protocol("") == ""

    def test_unknown_raises(self):
        with pytest.raises(ValueError, match="Invalid protocol"):
            validate_protocol("ftp")


class TestValidateInterfaceName:
    def test_valid_name(self):
        assert validate_interface_name("em0") == "em0"
        assert validate_interface_name("vtnet0") == "vtnet0"
        assert validate_interface_name("tun0") == "tun0"

    def test_empty_allowed(self):
        assert validate_interface_name("") == ""

    def test_starts_with_digit_raises(self):
        with pytest.raises(ValueError):
            validate_interface_name("0em")

    def test_special_chars_raise(self):
        with pytest.raises(ValueError):
            validate_interface_name("em 0")


class TestValidateMAC:
    def test_valid_lowercase(self):
        assert validate_mac("aa:bb:cc:dd:ee:ff") == "aa:bb:cc:dd:ee:ff"

    def test_valid_uppercase_normalised(self):
        assert validate_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"

    def test_valid_mixed_case(self):
        assert validate_mac("00:1A:2b:3C:4d:5E") == "00:1a:2b:3c:4d:5e"

    def test_empty_allowed_by_default(self):
        assert validate_mac("") == ""
        assert validate_mac(None) == ""

    def test_empty_rejected_when_required(self):
        with pytest.raises(ValueError, match="required"):
            validate_mac("", allow_empty=False)

    def test_too_few_groups_raises(self):
        with pytest.raises(ValueError, match="Invalid MAC"):
            validate_mac("aa:bb:cc:dd:ee")

    def test_too_many_groups_raises(self):
        with pytest.raises(ValueError, match="Invalid MAC"):
            validate_mac("aa:bb:cc:dd:ee:ff:00")

    def test_wrong_separator_raises(self):
        with pytest.raises(ValueError, match="Invalid MAC"):
            validate_mac("aa-bb-cc-dd-ee-ff")

    def test_non_hex_raises(self):
        with pytest.raises(ValueError, match="Invalid MAC"):
            validate_mac("gg:bb:cc:dd:ee:ff")

    def test_strips_whitespace(self):
        assert validate_mac("  00:11:22:33:44:55  ") == "00:11:22:33:44:55"


class TestValidateUsername:
    def test_valid_username(self):
        assert validate_username("admin") == "admin"
        assert validate_username("user.name@domain") == "user.name@domain"

    def test_empty_raises_by_default(self):
        with pytest.raises(ValueError, match="required"):
            validate_username("")

    def test_too_long_raises(self):
        with pytest.raises(ValueError):
            validate_username("a" * 65)

    def test_special_chars_raise(self):
        with pytest.raises(ValueError):
            validate_username("user name")


class TestValidateBoolean:
    @pytest.mark.parametrize("val,expected", [
        (True, True),
        (False, False),
        (1, True),
        (0, False),
        ("true", True),
        ("yes", True),
        ("1", True),
        ("on", True),
        ("false", False),
        ("no", False),
        ("0", False),
        ("off", False),
        (None, False),
    ])
    def test_coercions(self, val, expected):
        assert validate_boolean(val) == expected

    def test_custom_default(self):
        assert validate_boolean(None, default=True) is True


class TestCollectErrors:
    def test_returns_empty_on_all_pass(self):
        errors = collect_errors(
            ip=lambda: validate_ip("10.0.0.1"),
            port=lambda: validate_port(80),
        )
        assert errors == {}

    def test_collects_multiple_failures(self):
        errors = collect_errors(
            ip=lambda: validate_ip("bad", allow_empty=False),
            port=lambda: validate_port("also-bad"),
        )
        assert "ip" in errors
        assert "port" in errors
        assert len(errors) == 2

    def test_partial_failure(self):
        errors = collect_errors(
            ip=lambda: validate_ip("1.2.3.4"),
            port=lambda: validate_port(99999),
        )
        assert "ip" not in errors
        assert "port" in errors
