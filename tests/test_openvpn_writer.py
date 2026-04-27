"""
tests/test_openvpn_writer.py
----------------------------
Unit tests for app/services/openvpn_writer.py.
No FreeBSD required.
"""
import os
import pytest

os.environ.setdefault("SMARTSHIELD_DB_PATH", "file:ovpntest?mode=memory&cache=shared")
os.environ.setdefault("SECRET_KEY", "test-ovpn-key")
os.environ.setdefault("SMARTSHIELD_MASTER_KEY",
    __import__("base64").b64encode(__import__("secrets").token_bytes(32)).decode())


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def server_row():
    return {
        "id": 1, "description": "Test Server",
        "protocol": "udp4", "device_mode": "tun", "local_port": 1194,
        "tunnel_network": "10.8.0.0/24", "topology": "subnet",
        "redirect_gateway": 0, "local_network": "",
        "max_clients": 50, "inter_client_communication": 0,
        "compression": "", "dns_server1": "1.1.1.1", "dns_server2": "",
        "ntp_server1": "", "tls_key": 1, "custom_options": "",
    }


@pytest.fixture()
def client_row():
    return {
        "id": 1, "description": "Test Client",
        "protocol": "udp4", "server_hostname": "vpn.example.com",
        "server_port": 1194, "encryption_algorithm": "AES-256-GCM",
        "auth_digest_algorithm": "SHA256", "inactivity_timeout": 300,
        "ping_interval": 10, "ping_timeout": 60, "verbosity_level": 3,
        "use_tls_key": 0, "custom_options": "",
    }


# ---------------------------------------------------------------------------
# Config generation
# ---------------------------------------------------------------------------

class TestGenerateServerConf:

    def test_contains_port(self, server_row):
        from app.services.openvpn_writer import generate_server_conf
        conf = generate_server_conf(server_row)
        assert "port 1194" in conf

    def test_contains_proto(self, server_row):
        from app.services.openvpn_writer import generate_server_conf
        conf = generate_server_conf(server_row)
        assert "proto udp" in conf

    def test_contains_server_directive(self, server_row):
        from app.services.openvpn_writer import generate_server_conf
        conf = generate_server_conf(server_row)
        assert "server 10.8.0.0 255.255.255.0" in conf

    def test_dns_push_present(self, server_row):
        from app.services.openvpn_writer import generate_server_conf
        conf = generate_server_conf(server_row)
        assert 'push "dhcp-option DNS 1.1.1.1"' in conf

    def test_tls_crypt_present_when_enabled(self, server_row):
        from app.services.openvpn_writer import generate_server_conf
        conf = generate_server_conf(server_row)
        assert "tls-crypt" in conf

    def test_tls_crypt_absent_when_disabled(self, server_row):
        from app.services.openvpn_writer import generate_server_conf
        server_row["tls_key"] = 0
        conf = generate_server_conf(server_row)
        assert "tls-crypt" not in conf

    def test_redirect_gateway_push(self, server_row):
        from app.services.openvpn_writer import generate_server_conf
        server_row["redirect_gateway"] = 1
        conf = generate_server_conf(server_row)
        assert "redirect-gateway" in conf

    def test_custom_options_included(self, server_row):
        from app.services.openvpn_writer import generate_server_conf
        server_row["custom_options"] = "# my custom option"
        conf = generate_server_conf(server_row)
        assert "my custom option" in conf

    def test_tcp_proto(self, server_row):
        from app.services.openvpn_writer import generate_server_conf
        server_row["protocol"] = "tcp4"
        conf = generate_server_conf(server_row)
        assert "proto tcp" in conf

    def test_security_user_nobody(self, server_row):
        from app.services.openvpn_writer import generate_server_conf
        conf = generate_server_conf(server_row)
        assert "user nobody" in conf


class TestGenerateClientConf:

    def test_client_directive(self, client_row):
        from app.services.openvpn_writer import generate_client_conf
        conf = generate_client_conf(client_row)
        assert "client" in conf

    def test_remote_directive(self, client_row):
        from app.services.openvpn_writer import generate_client_conf
        conf = generate_client_conf(client_row)
        assert "remote vpn.example.com 1194" in conf

    def test_cipher(self, client_row):
        from app.services.openvpn_writer import generate_client_conf
        conf = generate_client_conf(client_row)
        assert "AES-256-GCM" in conf

    def test_tls_crypt_absent_by_default(self, client_row):
        from app.services.openvpn_writer import generate_client_conf
        conf = generate_client_conf(client_row)
        assert "tls-crypt" not in conf

    def test_tls_crypt_present_when_enabled(self, client_row):
        from app.services.openvpn_writer import generate_client_conf
        client_row["use_tls_key"] = 1
        conf = generate_client_conf(client_row)
        assert "tls-crypt" in conf


# ---------------------------------------------------------------------------
# Validation — server
# ---------------------------------------------------------------------------

class TestValidateServer:

    def test_valid_server_no_errors(self, server_row):
        from app.services.openvpn_writer import validate_server
        assert validate_server(server_row) == []

    def test_missing_protocol_error(self, server_row):
        from app.services.openvpn_writer import validate_server
        server_row["protocol"] = ""
        errors = validate_server(server_row)
        assert any("Protocol" in e for e in errors)

    def test_unknown_protocol_error(self, server_row):
        from app.services.openvpn_writer import validate_server
        server_row["protocol"] = "ftp"
        errors = validate_server(server_row)
        assert any("protocol" in e.lower() for e in errors)

    def test_invalid_port_error(self, server_row):
        from app.services.openvpn_writer import validate_server
        server_row["local_port"] = 99999
        errors = validate_server(server_row)
        assert any("65535" in e or "Port" in e for e in errors)

    def test_invalid_tunnel_network_error(self, server_row):
        from app.services.openvpn_writer import validate_server
        server_row["tunnel_network"] = "not-a-cidr"
        errors = validate_server(server_row)
        assert any("Tunnel" in e for e in errors)

    def test_missing_tunnel_network_error(self, server_row):
        from app.services.openvpn_writer import validate_server
        server_row["tunnel_network"] = ""
        errors = validate_server(server_row)
        assert any("Tunnel" in e for e in errors)

    def test_invalid_device_mode_error(self, server_row):
        from app.services.openvpn_writer import validate_server
        server_row["device_mode"] = "dummy"
        errors = validate_server(server_row)
        assert any("tun" in e or "tap" in e for e in errors)


# ---------------------------------------------------------------------------
# Validation — client
# ---------------------------------------------------------------------------

class TestValidateClient:

    def test_valid_client_no_errors(self, client_row):
        from app.services.openvpn_writer import validate_client
        assert validate_client(client_row) == []

    def test_missing_hostname_error(self, client_row):
        from app.services.openvpn_writer import validate_client
        client_row["server_hostname"] = ""
        errors = validate_client(client_row)
        assert any("hostname" in e.lower() for e in errors)

    def test_invalid_port_error(self, client_row):
        from app.services.openvpn_writer import validate_client
        client_row["server_port"] = 0
        errors = validate_client(client_row)
        assert any("65535" in e or "Port" in e or "port" in e for e in errors)

    def test_unknown_protocol_error(self, client_row):
        from app.services.openvpn_writer import validate_client
        client_row["protocol"] = "xyz"
        errors = validate_client(client_row)
        assert errors


# ---------------------------------------------------------------------------
# Status / connected clients (non-FreeBSD)
# ---------------------------------------------------------------------------

class TestGetOpenvpnStatus:

    def test_non_freebsd_returns_not_running(self):
        from app.services.openvpn_writer import get_openvpn_status
        status = get_openvpn_status()
        assert status["running"] is False

    def test_connected_clients_empty_when_no_status_file(self):
        from app.services.openvpn_writer import get_connected_clients
        clients = get_connected_clients(999)
        assert clients == []

    def test_log_empty_when_no_log_file(self):
        from app.services.openvpn_writer import get_openvpn_log
        log = get_openvpn_log(999)
        assert log == ""


# ---------------------------------------------------------------------------
# write / apply (dry-run)
# ---------------------------------------------------------------------------

class TestWriteOpenVpnConfigs:

    def test_non_freebsd_returns_ok(self):
        import secrets
        os.environ["SMARTSHIELD_DB_PATH"] = f"file:ovpn_{secrets.token_hex(4)}?mode=memory&cache=shared"
        from app.database import init_db, get_db
        from app.services.openvpn_writer import write_openvpn_configs
        init_db()
        conn = get_db()
        result = write_openvpn_configs(conn)
        # No servers → returns ok with "No enabled" message
        assert result["ok"] is True
