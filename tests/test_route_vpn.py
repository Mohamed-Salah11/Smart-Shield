"""Route-level tests for VPN blueprint."""
import pytest


class TestVpnRoutes:
    def test_vpn_home_requires_login(self, client):
        r = client.get("/vpn/")
        assert r.status_code in (302, 401)

    def test_vpn_home_accessible(self, superuser):
        client, _ = superuser
        r = client.get("/vpn/")
        assert r.status_code == 200

    def test_openvpn_servers_page(self, superuser):
        client, _ = superuser
        r = client.get("/vpn/openvpn/servers")
        assert r.status_code == 200

    def test_openvpn_clients_page(self, superuser):
        client, _ = superuser
        r = client.get("/vpn/openvpn/clients")
        assert r.status_code == 200

    def test_ipsec_page(self, superuser):
        client, _ = superuser
        r = client.get("/vpn/ipsec")
        assert r.status_code == 200

    def test_l2tp_page(self, superuser):
        client, _ = superuser
        r = client.get("/vpn/l2tp")
        assert r.status_code == 200

    def test_get_openvpn_servers_api(self, superuser):
        client, _ = superuser
        r = client.get("/vpn/api/openvpn/get-servers")
        assert r.status_code == 200

    def test_add_openvpn_server_requires_permission(self, plain_user):
        client, _ = plain_user
        r = client.post("/vpn/api/openvpn/save-server", json={
            "protocol": "udp4",
            "device_mode": "tun",
            "local_port": 1194,
            "tunnel_network": "10.8.0.0/24",
        })
        assert r.status_code in (401, 403)

    def test_certificates_page(self, superuser):
        client, _ = superuser
        r = client.get("/system/certificates")
        assert r.status_code == 200
