"""Route-level tests for services blueprint."""
import pytest


class TestServicesRoutes:
    def test_services_home_requires_login(self, client):
        r = client.get("/services/")
        assert r.status_code in (302, 401)

    def test_services_home_accessible(self, superuser):
        client, _ = superuser
        r = client.get("/services/")
        assert r.status_code == 200

    def test_dhcp_server_page(self, superuser):
        client, _ = superuser
        r = client.get("/services/dhcp-server")
        assert r.status_code == 200

    def test_dns_resolver_page(self, superuser):
        client, _ = superuser
        r = client.get("/services/dns-resolver")
        assert r.status_code == 200

    def test_ntp_page(self, superuser):
        client, _ = superuser
        r = client.get("/services/ntp")
        assert r.status_code == 200

    def test_api_get_ntp(self, superuser):
        client, _ = superuser
        r = client.get("/services/api/ntp")
        assert r.status_code == 200
        assert r.get_json().get("ok") is True

    def test_api_save_ntp_requires_permission(self, plain_user):
        client, _ = plain_user
        r = client.post("/services/api/ntp", json={"servers": ["pool.ntp.org"]})
        assert r.status_code in (401, 403)

    def test_captive_portal_settings_get(self, superuser):
        client, _ = superuser
        r = client.get("/services/api/captive-portal/settings")
        assert r.status_code == 200
        data = r.get_json()
        assert data["ok"] is True
        assert "settings" in data

    def test_captive_portal_settings_save_requires_permission(self, plain_user):
        client, _ = plain_user
        r = client.post("/services/api/captive-portal/settings", json={"enabled": True})
        assert r.status_code in (401, 403)

    def test_pppoe_status(self, superuser):
        client, _ = superuser
        r = client.get("/services/api/pppoe/status")
        assert r.status_code == 200
        data = r.get_json()
        assert data["ok"] is True

    def test_config_backup_list(self, superuser):
        client, _ = superuser
        r = client.get("/services/api/config-backup/list")
        assert r.status_code == 200
        data = r.get_json()
        assert data["ok"] is True
        assert isinstance(data["versions"], list)

    def test_dhcpv6_status(self, superuser):
        client, _ = superuser
        r = client.get("/services/api/dhcpv6/status")
        assert r.status_code == 200
