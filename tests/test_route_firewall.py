"""Route-level tests for firewall blueprint."""
import pytest
from tests.conftest import _create_user, _login, _create_group, _add_user_to_group, _grant_permission


class TestFirewallRoutes:
    def test_firewall_home_requires_login(self, client):
        r = client.get("/firewall/")
        assert r.status_code in (302, 401)

    def test_firewall_home_accessible_when_logged_in(self, superuser):
        client, _ = superuser
        r = client.get("/firewall/")
        assert r.status_code == 200

    def test_get_floating_rules_empty(self, superuser):
        client, _ = superuser
        r = client.get("/firewall/api/rules/floating")
        assert r.status_code == 200
        data = r.get_json()
        assert data["success"] is True
        assert isinstance(data["rules"], list)

    def test_add_floating_rule_requires_permission(self, plain_user):
        client, _ = plain_user
        r = client.post("/firewall/api/rules/floating", json={
            "action": "pass", "source": "any", "destination": "any",
        })
        assert r.status_code in (401, 403)

    def test_add_floating_rule_succeeds_with_permission(self, permitted_user):
        client, _ = permitted_user
        r = client.post("/firewall/api/rules/floating", json={
            "action": "pass",
            "source": "192.168.1.0/24",
            "destination": "any",
            "protocol": "tcp",
            "description": "test rule",
        })
        assert r.status_code == 200
        data = r.get_json()
        assert data["success"] is True

    def test_add_and_delete_floating_rule(self, superuser):
        client, _ = superuser
        # Add
        r = client.post("/firewall/api/rules/floating", json={
            "action": "block", "source": "10.0.0.0/8", "destination": "any",
            "description": "delete me",
        })
        assert r.status_code == 200
        rule_id = r.get_json().get("id")
        assert rule_id is not None
        # Delete
        r2 = client.delete(f"/firewall/api/rules/floating/{rule_id}")
        assert r2.status_code == 200
        assert r2.get_json()["success"] is True

    def test_get_wan_rules(self, superuser):
        client, _ = superuser
        r = client.get("/firewall/api/rules/wan")
        assert r.status_code == 200
        assert r.get_json()["success"] is True

    def test_get_lan_rules(self, superuser):
        client, _ = superuser
        r = client.get("/firewall/api/rules/lan")
        assert r.status_code == 200
        assert r.get_json()["success"] is True

    def test_traffic_shaper_page(self, superuser):
        client, _ = superuser
        r = client.get("/firewall/traffic-shaper")
        assert r.status_code == 200
