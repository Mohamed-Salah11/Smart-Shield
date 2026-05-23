"""Route-level tests for firewall blueprint."""
import pytest
from tests.conftest import _create_user, _login, _create_group, _add_user_to_group, _grant_permission


class TestFirewallRoutes:
    def test_firewall_home_requires_login(self, client):
        r = client.get("/firewall/")
        assert r.status_code in (302, 401)

    def test_firewall_home_accessible_when_logged_in(self, superuser):
        client, _ = superuser
        # /firewall/ redirects to the rules page; follow it and confirm 200.
        r = client.get("/firewall/", follow_redirects=True)
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


# ─── All six Shield Policy pages load ─────────────────────────────────────────

class TestShieldPolicyPages:
    @pytest.mark.parametrize("path", [
        "/firewall/rules", "/firewall/nat", "/firewall/aliases",
        "/firewall/schedules", "/firewall/traffic-shaper", "/firewall/virtual-ips",
    ])
    def test_page_loads(self, superuser, path):
        client, _ = superuser
        r = client.get(path, follow_redirects=True)
        assert r.status_code == 200


# ─── Read endpoints for the 4 NAT tabs + aliases + schedules + shaper + vips ─

class TestShieldPolicyReadEndpoints:
    @pytest.mark.parametrize("path", [
        # NAT (4 tabs)
        "/firewall/api/nat/pf", "/firewall/api/nat/1to1",
        "/firewall/api/nat/outbound", "/firewall/api/nat/npt",
        # Aliases
        "/firewall/api/aliases",
        # Schedules
        "/firewall/api/schedules",
        # Shaper / Limiters / VIPs
        "/firewall/get-traffic-shaper-configs",
        "/firewall/get-limiters-configs",
        "/firewall/get-virtual-ips-configs",
        # Apply state
        "/firewall/api/apply/status",
        "/firewall/api/apply/preview",
    ])
    def test_get_endpoint(self, superuser, path):
        client, _ = superuser
        r = client.get(path)
        assert r.status_code == 200, f"{path} -> {r.status_code}"


# ─── Permission gates: every mutating endpoint should reject plain_user ──────

class TestShieldPolicyPermissionGates:
    @pytest.mark.parametrize("method,path,body", [
        # NAT pf
        ("POST",   "/firewall/api/nat/pf", {}),
        ("PUT",    "/firewall/api/nat/pf/1", {}),
        ("DELETE", "/firewall/api/nat/pf/1", None),
        # NAT 1to1
        ("POST",   "/firewall/api/nat/1to1", {}),
        ("PUT",    "/firewall/api/nat/1to1/1", {}),
        ("DELETE", "/firewall/api/nat/1to1/1", None),
        # NAT outbound
        ("POST",   "/firewall/api/nat/outbound", {}),
        ("PUT",    "/firewall/api/nat/outbound/1", {}),
        ("DELETE", "/firewall/api/nat/outbound/1", None),
        # NAT npt
        ("POST",   "/firewall/api/nat/npt", {}),
        ("PUT",    "/firewall/api/nat/npt/1", {}),
        ("DELETE", "/firewall/api/nat/npt/1", None),
        # Aliases
        ("POST",   "/firewall/api/aliases", {}),
        ("PUT",    "/firewall/api/aliases/1", {}),
        ("DELETE", "/firewall/api/aliases/1", None),
        # Schedules
        ("POST",   "/firewall/api/schedules", {}),
        ("PUT",    "/firewall/api/schedules/1", {}),
        ("DELETE", "/firewall/api/schedules/1", None),
        # Shaper / Limiters / VIPs (these endpoints sit directly under /firewall/)
        ("POST",   "/firewall/save-traffic-shaper-config", {}),
        ("PUT",    "/firewall/update-traffic-shaper-config/1", {}),
        ("DELETE", "/firewall/delete-traffic-shaper-config/1", None),
        ("POST",   "/firewall/save-limiters-config", {}),
        ("PUT",    "/firewall/update-limiters-config/1", {}),
        ("DELETE", "/firewall/delete-limiters-config/1", None),
        ("POST",   "/firewall/save-virtual-ips-config", {}),
        ("PUT",    "/firewall/update-virtual-ips-config/1", {}),
        ("DELETE", "/firewall/delete-virtual-ips-config/1", None),
        # Apply / Rollback
        ("POST",   "/firewall/api/apply", {}),
        ("POST",   "/firewall/api/apply/rollback", {}),
        ("POST",   "/firewall/api/apply/all", {}),
        # Rule reorder
        ("POST",   "/firewall/api/rules/floating/reorder", {}),
    ])
    def test_mutation_rejects_plain_user(self, plain_user, method, path, body):
        client, _ = plain_user
        if method == "POST":
            r = client.post(path, json=body or {})
        elif method == "PUT":
            r = client.put(path, json=body or {})
        else:
            r = client.delete(path)
        assert r.status_code in (401, 403), f"{method} {path} -> {r.status_code}"


# ─── Apply endpoints (superuser, dry-run) ─────────────────────────────────────

class TestShieldPolicyApply:
    def test_apply_endpoint(self, superuser):
        client, _ = superuser
        r = client.post("/firewall/api/apply", json={})
        assert r.status_code == 200


# ─── Route registration regression guard ─────────────────────────────────────

class TestShieldPolicyRouteRegistration:
    def test_required_endpoints_registered(self, app):
        rules = {str(r) for r in app.url_map.iter_rules()}
        required = (
            "/firewall/rules", "/firewall/nat", "/firewall/aliases",
            "/firewall/schedules", "/firewall/traffic-shaper", "/firewall/virtual-ips",
            "/firewall/api/rules/floating", "/firewall/api/rules/wan", "/firewall/api/rules/lan",
            "/firewall/api/nat/pf", "/firewall/api/nat/1to1",
            "/firewall/api/nat/outbound", "/firewall/api/nat/npt",
            "/firewall/api/aliases", "/firewall/api/schedules",
            "/firewall/api/apply", "/firewall/api/apply/status",
            "/firewall/api/apply/preview", "/firewall/api/apply/rollback",
            "/firewall/api/apply/all",
            "/firewall/get-traffic-shaper-configs",
            "/firewall/save-traffic-shaper-config",
            "/firewall/get-limiters-configs", "/firewall/save-limiters-config",
            "/firewall/get-virtual-ips-configs", "/firewall/save-virtual-ips-config",
        )
        missing = [p for p in required if p not in rules]
        assert not missing, f"missing routes: {missing}"
