"""
tests/test_auth.py
------------------
Tests for authentication enforcement, superuser access, and permission denial.
"""

import pytest
from tests.conftest import _create_user, _login


# ---------------------------------------------------------------------------
# Login required
# ---------------------------------------------------------------------------

class TestLoginRequired:
    def test_unauthenticated_redirects_to_login(self, client):
        """Accessing a protected page without auth redirects to /login."""
        r = client.get("/system/dashboard", follow_redirects=False)
        assert r.status_code in (301, 302)
        assert "/login" in r.headers.get("Location", "")

    def test_unauthenticated_api_returns_401(self, client):
        """Calling a permission-protected API endpoint without auth returns JSON 401."""
        r = client.post(
            "/firewall/api/rules/floating",
            json={"interface": "WAN", "protocol": "tcp"},
        )
        assert r.status_code == 401
        data = r.get_json()
        assert data is not None
        assert "error" in data

    def test_login_with_valid_credentials(self, app, client):
        """Valid credentials produce a session and allow dashboard access."""
        _create_user(app, "validuser", "validpass", is_superuser=0)
        r = _login(client, "validuser", "validpass")
        assert r.status_code == 200

    def test_login_with_wrong_password_stays_on_login(self, app, client):
        """Wrong password keeps the user on the login page."""
        _create_user(app, "wrongpwuser", "correct", is_superuser=0)
        r = _login(client, "wrongpwuser", "WRONG")
        assert r.status_code == 200
        assert b"login" in r.data.lower() or b"password" in r.data.lower()


# ---------------------------------------------------------------------------
# Superuser bypass
# ---------------------------------------------------------------------------

class TestSuperuserAccess:
    def test_superuser_can_read_firewall_api(self, superuser):
        client, _ = superuser
        r = client.get("/firewall/api/rules/floating")
        assert r.status_code == 200
        data = r.get_json()
        assert data is not None
        assert data.get("success") is True

    def test_superuser_can_read_vpn_api(self, superuser):
        client, _ = superuser
        r = client.get("/vpn/api/ipsec/p1")
        assert r.status_code == 200

    def test_superuser_can_read_network_api(self, superuser):
        client, _ = superuser
        r = client.get("/api/network/interfaces")
        assert r.status_code == 200

    def test_superuser_can_write_firewall(self, superuser):
        client, _ = superuser
        r = client.post(
            "/firewall/api/rules/floating",
            json={
                "interface": "WAN",
                "protocol": "any",
                "source": "any",
                "destination": "any",
                "description": "Superuser test rule",
            },
        )
        assert r.status_code not in (401, 403)


# ---------------------------------------------------------------------------
# Non-superuser permission denial
# ---------------------------------------------------------------------------

class TestPermissionDenial:
    def test_plain_user_denied_firewall_write(self, plain_user):
        """Non-superuser without api.firewall.edit gets JSON 403."""
        client, _ = plain_user
        r = client.post(
            "/firewall/api/rules/floating",
            json={"interface": "WAN", "protocol": "tcp"},
        )
        assert r.status_code == 403
        data = r.get_json()
        assert data is not None
        assert data.get("error") == "Forbidden"
        assert "api.firewall.edit" in data.get("permission", "")

    def test_plain_user_denied_vpn_write(self, plain_user):
        client, _ = plain_user
        r = client.post("/vpn/api/ipsec/p1", json={"remote_gateway": "1.2.3.4"})
        assert r.status_code == 403

    def test_plain_user_denied_network_write(self, plain_user):
        client, _ = plain_user
        r = client.put(
            "/api/network/interfaces/LAN",
            json={"ipv4_config_type": "static"},
        )
        assert r.status_code == 403

    def test_plain_user_denied_ids_toggle(self, plain_user):
        client, _ = plain_user
        r = client.post("/ids/api/toggle", json={"enabled": True})
        assert r.status_code == 403

    def test_permitted_user_can_write_firewall(self, permitted_user):
        """User with api.firewall.edit can call the firewall write endpoint."""
        client, _ = permitted_user
        r = client.post(
            "/firewall/api/rules/floating",
            json={
                "interface": "WAN",
                "protocol": "any",
                "source": "any",
                "destination": "any",
                "description": "Permission test rule",
            },
        )
        assert r.status_code not in (401, 403)

    def test_permitted_user_still_denied_vpn(self, permitted_user):
        """api.firewall.edit does not grant access to VPN write endpoints."""
        client, _ = permitted_user
        r = client.post("/vpn/api/ipsec/p1", json={"remote_gateway": "1.2.3.4"})
        assert r.status_code == 403

    def test_wildcard_permission(self, app, client):
        """A group with 'api.firewall.*' grants api.firewall.edit access."""
        from tests.conftest import (
            _create_user, _create_group, _add_user_to_group, _grant_permission
        )
        uid = _create_user(app, "wildcard_fw", "wpass", is_superuser=0)
        gid = _create_group(app, "fw_wildcard_group")
        _add_user_to_group(app, uid, gid)
        _grant_permission(app, gid, "api.firewall.*")
        _login(client, "wildcard_fw", "wpass")

        r = client.post(
            "/firewall/api/rules/floating",
            json={"interface": "WAN", "protocol": "any"},
        )
        assert r.status_code not in (401, 403)


# ---------------------------------------------------------------------------
# CSRF
# ---------------------------------------------------------------------------

class TestCSRF:
    def test_get_requests_never_blocked_by_csrf(self, client):
        """GET requests must never be rejected by the CSRF guard."""
        r = client.get("/login")
        assert r.status_code == 200

    def test_options_not_blocked(self, client):
        r = client.options("/login")
        assert r.status_code != 400

    def test_csrf_skipped_in_testing_mode(self, client):
        """In TESTING mode, POST without CSRF token must not get 400."""
        r = client.post(
            "/firewall/api/rules/floating",
            json={"interface": "WAN"},
        )
        # Should get 401 (no auth) not 400 (CSRF rejection).
        assert r.status_code == 401
