"""Route-level tests for the VPN (Secure Tunnels) blueprint.

Covers every interactive control's endpoint on the three Secure Tunnels pages
(/vpn/openvpn, /vpn/ipsec, /vpn/l2tp) and their sub-pages and tab subpages.
"""
import pytest


# ─── Page loads ───────────────────────────────────────────────────────────────

class TestVpnPages:
    def test_vpn_home_requires_login(self, client):
        r = client.get("/vpn/")
        assert r.status_code in (302, 401)

    def test_vpn_home_accessible(self, superuser):
        client, _ = superuser
        r = client.get("/vpn/")
        assert r.status_code == 200

    @pytest.mark.parametrize("path", [
        "/vpn/openvpn",
        "/vpn/openvpn/servers",
        "/vpn/openvpn/clients",
        "/vpn/openvpn/cso",
        "/vpn/openvpn/portal-users",
        "/vpn/openvpn/wizards",
        "/vpn/ipsec",
        "/vpn/ipsec/mobile-clients",
        "/vpn/ipsec/pre-shared-keys",
        "/vpn/ipsec/advanced-settings",
        "/vpn/l2tp",
        "/vpn/l2tp/users",
    ])
    def test_subpage_loads(self, superuser, path):
        client, _ = superuser
        r = client.get(path, follow_redirects=True)
        assert r.status_code == 200, f"{path} returned {r.status_code}"


# ─── Read endpoints (all the tables and status badges load these on page load) ─

class TestVpnReadEndpoints:
    @pytest.mark.parametrize("path", [
        # OpenVPN
        "/vpn/api/openvpn/get-servers",
        "/vpn/api/openvpn/get-clients",
        "/vpn/api/openvpn/get-csos",
        "/vpn/api/openvpn/status",
        "/vpn/api/openvpn/certificates",
        "/vpn/api/openvpn/validate",
        # IPsec
        "/vpn/api/ipsec/p1",
        "/vpn/api/ipsec/p2",
        "/vpn/api/ipsec/mobile-clients",
        "/vpn/api/ipsec/psk",
        "/vpn/api/ipsec/advanced-settings",
        "/vpn/api/ipsec/status",
        "/vpn/api/ipsec/preview",
        "/vpn/api/ipsec/validate",
        "/vpn/api/ipsec/get-phase1",
        # L2TP
        "/vpn/api/l2tp/settings",
        "/vpn/api/l2tp/get-config",
        "/vpn/api/l2tp/get-users",
        "/vpn/api/l2tp/status",
        "/vpn/api/l2tp/preview",
        "/vpn/api/l2tp/validate",
        # Portal
        "/vpn/api/portal/config",
        "/vpn/api/portal/users",
        # Wizard
        "/vpn/api/wizard/get-cas",
        # Certs
        "/vpn/api/certs",
    ])
    def test_get_endpoint(self, superuser, path):
        client, _ = superuser
        r = client.get(path)
        assert r.status_code == 200, f"{path} returned {r.status_code}"


# ─── Permission gates: every mutating endpoint should reject plain_user ──────

class TestVpnPermissionGates:
    @pytest.mark.parametrize("method,path,body", [
        # OpenVPN
        ("POST",   "/vpn/api/openvpn/save-server", {"protocol": "udp4", "device_mode": "tun", "local_port": 1194, "tunnel_network": "10.8.0.0/24"}),
        ("POST",   "/vpn/api/openvpn/save-client", {}),
        ("POST",   "/vpn/api/openvpn/save-cso",    {}),
        ("PUT",    "/vpn/api/openvpn/update-server/1", {}),
        ("PUT",    "/vpn/api/openvpn/update-client/1", {}),
        ("PUT",    "/vpn/api/openvpn/update-cso/1",    {}),
        ("DELETE", "/vpn/api/openvpn/delete-server/1", None),
        ("DELETE", "/vpn/api/openvpn/delete-client/1", None),
        ("DELETE", "/vpn/api/openvpn/delete-cso/1",    None),
        ("POST",   "/vpn/api/openvpn/apply", {}),
        # IPsec
        ("POST",   "/vpn/api/ipsec/p1",  {}),
        ("POST",   "/vpn/api/ipsec/p2",  {}),
        ("PUT",    "/vpn/api/ipsec/p2/1", {}),
        ("DELETE", "/vpn/api/ipsec/p1/1", None),
        ("DELETE", "/vpn/api/ipsec/p2/1", None),
        ("POST",   "/vpn/api/ipsec/psk", {}),
        ("DELETE", "/vpn/api/ipsec/psk/1", None),
        ("POST",   "/vpn/api/ipsec/mobile-clients", {}),
        ("POST",   "/vpn/api/ipsec/advanced-settings", {}),
        ("POST",   "/vpn/api/ipsec/apply", {}),
        # L2TP
        ("POST",   "/vpn/api/l2tp/save-config", {}),
        ("POST",   "/vpn/api/l2tp/save-user", {}),
        ("PUT",    "/vpn/api/l2tp/update-user/1", {}),
        ("DELETE", "/vpn/api/l2tp/delete-user/1", None),
        ("POST",   "/vpn/api/l2tp/apply", {}),
        # Portal
        ("POST",   "/vpn/api/portal/users", {}),
        ("PUT",    "/vpn/api/portal/users/1", {}),
        ("DELETE", "/vpn/api/portal/users/1", None),
        # Wizard
        ("POST",   "/vpn/api/wizard/save-auth-type", {}),
        ("POST",   "/vpn/api/wizard/save-ca", {}),
        ("DELETE", "/vpn/api/wizard/delete-ca/1", None),
        # Certs
        ("POST",   "/vpn/api/certs/create-ca", {}),
        ("POST",   "/vpn/api/certs/create-server", {}),
        ("POST",   "/vpn/api/certs/create-client", {}),
        ("POST",   "/vpn/api/certs/1/revoke", {}),
    ])
    def test_mutation_requires_permission(self, plain_user, method, path, body):
        client, _ = plain_user
        if method == "POST":
            r = client.post(path, json=body or {})
        elif method == "PUT":
            r = client.put(path, json=body or {})
        else:
            r = client.delete(path)
        assert r.status_code in (401, 403), f"{method} {path} returned {r.status_code}, expected 401/403"


# ─── Apply endpoints (dry-run on Windows) ────────────────────────────────────

class TestVpnApply:
    """Apply endpoints should succeed (200) for superuser in dry-run."""

    @pytest.mark.parametrize("path", [
        "/vpn/api/openvpn/apply",
        "/vpn/api/ipsec/apply",
        "/vpn/api/l2tp/apply",
    ])
    def test_apply_endpoint(self, superuser, path):
        client, _ = superuser
        r = client.post(path, json={})
        assert r.status_code == 200, f"{path} returned {r.status_code}"


# ─── Route registration regression guard ─────────────────────────────────────

class TestVpnRouteRegistration:
    """Every endpoint the templates wire to must be registered."""

    def test_all_vpn_endpoints_registered(self, app):
        rules = {str(r) for r in app.url_map.iter_rules()}
        required = (
            # Pages
            "/vpn/", "/vpn/openvpn", "/vpn/openvpn/servers", "/vpn/openvpn/clients",
            "/vpn/openvpn/cso", "/vpn/openvpn/portal-users", "/vpn/openvpn/wizards",
            "/vpn/openvpn/wizards/step2", "/vpn/openvpn/wizards/step3",
            "/vpn/ipsec", "/vpn/ipsec/mobile-clients", "/vpn/ipsec/pre-shared-keys",
            "/vpn/ipsec/advanced-settings", "/vpn/l2tp", "/vpn/l2tp/users",
            # OpenVPN API
            "/vpn/api/openvpn/save-server", "/vpn/api/openvpn/get-servers",
            "/vpn/api/openvpn/get-server/<int:server_id>",
            "/vpn/api/openvpn/update-server/<int:server_id>",
            "/vpn/api/openvpn/delete-server/<int:server_id>",
            "/vpn/api/openvpn/save-client", "/vpn/api/openvpn/get-clients",
            "/vpn/api/openvpn/get-client/<int:client_id>",
            "/vpn/api/openvpn/update-client/<int:client_id>",
            "/vpn/api/openvpn/delete-client/<int:client_id>",
            "/vpn/api/openvpn/save-cso", "/vpn/api/openvpn/get-csos",
            "/vpn/api/openvpn/get-cso/<int:cso_id>",
            "/vpn/api/openvpn/update-cso/<int:cso_id>",
            "/vpn/api/openvpn/delete-cso/<int:cso_id>",
            "/vpn/api/openvpn/apply", "/vpn/api/openvpn/status",
            "/vpn/api/openvpn/validate", "/vpn/api/openvpn/certificates",
            # IPsec API
            "/vpn/api/ipsec/p1", "/vpn/api/ipsec/p1/<int:p1_id>",
            "/vpn/api/ipsec/p2", "/vpn/api/ipsec/p2/<int:p2_id>",
            "/vpn/api/ipsec/psk", "/vpn/api/ipsec/psk/<int:psk_id>",
            "/vpn/api/ipsec/mobile-clients", "/vpn/api/ipsec/advanced-settings",
            "/vpn/api/ipsec/apply", "/vpn/api/ipsec/status",
            "/vpn/api/ipsec/preview", "/vpn/api/ipsec/validate",
            # L2TP API
            "/vpn/api/l2tp/save-config", "/vpn/api/l2tp/get-config",
            "/vpn/api/l2tp/save-user",   "/vpn/api/l2tp/get-users",
            "/vpn/api/l2tp/get-user/<int:user_id>",
            "/vpn/api/l2tp/update-user/<int:user_id>",
            "/vpn/api/l2tp/delete-user/<int:user_id>",
            "/vpn/api/l2tp/apply", "/vpn/api/l2tp/status",
            "/vpn/api/l2tp/preview", "/vpn/api/l2tp/validate",
            "/vpn/api/l2tp/settings",
            # Portal / wizard / certs
            "/vpn/api/portal/config", "/vpn/api/portal/users",
            "/vpn/api/portal/users/<int:uid>",
            "/vpn/api/wizard/save-auth-type", "/vpn/api/wizard/save-ca",
            "/vpn/api/wizard/get-cas", "/vpn/api/wizard/delete-ca/<int:ca_id>",
            "/vpn/api/certs", "/vpn/api/certs/create-ca", "/vpn/api/certs/create-server",
            "/vpn/api/certs/create-client", "/vpn/api/certs/<int:cert_id>/revoke",
        )
        missing = [p for p in required if p not in rules]
        assert not missing, f"missing routes: {missing}"
