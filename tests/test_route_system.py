"""Route-level tests for system blueprint (dashboard, setup, certs)."""
import pytest


class TestSystemRoutes:
    def test_dashboard_requires_login(self, client):
        r = client.get("/system/dashboard")
        assert r.status_code in (302, 401)

    def test_dashboard_accessible(self, superuser):
        client, _ = superuser
        r = client.get("/system/dashboard")
        assert r.status_code == 200

    def test_dashboard_data_json(self, superuser):
        client, _ = superuser
        r = client.get("/system/dashboard/data")
        assert r.status_code == 200
        data = r.get_json()
        assert data["status"] == "success"
        assert "session_summary" in data["data"]
        assert "object_counts" in data["data"]
        assert "health" in data["data"]

    def test_general_setup_page(self, superuser):
        client, _ = superuser
        r = client.get("/system/general-setup")
        assert r.status_code == 200

    def test_certificates_page(self, superuser):
        client, _ = superuser
        r = client.get("/system/certificates")
        assert r.status_code == 200

    def test_preflight_page(self, superuser):
        client, _ = superuser
        r = client.get("/system/preflight")
        assert r.status_code == 200

    def test_revoke_nonexistent_cert_returns_error(self, superuser):
        client, _ = superuser
        r = client.post("/system/api/certificates/9999/revoke")
        assert r.status_code == 200
        data = r.get_json()
        assert data["ok"] is False

    def test_ocsp_nonexistent_cert_returns_404(self, superuser):
        client, _ = superuser
        r = client.get("/system/api/certificates/9999/ocsp")
        assert r.status_code == 404


class TestSetupWizard:
    def test_setup_index_redirects_to_step1(self, client):
        r = client.get("/setup/", follow_redirects=False)
        # Either redirects to step1 or to dashboard if already complete
        assert r.status_code in (302, 200)

    def test_step1_available_ports(self, client):
        r = client.get("/setup/api/step1/available-ports")
        assert r.status_code in (200, 403)
        if r.status_code == 200:
            data = r.get_json()
            assert data["status"] == "success"
            assert data["ok"] is True
            assert data["ports"][0]["name"] == "em0"
            assert "label" in data["ports"][0]

    def test_step1_save_missing_ports(self, client):
        r = client.post("/setup/api/step1/save", json={})
        assert r.status_code in (400, 403)

    def test_step1_save_same_port_rejected(self, client):
        r = client.post("/setup/api/step1/save", json={"wan_port": "em0", "lan_port": "em0"})
        assert r.status_code in (400, 403)

    def test_step3_short_password_rejected(self, client):
        r = client.post("/setup/api/step3/save", json={
            "username": "admin", "password": "short", "confirm": "short"
        })
        assert r.status_code in (400, 403)

    def test_step3_mismatched_passwords_rejected(self, client):
        r = client.post("/setup/api/step3/save", json={
            "username": "admin", "password": "longpassword1", "confirm": "longpassword2"
        })
        assert r.status_code in (400, 403)


# ─── All System Core pages (sidebar group 1) load for superuser ──────────────

class TestSystemCorePages:
    @pytest.mark.parametrize("path", [
        "/system/dashboard",
        "/system/general-setup",
        "/system/admin-access",
        "/system/certificates",
        "/system/high-availability",
        "/system/package-manager",
        "/system/preflight",
        "/system/routing/",
        "/system/theme-editor",
        "/system/update",
        "/system/notifications",
        "/system/user-manager/",
        "/system/api-tokens",
        "/system/reports",
    ])
    def test_page_loads(self, superuser, path):
        client, _ = superuser
        r = client.get(path, follow_redirects=True)
        assert r.status_code == 200, f"{path} -> {r.status_code}"

    def test_setup_wizard_redirects(self, superuser):
        client, _ = superuser
        # /system/setup-wizard redirects to /setup which then redirects to step1
        # or to the setup_not_authorized page (since setup is already complete).
        r = client.get("/system/setup-wizard", follow_redirects=False)
        assert r.status_code == 302

    def test_setup_wizard_step_redirects(self, superuser):
        """Legacy /system/setup-wizard/step/<n> also redirects to /setup.
        Pin this contract — base.html still resolves url_for('system.setup_wizard'),
        so the endpoint must stay registered as a redirect even though no new
        code links into it. If the endpoint is ever removed, the navbar breaks."""
        client, _ = superuser
        r = client.get("/system/setup-wizard/step/2", follow_redirects=False)
        assert r.status_code == 302
        assert "/setup" in (r.headers.get("Location") or "")


# ─── System Core read endpoints ──────────────────────────────────────────────

class TestSystemCoreReadEndpoints:
    @pytest.mark.parametrize("path", [
        "/system/dashboard/data",
        "/system/api/packages",
        "/system/api/preflight",
        "/system/routing/api/live-routes",
        "/system/routing/api/gateway-health",
    ])
    def test_get_endpoint(self, superuser, path):
        client, _ = superuser
        r = client.get(path)
        assert r.status_code == 200


# ─── System Core mutation permission gates ───────────────────────────────────

class TestSystemCoreMutations:
    @pytest.mark.parametrize("method,path,body", [
        # Packages
        ("POST", "/system/api/packages/install", {"name": "x"}),
        # Certificates
        ("POST",   "/system/api/certificates/1/revoke", {}),
        ("POST",   "/system/api/certificates/ca/1/crl", {}),
        ("POST",   "/system/api/certificates/acme/request", {}),
        ("DELETE", "/system/api/certificates/1", None),
        ("DELETE", "/system/api/certificates/ca/1", None),
        # System tunables (advanced)
        ("POST", "/system/advanced/system-tunables/save", {}),
        ("POST", "/system/advanced/system-tunables/delete/0", {}),
        # User Manager (superuser_required)
        ("POST", "/system/user-manager/add", {}),
        ("POST", "/system/user-manager/add-group", {}),
        ("POST", "/system/user-manager/edit-group/1", {}),
        ("POST", "/system/user-manager/delete-group/1", {}),
        ("POST", "/system/user-manager/group/1/add-member", {}),
        ("POST", "/system/user-manager/group/1/remove-member/1", {}),
        ("POST", "/system/user-manager/group/1/permissions", {}),
        ("POST", "/system/user-manager/delete/1", {}),
        ("POST", "/system/user-manager/change-password/1", {}),
        ("POST", "/system/user-manager/edit/1", {}),
        # Routing
        ("POST", "/system/routing/gateway/delete/1", {}),
        ("POST", "/system/routing/gateway/set-default", {}),
        ("POST", "/system/routing/gateway/apply/1", {}),
        ("POST", "/system/routing/static/delete/1", {}),
        ("POST", "/system/routing/group/delete/1", {}),
        ("POST", "/system/routing/api/apply-all", {}),
        ("POST", "/system/routing/api/gateway-failover/apply", {}),
    ])
    def test_mutation_rejects_plain_user(self, plain_user, method, path, body):
        client, _ = plain_user
        if method == "POST":
            r = client.post(path, json=body or {})
        else:
            r = client.delete(path)
        assert r.status_code in (401, 403), f"{method} {path} -> {r.status_code}"


# ─── Route registration regression guard ─────────────────────────────────────

class TestSystemCoreRouteRegistration:
    def test_required_endpoints_registered(self, app):
        rules = {str(r) for r in app.url_map.iter_rules()}
        required = (
            # Pages
            "/system/dashboard", "/system/general-setup", "/system/admin-access",
            "/system/certificates", "/system/high-availability",
            "/system/package-manager", "/system/preflight",
            "/system/setup-wizard", "/system/theme-editor", "/system/update",
            "/system/notifications", "/system/api-tokens", "/system/reports",
            "/system/routing/", "/system/user-manager/",
            # APIs
            "/system/dashboard/data",
            "/system/api/packages", "/system/api/packages/search",
            "/system/api/packages/install", "/system/api/preflight",
            "/system/api/certificates/<int:cert_id>/revoke",
            "/system/api/certificates/<int:cert_id>",
            "/system/api/certificates/ca/<int:ca_id>",
            "/system/api/certificates/ca/<int:ca_id>/crl",
            "/system/api/certificates/acme/request",
            "/system/routing/api/live-routes",
            "/system/routing/api/apply-all",
            "/system/routing/api/gateway-health",
        )
        missing = [p for p in required if p not in rules]
        assert not missing, f"missing routes: {missing}"
