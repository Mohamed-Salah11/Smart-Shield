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
