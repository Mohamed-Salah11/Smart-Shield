"""
tests/integration/test_security_hardening.py
---------------------------------------------
Integration tests for security-hardening phases.

Covers:
- Phase 32: factory_defaults_reset / halt_system_execute require superuser
             AND password re-authentication
- Phase 36: session idle timeout enforcement
- Phase 33: package manager API structure
"""

import os
import sys
import pytest

os.environ.setdefault("SMARTSHIELD_DB_PATH", "file:inttest_sec?mode=memory&cache=shared")
os.environ.setdefault("SECRET_KEY", "integration-security-test-key-xyz")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from tests.conftest import _create_user, _login


@pytest.fixture(scope="module")
def sec_app():
    from app import create_app
    app = create_app()
    app.config["TESTING"] = True
    return app


@pytest.fixture()
def sec_client(sec_app):
    return sec_app.test_client()


@pytest.fixture()
def superuser_client(sec_app, sec_client):
    _create_user(sec_app, "sec_super", "superpass123!", is_superuser=1)
    _login(sec_client, "sec_super", "superpass123!")
    return sec_client


@pytest.fixture()
def plain_client(sec_app, sec_client):
    client2 = sec_app.test_client()
    _create_user(sec_app, "sec_plain", "plainpass456", is_superuser=0)
    _login(client2, "sec_plain", "plainpass456")
    return client2


# ---------------------------------------------------------------------------
# Phase 32: Factory defaults security
# ---------------------------------------------------------------------------

class TestFactoryDefaultsSecurity:
    def test_factory_reset_requires_login(self, sec_client):
        r = sec_client.post(
            "/diagnostics/factory-defaults/reset",
            json={"confirm_password": "anything"},
        )
        assert r.status_code in (302, 401, 403)

    def test_factory_reset_requires_superuser(self, plain_client):
        r = plain_client.post(
            "/diagnostics/factory-defaults/reset",
            json={"confirm_password": "plainpass456"},
        )
        assert r.status_code == 403

    def test_factory_reset_requires_password(self, superuser_client):
        r = superuser_client.post(
            "/diagnostics/factory-defaults/reset",
            json={},
        )
        assert r.status_code == 400
        data = r.get_json()
        assert "confirm_password" in data.get("message", "").lower()

    def test_factory_reset_wrong_password_rejected(self, superuser_client):
        r = superuser_client.post(
            "/diagnostics/factory-defaults/reset",
            json={"confirm_password": "wrongpassword"},
        )
        assert r.status_code == 403
        data = r.get_json()
        assert data["ok"] is False

    def test_factory_reset_correct_password_succeeds(self, superuser_client):
        r = superuser_client.post(
            "/diagnostics/factory-defaults/reset",
            json={"confirm_password": "superpass123!"},
        )
        assert r.status_code == 200
        data = r.get_json()
        assert data["ok"] is True


# ---------------------------------------------------------------------------
# Phase 32: Halt system security
# ---------------------------------------------------------------------------

class TestHaltSystemSecurity:
    def test_halt_requires_superuser(self, plain_client):
        r = plain_client.post(
            "/diagnostics/halt-system/execute",
            json={"action": "reboot", "confirm_password": "plainpass456"},
        )
        assert r.status_code == 403

    def test_halt_requires_password(self, superuser_client):
        r = superuser_client.post(
            "/diagnostics/halt-system/execute",
            json={"action": "reboot"},
        )
        assert r.status_code == 400

    def test_halt_wrong_password_rejected(self, superuser_client):
        r = superuser_client.post(
            "/diagnostics/halt-system/execute",
            json={"action": "reboot", "confirm_password": "badpass"},
        )
        assert r.status_code == 403

    def test_halt_invalid_action_rejected(self, superuser_client):
        r = superuser_client.post(
            "/diagnostics/halt-system/execute",
            json={"action": "format", "confirm_password": "superpass123!"},
        )
        assert r.status_code == 400

    def test_halt_correct_password_non_freebsd(self, superuser_client):
        if sys.platform.startswith("freebsd"):
            pytest.skip("Skipped on live FreeBSD to avoid actual halt")
        r = superuser_client.post(
            "/diagnostics/halt-system/execute",
            json={"action": "reboot", "confirm_password": "superpass123!"},
        )
        assert r.status_code == 200
        data = r.get_json()
        assert data["ok"] is True
        assert "Non-FreeBSD" in data["message"]


# ---------------------------------------------------------------------------
# Phase 33: Package manager API
# ---------------------------------------------------------------------------

class TestPackageManagerApi:
    def test_packages_list_requires_login(self, sec_client):
        r = sec_client.get("/system/api/packages")
        assert r.status_code in (302, 401)

    def test_packages_list_structure(self, superuser_client):
        r = superuser_client.get("/system/api/packages")
        assert r.status_code == 200
        data = r.get_json()
        assert "ok" in data
        assert "packages" in data
        assert isinstance(data["packages"], list)

    def test_packages_search_requires_query(self, superuser_client):
        r = superuser_client.get("/system/api/packages/search")
        assert r.status_code == 400

    def test_packages_search_structure(self, superuser_client):
        r = superuser_client.get("/system/api/packages/search?q=curl")
        assert r.status_code == 200
        data = r.get_json()
        assert "ok" in data
        assert "results" in data

    def test_packages_install_requires_superuser(self, plain_client):
        r = plain_client.post("/system/api/packages/install", json={"name": "curl"})
        assert r.status_code == 403

    def test_packages_install_invalid_name_rejected(self, superuser_client):
        r = superuser_client.post(
            "/system/api/packages/install",
            json={"name": "curl; rm -rf /"},
        )
        assert r.status_code in (400, 200)
        data = r.get_json()
        if r.status_code == 200:
            assert data["ok"] is False


# ---------------------------------------------------------------------------
# Phase 36: Session idle timeout
# ---------------------------------------------------------------------------

class TestSessionTimeout:
    def test_last_active_set_after_request(self, superuser_client):
        with superuser_client.session_transaction() as sess:
            assert "_last_active" in sess

    def test_expired_session_redirects(self, sec_app, sec_client):
        _create_user(sec_app, "timeout_user", "timeoutpass", is_superuser=0)
        _login(sec_client, "timeout_user", "timeoutpass")
        import time
        with sec_client.session_transaction() as sess:
            sess["_last_active"] = time.time() - 7200
        r = sec_client.get("/system/dashboard", follow_redirects=False)
        assert r.status_code in (302, 401)
