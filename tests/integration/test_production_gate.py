"""
tests/integration/test_production_gate.py
-----------------------------------------
Integration tests for the production-gate endpoint and feature registry.

These tests run against the in-memory test DB and check that:
- GET /status/api/production-gate returns correct structure
- GET /status/api/features returns the feature registry
- GET /status/api/preflight includes runtime_mode
- GET /status/api/apply-jobs returns a list
"""

import os
import sys
import pytest

# Env must be set before importing the app.
os.environ.setdefault("SMARTSHIELD_DB_PATH", "file:inttest_gate?mode=memory&cache=shared")
os.environ.setdefault("SECRET_KEY", "integration-test-secret-key-xyz")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from tests.conftest import _create_user, _login  # noqa: E402


@pytest.fixture(scope="module")
def int_app():
    from app import create_app
    app = create_app()
    app.config["TESTING"] = True
    return app


@pytest.fixture()
def int_client(int_app):
    return int_app.test_client()


@pytest.fixture()
def auth_client(int_app, int_client):
    _create_user(int_app, "gate_admin", "gatepass", is_superuser=1)
    _login(int_client, "gate_admin", "gatepass")
    return int_client


# ---------------------------------------------------------------------------
# Production gate structure
# ---------------------------------------------------------------------------

class TestProductionGate:
    def test_requires_login(self, int_client):
        r = int_client.get("/status/api/production-gate")
        assert r.status_code in (302, 401)

    def test_gate_structure(self, auth_client):
        r = auth_client.get("/status/api/production-gate")
        assert r.status_code == 200
        data = r.get_json()
        assert "ok" in data
        assert "gates" in data
        assert "mode" in data
        assert "critical_failed" in data
        assert isinstance(data["gates"], list)

    def test_gate_items_have_required_fields(self, auth_client):
        r = auth_client.get("/status/api/production-gate")
        data = r.get_json()
        for gate in data["gates"]:
            assert "id" in gate
            assert "label" in gate
            assert "ok" in gate
            assert "severity" in gate
            assert gate["severity"] in ("critical", "warning", "info")

    def test_platform_gate_present(self, auth_client):
        r = auth_client.get("/status/api/production-gate")
        data = r.get_json()
        ids = {g["id"] for g in data["gates"]}
        assert "platform_freebsd" in ids

    def test_non_freebsd_is_not_production_ready(self, auth_client):
        r = auth_client.get("/status/api/production-gate")
        data = r.get_json()
        if not sys.platform.startswith("freebsd"):
            assert data["ok"] is False
            assert data["critical_failed"] > 0

    def test_mode_gate_present(self, auth_client):
        r = auth_client.get("/status/api/production-gate")
        data = r.get_json()
        ids = {g["id"] for g in data["gates"]}
        assert "mode_live" in ids


# ---------------------------------------------------------------------------
# Feature registry endpoint
# ---------------------------------------------------------------------------

class TestFeatureRegistry:
    def test_features_endpoint(self, auth_client):
        r = auth_client.get("/status/api/features")
        assert r.status_code == 200
        data = r.get_json()
        assert "features" in data
        assert "summary" in data
        assert "runtime_mode" in data
        assert isinstance(data["features"], list)
        assert len(data["features"]) > 0

    def test_features_have_mode(self, auth_client):
        r = auth_client.get("/status/api/features")
        data = r.get_json()
        for feat in data["features"]:
            assert "key" in feat
            assert "mode" in feat
            assert feat["mode"] in (
                "live", "dry-run", "config-only",
                "unsupported", "degraded", "unavailable",
            )

    def test_by_category_structure(self, auth_client):
        r = auth_client.get("/status/api/features")
        data = r.get_json()
        assert "by_category" in data
        assert isinstance(data["by_category"], dict)


# ---------------------------------------------------------------------------
# Preflight endpoint
# ---------------------------------------------------------------------------

class TestPreflight:
    def test_preflight_structure(self, auth_client):
        r = auth_client.get("/status/api/preflight")
        assert r.status_code == 200
        data = r.get_json()
        assert "runtime_mode" in data
        assert "production_ready" in data
        assert isinstance(data["production_ready"], bool)

    def test_preflight_includes_kernel_caps(self, auth_client):
        r = auth_client.get("/status/api/preflight")
        data = r.get_json()
        assert "kernel_caps" in data
        # kernel_caps is a list of {cap, ok, warning} on non-FreeBSD (simulated)
        assert isinstance(data["kernel_caps"], (dict, list))


# ---------------------------------------------------------------------------
# Apply-jobs endpoint
# ---------------------------------------------------------------------------

class TestApplyJobs:
    def test_apply_jobs_structure(self, auth_client):
        r = auth_client.get("/status/api/apply-jobs")
        assert r.status_code == 200
        data = r.get_json()
        assert "jobs" in data
        assert "count" in data
        assert isinstance(data["jobs"], list)

    def test_apply_jobs_limit_param(self, auth_client):
        r = auth_client.get("/status/api/apply-jobs?limit=5")
        assert r.status_code == 200
        data = r.get_json()
        assert data["count"] <= 5


# ---------------------------------------------------------------------------
# Schedules endpoint
# ---------------------------------------------------------------------------

class TestSchedules:
    def test_schedules_structure(self, auth_client):
        r = auth_client.get("/status/api/schedules")
        assert r.status_code == 200
        data = r.get_json()
        assert "schedules" in data
        # get_all_schedule_states returns a dict keyed by schedule name
        assert isinstance(data["schedules"], (dict, list))
