"""
tests/test_route_status.py
--------------------------
Tests for the /status blueprint's API endpoints.

Phase 1.8: the dashboard surfaces ``health_monitor.check_config_drift`` via
``GET /status/api/config-drift`` so a UI tile can show per-service drift
("pf", "dhcpd", "unbound") and link to /system/preflight when any service is
out of sync with the DB.
"""


class TestConfigDriftEndpoint:

    def test_config_drift_endpoint_returns_per_service_state(self, superuser):
        client, _ = superuser
        r = client.get("/status/api/config-drift")
        assert r.status_code == 200
        data = r.get_json()
        assert data["ok"] is True
        # Always-present services that check_config_drift compares.
        assert set(data["drift"].keys()) >= {"pf", "dhcpd", "unbound"}
        for svc, entry in data["drift"].items():
            assert "drifted" in entry, f"{svc} missing 'drifted'"
            assert "message" in entry, f"{svc} missing 'message'"
            assert isinstance(entry["drifted"], bool)
        # Drifted count is the number of services flagged as drifted.
        assert data["drifted_count"] == sum(
            1 for v in data["drift"].values() if v["drifted"]
        )

    def test_config_drift_requires_login(self, client):
        r = client.get("/status/api/config-drift")
        # @login_required redirects or 401s an unauthenticated caller.
        assert r.status_code in (302, 401)


class TestApiModeEndpoint:
    """Phase 2.3 — JSON view of the runtime-mode banner so the chatbot,
    operator CLI, and external monitors don't have to scrape the HTML."""

    def test_api_mode_returns_badge(self, superuser):
        client, _ = superuser
        r = client.get("/status/api/mode")
        assert r.status_code == 200
        data = r.get_json()
        assert data["ok"] is True
        # Every field is always present so callers can render without guards.
        assert "mode" in data
        assert isinstance(data["mode"], str) and data["mode"]
        assert "badge" in data
        for key in ("mode", "label", "color", "icon"):
            assert key in data["badge"], f"badge missing {key!r}"
        assert isinstance(data["production_ready"], bool)
        assert isinstance(data["issues"], list)
        # The badge.mode must agree with the top-level mode.
        assert data["badge"]["mode"] == data["mode"]

    def test_api_mode_requires_login(self, client):
        r = client.get("/status/api/mode")
        assert r.status_code in (302, 401)
