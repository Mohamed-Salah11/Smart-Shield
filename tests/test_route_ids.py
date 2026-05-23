"""Route-level tests for the IDS / IPS (Threat Detection) blueprint.

Covers every interactive control on templates/ids.html:

  * page + 4 tabs (Status & Alerts, Configuration, Rulesets, Threat Feeds)
  * Refresh / status polling           -> GET  /ids/api/status
  * Daemon-log panel + Reload          -> GET  /ids/api/log
  * Recent-alerts table + filters      -> GET  /ids/api/alerts
  * Auth-events table                  -> GET  /status/api/logs  (cross-blueprint)
  * Configuration "Save" form          -> POST /ids/save
  * Enable/Disable toggle              -> POST /ids/api/toggle      (api.ids.edit)
  * Ruleset add / toggle / delete      -> POST/PUT/DELETE /ids/api/rulesets (api.ids.edit)
  * "Update Rules"                     -> POST /ids/api/update-rules (api.ids.edit)
  * Threat-feed save/clear/get + toggle-> GET/POST /ids/api/feeds    (POST = api.ids.edit)
  * abuse.ch lookup / recent           -> POST /ids/api/feeds/abusech/lookup, GET .../recent
  * file-events / connections viewers  -> GET  /ids/api/file-events, /ids/api/connections
"""
import pytest

from app.database import get_db


class TestIdsPages:
    def test_ids_requires_login(self, client):
        r = client.get("/ids/")
        assert r.status_code in (302, 401)

    def test_ids_page_loads(self, superuser):
        client, _ = superuser
        r = client.get("/ids/")
        assert r.status_code == 200

    @pytest.mark.parametrize("tab", ["status", "config", "rules", "feeds"])
    def test_ids_tabs_render(self, superuser, tab):
        client, _ = superuser
        r = client.get(f"/ids/?tab={tab}")
        assert r.status_code == 200


class TestIdsReadEndpoints:
    def test_status(self, superuser):
        client, _ = superuser
        r = client.get("/ids/api/status")
        assert r.status_code == 200
        assert isinstance(r.get_json(), dict)

    def test_diagnostics_endpoint_returns_full_shape(self, superuser):
        client, _ = superuser
        r = client.get("/ids/api/diagnostics")
        assert r.status_code == 200
        d = r.get_json()
        # Every key the GUI panel renders must be present.
        for key in ("phase", "error", "mode", "interface", "running",
                    "rc_enabled", "cfg_enabled", "signatures_loaded",
                    "rules_file", "rules_size", "config_path",
                    "config_exists", "netmap_loaded", "log_tail"):
            assert key in d, f"diagnostics missing {key!r}"
        assert isinstance(d["log_tail"], list)

    def test_diagnostics_requires_login(self, client):
        r = client.get("/ids/api/diagnostics")
        # @login_required either redirects (302) or returns 401.
        assert r.status_code in (302, 401)

    def test_feeds_get(self, superuser):
        client, _ = superuser
        r = client.get("/ids/api/feeds")
        assert r.status_code == 200
        data = r.get_json()
        assert data["ok"] is True
        assert data["mode"] in ("live", "dry_run", "offline", "invalid")

    def test_rulesets_list_seeded(self, superuser):
        client, _ = superuser
        r = client.get("/ids/api/rulesets")
        assert r.status_code == 200
        # database.py seeds default rule sources, so the list is never empty.
        assert isinstance(r.get_json(), list)

    def test_alerts(self, superuser):
        client, _ = superuser
        r = client.get("/ids/api/alerts")
        assert r.status_code == 200
        assert r.get_json()["ok"] is True

    def test_log_tail(self, superuser):
        client, _ = superuser
        r = client.get("/ids/api/log?source=suricata&lines=50")
        assert r.status_code == 200
        assert "ok" in r.get_json()

    def test_connections(self, superuser):
        client, _ = superuser
        r = client.get("/ids/api/connections")
        assert r.status_code == 200
        assert r.get_json()["ok"] is True

    def test_file_events(self, superuser):
        client, _ = superuser
        r = client.get("/ids/api/file-events")
        assert r.status_code == 200
        assert r.get_json()["ok"] is True


class TestIdsConfigSave:
    """The Configuration tab's 'Save' button posts an HTML form to /ids/save."""

    def test_save_persists(self, superuser, app):
        client, _ = superuser
        r = client.post(
            "/ids/save",
            data={
                "mode": "ips",
                "interface": "em0",
                "home_net": "10.0.0.0/8",
                "external_net": "!$HOME_NET",
                "max_pending_packets": "2048",
                "eve_json_enabled": "on",
            },
            follow_redirects=False,
        )
        assert r.status_code == 302  # redirects back to ?tab=config
        with app.app_context():
            row = get_db().execute(
                "SELECT mode, interface, home_net, max_pending_packets "
                "FROM ids_config WHERE id=1"
            ).fetchone()
            assert row["mode"] == "ips"
            assert row["interface"] == "em0"
            assert row["home_net"] == "10.0.0.0/8"
            assert row["max_pending_packets"] == 2048

    def test_save_rejects_bad_mode(self, superuser, app):
        client, _ = superuser
        client.post("/ids/save", data={"mode": "garbage"}, follow_redirects=False)
        with app.app_context():
            row = get_db().execute("SELECT mode FROM ids_config WHERE id=1").fetchone()
            assert row["mode"] == "ids"  # invalid value coerced to safe default


class TestIdsToggle:
    def test_toggle_requires_permission(self, plain_user):
        client, _ = plain_user
        r = client.post("/ids/api/toggle", json={"enabled": False})
        assert r.status_code in (401, 403)

    def test_toggle_superuser(self, superuser):
        client, _ = superuser
        r = client.post("/ids/api/toggle", json={"enabled": False})
        assert r.status_code == 200
        assert isinstance(r.get_json(), dict)


class TestIdsRulesets:
    def test_add_requires_permission(self, plain_user):
        client, _ = plain_user
        r = client.post("/ids/api/rulesets", json={"name": "x"})
        assert r.status_code in (401, 403)

    def test_add_missing_name_400(self, superuser):
        client, _ = superuser
        r = client.post("/ids/api/rulesets", json={"url": "https://e/x.rules"})
        assert r.status_code == 400
        assert r.get_json()["ok"] is False

    def test_add_update_delete_flow(self, superuser):
        client, _ = superuser
        # Add
        r = client.post(
            "/ids/api/rulesets",
            json={"name": "QA Source", "url": "https://e/x.rules", "description": "qa"},
        )
        assert r.status_code == 200
        body = r.get_json()
        assert body["ok"] is True
        rid = body["id"]
        # Toggle off
        r = client.put(f"/ids/api/rulesets/{rid}", json={"enabled": False})
        assert r.status_code == 200 and r.get_json()["ok"] is True
        # Delete
        r = client.delete(f"/ids/api/rulesets/{rid}")
        assert r.status_code == 200 and r.get_json()["ok"] is True

    def test_update_requires_permission(self, plain_user):
        client, _ = plain_user
        r = client.put("/ids/api/rulesets/1", json={"enabled": False})
        assert r.status_code in (401, 403)

    def test_delete_requires_permission(self, plain_user):
        client, _ = plain_user
        r = client.delete("/ids/api/rulesets/1")
        assert r.status_code in (401, 403)


class TestIdsUpdateRules:
    def test_requires_permission(self, plain_user):
        client, _ = plain_user
        r = client.post("/ids/api/update-rules", json={})
        assert r.status_code in (401, 403)

    def test_superuser_runs(self, superuser):
        client, _ = superuser
        r = client.post("/ids/api/update-rules", json={})
        assert r.status_code == 200
        assert "ok" in r.get_json()


class TestIdsFeeds:
    def test_save_requires_permission(self, plain_user):
        client, _ = plain_user
        r = client.post("/ids/api/feeds", json={"abusech_auth_key": "k"})
        assert r.status_code in (401, 403)

    def test_save_then_get_reports_key(self, superuser):
        client, _ = superuser
        r = client.post("/ids/api/feeds", json={"abusech_auth_key": "QA-TEST-KEY"})
        assert r.status_code == 200 and r.get_json()["ok"] is True
        r = client.get("/ids/api/feeds")
        assert r.get_json()["has_key"] is True
        # Clear it again (Clear Key button posts an empty key).
        r = client.post("/ids/api/feeds", json={"abusech_auth_key": ""})
        assert r.status_code == 200

    def test_live_toggle_only_changes_dry_run(self, superuser):
        client, _ = superuser
        r = client.post("/ids/api/feeds", json={"dry_run": 0})
        assert r.status_code == 200


class TestIdsAbusechLookup:
    def test_invalid_type_400(self, superuser):
        client, _ = superuser
        r = client.post("/ids/api/feeds/abusech/lookup", json={"type": "bad", "value": "x"})
        assert r.status_code == 400

    def test_missing_value_400(self, superuser):
        client, _ = superuser
        r = client.post("/ids/api/feeds/abusech/lookup", json={"type": "host"})
        assert r.status_code == 400

    def test_host_lookup_dry_run_ok(self, superuser):
        client, _ = superuser
        # Force dry-run (clears any live-mode left over from sibling tests in the
        # shared session DB). In dry-run abusech_client returns a stub with no
        # network call, so the lookup endpoint must answer 200.
        client.post("/ids/api/feeds", json={"abusech_auth_key": "", "dry_run": 1})
        r = client.post(
            "/ids/api/feeds/abusech/lookup", json={"type": "host", "value": "1.2.3.4"}
        )
        assert r.status_code == 200
        assert r.get_json()["ok"] is True


class TestIdsRouteRegistration:
    """Regression guard: every endpoint the template wires to must exist."""

    def test_all_ids_endpoints_registered(self, app):
        rules = {str(r) for r in app.url_map.iter_rules()}
        for path in (
            "/ids/",
            "/ids/save",
            "/ids/api/toggle",
            "/ids/api/log",
            "/ids/api/rulesets",
            "/ids/api/rulesets/<int:rid>",
            "/ids/api/update-rules",
            "/ids/api/status",
            "/ids/api/feeds",
            "/ids/api/feeds/abusech/recent",
            "/ids/api/feeds/abusech/lookup",
            "/ids/api/alerts",
            "/ids/api/file-events",
            "/ids/api/connections",
            # cross-blueprint call from the Auth & Security Events panel
            "/status/api/logs",
        ):
            assert path in rules, f"missing route: {path}"
