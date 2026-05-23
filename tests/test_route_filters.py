"""Route-level tests for the filters / Content Guard blueprint.

Covers the three pages (/filters/dns, /filters/web, /filters/app) and every
interactive control: add / edit / toggle / delete / apply on each filter type,
plus the shared mode get/set, signatures, conflicts, preview, runtime status,
and export.
"""
import pytest

from app.database import get_db


# ─── Page loads ───────────────────────────────────────────────────────────────

class TestFilterPages:
    def test_filters_index_requires_login(self, client):
        r = client.get("/filters/")
        assert r.status_code in (302, 401)

    @pytest.mark.parametrize("path", ["/filters/dns", "/filters/web", "/filters/app"])
    def test_filter_pages_load(self, superuser, path):
        client, _ = superuser
        r = client.get(path)
        assert r.status_code == 200


# ─── Read endpoints ──────────────────────────────────────────────────────────

class TestFilterReadEndpoints:
    @pytest.mark.parametrize("path", [
        "/filters/api/content-policy/mode",
        "/filters/api/signatures",
        "/filters/api/conflicts",
        "/filters/api/preview",
        "/filters/api/runtime/policy-status",
    ])
    def test_get_endpoint(self, superuser, path):
        client, _ = superuser
        r = client.get(path)
        assert r.status_code == 200, f"{path} returned {r.status_code}"

    @pytest.mark.parametrize("ftype", ["dns", "web", "app"])
    def test_export_endpoint(self, superuser, ftype):
        client, _ = superuser
        r = client.get(f"/filters/api/export/{ftype}")
        assert r.status_code == 200


# ─── Permission gates: every mutating endpoint should reject plain_user ──────

class TestFilterPermissionGates:
    @pytest.mark.parametrize("method,path,body", [
        # Shared mode
        ("POST",   "/filters/api/content-policy/mode", {"mode": "permissive"}),
        # DNS
        ("POST",   "/filters/dns/add", {"domain": "x.com"}),
        ("POST",   "/filters/dns/1/toggle", {"enabled": False}),
        ("PUT",    "/filters/dns/1/edit", {"domain": "x.com"}),
        ("POST",   "/filters/dns/1/delete", {}),
        ("POST",   "/filters/dns/apply", {}),
        # Web
        ("POST",   "/filters/web/add", {"url_pattern": "*.example.com"}),
        ("POST",   "/filters/web/1/toggle", {"enabled": False}),
        ("PUT",    "/filters/web/1/edit", {"url_pattern": "*.example.com"}),
        ("POST",   "/filters/web/1/delete", {}),
        ("POST",   "/filters/web/apply", {}),
        # App
        ("POST",   "/filters/app/add", {"app_name": "TestApp"}),
        ("POST",   "/filters/app/add-signature", {"sig_key": "torrent"}),
        ("POST",   "/filters/app/1/toggle", {"enabled": False}),
        ("PUT",    "/filters/app/1/edit", {"app_name": "TestApp"}),
        ("POST",   "/filters/app/1/delete", {}),
        ("POST",   "/filters/app/apply", {}),
        # Import endpoints
        ("POST",   "/filters/api/import/dns", {}),
        ("POST",   "/filters/api/import/web", {}),
        ("POST",   "/filters/api/import/app", {}),
    ])
    def test_mutation_requires_permission(self, plain_user, method, path, body):
        client, _ = plain_user
        if method == "POST":
            r = client.post(path, json=body or {})
        else:
            r = client.put(path, json=body or {})
        assert r.status_code in (401, 403), f"{method} {path} returned {r.status_code}"


# ─── DNS filter: full add → edit → toggle → delete flow ──────────────────────

class TestDnsFilterFlow:
    def test_add_missing_domain_400(self, superuser):
        client, _ = superuser
        r = client.post("/filters/dns/add", json={"action": "block"})
        assert r.status_code == 400
        assert r.get_json()["ok"] is False

    def test_add_bad_action_400(self, superuser):
        client, _ = superuser
        r = client.post("/filters/dns/add", json={"domain": "ads.example.com", "action": "nuke"})
        assert r.status_code == 400

    def test_full_flow(self, superuser):
        client, _ = superuser
        r = client.post("/filters/dns/add",
                        json={"domain": "qa-dns.example.test", "action": "block",
                              "category": "qa", "description": "test"})
        assert r.status_code == 200 and r.get_json()["ok"] is True
        rid = r.get_json()["id"]
        r = client.post(f"/filters/dns/{rid}/toggle", json={"enabled": False})
        assert r.status_code == 200 and r.get_json()["ok"] is True
        r = client.put(f"/filters/dns/{rid}/edit",
                       json={"domain": "qa-dns2.example.test", "action": "allow",
                             "category": "qa"})
        assert r.status_code == 200 and r.get_json()["ok"] is True
        assert r.get_json()["rule"]["domain"] == "qa-dns2.example.test"
        r = client.post(f"/filters/dns/{rid}/delete", json={})
        assert r.status_code == 200 and r.get_json()["ok"] is True


# ─── Web filter: full add → edit → toggle → delete flow ──────────────────────

class TestWebFilterFlow:
    def test_add_missing_pattern_400(self, superuser):
        client, _ = superuser
        r = client.post("/filters/web/add", json={"action": "block"})
        assert r.status_code == 400

    def test_full_flow(self, superuser):
        client, _ = superuser
        r = client.post("/filters/web/add",
                        json={"url_pattern": "*.qa-web.test", "action": "block",
                              "category": "qa", "description": "test"})
        assert r.status_code == 200 and r.get_json()["ok"] is True
        rid = r.get_json()["id"]
        r = client.post(f"/filters/web/{rid}/toggle", json={"enabled": False})
        assert r.status_code == 200
        r = client.put(f"/filters/web/{rid}/edit",
                       json={"url_pattern": "*.qa-web2.test", "action": "allow",
                             "category": "qa"})
        assert r.status_code == 200
        r = client.post(f"/filters/web/{rid}/delete", json={})
        assert r.status_code == 200


# ─── App filter: full add → edit → toggle → delete flow ──────────────────────

class TestAppFilterFlow:
    def test_add_missing_name_400(self, superuser):
        client, _ = superuser
        r = client.post("/filters/app/add", json={"action": "block"})
        assert r.status_code == 400

    def test_add_signature_missing_400(self, superuser):
        client, _ = superuser
        r = client.post("/filters/app/add-signature", json={"action": "block"})
        assert r.status_code == 400

    def test_full_flow(self, superuser):
        client, _ = superuser
        r = client.post("/filters/app/add",
                        json={"app_name": "qa-app", "action": "block",
                              "protocol": "tcp", "ports": "8443"})
        assert r.status_code == 200 and r.get_json()["ok"] is True
        rid = r.get_json()["id"]
        r = client.post(f"/filters/app/{rid}/toggle", json={"enabled": False})
        assert r.status_code == 200
        r = client.put(f"/filters/app/{rid}/edit", json={"app_name": "qa-app-2"})
        assert r.status_code == 200
        r = client.post(f"/filters/app/{rid}/delete", json={})
        assert r.status_code == 200


# ─── Apply endpoints (superuser, dry-run on Windows) ─────────────────────────

class TestFilterApply:
    @pytest.mark.parametrize("path", [
        "/filters/dns/apply",
        "/filters/web/apply",
        "/filters/app/apply",
    ])
    def test_apply_endpoint(self, superuser, path):
        client, _ = superuser
        r = client.post(path, json={})
        assert r.status_code == 200, f"{path} returned {r.status_code}"


# ─── Content-policy mode toggle ──────────────────────────────────────────────

class TestContentPolicyMode:
    def test_get_mode(self, superuser):
        client, _ = superuser
        r = client.get("/filters/api/content-policy/mode")
        assert r.status_code == 200

    def test_set_mode_superuser(self, superuser):
        client, _ = superuser
        r = client.post("/filters/api/content-policy/mode", json={"mode": "dns_nxdomain_only"})
        assert r.status_code == 200
        assert r.get_json()["mode"] == "dns_nxdomain_only"

    def test_set_mode_invalid_400(self, superuser):
        client, _ = superuser
        r = client.post("/filters/api/content-policy/mode", json={"mode": "bogus"})
        assert r.status_code == 400


# ─── Route registration regression guard ─────────────────────────────────────

class TestFilterRouteRegistration:
    def test_all_filter_endpoints_registered(self, app):
        rules = {str(r) for r in app.url_map.iter_rules()}
        required = (
            "/filters/", "/filters/dns", "/filters/web", "/filters/app",
            "/filters/dns/add", "/filters/dns/<int:rule_id>/toggle",
            "/filters/dns/<int:rule_id>/edit", "/filters/dns/<int:rule_id>/delete",
            "/filters/dns/apply",
            "/filters/web/add", "/filters/web/<int:rule_id>/toggle",
            "/filters/web/<int:rule_id>/edit", "/filters/web/<int:rule_id>/delete",
            "/filters/web/apply",
            "/filters/app/add", "/filters/app/add-signature",
            "/filters/app/<int:rule_id>/toggle",
            "/filters/app/<int:rule_id>/edit", "/filters/app/<int:rule_id>/delete",
            "/filters/app/apply",
            "/filters/api/content-policy/mode",
            "/filters/api/signatures", "/filters/api/conflicts",
            "/filters/api/preview", "/filters/api/runtime/policy-status",
            "/filters/api/export/<filter_type>",
            "/filters/api/import/<filter_type>",
        )
        missing = [p for p in required if p not in rules]
        assert not missing, f"missing routes: {missing}"
