"""Route-level tests for the Security Operations sidebar group.

The five pages are all superuser-gated:
  - /system/soc-portal-settings        (SOC Portal Control)
  - /system/soc-recommendations        (Response Recommendations)
  - /system/mail-alerts                (Mail Alerts)
  - /system/playbooks                  (Playbooks)
  - /system/inventory                  (Asset Inventory)
"""
import pytest


SUPERUSER_PAGES = (
    "/system/soc-portal-settings",
    "/system/soc-recommendations",
    "/system/playbooks",
    "/system/inventory",
)


# Mail Alerts page is login_required only (the mutating endpoints below are
# superuser_required).
LOGIN_ONLY_PAGES = ("/system/mail-alerts",)


class TestSecurityOpsPages:
    @pytest.mark.parametrize("path", SUPERUSER_PAGES + LOGIN_ONLY_PAGES)
    def test_page_loads_for_superuser(self, superuser, path):
        client, _ = superuser
        r = client.get(path, follow_redirects=True)
        assert r.status_code == 200, f"{path} -> {r.status_code}"

    @pytest.mark.parametrize("path", SUPERUSER_PAGES)
    def test_page_blocks_non_superuser(self, plain_user, path):
        client, _ = plain_user
        r = client.get(path)
        # superuser_required renders 'not_authorized.html' with 403
        assert r.status_code == 403, f"{path} -> {r.status_code}"


class TestSecurityOpsMutations:
    """Every mutating endpoint must reject a non-superuser."""

    @pytest.mark.parametrize("method,path,body", [
        # SOC Portal
        ("POST", "/system/soc-portal-settings",          {"enabled": True}),
        ("POST", "/system/soc-portal-settings/restart",  {}),
        ("POST", "/system/soc-portal-settings/add-user", {"username": "x", "email": "x@y", "password": "p"}),
        # SOC Recommendations
        ("POST", "/system/soc-recommendations/1/approve", {}),
        ("POST", "/system/soc-recommendations/1/reject",  {}),
        # Mail Alerts (config / recipients / test are superuser_required)
        ("POST",   "/system/api/mail-alerts/config",            {"enabled": False}),
        ("POST",   "/system/api/mail-alerts/recipients",        {"email": "x@y"}),
        ("DELETE", "/system/api/mail-alerts/recipients/1",      None),
        ("POST",   "/system/api/mail-alerts/test",              {}),
        # Playbooks / Inventory pages accept POST for save
        ("POST", "/system/playbooks", {}),
        ("POST", "/system/inventory", {}),
    ])
    def test_mutation_rejects_non_superuser(self, plain_user, method, path, body):
        client, _ = plain_user
        if method == "POST":
            r = client.post(path, json=body if body is not None else {})
        else:
            r = client.delete(path)
        assert r.status_code in (401, 403), f"{method} {path} -> {r.status_code}"


class TestMailAlertsRecipients:
    """Mail Alerts recipients GET is the page-load support endpoint."""

    def test_get_recipients_superuser(self, superuser):
        client, _ = superuser
        r = client.get("/system/api/mail-alerts/recipients")
        assert r.status_code == 200
        assert "recipients" in r.get_json() or isinstance(r.get_json(), list) or "ok" in r.get_json()


class TestSecurityOpsRouteRegistration:
    def test_all_security_ops_endpoints_registered(self, app):
        rules = {str(r) for r in app.url_map.iter_rules()}
        required = (
            "/system/soc-portal-settings",
            "/system/soc-portal-settings/restart",
            "/system/soc-portal-settings/add-user",
            "/system/soc-recommendations",
            "/system/soc-recommendations/<int:rec_id>/approve",
            "/system/soc-recommendations/<int:rec_id>/reject",
            "/system/mail-alerts",
            "/system/api/mail-alerts/config",
            "/system/api/mail-alerts/recipients",
            "/system/api/mail-alerts/recipients/<int:rid>",
            "/system/api/mail-alerts/test",
            "/system/playbooks",
            "/system/inventory",
        )
        missing = [p for p in required if p not in rules]
        assert not missing, f"missing routes: {missing}"
