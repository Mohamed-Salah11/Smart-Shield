"""Route-level tests for services blueprint."""
import pytest


class TestServicesRoutes:
    def test_services_home_requires_login(self, client):
        r = client.get("/services/")
        assert r.status_code in (302, 401)

    def test_services_home_accessible(self, superuser):
        client, _ = superuser
        # /services/ redirects to a real sub-page (DHCP server); follow it and
        # confirm the landing page renders.
        r = client.get("/services/", follow_redirects=True)
        assert r.status_code == 200

    def test_dhcp_server_page(self, superuser):
        client, _ = superuser
        r = client.get("/services/dhcp-server")
        assert r.status_code == 200

    def test_dns_resolver_page(self, superuser):
        client, _ = superuser
        r = client.get("/services/dns-resolver")
        assert r.status_code == 200

    def test_ntp_page(self, superuser):
        client, _ = superuser
        r = client.get("/services/ntp")
        assert r.status_code == 200

    def test_api_get_ntp(self, superuser):
        client, _ = superuser
        r = client.get("/services/api/ntp")
        assert r.status_code == 200
        assert r.get_json().get("ok") is True

    def test_api_save_ntp_requires_permission(self, plain_user):
        client, _ = plain_user
        r = client.post("/services/api/ntp", json={"servers": ["pool.ntp.org"]})
        assert r.status_code in (401, 403)

    def test_captive_portal_settings_get(self, superuser):
        client, _ = superuser
        r = client.get("/services/api/captive-portal/settings")
        assert r.status_code == 200
        data = r.get_json()
        assert data["ok"] is True
        assert "settings" in data

    def test_captive_portal_settings_save_requires_permission(self, plain_user):
        client, _ = plain_user
        r = client.post("/services/api/captive-portal/settings", json={"enabled": True})
        assert r.status_code in (401, 403)

    def test_pppoe_status(self, superuser):
        client, _ = superuser
        r = client.get("/services/api/pppoe/status")
        assert r.status_code == 200
        data = r.get_json()
        assert data["ok"] is True

    def test_config_backup_list(self, superuser):
        client, _ = superuser
        r = client.get("/services/api/config-backup/list")
        assert r.status_code == 200
        data = r.get_json()
        assert data["ok"] is True
        assert isinstance(data["versions"], list)

    def test_dhcpv6_status(self, superuser):
        client, _ = superuser
        r = client.get("/services/api/dhcpv6/status")
        assert r.status_code == 200

    def test_ntp_endpoints_registered(self, app):
        """Regression guard for the §A10 bug: templates/ntp.html used to call
        /api/ntp (no prefix), which 404'd because the services blueprint is
        mounted at /services. Assert the prefixed routes exist."""
        rules = {str(r) for r in app.url_map.iter_rules()}
        for path in (
            "/services/api/ntp",
            "/services/api/ntp/status",
            "/services/api/ntp/validate",
            "/services/api/ntp/preview",
            "/services/api/ntp/apply",
            "/services/api/ntp/force-sync",
        ):
            assert path in rules, f"missing route: {path}"


# ─── All 16 Service Engine sidebar pages load ────────────────────────────────

class TestServiceEnginePages:
    @pytest.mark.parametrize("path", [
        "/services/auto-config-backup",
        "/services/captive-portal",
        "/services/dhcp-server",
        "/services/dhcp-relay",
        "/services/dhcpv6-server",
        "/services/dhcpv6-relay",
        "/services/dns-resolver",
        "/services/dns-forwarder",
        "/services/dynamic-dns",
        "/services/igmp-proxy",
        "/services/ntp",
        "/services/openvpn-server",
        "/services/router-advertisement",
        "/services/snmp",
        "/services/upnp-igd-pcp",
        "/services/wake-on-lan",
    ])
    def test_page_loads(self, superuser, path):
        client, _ = superuser
        r = client.get(path, follow_redirects=True)
        assert r.status_code == 200, f"{path} -> {r.status_code}"


# ─── Service Engine apply endpoints — round-trip in dry-run as superuser ─────

class TestServiceEngineApply:
    @pytest.mark.parametrize("path", [
        "/services/api/ntp/apply",
        "/services/api/captive-portal/apply",
        "/services/api/pppoe/apply",
    ])
    def test_apply_endpoint(self, superuser, path):
        client, _ = superuser
        r = client.post(path, json={})
        assert r.status_code == 200, f"{path} -> {r.status_code}"


# ─── Service Engine mutation permission gates (high-value endpoints) ─────────

class TestServiceEngineMutations:
    @pytest.mark.parametrize("method,path,body", [
        ("POST", "/services/api/config-backup", {}),
        ("POST", "/services/api/config-backup/1/restore", {}),
        ("POST", "/services/api/dhcp-relay", {}),
        ("POST", "/services/api/dhcp-server/em1", {}),
        ("POST", "/services/api/ntp", {"servers": ["pool.ntp.org"]}),
        ("POST", "/services/api/ntp/apply", {}),
        ("POST", "/services/api/captive-portal/settings", {"enabled": False}),
        ("POST", "/services/api/captive-portal/apply", {}),
        ("POST", "/services/api/captive-portal/sessions/1/logout", {}),
        ("POST", "/services/api/captive-portal/sessions/logout-all", {}),
        ("POST", "/services/api/captive-portal/vouchers", {}),
        ("DELETE", "/services/api/captive-portal/vouchers/1", None),
        ("POST", "/services/api/pppoe/apply", {}),
        ("POST", "/services/api/pppoe/disconnect", {}),
    ])
    def test_mutation_rejects_plain_user(self, plain_user, method, path, body):
        client, _ = plain_user
        if method == "POST":
            r = client.post(path, json=body or {})
        else:
            r = client.delete(path)
        assert r.status_code in (401, 403), f"{method} {path} -> {r.status_code}"


# ─── Route registration regression guard ─────────────────────────────────────

class TestServiceEngineRouteRegistration:
    def test_required_endpoints_registered(self, app):
        rules = {str(r) for r in app.url_map.iter_rules()}
        required = (
            # All 16 sidebar pages
            "/services/auto-config-backup", "/services/captive-portal",
            "/services/dhcp-server", "/services/dhcp-relay",
            "/services/dhcpv6-server", "/services/dhcpv6-relay",
            "/services/dns-resolver", "/services/dns-forwarder",
            "/services/dynamic-dns", "/services/igmp-proxy",
            "/services/ntp", "/services/openvpn-server",
            "/services/router-advertisement", "/services/snmp",
            "/services/upnp-igd-pcp", "/services/wake-on-lan",
            # Apply endpoints
            "/services/api/ntp/apply", "/services/api/captive-portal/apply",
            "/services/api/pppoe/apply",
            # Config backup
            "/services/api/config-backup", "/services/api/config-backup/list",
            "/services/api/config-backup/<int:version_id>/restore",
        )
        missing = [p for p in required if p not in rules]
        assert not missing, f"missing routes: {missing}"


class TestTemplateHandlerHygiene:
    """Static checks that the strict-CSP handler migration stays correct."""

    def test_migrate_handlers_check_passes(self):
        """Fail if any template has a dead `<!-- inline-handlers:auto -->` block
        (placed after the final `{% endblock %}` in a child template) or any
        registration line still references an out-of-scope template variable
        (`${...}` / `{{ ... }}`) or an invalid backslash-escaped quote."""
        import subprocess
        import sys
        from pathlib import Path
        root = Path(__file__).resolve().parent.parent
        result = subprocess.run(
            [sys.executable, "scripts/migrate_handlers.py", "--check"],
            cwd=root, capture_output=True, text=True, check=False,
        )
        assert result.returncode == 0, (
            f"migrate_handlers.py --check failed:\n{result.stdout}\n{result.stderr}"
        )
