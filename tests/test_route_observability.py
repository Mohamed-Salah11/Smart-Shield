"""Route-level tests for the Observability sidebar group.

Covers status.*, firewall_logs.*, dns_logs.* blueprints (14 sidebar pages).
"""
import pytest


# 14 sidebar pages (Log-Forwarding + Correlation-Rules are superuser-only)
OBSERVABILITY_PAGES = [
    "/status/carp-failover",
    "/status/gateways",
    "/status/monitoring",
    "/status/queues",
    "/status/traffic-graph",
    "/status/mrtg",
    "/status/dhcp-leases",
    "/status/system-logs",
    "/firewall/logs",
    "/dns/logs",
    "/status/collector-health",
    "/status/filter-reload",
    "/status/log-forwarding",
    "/status/correlation-rules",
]


class TestObservabilityPages:
    @pytest.mark.parametrize("path", OBSERVABILITY_PAGES)
    def test_page_loads(self, superuser, path):
        client, _ = superuser
        r = client.get(path, follow_redirects=True)
        assert r.status_code == 200, f"{path} -> {r.status_code}"


class TestObservabilityReadEndpoints:
    @pytest.mark.parametrize("path", [
        "/status/api/logs",
        "/status/api/logs/stats",
        "/status/api/logs/timeseries",
        "/status/api/app-logs",
        "/status/api/app-logs/stats",
        "/status/api/interface-stats",
        "/status/api/collector-health",
        "/status/api/migration-health",
        "/status/api/pf/preview",
        "/status/api/dhcp/preview",
        "/status/api/dhcp/leases",
        "/status/api/dns/preview",
        "/status/api/config-history",
        "/status/api/health",
        "/status/api/health/full",
        "/status/api/health/history",
        "/status/api/health/disk",
        "/status/api/health/system",
    ])
    def test_get_endpoint(self, superuser, path):
        client, _ = superuser
        r = client.get(path)
        assert r.status_code == 200, f"{path} -> {r.status_code}"


class TestObservabilityPublicProbes:
    """Liveness / readiness probes do not require auth."""

    def test_health_open(self, client):
        r = client.get("/status/health")
        assert r.status_code == 200

    def test_readiness_open(self, client):
        r = client.get("/status/readiness")
        assert r.status_code in (200, 503)  # 503 if dependencies degraded


class TestObservabilityMutations:
    """Mutating endpoints reject non-superuser / non-permitted."""

    @pytest.mark.parametrize("method,path,body", [
        ("POST", "/status/filter-reload/apply", {}),
        ("POST", "/status/log-forwarding", {"enabled": False}),
        ("POST", "/status/correlation-rules/add", {"name": "x"}),
        ("POST", "/status/correlation-rules/test", {}),
        ("POST", "/status/correlation-rules/1/toggle", {}),
        ("POST", "/status/correlation-rules/1/delete", {}),
        ("POST", "/status/api/collector-health/dlq/1/replay", {}),
        ("POST", "/status/api/collector-health/dlq/purge", {}),
        ("POST", "/status/api/pf/rollback", {}),
        ("POST", "/status/api/dhcp/apply", {}),
        ("POST", "/status/api/dns/apply", {}),
        ("POST", "/status/api/config-history/1/rollback", {}),
        ("POST", "/status/api/config-history/dhcp/prune", {}),
    ])
    def test_mutation_rejects_plain_user(self, plain_user, method, path, body):
        client, _ = plain_user
        if method == "POST":
            r = client.post(path, json=body or {})
        else:
            r = client.delete(path)
        # Some of these endpoints are superuser-only; others are api.network.edit.
        # Either way, plain_user must NOT be allowed.
        assert r.status_code in (401, 403), f"{method} {path} -> {r.status_code}"


class TestDnsTestEndpoint:
    """/api/dns/test is a GET endpoint that triggers a server-side DNS lookup.
    Now permission-gated (api.network.edit) after the audit."""

    def test_dns_test_requires_permission(self, plain_user):
        client, _ = plain_user
        r = client.get("/status/api/dns/test?hostname=example.com")
        assert r.status_code in (401, 403)

    def test_dns_test_superuser(self, superuser):
        client, _ = superuser
        r = client.get("/status/api/dns/test?hostname=example.com")
        assert r.status_code == 200


class TestObservabilityRouteRegistration:
    def test_required_endpoints_registered(self, app):
        rules = {str(r) for r in app.url_map.iter_rules()}
        required = (
            "/status/", "/status/carp-failover", "/status/gateways",
            "/status/monitoring", "/status/queues", "/status/traffic-graph",
            "/status/mrtg", "/status/dhcp-leases", "/status/system-logs",
            "/status/collector-health", "/status/filter-reload",
            "/status/log-forwarding", "/status/correlation-rules",
            "/firewall/logs", "/dns/logs",
            "/status/api/logs", "/status/api/logs/stats",
            "/status/api/logs/timeseries", "/status/api/logs/stream",
            "/status/api/logs/export",
            "/status/api/collector-health",
            "/status/api/health", "/status/health", "/status/readiness",
        )
        missing = [p for p in required if p not in rules]
        assert not missing, f"missing routes: {missing}"
