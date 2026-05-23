"""Smoke: DHCP, DNS, and IDS settings pages render for a superuser."""

import pytest


@pytest.mark.parametrize("path", [
    "/services/dhcp",
    "/services/dns",
    "/ids/",
])
def test_service_page_loads(superuser, path):
    client, _ = superuser
    response = client.get(path)
    # Acceptable: 200 (rendered), 302 (redirect to canonical URL),
    # 308 (permanent redirect from prefix), or 404 if the page is gated
    # behind ENABLE_UNFINISHED_PAGES — what we care about is "did not crash".
    assert response.status_code < 500, f"GET {path} returned {response.status_code}"
