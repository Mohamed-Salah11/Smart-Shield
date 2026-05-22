"""Smoke: OpenVPN, IPsec, and L2TP setup pages render for a superuser."""

import pytest


@pytest.mark.parametrize("path", [
    "/vpn/openvpn",
    "/vpn/ipsec",
    "/vpn/l2tp",
])
def test_vpn_page_loads(superuser, path):
    client, _ = superuser
    response = client.get(path)
    assert response.status_code < 500, f"GET {path} returned {response.status_code}"
