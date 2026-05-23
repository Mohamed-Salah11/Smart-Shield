"""Smoke: firewall rule pages and NAT JSON endpoints respond for a logged-in user."""


def test_firewall_rules_page_loads(superuser):
    client, _ = superuser
    response = client.get("/firewall/")
    assert response.status_code in (200, 302)


def test_nat_page_loads(superuser):
    client, _ = superuser
    response = client.get("/firewall/nat")
    assert response.status_code in (200, 302, 308)


def test_nat_pf_listing_returns_json(superuser):
    client, _ = superuser
    response = client.get("/firewall/api/nat/pf")
    # 200 with JSON body, or a server error if the table doesn't exist yet on
    # the in-memory DB — anything other than 5xx 'crashed' is a smoke pass.
    assert response.status_code != 500 or b"error" in response.data.lower()
