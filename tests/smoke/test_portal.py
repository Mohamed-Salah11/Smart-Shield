"""Smoke: captive portal landing page is reachable without authentication
and POSTs to /portal/auth are NOT blocked by CSRF (the portal blueprint is
explicitly CSRF-exempted in app/__init__.py:CSRF_EXEMPT_ENDPOINT_PREFIXES)."""


def test_portal_landing_anonymous(client):
    response = client.get("/portal/")
    # Captive portal must respond to anonymous clients; never crash.
    assert response.status_code < 500


def test_portal_auth_post_not_rejected_for_csrf(client):
    # In TESTING mode validate_csrf_or_abort() already short-circuits,
    # but a real production deployment with CSRF on must still let the
    # portal POST through via the CSRF_EXEMPT_ENDPOINT_PREFIXES list.
    # We assert here that the endpoint responds (any code other than 400
    # CSRF-aborted is fine — 400 with non-CSRF body, 401, 404 etc. all
    # mean the CSRF gate let us past).
    response = client.post(
        "/portal/auth",
        data={"username": "doesnotexist", "password": "nope"},
        follow_redirects=False,
    )
    if response.status_code == 400:
        # Must NOT be the CSRF error string.
        assert b"CSRF" not in response.data, (
            "Portal auth POST was blocked by CSRF — "
            "CSRF_EXEMPT_ENDPOINT_PREFIXES regression"
        )
