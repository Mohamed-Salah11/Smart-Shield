"""Smoke: login, logout, and login-required gating."""


def test_login_page_loads(client):
    """With an empty users table, /login redirects to the setup wizard.
    With at least one user, /login returns 200. Accept both."""
    response = client.get("/login", follow_redirects=False)
    if response.status_code == 302:
        # First-boot path: must redirect into the setup wizard
        assert "/setup/" in response.headers.get("Location", "")
    else:
        assert response.status_code == 200


def test_login_page_loads_with_admin(superuser):
    """Once a user exists, the login page must return 200 (no setup redirect)."""
    client, _uid = superuser
    # superuser fixture has already logged in; log out first so we hit /login fresh
    client.post("/system/logout", follow_redirects=False)
    response = client.get("/login", follow_redirects=False)
    assert response.status_code == 200


def test_login_then_logout_round_trip(superuser):
    client, _uid = superuser
    # superuser fixture has already logged in; dashboard should be reachable
    dashboard = client.get("/system/dashboard", follow_redirects=False)
    assert dashboard.status_code in (200, 302)
    # /system/logout is POST-only and CSRF-protected (bypassed in TESTING mode)
    logout = client.post("/system/logout", follow_redirects=False)
    assert logout.status_code in (302, 303)
    assert "/login" in logout.headers.get("Location", "")


def test_logout_get_is_rejected(superuser):
    """GET on /system/logout must NOT clear the session. The endpoint is
    POST-only by design to prevent CSRF-driven logout."""
    client, _uid = superuser
    response = client.get("/system/logout", follow_redirects=False)
    assert response.status_code == 405


def test_unauthenticated_dashboard_redirects_to_login(client):
    response = client.get("/system/dashboard", follow_redirects=False)
    assert response.status_code in (302, 303)
    assert "/login" in response.headers.get("Location", "")
