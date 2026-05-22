"""Smoke: login, logout, and login-required gating."""


def test_login_page_loads(client):
    response = client.get("/login")
    assert response.status_code == 200


def test_login_then_logout_round_trip(superuser):
    client, _uid = superuser
    # superuser fixture has already logged in; dashboard should be reachable
    dashboard = client.get("/system/dashboard", follow_redirects=False)
    assert dashboard.status_code in (200, 302)
    # logout clears the session and redirects back to /login
    logout = client.get("/system/logout", follow_redirects=False)
    assert logout.status_code in (302, 303)


def test_unauthenticated_dashboard_redirects_to_login(client):
    response = client.get("/system/dashboard", follow_redirects=False)
    assert response.status_code in (302, 303)
    assert "/login" in response.headers.get("Location", "")
