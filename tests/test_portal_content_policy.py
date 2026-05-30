import time

import pytest

from app.database import get_db
from tests.conftest import _create_user


@pytest.fixture()
def conn(app):
    with app.app_context():
        db = get_db()
        for table in (
            "filter_dns_rules",
            "filter_web_rules",
            "filter_app_rules",
            "captive_sessions",
        ):
            db.execute(f"DELETE FROM {table}")
        db.commit()
        yield db
        for table in (
            "filter_dns_rules",
            "filter_web_rules",
            "filter_app_rules",
            "captive_sessions",
        ):
            db.execute(f"DELETE FROM {table}")
        db.commit()


def _add_dns_block(conn, domain="blocked.test"):
    conn.execute(
        "INSERT INTO filter_dns_rules (domain, action, enabled) VALUES (?, 'block', 1)",
        (domain,),
    )
    conn.commit()


def test_no_content_policy_keeps_admin_login_redirect(client, conn):
    response = client.get(
        "/system/dashboard",
        headers={"Host": "blocked.test"},
        follow_redirects=False,
    )

    assert response.status_code in (301, 302)
    assert "/login" in response.headers.get("Location", "")
    assert "/portal" not in response.headers.get("Location", "")


def test_active_blocked_host_redirects_to_block_page(client, conn):
    _add_dns_block(conn)

    response = client.get(
        "/system/dashboard",
        headers={"Host": "blocked.test"},
        follow_redirects=False,
    )

    location = response.headers.get("Location", "")
    assert response.status_code in (301, 302)
    assert "/portal/block?" in location
    assert "policy=content" in location
    assert "domain=blocked.test" in location


def test_active_captive_session_skips_portal_redirect(client, conn):
    _add_dns_block(conn)
    conn.execute(
        """
        INSERT INTO captive_sessions (mac_address, ip_address, expires_at, logged_out)
        VALUES ('ip:127.0.0.1', '127.0.0.1', ?, 0)
        """,
        (int(time.time()) + 300,),
    )
    conn.commit()

    response = client.get(
        "/system/dashboard",
        headers={"Host": "blocked.test"},
        follow_redirects=False,
    )

    assert response.status_code == 200
    assert b"Session Active" in response.data


def _add_admin_bypass_session(conn, ip="127.0.0.1"):
    conn.execute(
        "INSERT INTO captive_sessions (mac_address, ip_address, is_superuser, expires_at, logged_out) "
        "VALUES (?, ?, 1, ?, 0)",
        (f"ip:{ip}", ip, int(time.time()) + 300),
    )
    conn.commit()


def _set_cp_settings(conn, **kw):
    import json
    conn.execute(
        "INSERT OR REPLACE INTO service_state (key_name, value_json) VALUES "
        "('captive_portal_settings', ?)",
        (json.dumps(kw),),
    )
    conn.commit()


def test_admin_bypass_without_dns_bypass_redirects_not_404(client, conn):
    # P.4: an admin-bypass client hitting a blocked domain WITHOUT
    # dns_bypass_for_admin must be redirected to the block page, not passed
    # through to a 404 (DNS still points it at the LAN IP).
    _add_dns_block(conn)
    _add_admin_bypass_session(conn)
    try:
        response = client.get(
            "/system/dashboard",
            headers={"Host": "blocked.test"},
            follow_redirects=False,
        )
        location = response.headers.get("Location", "")
        assert response.status_code in (301, 302)
        assert "/portal/block?" in location
    finally:
        conn.execute("DELETE FROM service_state WHERE key_name='captive_portal_settings'")
        conn.commit()


def test_admin_bypass_with_dns_bypass_passes_through(client, conn):
    # P.4: with dns_bypass_for_admin enabled the middleware short-circuits
    # (returns None) and the request continues to normal app routing — it is
    # NOT sent to the portal block page.
    _add_dns_block(conn)
    _add_admin_bypass_session(conn)
    _set_cp_settings(conn, dns_bypass_for_admin=True)
    try:
        response = client.get(
            "/system/dashboard",
            headers={"Host": "blocked.test"},
            follow_redirects=False,
        )
        location = response.headers.get("Location", "")
        assert "/portal/block" not in location
    finally:
        conn.execute("DELETE FROM service_state WHERE key_name='captive_portal_settings'")
        conn.commit()


def test_invalid_portal_credentials_preserve_policy_context(client, conn):
    response = client.post(
        "/portal/auth",
        data={
            "auth_type": "credentials",
            "username": "nobody",
            "password": "wrong",
            "policy": "content",
            "domain": "blocked.test",
            "orig_url": "http://blocked.test/page",
        },
    )

    assert response.status_code == 200
    assert b'Invalid username or password.' in response.data
    assert b'name="policy" value="content"' in response.data
    assert b'name="domain" value="blocked.test"' in response.data
    assert b'name="orig_url" value="http://blocked.test/page"' in response.data


def test_valid_portal_credentials_render_policy_success(app, client, conn):
    _create_user(app, "portaluser", "portalpass", is_superuser=0)

    response = client.post(
        "/portal/auth",
        data={
            "auth_type": "credentials",
            "username": "portaluser",
            "password": "portalpass",
            "policy": "content",
            "domain": "blocked.test",
            "orig_url": "http://blocked.test/page",
            "back_template": "block",
        },
    )

    assert response.status_code == 200
    assert b"Access Granted" in response.data
    assert b"blocked.test" in response.data


def test_block_route_renders_block_page_for_unauthenticated(client, conn):
    # Default mode is dns_redirect_block_page: the branded block page renders
    # with the blocked domain and the honest "contact your administrator" copy,
    # and offers no login CTA (a normal login cannot unblock in this mode).
    response = client.get(
        "/portal/block?domain=blocked.test&url=http://blocked.test/page",
        follow_redirects=False,
    )

    assert response.status_code == 200
    assert b"This site has been blocked" in response.data
    assert b"blocked.test" in response.data
    assert b"contact your administrator" in response.data
    assert b"Proceed to Login" not in response.data


def test_block_route_shows_login_cta_in_captive_auth_required(client, conn):
    import json

    conn.execute(
        "INSERT OR REPLACE INTO service_state (key_name, value_json) VALUES "
        "('content_policy_settings', ?)",
        (json.dumps({"mode": "captive_auth_required"}),),
    )
    conn.commit()
    try:
        response = client.get(
            "/portal/block?domain=blocked.test&url=http://blocked.test/page",
            follow_redirects=False,
        )

        assert response.status_code == 200
        assert b"This site has been blocked" in response.data
        assert b"Proceed to Login" in response.data
        assert b"sign in" in response.data.lower()
    finally:
        conn.execute(
            "DELETE FROM service_state WHERE key_name='content_policy_settings'"
        )
        conn.commit()
