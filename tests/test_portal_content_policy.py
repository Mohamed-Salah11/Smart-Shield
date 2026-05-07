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


def test_active_blocked_host_redirects_to_portal_login(client, conn):
    _add_dns_block(conn)

    response = client.get(
        "/system/dashboard",
        headers={"Host": "blocked.test"},
        follow_redirects=False,
    )

    location = response.headers.get("Location", "")
    assert response.status_code in (301, 302)
    assert location.startswith("/portal/?")
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

    location = response.headers.get("Location", "")
    assert response.status_code in (301, 302)
    assert "/login" in location
    assert "/portal" not in location


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
        },
    )

    assert response.status_code == 200
    assert b"Access granted" in response.data
    assert b"blocked.test" in response.data
    assert b"Continue to" not in response.data


def test_block_route_redirects_unauthenticated_policy_to_login(client, conn):
    response = client.get(
        "/portal/block?domain=blocked.test&url=http://blocked.test/page",
        follow_redirects=False,
    )

    location = response.headers.get("Location", "")
    assert response.status_code in (301, 302)
    assert location.startswith("/portal/?")
    assert "policy=content" in location
    assert "domain=blocked.test" in location
