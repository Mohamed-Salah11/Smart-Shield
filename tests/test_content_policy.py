import time

import pytest

from app.database import get_db


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


def test_domain_matches_exact_and_subdomain():
    from app.services.content_policy import domain_matches

    assert domain_matches("example.com", "example.com") is True
    assert domain_matches("www.example.com", "example.com") is True
    assert domain_matches("badexample.com", "example.com") is False


def test_active_rule_detection_includes_dns_web_and_app_ports(conn):
    from app.services.content_policy import has_active_content_policy

    assert has_active_content_policy(conn) is False

    conn.execute(
        "INSERT INTO filter_dns_rules (domain, action, enabled) VALUES ('blocked.test', 'block', 1)"
    )
    conn.commit()
    assert has_active_content_policy(conn) is True

    conn.execute("DELETE FROM filter_dns_rules")
    conn.execute(
        """
        INSERT INTO filter_web_rules (url_pattern, action, enabled)
        VALUES ('example.test', 'block', 1)
        """
    )
    conn.commit()
    assert has_active_content_policy(conn) is True

    conn.execute("DELETE FROM filter_web_rules")
    conn.execute(
        """
        INSERT INTO filter_app_rules
            (app_name, action, enabled, block_dns, block_ports, ports)
        VALUES ('BitTorrent', 'block', 1, 0, 1, '6881')
        """
    )
    conn.commit()
    assert has_active_content_policy(conn) is True


def test_blocked_domain_detection_matches_enabled_block_rules(conn):
    from app.services.content_policy import is_blocked_domain

    conn.execute(
        "INSERT INTO filter_dns_rules (domain, action, enabled) VALUES ('blocked.test', 'block', 1)"
    )
    conn.execute(
        """
        INSERT INTO filter_app_rules
            (app_name, action, enabled, block_dns, domains)
        VALUES ('Video', 'block', 1, 1, 'video.test,cdn.video.test')
        """
    )
    conn.commit()

    assert is_blocked_domain(conn, "www.blocked.test") is True
    assert is_blocked_domain(conn, "cdn.video.test") is True
    assert is_blocked_domain(conn, "allowed.test") is False


def test_active_captive_session_detection(conn):
    from app.services.content_policy import has_active_captive_session

    now = int(time.time())
    conn.execute(
        """
        INSERT INTO captive_sessions (mac_address, ip_address, expires_at, logged_out)
        VALUES ('aa:bb:cc:dd:ee:ff', '192.0.2.10', ?, 0)
        """,
        (now + 60,),
    )
    conn.execute(
        """
        INSERT INTO captive_sessions (mac_address, ip_address, expires_at, logged_out)
        VALUES ('bb:cc:dd:ee:ff:00', '192.0.2.11', ?, 1)
        """,
        (now + 60,),
    )
    conn.commit()

    assert has_active_captive_session(conn, "192.0.2.10", now=now) is True
    assert has_active_captive_session(conn, "192.0.2.11", now=now) is False
    assert has_active_captive_session(conn, "192.0.2.12", now=now) is False


def test_app_filter_pf_port_blocks_skip_authenticated_clients(conn):
    from app.services.app_filter import generate_app_filter_pf_rules

    conn.execute(
        """
        INSERT INTO filter_app_rules
            (app_name, action, enabled, block_ports, ports, protocol)
        VALUES ('BitTorrent', 'block', 1, 1, '6881-6889,6969', 'tcp+udp')
        """
    )
    conn.commit()

    rules = generate_app_filter_pf_rules(conn)
    assert "block quick proto tcp from !<authenticated_clients> to any port { 6881:6889 6969 }" in rules
    assert "block quick proto udp from !<authenticated_clients> to any port { 6881:6889 6969 }" in rules
    assert "from any to any port" not in rules


def test_freebsd_pf_table_failure_makes_authentication_fail(conn, monkeypatch):
    from app.services.network_service import CommandResult
    from app.services import captive_portal

    def fake_run_privileged(*args, **kwargs):
        return CommandResult(command=[], returncode=1, stdout="", stderr="pf table error")

    monkeypatch.setattr(captive_portal.sys, "platform", "freebsd13")
    monkeypatch.setattr(captive_portal, "run_privileged", fake_run_privileged)

    result = captive_portal.authenticate_session(
        conn,
        "aa:bb:cc:dd:ee:11",
        "192.0.2.20",
        "portaluser",
    )

    assert result["ok"] is False
    assert "pf table error" in result["message"]
    assert captive_portal.get_active_sessions(conn) == []
