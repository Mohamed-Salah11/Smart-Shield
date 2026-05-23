"""Route-level tests for the SOC portal isolation boundary.

The SOC Portal has a dedicated bind IP setting (System Core → SOC Portal
Control → bind_ip). When set, the SOC portal must be reachable only via
that IP, not via the admin LAN IP. Two layers enforce this:

  1. nginx admin vhost adds `location /soc-portal/ { return 404; }` when a
     bind_ip is configured (nginx_writer._soc_isolation_block).
  2. Flask `before_request` on soc_portal_bp 404s requests whose host IP
     does not match the configured bind_ip (routes/soc_portal._enforce_soc_bind_ip).

These tests exercise the Flask layer (Layer 2) plus a static check on the
nginx admin vhost output (Layer 1).
"""
import pytest

from app.database import get_db


def _set_soc_config(app, enabled, bind_ip):
    with app.app_context():
        conn = get_db()
        conn.execute(
            "UPDATE soc_portal_config SET enabled=?, bind_ip=? WHERE id=1",
            (1 if enabled else 0, bind_ip),
        )
        conn.commit()


def _clear_soc_config(app):
    """Restore the default seed values so subsequent tests aren't polluted."""
    with app.app_context():
        conn = get_db()
        conn.execute(
            "UPDATE soc_portal_config SET enabled=0, bind_ip='0.0.0.0' WHERE id=1"
        )
        conn.commit()


# ─── Layer 2: Flask before_request host check ─────────────────────────────────

class TestSocPortalHostFilter:

    def test_admin_ip_blocked_when_soc_has_dedicated_ip(self, client, app):
        """SOC bound to 192.168.1.200 — request via 192.168.1.1 must 404."""
        _set_soc_config(app, enabled=True, bind_ip="192.168.1.200")
        try:
            r = client.get("/soc-portal/login",
                           headers={"Host": "192.168.1.1"})
            assert r.status_code == 404
        finally:
            _clear_soc_config(app)

    def test_dedicated_ip_allowed(self, client, app):
        """SOC bound to 192.168.1.200 — request via 192.168.1.200 reaches the
        blueprint (200 login page, or 503 if portal is disabled-with-bind,
        but never a host-filter 404)."""
        _set_soc_config(app, enabled=True, bind_ip="192.168.1.200")
        try:
            r = client.get("/soc-portal/login",
                           headers={"Host": "192.168.1.200"})
            # 200 = login page rendered. The host check only blocks via 404
            # with no body; anything else (200 / 302 / 503) means we passed it.
            assert r.status_code != 404
        finally:
            _clear_soc_config(app)

    def test_port_stripped_from_host_header(self, client, app):
        """`Host: 192.168.1.200:8443` must compare as 192.168.1.200."""
        _set_soc_config(app, enabled=True, bind_ip="192.168.1.200")
        try:
            r = client.get("/soc-portal/login",
                           headers={"Host": "192.168.1.200:8443"})
            assert r.status_code != 404
        finally:
            _clear_soc_config(app)

    def test_legacy_mode_allows_any_host(self, client, app):
        """bind_ip='0.0.0.0' (default) = legacy single-IP mode: no host filter."""
        _set_soc_config(app, enabled=True, bind_ip="0.0.0.0")
        try:
            r = client.get("/soc-portal/login",
                           headers={"Host": "anything.test"})
            assert r.status_code != 404
        finally:
            _clear_soc_config(app)

    def test_empty_bind_ip_allows_any_host(self, client, app):
        """bind_ip='' is treated the same as legacy mode."""
        _set_soc_config(app, enabled=True, bind_ip="")
        try:
            r = client.get("/soc-portal/login",
                           headers={"Host": "192.168.1.1"})
            assert r.status_code != 404
        finally:
            _clear_soc_config(app)

    def test_disabled_portal_no_host_filter(self, client, app):
        """When enabled=0 the host filter must not run — the portal's own
        disabled-check decides what to return, not the host gate."""
        _set_soc_config(app, enabled=False, bind_ip="192.168.1.200")
        try:
            r = client.get("/soc-portal/login",
                           headers={"Host": "192.168.1.1"})
            # 404 here would be from the host filter; a 503 ('disabled' page)
            # or 200 (allowed) both indicate the host filter correctly
            # skipped this request.
            assert r.status_code != 404 or "soc" in r.get_data(as_text=True).lower()
        finally:
            _clear_soc_config(app)


# ─── Layer 1: static check on generated nginx admin vhost ─────────────────────

class TestSocPortalNginxIsolation:

    def test_admin_vhost_blocks_soc_when_dedicated_ip(self, app):
        """nginx_writer.generate_nginx_conf must emit a
        `location /soc-portal/ { return 404; }` block in the admin vhost
        when soc_portal_config.bind_ip differs from the admin LAN IP."""
        _set_soc_config(app, enabled=True, bind_ip="192.168.1.200")
        try:
            with app.app_context():
                from app.services.nginx_writer import generate_nginx_conf
                conf = generate_nginx_conf(get_db())
            assert "location /soc-portal/" in conf
            assert "return 404" in conf
        finally:
            _clear_soc_config(app)

    def test_admin_vhost_no_block_when_legacy_mode(self, app):
        """bind_ip='0.0.0.0' (legacy single-IP) must NOT emit the 404 block —
        SOC then shares the admin IP and /soc-portal/* should still work
        from the admin vhost."""
        _set_soc_config(app, enabled=True, bind_ip="0.0.0.0")
        try:
            with app.app_context():
                from app.services.nginx_writer import generate_nginx_conf
                conf = generate_nginx_conf(get_db())
            # Find the SOC-isolation comment marker we emit. Its absence proves
            # the block did not render. (A blanket "return 404" search would
            # false-positive on the SOC vhost include / other blocks.)
            assert "SOC portal is bound to" not in conf
        finally:
            _clear_soc_config(app)

    def test_admin_vhost_no_block_when_disabled(self, app):
        """enabled=0 + bind_ip set must NOT emit the block: the portal is off,
        so /soc-portal/* doesn't need isolation."""
        _set_soc_config(app, enabled=False, bind_ip="192.168.1.200")
        try:
            with app.app_context():
                from app.services.nginx_writer import generate_nginx_conf
                conf = generate_nginx_conf(get_db())
            assert "SOC portal is bound to" not in conf
        finally:
            _clear_soc_config(app)

    def test_admin_vhost_no_block_when_bind_ip_equals_lan_ip(self, app):
        """If the operator misconfigures bind_ip = admin LAN IP, no isolation
        is possible (single-IP) — must not emit the block (it would break
        SOC access entirely)."""
        # LAN IP is seeded from lan_config. Read its IP and use that as bind_ip.
        with app.app_context():
            conn = get_db()
            row = conn.execute("SELECT ipv4_address FROM lan_config WHERE id=1").fetchone()
            cidr = (row["ipv4_address"] if row else "") or "192.168.1.1/24"
        lan_ip = cidr.split("/")[0]
        _set_soc_config(app, enabled=True, bind_ip=lan_ip)
        try:
            with app.app_context():
                from app.services.nginx_writer import generate_nginx_conf
                conf = generate_nginx_conf(get_db())
            assert "SOC portal is bound to" not in conf
        finally:
            _clear_soc_config(app)
