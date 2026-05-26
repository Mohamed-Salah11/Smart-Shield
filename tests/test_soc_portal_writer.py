"""
tests/test_soc_portal_writer.py
-------------------------------
Unit tests for the generated SOC Portal nginx server block.

Regression guard for the defect where the SOC vhost proxied only
``/soc-portal/`` to Flask and 404'd everything else — including ``/static/*``.
That broke every page extending the SOC base template (no Bootstrap, no icons,
no JS), because static assets live under ``/static/`` and never reach Flask.
"""

import os

os.environ.setdefault("SECRET_KEY", "test-soc-writer-key")
os.environ.setdefault(
    "SMARTSHIELD_MASTER_KEY",
    __import__("base64").b64encode(__import__("secrets").token_bytes(32)).decode(),
)

from app.services.soc_portal_writer import generate_soc_nginx_block  # noqa: E402


class TestGenerateSocNginxBlock:
    def _block(self):
        return generate_soc_nginx_block(
            "192.168.100.1", 8443, "/etc/ssl/soc-cert.pem", "/etc/ssl/soc-key.pem"
        )

    def test_serves_static_assets(self):
        """A /static/ location must proxy to Flask so the portal UI can load
        Bootstrap / Font Awesome / CSS / JS."""
        block = self._block()
        assert "location /static/ {" in block, "missing /static/ location"
        # The /static/ block must proxy to the Flask app.
        static_idx = block.index("location /static/ {")
        static_segment = block[static_idx:static_idx + 400]
        assert "proxy_pass         http://127.0.0.1:5000;" in static_segment

    def test_still_proxies_soc_portal(self):
        block = self._block()
        assert "location /soc-portal/ {" in block
        assert "http://127.0.0.1:5000" in block

    def test_admin_routes_still_blocked(self):
        """Network isolation must be preserved: everything not /soc-portal/ or
        /static/ still returns 404 (analysts cannot reach the admin UI)."""
        block = self._block()
        assert "location / {" in block
        # The catch-all must 404, and must come AFTER the /static/ block so it
        # does not shadow it.
        assert "return 404;" in block
        assert block.index("location /static/ {") < block.index("location / {")

    def test_listen_and_tls_present(self):
        block = self._block()
        assert "listen      192.168.100.1:8443 ssl;" in block
        assert "ssl_certificate     /etc/ssl/soc-cert.pem;" in block
        assert "ssl_certificate_key /etc/ssl/soc-key.pem;" in block
