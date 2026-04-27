"""
tests/test_filter_conflicts.py
-------------------------------
Tests for app/services/filter_conflicts.py — conflict detection, preview,
import, and export.
No FreeBSD required.
"""
import os
import pytest

os.environ.setdefault("SMARTSHIELD_DB_PATH", "file:filterconflict?mode=memory&cache=shared")
os.environ.setdefault("SECRET_KEY", "test-filter-key")
os.environ.setdefault("SMARTSHIELD_MASTER_KEY",
    __import__("base64").b64encode(__import__("secrets").token_bytes(32)).decode())


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def conn():
    import secrets
    os.environ["SMARTSHIELD_DB_PATH"] = f"file:fc_{secrets.token_hex(4)}?mode=memory&cache=shared"
    from app.database import init_db, get_db
    init_db()
    db = get_db()
    yield db
    db.close()


# ---------------------------------------------------------------------------
# Conflict detection
# ---------------------------------------------------------------------------

class TestDetectConflicts:

    def test_no_rules_no_conflicts(self, conn):
        from app.services.filter_conflicts import detect_conflicts
        result = detect_conflicts(conn)
        assert result["errors"] == []
        assert result["warnings"] == []

    def test_duplicate_domain_warning(self, conn):
        from app.services.filter_conflicts import detect_conflicts
        conn.execute(
            "INSERT INTO filter_dns_rules (enabled, domain, action) VALUES (1, 'evil.com', 'block')"
        )
        conn.execute(
            "INSERT INTO filter_web_rules (enabled, url_pattern, action) VALUES (1, 'evil.com', 'block')"
        )
        conn.commit()
        result = detect_conflicts(conn)
        assert any("evil.com" in w for w in result["warnings"])

    def test_allow_block_conflict_is_error(self, conn):
        from app.services.filter_conflicts import detect_conflicts
        conn.execute(
            "INSERT INTO filter_dns_rules (enabled, domain, action) VALUES (1, 'mysite.com', 'allow')"
        )
        conn.execute(
            "INSERT INTO filter_web_rules (enabled, url_pattern, action) VALUES (1, 'mysite.com', 'block')"
        )
        conn.commit()
        result = detect_conflicts(conn)
        assert any("mysite.com" in e for e in result["errors"])

    def test_redirect_without_ip_is_error(self, conn):
        from app.services.filter_conflicts import detect_conflicts
        conn.execute(
            "INSERT INTO filter_dns_rules (enabled, domain, action, redirect_ip) "
            "VALUES (1, 'redir.com', 'redirect', '')"
        )
        conn.commit()
        result = detect_conflicts(conn)
        assert any("redir.com" in e and "redirect IP" in e for e in result["errors"])

    def test_redirect_with_invalid_ip_is_error(self, conn):
        from app.services.filter_conflicts import detect_conflicts
        conn.execute(
            "INSERT INTO filter_dns_rules (enabled, domain, action, redirect_ip) "
            "VALUES (1, 'redir2.com', 'redirect', 'not-an-ip')"
        )
        conn.commit()
        result = detect_conflicts(conn)
        assert any("redir2.com" in e for e in result["errors"])

    def test_redirect_with_valid_ip_no_error(self, conn):
        from app.services.filter_conflicts import detect_conflicts
        conn.execute(
            "INSERT INTO filter_dns_rules (enabled, domain, action, redirect_ip) "
            "VALUES (1, 'redir3.com', 'redirect', '192.168.1.99')"
        )
        conn.commit()
        result = detect_conflicts(conn)
        assert not any("redir3.com" in e for e in result["errors"])

    def test_disabled_rules_not_considered(self, conn):
        from app.services.filter_conflicts import detect_conflicts
        conn.execute(
            "INSERT INTO filter_dns_rules (enabled, domain, action) VALUES (0, 'disabled.com', 'block')"
        )
        conn.execute(
            "INSERT INTO filter_web_rules (enabled, url_pattern, action) VALUES (0, 'disabled.com', 'allow')"
        )
        conn.commit()
        result = detect_conflicts(conn)
        # Disabled rules should not trigger any conflict
        assert not any("disabled.com" in e for e in result["errors"])
        assert not any("disabled.com" in w for w in result["warnings"])


# ---------------------------------------------------------------------------
# Preview
# ---------------------------------------------------------------------------

class TestGetFilterPreview:

    def test_preview_returns_expected_keys(self, conn):
        from app.services.filter_conflicts import get_filter_preview
        result = get_filter_preview(conn)
        assert "dns_zones" in result
        assert "pf_rules" in result
        assert "conflicts" in result
        assert "dns_zone_count" in result

    def test_preview_includes_dns_filter_zones(self, conn):
        from app.services.filter_conflicts import get_filter_preview
        conn.execute(
            "INSERT INTO filter_dns_rules (enabled, domain, action) VALUES (1, 'blocked.com', 'block')"
        )
        conn.commit()
        result = get_filter_preview(conn)
        assert any("blocked.com" in z for z in result["dns_zones"])


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

class TestExportFilterList:

    def test_export_dns_returns_domains(self, conn):
        from app.services.filter_conflicts import export_filter_list
        conn.execute(
            "INSERT INTO filter_dns_rules (enabled, domain, action) VALUES (1, 'a.com', 'block')"
        )
        conn.execute(
            "INSERT INTO filter_dns_rules (enabled, domain, action) VALUES (1, 'b.com', 'block')"
        )
        conn.commit()
        text = export_filter_list(conn, "dns")
        assert "a.com" in text
        assert "b.com" in text

    def test_export_web_returns_patterns(self, conn):
        from app.services.filter_conflicts import export_filter_list
        conn.execute(
            "INSERT INTO filter_web_rules (enabled, url_pattern, action) VALUES (1, 'social.net', 'block')"
        )
        conn.commit()
        text = export_filter_list(conn, "web")
        assert "social.net" in text

    def test_export_disabled_excluded(self, conn):
        from app.services.filter_conflicts import export_filter_list
        conn.execute(
            "INSERT INTO filter_dns_rules (enabled, domain, action) VALUES (0, 'hidden.com', 'block')"
        )
        conn.commit()
        text = export_filter_list(conn, "dns")
        assert "hidden.com" not in text

    def test_export_unknown_type_returns_empty(self, conn):
        from app.services.filter_conflicts import export_filter_list
        assert export_filter_list(conn, "unknown") == ""


# ---------------------------------------------------------------------------
# Import
# ---------------------------------------------------------------------------

class TestImportFilterList:

    def test_import_dns_domains(self, conn):
        from app.services.filter_conflicts import import_filter_list
        text = "import1.com\nimport2.com\nimport3.com"
        result = import_filter_list(conn, text, "dns", action="block")
        assert result["ok"] is True
        assert result["imported"] == 3
        assert result["skipped"] == 0

    def test_import_skips_comments(self, conn):
        from app.services.filter_conflicts import import_filter_list
        text = "# comment\ngood.com\n# another comment"
        result = import_filter_list(conn, text, "dns")
        assert result["imported"] == 1

    def test_import_skips_empty_lines(self, conn):
        from app.services.filter_conflicts import import_filter_list
        text = "valid.com\n\n\nalso-valid.com"
        result = import_filter_list(conn, text, "dns")
        assert result["imported"] == 2

    def test_import_unknown_type_returns_error(self, conn):
        from app.services.filter_conflicts import import_filter_list
        result = import_filter_list(conn, "domain.com", "unknown")
        assert result["ok"] is False

    def test_import_allow_action(self, conn):
        from app.services.filter_conflicts import import_filter_list, export_filter_list
        text = "allowed-site.com"
        result = import_filter_list(conn, text, "dns", action="allow")
        assert result["imported"] == 1
        # Verify it's in the DB
        rows = conn.execute(
            "SELECT action FROM filter_dns_rules WHERE domain='allowed-site.com'"
        ).fetchall()
        assert rows and rows[0][0] == "allow"
