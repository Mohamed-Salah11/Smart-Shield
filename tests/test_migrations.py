"""
tests/test_migrations.py
------------------------
Tests for the database migration system.

Covers:
  - v11: certificate table column rename (key_pem_enc → private_key_enc,
         serial_number → serial) and revoked_at addition.
  - Idempotency of v11 when run on a fresh-schema DB.
  - DNS filter update accepts 'redirect' action (regression guard for the
    action validation fix in dns_filter.py).
  - L2TP save-config route persists all fields, not just 'enabled'.
"""

import os
import secrets
import sqlite3

import pytest

os.environ.setdefault("SMARTSHIELD_DB_PATH", "file:migtest?mode=memory&cache=shared")
os.environ.setdefault("SECRET_KEY", "test-migration-key")
os.environ.setdefault(
    "SMARTSHIELD_MASTER_KEY",
    __import__("base64").b64encode(__import__("secrets").token_bytes(32)).decode(),
)


def _fresh_conn() -> sqlite3.Connection:
    """Return an independent in-memory SQLite connection (not shared cache)."""
    conn = sqlite3.connect(f"file:mig_{secrets.token_hex(6)}?mode=memory&cache=shared", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def _col_names(conn, table: str) -> set:
    """Return the set of column names for *table* via PRAGMA table_info."""
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return {row[1] for row in rows}


# ---------------------------------------------------------------------------
# v11 migration: certificate column rename
# ---------------------------------------------------------------------------

class TestMigrationV11:
    def _build_v3_schema(self, conn):
        """Create the certificates table exactly as migration v3 did (old schema)."""
        conn.execute("""
        CREATE TABLE schema_version (
            version INTEGER PRIMARY KEY,
            applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        conn.execute("INSERT INTO schema_version (version) VALUES (3)")
        conn.execute("""
        CREATE TABLE certificates (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            cert_type     TEXT NOT NULL,
            name          TEXT NOT NULL,
            common_name   TEXT NOT NULL,
            ca_id         INTEGER,
            cert_pem      TEXT NOT NULL,
            key_pem_enc   TEXT NOT NULL,
            chain_pem     TEXT DEFAULT '',
            serial_number TEXT DEFAULT '',
            not_before    TEXT DEFAULT '',
            not_after     TEXT DEFAULT '',
            revoked       INTEGER DEFAULT 0,
            created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(ca_id) REFERENCES certificates(id)
        )
        """)
        # Insert a row with real data so renaming doesn't wipe content.
        conn.execute("""
        INSERT INTO certificates (cert_type, name, common_name, cert_pem, key_pem_enc, serial_number)
        VALUES ('ca', 'Test CA', 'Test CA', 'CERT', 'ENCKEY', 'SN001')
        """)
        conn.commit()

    def test_v11_renames_key_pem_enc(self):
        conn = _fresh_conn()
        self._build_v3_schema(conn)
        from app.migrations import _migration_v11
        _migration_v11(conn)
        conn.commit()
        cols = _col_names(conn, "certificates")
        assert "private_key_enc" in cols, "private_key_enc must exist after v11"
        assert "key_pem_enc" not in cols, "key_pem_enc must be gone after v11"

    def test_v11_renames_serial_number(self):
        conn = _fresh_conn()
        self._build_v3_schema(conn)
        from app.migrations import _migration_v11
        _migration_v11(conn)
        conn.commit()
        cols = _col_names(conn, "certificates")
        assert "serial" in cols, "serial must exist after v11"
        assert "serial_number" not in cols, "serial_number must be gone after v11"

    def test_v11_adds_revoked_at(self):
        conn = _fresh_conn()
        self._build_v3_schema(conn)
        from app.migrations import _migration_v11
        _migration_v11(conn)
        conn.commit()
        cols = _col_names(conn, "certificates")
        assert "revoked_at" in cols, "revoked_at must be added by v11"

    def test_v11_preserves_data(self):
        """Column renames must not lose the stored values."""
        conn = _fresh_conn()
        self._build_v3_schema(conn)
        from app.migrations import _migration_v11
        _migration_v11(conn)
        conn.commit()
        row = conn.execute("SELECT private_key_enc, serial FROM certificates LIMIT 1").fetchone()
        assert row is not None
        assert row[0] == "ENCKEY"
        assert row[1] == "SN001"

    def test_v11_idempotent_on_fresh_schema(self):
        """Running v11 on a DB that already has the correct column names is a no-op."""
        conn = _fresh_conn()
        # Simulate a fresh-schema DB (already has correct column names).
        conn.execute("""
        CREATE TABLE certificates (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            name            TEXT NOT NULL,
            cert_type       TEXT NOT NULL DEFAULT 'client',
            common_name     TEXT NOT NULL,
            ca_id           INTEGER,
            cert_pem        TEXT NOT NULL DEFAULT '',
            private_key_enc TEXT NOT NULL DEFAULT '',
            serial          TEXT DEFAULT '',
            not_before      TEXT DEFAULT '',
            not_after       TEXT DEFAULT '',
            revoked         INTEGER DEFAULT 0,
            revoked_at      TIMESTAMP,
            created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        conn.commit()
        from app.migrations import _migration_v11
        _migration_v11(conn)  # must not raise
        conn.commit()
        cols = _col_names(conn, "certificates")
        assert "private_key_enc" in cols
        assert "serial" in cols
        assert "revoked_at" in cols


# ---------------------------------------------------------------------------
# DNS filter: redirect action round-trip
# ---------------------------------------------------------------------------

class TestDnsFilterRedirectAction:
    @pytest.fixture()
    def db_conn(self):
        """Isolated in-memory DB with the DNS filter table."""
        conn = _fresh_conn()
        conn.execute("""
        CREATE TABLE filter_dns_rules (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            domain      TEXT NOT NULL UNIQUE,
            action      TEXT NOT NULL DEFAULT 'block',
            redirect_ip TEXT DEFAULT '',
            enabled     INTEGER DEFAULT 1,
            category    TEXT DEFAULT 'custom',
            description TEXT DEFAULT '',
            created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        conn.commit()
        yield conn
        conn.close()

    def test_create_redirect_rule(self, db_conn):
        from app.services.dns_filter import add_dns_filter_rule
        rule_id = add_dns_filter_rule(
            db_conn, "ads.example.com", action="redirect", redirect_ip="0.0.0.0"
        )
        assert rule_id is not None
        row = db_conn.execute(
            "SELECT action, redirect_ip FROM filter_dns_rules WHERE id=?", (rule_id,)
        ).fetchone()
        assert row["action"] == "redirect"
        assert row["redirect_ip"] == "0.0.0.0"

    def test_update_redirect_rule(self, db_conn):
        from app.services.dns_filter import add_dns_filter_rule, update_dns_filter_rule
        rule_id = add_dns_filter_rule(db_conn, "tracker.example.com", action="block")
        # Should NOT raise ValueError now that redirect is allowed in update.
        update_dns_filter_rule(
            db_conn, rule_id, "tracker.example.com",
            action="redirect", redirect_ip="192.168.1.1"
        )
        row = db_conn.execute(
            "SELECT action, redirect_ip FROM filter_dns_rules WHERE id=?", (rule_id,)
        ).fetchone()
        assert row["action"] == "redirect"
        assert row["redirect_ip"] == "192.168.1.1"

    def test_update_redirect_requires_ip(self, db_conn):
        from app.services.dns_filter import add_dns_filter_rule, update_dns_filter_rule
        rule_id = add_dns_filter_rule(db_conn, "bad.example.com", action="block")
        with pytest.raises(ValueError, match="redirect_ip"):
            update_dns_filter_rule(
                db_conn, rule_id, "bad.example.com", action="redirect", redirect_ip=""
            )

    def test_update_invalid_action_rejected(self, db_conn):
        from app.services.dns_filter import add_dns_filter_rule, update_dns_filter_rule
        rule_id = add_dns_filter_rule(db_conn, "ok.example.com", action="block")
        with pytest.raises(ValueError):
            update_dns_filter_rule(
                db_conn, rule_id, "ok.example.com", action="drop"
            )


# ---------------------------------------------------------------------------
# L2TP save-config: full field round-trip
# ---------------------------------------------------------------------------

class TestL2tpSaveConfig:
    def test_l2tp_save_persists_all_fields(self, superuser):
        """POST /vpn/api/l2tp/save-config must save all config fields, not just enabled."""
        client, _ = superuser
        payload = {
            "enabled": True,
            "interface": "wan",
            "server_address": "192.168.1.1",
            "remote_address_range": "192.168.1.200",
            "subnet_mask": "255.255.255.0",
            "dns_server1": "8.8.8.8",
            "dns_server2": "8.8.4.4",
            "wins_server": "",
            "authentication": "chap",
            "require_chap": True,
            "require_pap": False,
            "radius_server": "",
            "radius_secret": "",
        }
        r = client.post("/vpn/api/l2tp/save-config", json=payload)
        assert r.status_code == 200
        assert r.get_json()["status"] == "success"

        # GET must now return the saved fields.
        r2 = client.get("/vpn/api/l2tp/get-config")
        assert r2.status_code == 200
        data = r2.get_json()
        assert data["server_address"] == "192.168.1.1"
        assert data["remote_address_range"] == "192.168.1.200"
        assert data["dns_server1"] == "8.8.8.8"
        assert data["authentication"] == "chap"
        # radius_secret must never be returned
        assert "radius_secret" not in data

    def test_l2tp_save_rejects_invalid_ip(self, superuser):
        client, _ = superuser
        r = client.post("/vpn/api/l2tp/save-config", json={
            "enabled": True,
            "server_address": "not-an-ip",
        })
        assert r.status_code == 400
        assert "server_address" in r.get_json().get("message", "")

    def test_l2tp_save_rejects_invalid_auth(self, superuser):
        client, _ = superuser
        r = client.post("/vpn/api/l2tp/save-config", json={
            "enabled": True,
            "authentication": "kerberos",
        })
        assert r.status_code == 400
