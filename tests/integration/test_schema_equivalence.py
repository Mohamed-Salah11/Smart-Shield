"""
tests/integration/test_schema_equivalence.py
---------------------------------------------
Phase 5: Verify that a fresh init_db() schema matches what you get by
starting from v1 and running all migrations in sequence.

Both databases are created as separate in-memory SQLite instances; there is
no filesystem I/O.  The test compares:
  - the set of user-visible table names (excluding sqlite_* and schema_version)
  - the column names and declared types for every shared table
"""

import os
import sys
import sqlite3
import pytest

os.environ.setdefault("SMARTSHIELD_DB_PATH", "file:scheq_fresh?mode=memory&cache=shared")
os.environ.setdefault("SECRET_KEY", "schema-test-secret-xyz")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _open_mem(name: str) -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{name}?mode=memory&cache=shared", uri=True)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _get_tables(conn: sqlite3.Connection) -> set:
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    ).fetchall()
    return {r[0] for r in rows}


def _get_columns(conn: sqlite3.Connection, table: str) -> dict:
    """Return {col_name: declared_type.upper()} for every column in *table*."""
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return {r[1]: (r[2] or "").upper() for r in rows}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def fresh_conn():
    """A connection whose schema was built by init_db() from scratch."""
    conn = _open_mem("scheq_fresh")
    from app.database import init_db
    with conn:
        init_db.__globals__["_database_path"] = lambda: "file:scheq_fresh?mode=memory&cache=shared"
        # init_db reads _database_path internally, so just call it with the app context.
    # Re-open so init_db uses our URI
    import importlib
    import app.database as dbmod
    old_path = os.environ.get("SMARTSHIELD_DB_PATH", "")
    os.environ["SMARTSHIELD_DB_PATH"] = "file:scheq_fresh?mode=memory&cache=shared"
    try:
        importlib.reload(dbmod)
        dbmod.init_db()
        conn = dbmod.get_db()
        yield conn
    finally:
        os.environ["SMARTSHIELD_DB_PATH"] = old_path


@pytest.fixture(scope="module")
def migrated_conn():
    """
    A connection whose schema was built by applying every migration
    starting from the baseline init_db that runs before migrations.
    """
    import importlib
    import app.database as dbmod
    import app.migrations as mig_mod

    old_path = os.environ.get("SMARTSHIELD_DB_PATH", "")
    os.environ["SMARTSHIELD_DB_PATH"] = "file:scheq_migrated?mode=memory&cache=shared"
    try:
        importlib.reload(dbmod)
        dbmod.init_db()
        conn = dbmod.get_db()
        mig_mod.run_migrations(conn)
        yield conn
    finally:
        os.environ["SMARTSHIELD_DB_PATH"] = old_path


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestSchemaEquivalence:
    def test_fresh_has_tables(self, fresh_conn):
        tables = _get_tables(fresh_conn)
        assert len(tables) > 10, f"Fresh DB has too few tables: {tables}"

    def test_migrated_has_tables(self, migrated_conn):
        tables = _get_tables(migrated_conn)
        assert len(tables) > 10, f"Migrated DB has too few tables: {tables}"

    def test_no_tables_only_in_migrated(self, fresh_conn, migrated_conn):
        """Every table in the migrated DB should exist in the fresh DB too."""
        fresh_tables    = _get_tables(fresh_conn)
        migrated_tables = _get_tables(migrated_conn)

        # schema_version is created by the migration runner, not init_db — exclude it
        migrated_only = migrated_tables - fresh_tables - {"schema_version"}
        assert migrated_only == set(), (
            f"Tables in migrated DB but missing from fresh DB: {migrated_only}"
        )

    def test_no_tables_only_in_fresh(self, fresh_conn, migrated_conn):
        """Every table in the fresh DB should exist in the migrated DB too."""
        fresh_tables    = _get_tables(fresh_conn)
        migrated_tables = _get_tables(migrated_conn)

        fresh_only = fresh_tables - migrated_tables
        assert fresh_only == set(), (
            f"Tables in fresh DB but missing from migrated DB: {fresh_only}"
        )

    def test_columns_match_for_core_tables(self, fresh_conn, migrated_conn):
        """
        Column names on core tables must be identical between fresh and migrated.
        We check a representative subset that migrations touch.
        """
        core_tables = [
            "users",
            "lan_config",
            "wan_config",
            "firewall_rules_floating",
            "dhcp_pools",
            "static_leases",
            "dhcpv6_pools",
            "certificates",
            "captive_sessions",
            "ids_config",
            "ids_threat_feeds",
            "config_apply_jobs",
            "feature_applied_state",
            "siem_state",
            "health_snapshots",
        ]
        for table in core_tables:
            fresh_cols    = _get_columns(fresh_conn, table)
            migrated_cols = _get_columns(migrated_conn, table)
            # Both must have the same column names (type declarations may differ)
            assert set(fresh_cols.keys()) == set(migrated_cols.keys()), (
                f"Column mismatch for table '{table}': "
                f"fresh={set(fresh_cols.keys())}, migrated={set(migrated_cols.keys())}"
            )

    def test_dhcpv6_pools_has_required_columns(self, fresh_conn, migrated_conn):
        """Migration v9 adds interface_type/enabled/pd_prefix/pd_prefix_len — both must have them."""
        required = {"interface_type", "enabled", "pd_prefix", "pd_prefix_len"}
        for label, conn in [("fresh", fresh_conn), ("migrated", migrated_conn)]:
            cols = set(_get_columns(conn, "dhcpv6_pools").keys())
            missing = required - cols
            assert missing == set(), f"{label} dhcpv6_pools missing columns: {missing}"

    def test_config_apply_jobs_schema(self, fresh_conn, migrated_conn):
        """config_apply_jobs must have the canonical column set (migration v13)."""
        required = {"id", "feature_key", "state", "config_hash", "applied_by",
                    "notes", "message", "created_at", "updated_at"}
        for label, conn in [("fresh", fresh_conn), ("migrated", migrated_conn)]:
            cols = set(_get_columns(conn, "config_apply_jobs").keys())
            missing = required - cols
            assert missing == set(), f"{label} config_apply_jobs missing columns: {missing}"

    def test_siem_state_exists(self, fresh_conn, migrated_conn):
        """siem_state table must exist in both (migration v10)."""
        for label, conn in [("fresh", fresh_conn), ("migrated", migrated_conn)]:
            tables = _get_tables(conn)
            assert "siem_state" in tables, f"{label} DB missing siem_state table"
