"""
migrations.py
-------------
Formal database schema migration system for Smart Shield.

All schema changes are expressed as discrete, numbered migration functions.
The ``schema_version`` table records which migrations have been applied.

Usage
-----
    from app.migrations import run_migrations, CURRENT_SCHEMA_VERSION
    run_migrations(conn)   # called once at startup from init_db()

Safety guarantees
-----------------
* Backs up the SQLite file before applying any pending migration (FreeBSD).
* Raises ``SchemaVersionError`` if the DB version is NEWER than the code
  supports — prevents an old codebase from corrupting a newer DB.
* Each migration runs inside a transaction; any failure rolls back cleanly.
* Migrations are idempotent (``CREATE TABLE IF NOT EXISTS``, ``ADD COLUMN``
  guarded by column-existence checks, etc.).
* Running ``run_migrations`` on an up-to-date DB is a no-op.
"""

import os
import shutil
import sys
from datetime import datetime, timezone

# The highest schema version this codebase knows about.
CURRENT_SCHEMA_VERSION = 15


class SchemaVersionError(RuntimeError):
    """Raised when the DB schema is newer than the running code."""


# ---------------------------------------------------------------------------
# Migration functions — one per schema increment
# ---------------------------------------------------------------------------
# Convention: each function receives an open sqlite3 connection and may
# execute DDL/DML.  Do NOT call conn.commit() inside — the runner handles it.

def _migration_v2(conn):
    """Phase 2: pending_interface_changes table."""
    conn.execute("""
    CREATE TABLE IF NOT EXISTS pending_interface_changes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        interface_type TEXT NOT NULL,
        snapshot_json TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)


def _migration_v3(conn):
    """Phase 3: certificates table."""
    conn.execute("""
    CREATE TABLE IF NOT EXISTS certificates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cert_type TEXT NOT NULL,
        name TEXT NOT NULL,
        common_name TEXT NOT NULL,
        ca_id INTEGER,
        cert_pem TEXT NOT NULL,
        key_pem_enc TEXT NOT NULL,
        chain_pem TEXT DEFAULT '',
        serial_number TEXT DEFAULT '',
        not_before TEXT DEFAULT '',
        not_after TEXT DEFAULT '',
        revoked INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(ca_id) REFERENCES certificates(id)
    )
    """)


def _migration_v4(conn):
    """Phase 4: DHCPv6, RA, WoL, and Captive Portal tables."""
    conn.execute("""
    CREATE TABLE IF NOT EXISTS dhcpv6_pools (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        interface_name TEXT NOT NULL,
        prefix TEXT NOT NULL,
        start_address TEXT NOT NULL,
        end_address TEXT NOT NULL,
        preferred_lifetime INTEGER DEFAULT 3600,
        valid_lifetime INTEGER DEFAULT 7200,
        dns_servers TEXT DEFAULT '',
        domain_search TEXT DEFAULT '',
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.execute("""
    CREATE TABLE IF NOT EXISTS ra_settings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        interface_name TEXT NOT NULL UNIQUE,
        min_interval INTEGER DEFAULT 200,
        max_interval INTEGER DEFAULT 600,
        managed_flag INTEGER DEFAULT 0,
        other_flag INTEGER DEFAULT 0,
        prefix TEXT DEFAULT '',
        prefix_length INTEGER DEFAULT 64,
        dns_servers TEXT DEFAULT '',
        domain_search TEXT DEFAULT '',
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.execute("""
    CREATE TABLE IF NOT EXISTS wol_hosts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        mac_address TEXT NOT NULL UNIQUE,
        interface_name TEXT NOT NULL,
        broadcast_ip TEXT DEFAULT '255.255.255.255',
        description TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.execute("""
    CREATE TABLE IF NOT EXISTS captive_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mac_address TEXT NOT NULL UNIQUE,
        ip_address TEXT NOT NULL,
        username TEXT DEFAULT '',
        expires_at INTEGER NOT NULL,
        logged_out INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.execute("""
    CREATE TABLE IF NOT EXISTS captive_vouchers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT NOT NULL UNIQUE,
        duration_minutes INTEGER NOT NULL DEFAULT 60,
        bandwidth_kbps INTEGER DEFAULT 0,
        redeemed INTEGER DEFAULT 0,
        redeemed_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)


def _migration_v5(conn):
    """Phase 5: config_versions and health_snapshots tables."""
    conn.execute("""
    CREATE TABLE IF NOT EXISTS config_versions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        service TEXT NOT NULL,
        version_num INTEGER NOT NULL DEFAULT 1,
        content TEXT NOT NULL,
        content_hash TEXT DEFAULT '',
        applied_by TEXT DEFAULT 'system',
        applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        validation_ok INTEGER DEFAULT 1,
        apply_ok INTEGER DEFAULT 1,
        notes TEXT DEFAULT '',
        file_path TEXT DEFAULT ''
    )
    """)

    conn.execute("""
    CREATE INDEX IF NOT EXISTS idx_config_versions_service_version
    ON config_versions(service, version_num DESC)
    """)

    conn.execute("""
    CREATE TABLE IF NOT EXISTS health_snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        snapshot_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        services_json TEXT NOT NULL DEFAULT '{}',
        disk_json TEXT NOT NULL DEFAULT '{}',
        system_json TEXT NOT NULL DEFAULT '{}'
    )
    """)

    conn.execute("""
    CREATE INDEX IF NOT EXISTS idx_health_snapshots_at
    ON health_snapshots(snapshot_at DESC)
    """)


def _migration_v6(conn):
    """Phase 6: ids_threat_feeds table for encrypted abuse.ch Auth-Key storage."""
    conn.execute("""
    CREATE TABLE IF NOT EXISTS ids_threat_feeds (
        id               INTEGER PRIMARY KEY CHECK (id = 1),
        abusech_auth_key TEXT    DEFAULT '',
        updated_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    conn.execute("INSERT OR IGNORE INTO ids_threat_feeds (id) VALUES (1)")


def _migration_v7(conn):
    """Phase 7: add disabled flag to captive_vouchers for temporary suspension."""
    try:
        conn.execute("ALTER TABLE captive_vouchers ADD COLUMN disabled INTEGER DEFAULT 0")
    except Exception:
        pass  # column already exists on fresh installs


def _migration_v8(conn):
    """Phase 8: add abusech_dry_run flag to ids_threat_feeds for GUI control."""
    try:
        conn.execute(
            "ALTER TABLE ids_threat_feeds ADD COLUMN abusech_dry_run INTEGER DEFAULT 1"
        )
    except Exception:
        pass  # column already exists on fresh installs


def _migration_v9(conn):
    """Phase 9: add missing columns to dhcpv6_pools.

    Migration v4 created dhcpv6_pools without interface_type, enabled,
    pd_prefix, and pd_prefix_len, but dhcpv6_writer.py reads all four.
    Fresh installs (database.py) already have these columns; this migration
    brings existing installs up to the same schema.
    """
    for ddl in [
        "ALTER TABLE dhcpv6_pools ADD COLUMN interface_type TEXT DEFAULT 'LAN'",
        "ALTER TABLE dhcpv6_pools ADD COLUMN enabled INTEGER DEFAULT 0",
        "ALTER TABLE dhcpv6_pools ADD COLUMN pd_prefix TEXT DEFAULT ''",
        "ALTER TABLE dhcpv6_pools ADD COLUMN pd_prefix_len INTEGER DEFAULT 64",
    ]:
        try:
            conn.execute(ddl)
        except Exception:
            pass  # column already exists (fresh install or re-run)


def _migration_v10(conn):
    """Phase 10: siem_state table for SIEM collector offset persistence."""
    conn.execute("""
    CREATE TABLE IF NOT EXISTS siem_state (
        key        TEXT PRIMARY KEY,
        value      TEXT NOT NULL DEFAULT '',
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)


def _migration_v11(conn):
    """Phase 11: Fix certificates table column name mismatches.

    Migration v3 created the certificates table with:
      - key_pem_enc   (fresh installs use private_key_enc)
      - serial_number (fresh installs use serial)
      - chain_pem     (not in fresh schema; left in place as harmless extra column)
      - no revoked_at (fresh installs include revoked_at TIMESTAMP)

    This migration renames the mismatched columns and adds revoked_at so that
    upgraded databases have the same schema as fresh installs.
    """
    info = conn.execute("PRAGMA table_info(certificates)").fetchall()
    # PRAGMA table_info columns: cid, name, type, notnull, dflt_value, pk
    cols = {row[1] for row in info}

    if "key_pem_enc" in cols and "private_key_enc" not in cols:
        conn.execute(
            "ALTER TABLE certificates RENAME COLUMN key_pem_enc TO private_key_enc"
        )

    if "serial_number" in cols and "serial" not in cols:
        conn.execute(
            "ALTER TABLE certificates RENAME COLUMN serial_number TO serial"
        )

    if "revoked_at" not in cols:
        try:
            conn.execute("ALTER TABLE certificates ADD COLUMN revoked_at TIMESTAMP")
        except Exception:
            pass  # already present


def _migration_v12(conn):
    """Phase 12: Add firewall hardening toggle columns to advanced_firewall_nat.

    block_bogons       — block bogon/unroutable addresses arriving on WAN (default ON)
    block_private_nets — block RFC-1918 private source addresses on WAN (default ON)
    """
    for ddl in [
        "ALTER TABLE advanced_firewall_nat ADD COLUMN block_bogons INTEGER DEFAULT 1",
        "ALTER TABLE advanced_firewall_nat ADD COLUMN block_private_nets INTEGER DEFAULT 1",
    ]:
        try:
            conn.execute(ddl)
        except Exception:
            pass  # column already exists (fresh install or re-run)


def _migration_v13(conn):
    """Phase 13: Applied-state tracking tables (Phases 37 and 38).

    config_apply_jobs     — one row per apply operation with full lifecycle state
    feature_applied_state — one row per feature with current summary state

    These tables power the UI applied-state badges and the config transaction
    manager rollback decisions.
    """
    conn.execute("""
    CREATE TABLE IF NOT EXISTS config_apply_jobs (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        feature_key TEXT    NOT NULL,
        state       TEXT    NOT NULL DEFAULT 'saved',
        config_hash TEXT    DEFAULT '',
        applied_by  TEXT    DEFAULT 'system',
        notes       TEXT    DEFAULT '',
        message     TEXT    DEFAULT '',
        created_at  REAL    NOT NULL DEFAULT 0,
        updated_at  REAL    NOT NULL DEFAULT 0
    )
    """)

    conn.execute("""
    CREATE INDEX IF NOT EXISTS idx_cap_jobs_feature_created
    ON config_apply_jobs(feature_key, created_at DESC)
    """)

    conn.execute("""
    CREATE TABLE IF NOT EXISTS feature_applied_state (
        feature_key TEXT PRIMARY KEY,
        state       TEXT    NOT NULL DEFAULT 'saved',
        message     TEXT    DEFAULT '',
        last_job_id INTEGER,
        updated_at  REAL    NOT NULL DEFAULT 0,
        FOREIGN KEY(last_job_id) REFERENCES config_apply_jobs(id)
    )
    """)


def _migration_v14(conn):
    """Phase 14: Policy-based routing table and new columns for advanced_firewall_nat.

    policy_routes       — per-rule entries for PF route-to policy routing
    nat_reflection      — integer toggle for hairpin NAT on advanced_firewall_nat
    kill_states_on_reload — integer toggle to flush all PF states after reload
    """
    conn.execute("""
    CREATE TABLE IF NOT EXISTS policy_routes (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        enabled          INTEGER DEFAULT 1,
        priority         INTEGER DEFAULT 100,
        description      TEXT    DEFAULT '',
        interface_type   TEXT    DEFAULT 'LAN',
        source           TEXT    DEFAULT 'any',
        destination      TEXT    DEFAULT 'any',
        gateway_id       INTEGER REFERENCES gateways(id),
        created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    for ddl in [
        "ALTER TABLE advanced_firewall_nat ADD COLUMN nat_reflection INTEGER DEFAULT 0",
        "ALTER TABLE advanced_firewall_nat ADD COLUMN kill_states_on_reload INTEGER DEFAULT 0",
    ]:
        try:
            conn.execute(ddl)
        except Exception:
            pass  # column already exists on fresh installs


def _migration_v15(conn):
    """Phase 15: Add CARP-specific columns to virtual_ips_configs.

    vhid         — CARP virtual host ID (1-255)
    carp_pass    — CARP password (encrypted)
    advskew      — CARP advertisement skew (0-254); 0 = master, higher = backup
    advbase      — CARP advertisement base interval (seconds, default 1)
    """
    for ddl in [
        "ALTER TABLE virtual_ips_configs ADD COLUMN vhid INTEGER DEFAULT 1",
        "ALTER TABLE virtual_ips_configs ADD COLUMN carp_pass TEXT DEFAULT ''",
        "ALTER TABLE virtual_ips_configs ADD COLUMN advskew INTEGER DEFAULT 0",
        "ALTER TABLE virtual_ips_configs ADD COLUMN advbase INTEGER DEFAULT 1",
    ]:
        try:
            conn.execute(ddl)
        except Exception:
            pass  # column already exists on fresh installs


# Ordered list of (version, fn) pairs.  The runner applies all migrations
# whose version > current DB version, in ascending order.
MIGRATIONS = [
    (2, _migration_v2),
    (3, _migration_v3),
    (4, _migration_v4),
    (5, _migration_v5),
    (6, _migration_v6),
    (7, _migration_v7),
    (8, _migration_v8),
    (9, _migration_v9),
    (10, _migration_v10),
    (11, _migration_v11),
    (12, _migration_v12),
    (13, _migration_v13),
    (14, _migration_v14),
    (15, _migration_v15),
]


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def _get_db_version(conn) -> int:
    try:
        row = conn.execute(
            "SELECT COALESCE(MAX(version), 0) AS v FROM schema_version"
        ).fetchone()
        return row["v"] if row else 0
    except Exception:
        return 0


def _set_db_version(conn, version: int):
    conn.execute("INSERT OR IGNORE INTO schema_version (version) VALUES (?)", (version,))


def _backup_db(path: str) -> str:
    """Copy the DB file to <path>.bak-YYYYMMDDTHHMMSS.  Returns backup path."""
    ts   = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    dest = f"{path}.bak-{ts}"
    shutil.copy2(path, dest)
    return dest


def run_migrations(conn) -> list:
    """
    Apply all pending migrations.

    Returns a list of applied version numbers (empty if already up-to-date).
    Raises ``SchemaVersionError`` if the DB is newer than CURRENT_SCHEMA_VERSION.
    """
    # Ensure schema_version table exists (created in init_db before this runs)
    conn.execute("""
    CREATE TABLE IF NOT EXISTS schema_version (
        version INTEGER PRIMARY KEY,
        applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    db_version = _get_db_version(conn)

    if db_version > CURRENT_SCHEMA_VERSION:
        raise SchemaVersionError(
            f"Database schema version {db_version} is newer than the "
            f"application supports ({CURRENT_SCHEMA_VERSION}).  "
            "Please upgrade the Smart Shield application."
        )

    pending = [(v, fn) for v, fn in MIGRATIONS if v > db_version]
    if not pending:
        return []

    # Backup DB file before any structural change (FreeBSD, file DB only)
    db_path = os.getenv("SMARTSHIELD_DB_PATH", "")
    if sys.platform.startswith("freebsd") and db_path and os.path.isfile(db_path):
        try:
            backup = _backup_db(db_path)
            _log_migration_event(f"DB backup created before migrations: {backup}")
        except OSError as exc:
            _log_migration_event(f"WARNING: DB backup failed: {exc} — proceeding anyway.")

    applied = []
    for version, fn in pending:
        try:
            fn(conn)
            _set_db_version(conn, version)
            conn.commit()
            applied.append(version)
            _log_migration_event(f"Migration v{version} applied successfully.")
        except Exception as exc:
            conn.rollback()
            raise RuntimeError(
                f"Migration v{version} failed: {exc}.  "
                "Database has been rolled back to the previous state."
            ) from exc

    return applied


def _log_migration_event(message: str):
    try:
        from app.audit_log import log_event
        log_event(
            category="system",
            action="db_migration",
            username="system",
            remote_addr="",
            details={"message": message},
        )
    except Exception:
        print(f"[migrations] {message}", flush=True)
