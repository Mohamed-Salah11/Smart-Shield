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

import logging
import os
import shutil
import sys
from datetime import datetime, timezone

_log = logging.getLogger(__name__)

# The highest schema version this codebase knows about.
CURRENT_SCHEMA_VERSION = 46


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
        is_superuser INTEGER DEFAULT 0,
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


def _migration_v16(conn):
    """
    Add gateway health tracking columns to the gateways table.

    reachable  — last known ping result (1=up, 0=down, NULL=never checked)
    last_seen  — timestamp of last successful reachability check
    """
    for ddl in [
        "ALTER TABLE gateways ADD COLUMN reachable INTEGER DEFAULT NULL",
        "ALTER TABLE gateways ADD COLUMN last_seen  TIMESTAMP DEFAULT NULL",
    ]:
        try:
            conn.execute(ddl)
        except Exception:
            pass  # column already exists on fresh installs


def _migration_v17(conn):
    """
    Add SIEM case management tables for SOC incident tracking.

    siem_cases       — incident records with assignment and status
    siem_case_notes  — analyst notes / investigation timeline per case
    siem_case_events — audit log events linked to a case
    """
    conn.execute("""
    CREATE TABLE IF NOT EXISTS siem_cases (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        title        TEXT    NOT NULL,
        description  TEXT    DEFAULT '',
        severity     TEXT    DEFAULT 'medium',
        status       TEXT    DEFAULT 'open',
        assigned_to  INTEGER,
        created_by   TEXT    NOT NULL DEFAULT 'system',
        source_event TEXT    DEFAULT '',
        tags         TEXT    DEFAULT '',
        created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(assigned_to) REFERENCES users(id) ON DELETE SET NULL
    )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_siem_cases_status   ON siem_cases(status)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_siem_cases_assigned ON siem_cases(assigned_to)"
    )
    conn.execute("""
    CREATE TABLE IF NOT EXISTS siem_case_notes (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id    INTEGER NOT NULL,
        note       TEXT    NOT NULL,
        created_by TEXT    NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(case_id) REFERENCES siem_cases(id) ON DELETE CASCADE
    )
    """)
    conn.execute("""
    CREATE TABLE IF NOT EXISTS siem_case_events (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id         INTEGER NOT NULL,
        event_timestamp TEXT    NOT NULL,
        event_action    TEXT    NOT NULL DEFAULT '',
        event_category  TEXT    NOT NULL DEFAULT '',
        event_summary   TEXT    DEFAULT '',
        event_uuid      TEXT    DEFAULT '',
        event_details   TEXT    DEFAULT '',
        FOREIGN KEY(case_id) REFERENCES siem_cases(id) ON DELETE CASCADE
    )
    """)


def _migration_v18(conn):
    """
    Add siem_alert_actions table for SOC L1 triage tracking.

    Stores analyst actions (acknowledge / false_positive / escalate) on
    individual audit-log events identified by their ISO-8601 timestamp key.
    """
    conn.execute("""
    CREATE TABLE IF NOT EXISTS siem_alert_actions (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        event_key    TEXT    NOT NULL,
        event_action TEXT    NOT NULL DEFAULT '',
        action       TEXT    NOT NULL,
        taken_by     TEXT    NOT NULL,
        taken_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        note         TEXT    DEFAULT '',
        case_id      INTEGER
    )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_saa_event_key ON siem_alert_actions(event_key)"
    )


def _migration_v20(conn):
    """
    Phase 20: SOC case escalation and closure-type tracking.

    escalation_tier — set by L1 (→ 'L2') or L2 (→ 'L3') when a true positive
                      is passed up to the next response tier.
    closure_type    — 'false_positive' (L1/L2/L3) or 'resolved' (L3 only),
                      recorded when the case is closed.
    """
    for ddl in [
        "ALTER TABLE siem_cases ADD COLUMN escalation_tier TEXT DEFAULT NULL",
        "ALTER TABLE siem_cases ADD COLUMN closure_type    TEXT DEFAULT NULL",
    ]:
        try:
            conn.execute(ddl)
        except Exception:
            pass  # column already exists (fresh install)


def _migration_v19(conn):
    """
    Phase 19: SOC Team Portal — tier assignment on groups + portal config table.

    soc_tier column on groups: NULL (not a SOC group), 'L1', 'L2', or 'L3'.
    soc_portal_config: singleton row holding the portal bind IP, port, and cert.
    """
    try:
        conn.execute("ALTER TABLE groups ADD COLUMN soc_tier TEXT DEFAULT NULL")
    except Exception:
        pass  # column already exists (fresh install)

    conn.execute("""
    CREATE TABLE IF NOT EXISTS soc_portal_config (
        id          INTEGER PRIMARY KEY CHECK (id = 1),
        enabled     INTEGER DEFAULT 0,
        bind_ip     TEXT    DEFAULT '0.0.0.0',
        bind_port   INTEGER DEFAULT 8443,
        ssl_cert_id INTEGER DEFAULT NULL,
        updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    conn.execute("INSERT OR IGNORE INTO soc_portal_config (id) VALUES (1)")


def _migration_v21(conn):
    """
    Phase 21: per-user SOC tier assignment.

    soc_tier column on users: NULL (no direct SOC tier), 'L1', 'L2', or 'L3'.
    Complements group-based tiers — get_user_soc_tier() returns the highest of
    the user's own tier and any tier inherited from their groups.
    """
    try:
        conn.execute("ALTER TABLE users ADD COLUMN soc_tier TEXT DEFAULT NULL")
    except Exception:
        pass  # column already exists (fresh install)


def _migration_v22(conn):
    """
    Phase 22: indexed event store.

    Every audit event is mirrored into the `events` table so queries, stats
    and charts use indexed lookups instead of re-parsing the whole audit.log
    file.  The audit.log file remains the durable append-only forensic record.
    Existing audit.log contents are backfilled once so history stays queryable.
    """
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS events (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        ts          TEXT NOT NULL,
        severity    TEXT DEFAULT 'info',
        category    TEXT,
        action      TEXT,
        username    TEXT,
        remote_addr TEXT,
        details     TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_events_ts       ON events(ts);
    CREATE INDEX IF NOT EXISTS idx_events_category ON events(category);
    CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
    CREATE INDEX IF NOT EXISTS idx_events_action   ON events(action);
    """)

    # One-time backfill from the existing audit.log file.
    if conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]:
        return
    try:
        import json as _json
        import os as _os
        from app.audit_log import _audit_log_path
        path = _audit_log_path()
        if not _os.path.exists(path):
            return
        rows = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = _json.loads(line)
                except Exception:
                    continue
                rows.append((
                    e.get("timestamp", ""),
                    e.get("severity", "info"),
                    e.get("category", ""),
                    e.get("action", ""),
                    e.get("username", ""),
                    e.get("remote_addr", ""),
                    _json.dumps(e.get("details", {})),
                ))
        if rows:
            conn.executemany(
                "INSERT INTO events (ts, severity, category, action, "
                "username, remote_addr, details) VALUES (?,?,?,?,?,?,?)",
                rows,
            )
    except Exception:
        pass  # backfill is best-effort; new events still index going forward


def _migration_v23(conn):
    """
    Phase 23: user-defined correlation rule engine.

    correlation_rules drives correlation_engine.py — each rule counts events
    matching a category/action filter within a sliding window, grouped by a
    field, and fires a `correlation_match` security event (tagged with a MITRE
    ATT&CK technique) when a group crosses its threshold.  The two formerly
    hard-coded detectors are seeded here as default rules.
    """
    conn.execute("""
    CREATE TABLE IF NOT EXISTS correlation_rules (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        name            TEXT NOT NULL,
        enabled         INTEGER DEFAULT 1,
        category_filter TEXT DEFAULT '',
        action_filter   TEXT DEFAULT '',
        group_by        TEXT DEFAULT 'remote_addr',
        threshold       INTEGER DEFAULT 5,
        window_seconds  INTEGER DEFAULT 300,
        severity        TEXT DEFAULT 'high',
        mitre_technique TEXT DEFAULT '',
        created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    if conn.execute("SELECT COUNT(*) FROM correlation_rules").fetchone()[0] == 0:
        conn.executemany(
            "INSERT INTO correlation_rules (name, category_filter, action_filter, "
            "group_by, threshold, window_seconds, severity, mitre_technique) "
            "VALUES (?,?,?,?,?,?,?,?)",
            [
                ("Brute-force login attempt", "", "login_failed",
                 "remote_addr", 5, 300, "high", "T1110"),
                ("IDS alert flood from host", "ids", "ids_alert",
                 "details.src_ip", 10, 300, "high", "T1046"),
            ],
        )


def _migration_v24(conn):
    """
    Phase 24: SOC portal binds to a dedicated virtual IP alias on LAN.

    vip_prefix is the CIDR mask used when adding the alias via
    `ifconfig <lan> inet <bind_ip>/<vip_prefix> alias`. Default /32 keeps the
    primary LAN IP as the subnet owner while letting the alias add an extra
    reachable address.
    """
    try:
        conn.execute(
            "ALTER TABLE soc_portal_config ADD COLUMN vip_prefix INTEGER DEFAULT 32"
        )
    except Exception:
        pass  # column already exists


def _migration_v25(conn):
    """
    Phase 25: SOC portal hardening — TOTP MFA per user account.

    totp_secret is the AES-GCM-encrypted base32 TOTP seed (via secret_store).
    totp_enabled gates whether the second-factor prompt is shown after a
    correct password on the SOC portal login. The same secret can later gate
    admin-UI login too; this migration only adds the storage columns.
    """
    for col, ddl in (
        ("totp_secret",  "ALTER TABLE users ADD COLUMN totp_secret TEXT DEFAULT ''"),
        ("totp_enabled", "ALTER TABLE users ADD COLUMN totp_enabled INTEGER DEFAULT 0"),
    ):
        try:
            conn.execute(ddl)
        except Exception:
            pass  # column already exists


def _migration_v26(conn):
    """
    Phase 26: SOC SIEM platform extensions.

    - correlation_rules: auto_case (open a siem_cases row when the rule
      fires) and prerequisite_action (chained-rule support: only count
      matches when the group has previously seen this preceding action
      within the rule's window).
    - api_tokens: scoped service-account credentials for the HEC ingest
      endpoint and other programmatic surfaces. Token stored as sha-256
      hash; scopes are a comma-separated list.
    """
    for ddl in (
        "ALTER TABLE correlation_rules ADD COLUMN auto_case INTEGER DEFAULT 0",
        "ALTER TABLE correlation_rules ADD COLUMN prerequisite_action TEXT DEFAULT ''",
    ):
        try:
            conn.execute(ddl)
        except Exception:
            pass

    conn.execute("""
    CREATE TABLE IF NOT EXISTS api_tokens (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        name         TEXT    NOT NULL,
        token_hash   TEXT    NOT NULL UNIQUE,
        scopes       TEXT    NOT NULL DEFAULT '',
        created_by   TEXT    NOT NULL DEFAULT 'system',
        created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_used_at TIMESTAMP,
        revoked_at   TIMESTAMP
    )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_api_tokens_hash ON api_tokens(token_hash)"
    )


def _migration_v27(conn):
    """
    Phase 27: SOC maturity layer.

    Adds the storage for:
      * assets / identities         — admin-managed inventory used for
                                       per-event enrichment and reports
      * risk_scores                  — decaying per-entity score updated
                                       whenever a correlation rule fires
      * saved_searches               — analyst-defined queries, optionally
                                       scheduled to re-run on an interval
      * playbooks / playbook_runs    — trigger → ordered steps automation
                                       (with optional approval gate per step)
      * events_fts (FTS5 virtual)    — full-text index over the events table
                                       so the L2 hunt is no longer a LIKE %x%
                                       scan; kept in sync by triggers
    """
    # ---- inventory: assets ------------------------------------------------
    conn.execute("""
    CREATE TABLE IF NOT EXISTS assets (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        ip            TEXT NOT NULL,
        hostname      TEXT DEFAULT '',
        mac           TEXT DEFAULT '',
        owner         TEXT DEFAULT '',
        business_unit TEXT DEFAULT '',
        criticality   TEXT DEFAULT 'medium',  -- low | medium | high | crown_jewel
        tags          TEXT DEFAULT '',        -- comma-separated
        notes         TEXT DEFAULT '',
        created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip)")

    # ---- inventory: identities --------------------------------------------
    conn.execute("""
    CREATE TABLE IF NOT EXISTS identities (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        username      TEXT NOT NULL,
        full_name     TEXT DEFAULT '',
        email         TEXT DEFAULT '',
        role          TEXT DEFAULT '',
        manager       TEXT DEFAULT '',
        business_unit TEXT DEFAULT '',
        sensitivity   TEXT DEFAULT 'standard', -- standard | privileged | crown_jewel
        notes         TEXT DEFAULT '',
        created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_identities_username ON identities(username)")

    # ---- risk scoring -----------------------------------------------------
    conn.execute("""
    CREATE TABLE IF NOT EXISTS risk_scores (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        entity_type   TEXT NOT NULL,  -- 'ip' | 'username'
        entity_value  TEXT NOT NULL,
        score         REAL NOT NULL DEFAULT 0,
        last_updated  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(entity_type, entity_value)
    )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_risk_scores_score "
        "ON risk_scores(score DESC)"
    )

    # ---- saved searches ---------------------------------------------------
    conn.execute("""
    CREATE TABLE IF NOT EXISTS saved_searches (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        name            TEXT NOT NULL,
        owner           TEXT NOT NULL DEFAULT 'system',
        query_json      TEXT NOT NULL DEFAULT '{}',
        schedule_minutes INTEGER DEFAULT 0,  -- 0 = manual only
        last_run_at     TIMESTAMP,
        last_match_count INTEGER DEFAULT 0,
        enabled         INTEGER DEFAULT 1,
        created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # ---- playbooks --------------------------------------------------------
    conn.execute("""
    CREATE TABLE IF NOT EXISTS playbooks (
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        name              TEXT NOT NULL,
        description       TEXT DEFAULT '',
        enabled           INTEGER DEFAULT 1,
        trigger_action    TEXT NOT NULL DEFAULT 'correlation_match',
        trigger_category  TEXT DEFAULT 'security',
        trigger_min_sev   TEXT DEFAULT 'medium',
        steps_json        TEXT NOT NULL DEFAULT '[]',
        created_by        TEXT DEFAULT 'system',
        created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    conn.execute("""
    CREATE TABLE IF NOT EXISTS playbook_runs (
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        playbook_id       INTEGER NOT NULL,
        trigger_event_ts  TEXT,
        trigger_event_action TEXT,
        status            TEXT DEFAULT 'pending',  -- pending | running | done | failed | awaiting_approval
        steps_log_json    TEXT DEFAULT '[]',
        started_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        finished_at       TIMESTAMP,
        FOREIGN KEY(playbook_id) REFERENCES playbooks(id) ON DELETE CASCADE
    )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_playbook_runs_status ON playbook_runs(status)"
    )

    # ---- reports ----------------------------------------------------------
    conn.execute("""
    CREATE TABLE IF NOT EXISTS reports (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        report_type  TEXT NOT NULL,    -- executive | pci_dss | iso_27001 | hipaa
        period_start TEXT NOT NULL,
        period_end   TEXT NOT NULL,
        generated_by TEXT DEFAULT 'system',
        generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        html         TEXT NOT NULL,
        summary_json TEXT DEFAULT '{}'
    )
    """)

    # ---- FTS5 over events.details ----------------------------------------
    # Wrap each step so a missing FTS5 extension or a half-existing index
    # never blocks the rest of the migration.
    try:
        conn.execute("""
        CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
            category, action, username, remote_addr, details,
            content='events', content_rowid='id', tokenize='unicode61'
        )
        """)
        # Backfill: copy existing rows into the FTS index.
        conn.execute(
            "INSERT INTO events_fts(rowid, category, action, username, remote_addr, details) "
            "SELECT id, COALESCE(category,''), COALESCE(action,''), COALESCE(username,''), "
            "COALESCE(remote_addr,''), COALESCE(details,'') FROM events "
            "WHERE id NOT IN (SELECT rowid FROM events_fts)"
        )
        # Keep the index in sync. The triggers reference the actual table
        # columns, so a future schema change to events would surface here.
        for trig in (
            """CREATE TRIGGER IF NOT EXISTS trg_events_fts_ai AFTER INSERT ON events BEGIN
               INSERT INTO events_fts(rowid, category, action, username, remote_addr, details)
               VALUES (new.id, COALESCE(new.category,''), COALESCE(new.action,''),
                       COALESCE(new.username,''), COALESCE(new.remote_addr,''),
                       COALESCE(new.details,''));
               END""",
            """CREATE TRIGGER IF NOT EXISTS trg_events_fts_ad AFTER DELETE ON events BEGIN
               INSERT INTO events_fts(events_fts, rowid, category, action, username,
                                      remote_addr, details)
               VALUES ('delete', old.id, COALESCE(old.category,''), COALESCE(old.action,''),
                       COALESCE(old.username,''), COALESCE(old.remote_addr,''),
                       COALESCE(old.details,''));
               END""",
        ):
            conn.execute(trig)
    except Exception:
        # FTS5 not compiled into this sqlite — analysts fall back to the
        # existing substring search; everything else in v27 still applies.
        pass


def _migration_v28(conn):
    """
    Phase 28: IDS self-healing watchdog opt-out.

    The background watchdog (started from siem_collector) re-launches Suricata
    when ids_config.enabled=1 but the process is gone. Admins debugging a
    crash loop need to be able to disable that loop without flipping the
    main enabled flag — hence a separate watchdog_enabled column.
    """
    try:
        conn.execute(
            "ALTER TABLE ids_config ADD COLUMN watchdog_enabled INTEGER DEFAULT 1"
        )
    except Exception:
        pass  # column already exists


def _migration_v29(conn):
    """
    Phase 29: VPN — finish the OpenVPN server schema and add a self-service
    portal user table.

    Part 1: openvpn_servers had a 12-column gap between the schema in
    database.py and the columns routes/vpn.py.save_openvpn_server() actually
    inserts. Every "Save Server" click currently fails with
    `OperationalError: table openvpn_servers has no column named ca_id`.
    This migration adds the missing columns with safe defaults so existing
    rows keep working and new inserts no longer 500.

    Part 2: vpn_portal_users + vpn_portal_login_attempts power the new
    /vpn-portal blueprint where remote VPN users self-serve their `.ovpn`
    profiles. Passwords are argon2-hashed; TOTP secret is AES-GCM-encrypted
    via secret_store; lockout state is computed from
    vpn_portal_login_attempts via the same pattern the SOC portal uses.
    """
    openvpn_cols = (
        ("ca_id",                              "INTEGER"),
        ("server_cert_id",                     "INTEGER"),
        ("inactivity_timeout",                 "INTEGER DEFAULT 300"),
        ("ping_method",                        "TEXT DEFAULT 'keepalive'"),
        ("ping_interval",                      "INTEGER DEFAULT 10"),
        ("ping_timeout",                       "INTEGER DEFAULT 60"),
        ("dh_parameter_length",                "TEXT DEFAULT '2048'"),
        ("ecdh_curve",                         "TEXT DEFAULT 'default'"),
        ("data_encryption_algorithms",         "TEXT DEFAULT 'AES-256-GCM'"),
        ("fallback_data_encryption_algorithm", "TEXT DEFAULT 'AES-256-CBC'"),
        ("auth_digest_algorithm",              "TEXT DEFAULT 'SHA256'"),
        ("verbosity_level",                    "INTEGER DEFAULT 1"),
    )
    for name, ddl in openvpn_cols:
        try:
            conn.execute(f"ALTER TABLE openvpn_servers ADD COLUMN {name} {ddl}")
        except Exception:
            pass  # column already exists (fresh install or re-run)

    conn.execute("""
    CREATE TABLE IF NOT EXISTS vpn_portal_users (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        username        TEXT NOT NULL UNIQUE,
        password_hash   TEXT NOT NULL,
        email           TEXT DEFAULT '',
        full_name       TEXT DEFAULT '',
        totp_secret_enc TEXT DEFAULT '',
        totp_enrolled   INTEGER DEFAULT 0,
        client_cert_id  INTEGER,
        ovpn_server_id  INTEGER,
        disabled        INTEGER DEFAULT 0,
        created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login_at   TIMESTAMP
    )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_vpn_portal_users_username "
        "ON vpn_portal_users(username)"
    )

    conn.execute("""
    CREATE TABLE IF NOT EXISTS vpn_portal_login_attempts (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        username    TEXT DEFAULT '',
        remote_addr TEXT DEFAULT '',
        success     INTEGER DEFAULT 0,
        reason      TEXT DEFAULT '',
        ts          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_vpla_user_ts "
        "ON vpn_portal_login_attempts(username, ts DESC)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_vpla_ip_ts "
        "ON vpn_portal_login_attempts(remote_addr, ts DESC)"
    )

    # Singleton config: whether the portal listener is exposed at all.
    conn.execute("""
    CREATE TABLE IF NOT EXISTS vpn_portal_config (
        id              INTEGER PRIMARY KEY CHECK (id = 1),
        enabled         INTEGER DEFAULT 0,
        public_hostname TEXT DEFAULT '',
        updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    conn.execute("INSERT OR IGNORE INTO vpn_portal_config (id) VALUES (1)")


def _migration_v30(conn):
    """
    Phase 30: outbound mail-alert service (Gmail app-password SMTP).

    mail_alerts_config — singleton holding the SMTP credentials (the app
    password is AES-GCM-encrypted via secret_store), the severity/category
    filter, and the flood-control knobs.

    mail_alert_recipients — the shared recipient list. A row is either
    user-linked (user_id set, email resolved live from users.email) or a
    free-text address (email set, user_id NULL).
    """
    conn.execute("""
    CREATE TABLE IF NOT EXISTS mail_alerts_config (
        id                INTEGER PRIMARY KEY CHECK (id = 1),
        enabled           INTEGER DEFAULT 1,
        smtp_host         TEXT    DEFAULT 'smtp.gmail.com',
        smtp_port         INTEGER DEFAULT 587,
        smtp_security     TEXT    DEFAULT 'starttls',
        smtp_username     TEXT    DEFAULT '',
        smtp_app_password TEXT    DEFAULT '',
        from_name         TEXT    DEFAULT 'Smart Shield',
        min_severity      TEXT    DEFAULT 'high',
        category_filter   TEXT    DEFAULT '',
        cooldown_minutes  INTEGER DEFAULT 10,
        max_per_hour      INTEGER DEFAULT 20,
        updated_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    conn.execute("INSERT OR IGNORE INTO mail_alerts_config (id) VALUES (1)")

    conn.execute("""
    CREATE TABLE IF NOT EXISTS mail_alert_recipients (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id    INTEGER,
        email      TEXT DEFAULT '',
        label      TEXT DEFAULT '',
        disabled   INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)


def _migration_v31(conn):
    """
    Phase 31: SOC Team Portal improvements.

    soc_blocked_ips      — IPs an L3 analyst has blocked from the portal; the
                           source of truth for the persistent <soc_blocklist>
                           PF table.
    siem_alert_assignments — current analyst assignment for a live alert,
                           keyed by event_key (the event timestamp).
    soc_active_sessions  — presence heartbeat so the portal knows which
                           analysts are currently logged in.
    """
    conn.execute("""
    CREATE TABLE IF NOT EXISTS soc_blocked_ips (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        ip         TEXT    NOT NULL UNIQUE,
        note       TEXT    DEFAULT '',
        blocked_by TEXT    DEFAULT '',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.execute("""
    CREATE TABLE IF NOT EXISTS siem_alert_assignments (
        event_key     TEXT    PRIMARY KEY,
        assignee_id   INTEGER,
        assignee_name TEXT    DEFAULT '',
        assigned_by   TEXT    DEFAULT '',
        assigned_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.execute("""
    CREATE TABLE IF NOT EXISTS soc_active_sessions (
        user_id   INTEGER PRIMARY KEY,
        username  TEXT    DEFAULT '',
        tier      TEXT    DEFAULT '',
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)


def _migration_v32(conn):
    """
    Phase 32: SOC Portal Control runtime fields + response-recommendation table.

    soc_portal_config gains the runtime/access fields exposed on the SOC Portal
    Control page (public URL, allowed source networks, external ingest toggle,
    retention). soc_recommendations is the SOC→Core response-recommendation
    workflow table (fresh installs get it from database.py; this brings
    existing installs to the same schema).
    """
    for ddl in [
        "ALTER TABLE soc_portal_config ADD COLUMN public_url TEXT DEFAULT ''",
        "ALTER TABLE soc_portal_config ADD COLUMN allowed_networks TEXT DEFAULT ''",
        "ALTER TABLE soc_portal_config ADD COLUMN external_ingest_enabled INTEGER DEFAULT 0",
        "ALTER TABLE soc_portal_config ADD COLUMN retention_days INTEGER DEFAULT 90",
    ]:
        try:
            conn.execute(ddl)
        except Exception:
            pass  # column already exists (fresh install or re-run)

    conn.execute("""
    CREATE TABLE IF NOT EXISTS soc_recommendations (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        source_alert_id  TEXT    DEFAULT '',
        action_type      TEXT    NOT NULL,
        target_value     TEXT    NOT NULL,
        reason           TEXT    DEFAULT '',
        severity         TEXT    DEFAULT 'medium',
        status           TEXT    DEFAULT 'pending',
        created_by       TEXT    DEFAULT '',
        reviewed_by      TEXT    DEFAULT '',
        reviewed_at      TIMESTAMP,
        exported_at      TIMESTAMP,
        core_approved_by TEXT    DEFAULT '',
        core_approved_at TIMESTAMP
    )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_soc_recommendations_status "
        "ON soc_recommendations(status)"
    )


def _migration_v33(conn):
    """
    Phase 33: captive portal authentication rate-limit table.

    Tracks every portal login / voucher attempt so the auth routes can throttle
    brute-force activity (see app/services/captive_portal.py
    too_many_recent_attempts).
    """
    conn.execute("""
    CREATE TABLE IF NOT EXISTS captive_auth_attempts (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT NOT NULL,
        username   TEXT DEFAULT '',
        auth_type  TEXT DEFAULT '',
        success    INTEGER DEFAULT 0,
        created_at INTEGER NOT NULL
    )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_captive_auth_attempts_ip_time "
        "ON captive_auth_attempts(ip_address, created_at)"
    )


def _migration_v34(conn):
    """
    Phase 34: stable event_uuid + normalized event fields (Wave A foundations).

    The `events` table was a single 7-column row keyed by integer id + ISO
    timestamp string.  SOC analyst actions, alert assignments, and case event
    links all used the timestamp as the join key — same-millisecond events
    collided.  Detection/UI code had to JSON-parse the `details` blob for every
    IP / port / domain / rule lookup, blocking any per-source-type view.

    This migration:
      * adds ``event_uuid`` (TEXT) — unique, stable, generated by log_event()
        for every new row, backfilled here for existing rows
      * adds normalized columns lifted out of the `details` JSON so common
        queries can filter on indexed columns instead of LIKE %"src_ip"%
      * indexes the columns SOC + firewall views will sort/filter on
      * backfills both ``event_uuid`` (random hex) and the normalized columns
        (extracted from existing details JSON) for every pre-existing row

    The unique index on event_uuid is created AFTER backfill so the index
    creation never sees duplicate NULLs from pre-migration rows.
    """
    new_columns = (
        # uuid
        ("event_uuid",      "ALTER TABLE events ADD COLUMN event_uuid TEXT"),
        # source provenance
        ("source_type",     "ALTER TABLE events ADD COLUMN source_type TEXT"),
        ("source_name",     "ALTER TABLE events ADD COLUMN source_name TEXT"),
        # network 5-tuple
        ("src_ip",          "ALTER TABLE events ADD COLUMN src_ip TEXT"),
        ("src_port",        "ALTER TABLE events ADD COLUMN src_port INTEGER"),
        ("dst_ip",          "ALTER TABLE events ADD COLUMN dst_ip TEXT"),
        ("dst_port",        "ALTER TABLE events ADD COLUMN dst_port INTEGER"),
        ("protocol",        "ALTER TABLE events ADD COLUMN protocol TEXT"),
        ("interface",       "ALTER TABLE events ADD COLUMN interface TEXT"),
        ("direction",       "ALTER TABLE events ADD COLUMN direction TEXT"),
        # identity / asset
        ("hostname",        "ALTER TABLE events ADD COLUMN hostname TEXT"),
        ("mac",             "ALTER TABLE events ADD COLUMN mac TEXT"),
        # application
        ("domain",          "ALTER TABLE events ADD COLUMN domain TEXT"),
        ("url",             "ALTER TABLE events ADD COLUMN url TEXT"),
        # rule / policy
        ("rule_id",         "ALTER TABLE events ADD COLUMN rule_id TEXT"),
        ("rule_name",       "ALTER TABLE events ADD COLUMN rule_name TEXT"),
        ("policy_id",       "ALTER TABLE events ADD COLUMN policy_id TEXT"),
        ("policy_name",     "ALTER TABLE events ADD COLUMN policy_name TEXT"),
        # detection enrichment
        ("mitre_tactic",    "ALTER TABLE events ADD COLUMN mitre_tactic TEXT"),
        ("mitre_technique", "ALTER TABLE events ADD COLUMN mitre_technique TEXT"),
        # SOC bookkeeping (integer flag for indexability)
        ("soc_origin",      "ALTER TABLE events ADD COLUMN soc_origin INTEGER DEFAULT 0"),
        # original source payload (truncated)
        ("raw",             "ALTER TABLE events ADD COLUMN raw TEXT"),
    )
    info = conn.execute("PRAGMA table_info(events)").fetchall()
    existing = {row[1] for row in info}
    for col, ddl in new_columns:
        if col in existing:
            continue
        try:
            conn.execute(ddl)
        except Exception:
            pass  # idempotent re-run after partial failure

    # Backfill: every pre-existing row gets a UUID + normalized columns
    # derived from its details JSON. Done in batches so we never load the
    # entire events table into RAM at once.
    import json as _json
    import uuid as _uuid

    # Step 1: event_uuid backfill
    while True:
        rows = conn.execute(
            "SELECT id FROM events WHERE event_uuid IS NULL OR event_uuid = '' LIMIT 5000"
        ).fetchall()
        if not rows:
            break
        conn.executemany(
            "UPDATE events SET event_uuid = ? WHERE id = ?",
            [(_uuid.uuid4().hex, r[0]) for r in rows],
        )

    # Step 2: normalized-field backfill from details JSON
    def _pick(d, *keys):
        for k in keys:
            v = d.get(k)
            if v not in (None, ""):
                return v
        return None

    def _int_or_none(v):
        try:
            return int(v) if v is not None and v != "" else None
        except (TypeError, ValueError):
            return None

    # Paginate strictly by id (WHERE id > last_id). Rows whose details JSON
    # carries none of the normalized keys are backfilled to NULL again and would
    # otherwise keep matching the IS NULL predicate forever — when >= one full
    # batch of them exists, the old "re-select by predicate" loop never made
    # progress and spun indefinitely. Advancing by id guarantees termination.
    last_id = 0
    batch = 2000
    while True:
        rows = conn.execute(
            "SELECT id, details FROM events "
            "WHERE id > ? "
            "  AND source_type IS NULL AND src_ip IS NULL "
            "  AND dst_ip IS NULL AND domain IS NULL "
            "  AND rule_id IS NULL "
            "ORDER BY id LIMIT ?",
            (last_id, batch),
        ).fetchall()
        if not rows:
            break
        updates = []
        for row in rows:
            try:
                d = _json.loads(row[1] or "{}") or {}
                if not isinstance(d, dict):
                    d = {}
            except Exception:
                d = {}
            updates.append((
                _pick(d, "source_type", "collector"),
                _pick(d, "source_name"),
                _pick(d, "src_ip", "source_ip", "client_ip"),
                _int_or_none(_pick(d, "src_port", "source_port")),
                _pick(d, "dst_ip", "dest_ip", "destination_ip"),
                _int_or_none(_pick(d, "dst_port", "dest_port", "destination_port")),
                _pick(d, "protocol", "proto"),
                _pick(d, "interface", "iface"),
                _pick(d, "direction"),
                _pick(d, "hostname", "host"),
                _pick(d, "mac", "mac_address"),
                _pick(d, "domain", "query"),
                _pick(d, "url"),
                _pick(d, "rule_id"),
                _pick(d, "rule_name", "rule_label"),
                _pick(d, "policy_id"),
                _pick(d, "policy_name"),
                _pick(d, "mitre_tactic"),
                _pick(d, "mitre_technique"),
                1 if d.get("soc_origin") else 0,
                _pick(d, "raw", "raw_line"),
                row[0],
            ))
        # Advance the cursor past this batch BEFORE the update so rows that stay
        # all-NULL after backfill are never re-selected.
        last_id = rows[-1][0]
        conn.executemany(
            "UPDATE events SET "
            "  source_type = ?, source_name = ?, "
            "  src_ip = ?, src_port = ?, dst_ip = ?, dst_port = ?, "
            "  protocol = ?, interface = ?, direction = ?, "
            "  hostname = ?, mac = ?, domain = ?, url = ?, "
            "  rule_id = ?, rule_name = ?, policy_id = ?, policy_name = ?, "
            "  mitre_tactic = ?, mitre_technique = ?, "
            "  soc_origin = ?, raw = ? "
            "WHERE id = ?",
            updates,
        )
        if len(rows) < batch:
            break

    # Step 3: unique index on event_uuid AFTER backfill (otherwise pre-existing
    # NULL rows would block index creation on SQLite versions that count NULL
    # equal to NULL — modern SQLite does not, but we play safe).
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_events_event_uuid "
        "ON events(event_uuid)"
    )

    # Step 4: indexes on normalized columns the firewall + SOC views will use.
    for ddl in (
        "CREATE INDEX IF NOT EXISTS idx_events_source_type ON events(source_type)",
        "CREATE INDEX IF NOT EXISTS idx_events_src_ip      ON events(src_ip)",
        "CREATE INDEX IF NOT EXISTS idx_events_dst_ip      ON events(dst_ip)",
        "CREATE INDEX IF NOT EXISTS idx_events_dst_port    ON events(dst_port)",
        "CREATE INDEX IF NOT EXISTS idx_events_protocol    ON events(protocol)",
        "CREATE INDEX IF NOT EXISTS idx_events_interface   ON events(interface)",
        "CREATE INDEX IF NOT EXISTS idx_events_domain      ON events(domain)",
        "CREATE INDEX IF NOT EXISTS idx_events_rule_id     ON events(rule_id)",
        "CREATE INDEX IF NOT EXISTS idx_events_soc_origin  ON events(soc_origin)",
        "CREATE INDEX IF NOT EXISTS idx_events_ts_sev      ON events(ts, severity)",
    ):
        try:
            conn.execute(ddl)
        except Exception:
            pass


def _migration_v35(conn):
    """
    Phase 35: stable event_uuid join key for SOC alert actions/assignments.

    The SOC L1 triage workflow stores analyst actions in ``siem_alert_actions``
    and the current owning analyst in ``siem_alert_assignments``.  Both tables
    keyed those rows by the event's ISO-8601 timestamp string (``event_key``).
    Two events generated in the same millisecond therefore shared a key — an
    ack on one applied to the other, a false-positive on one suppressed the
    other.

    This migration adds an indexed ``event_uuid`` column to both tables and
    backfills it by joining ``events.event_uuid`` on the timestamp.  Once the
    routes start writing both keys, every new action/assignment row has a
    unique join key and the collision is gone.

    The legacy ``event_key`` column is left in place.  Old rows where the
    timestamp join finds no match (e.g. the event has aged out of the events
    table) stay reachable by their legacy key, and any old browser tab still
    posting timestamps is handled at the route layer (it resolves the
    timestamp to a uuid before writing).
    """
    for table, ddl in (
        ("siem_alert_actions",
         "ALTER TABLE siem_alert_actions ADD COLUMN event_uuid TEXT"),
        ("siem_alert_assignments",
         "ALTER TABLE siem_alert_assignments ADD COLUMN event_uuid TEXT"),
    ):
        info = conn.execute(f"PRAGMA table_info({table})").fetchall()
        existing = {row[1] for row in info}
        if "event_uuid" in existing:
            continue
        try:
            conn.execute(ddl)
        except Exception:
            pass

    # Backfill: copy events.event_uuid into each row whose event_key matches
    # an events.ts. The events table was UUID-stamped in migration v34 so by
    # the time this runs every queryable row has a uuid.
    conn.execute(
        "UPDATE siem_alert_actions "
        "SET event_uuid = (SELECT e.event_uuid FROM events e "
        "                  WHERE e.ts = siem_alert_actions.event_key "
        "                  ORDER BY e.id DESC LIMIT 1) "
        "WHERE (event_uuid IS NULL OR event_uuid = '') "
        "  AND event_key IS NOT NULL"
    )
    conn.execute(
        "UPDATE siem_alert_assignments "
        "SET event_uuid = (SELECT e.event_uuid FROM events e "
        "                  WHERE e.ts = siem_alert_assignments.event_key "
        "                  ORDER BY e.id DESC LIMIT 1) "
        "WHERE (event_uuid IS NULL OR event_uuid = '') "
        "  AND event_key IS NOT NULL"
    )

    for ddl in (
        "CREATE INDEX IF NOT EXISTS idx_saa_event_uuid "
        "ON siem_alert_actions(event_uuid)",
        "CREATE INDEX IF NOT EXISTS idx_saasign_event_uuid "
        "ON siem_alert_assignments(event_uuid)",
    ):
        try:
            conn.execute(ddl)
        except Exception:
            pass


def _migration_v36(conn):
    """
    Phase 36: firewall_events specialised table + per-rule log_enabled toggle
              (Wave B foundations).

    The `events` table is the global audit index. Firewall packet logs from
    pflog0 used to be stored only there, with their parsed fields buried in
    the JSON ``details`` blob — meaning the firewall log page had to LIKE-
    scan JSON for every "what blocked this source IP" question.

    This migration:
      * creates ``firewall_events`` — one row per parsed pflog line, with
        the full 5-tuple plus PF-specific fields (action, direction, rule
        id, rule label, anchor, reason, TCP flags, ICMP type/code, NAT
        rewrites, packet length) as proper indexed columns. Every row joins
        back to ``events`` via ``event_id`` + ``event_uuid``.
      * adds ``log_enabled`` to firewall_rules_lan/wan/floating so the admin
        UI can flip per-rule packet logging. Default 0 — current behaviour
        (only block/reject rules log) is unchanged until an operator toggles
        the new checkbox.
    """
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS firewall_events (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id        INTEGER,
        event_uuid      TEXT,
        ts              TEXT NOT NULL,
        action          TEXT NOT NULL,            -- pass | block | reject
        direction       TEXT,                     -- in | out
        interface       TEXT,
        ip_version      INTEGER,                  -- 4 | 6
        protocol        TEXT,
        src_ip          TEXT,
        src_port        INTEGER,
        dst_ip          TEXT,
        dst_port        INTEGER,
        rule_id         TEXT,                     -- numeric id parsed from label
        rule_label      TEXT,                     -- full label text
        anchor          TEXT,
        reason          TEXT,
        tcp_flags       TEXT,
        icmp_type       TEXT,
        icmp_code       TEXT,
        packet_length   INTEGER,
        nat_src_ip      TEXT,
        nat_src_port    INTEGER,
        nat_dst_ip      TEXT,
        nat_dst_port    INTEGER,
        hostname        TEXT,
        mac             TEXT,
        severity        TEXT DEFAULT 'low',
        policy_source   TEXT,                     -- user_rule | default | captive | content
        captive_portal  INTEGER DEFAULT 0,
        content_policy  INTEGER DEFAULT 0,
        soc_origin      INTEGER DEFAULT 0,
        raw_line        TEXT,
        created_at      TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_fwev_ts          ON firewall_events(ts);
    CREATE INDEX IF NOT EXISTS idx_fwev_action      ON firewall_events(action);
    CREATE INDEX IF NOT EXISTS idx_fwev_interface   ON firewall_events(interface);
    CREATE INDEX IF NOT EXISTS idx_fwev_direction   ON firewall_events(direction);
    CREATE INDEX IF NOT EXISTS idx_fwev_src_ip      ON firewall_events(src_ip);
    CREATE INDEX IF NOT EXISTS idx_fwev_dst_ip      ON firewall_events(dst_ip);
    CREATE INDEX IF NOT EXISTS idx_fwev_dst_port    ON firewall_events(dst_port);
    CREATE INDEX IF NOT EXISTS idx_fwev_protocol    ON firewall_events(protocol);
    CREATE INDEX IF NOT EXISTS idx_fwev_rule_id     ON firewall_events(rule_id);
    CREATE INDEX IF NOT EXISTS idx_fwev_event_uuid  ON firewall_events(event_uuid);
    CREATE INDEX IF NOT EXISTS idx_fwev_soc_origin  ON firewall_events(soc_origin);
    CREATE INDEX IF NOT EXISTS idx_fwev_severity_ts ON firewall_events(severity, ts);
    """)

    # Per-rule logging toggle. Default 0 — without it the PF generator keeps
    # the existing behaviour (only block rules emit the `log` keyword).
    for tbl in ("firewall_rules_lan",
                "firewall_rules_wan",
                "firewall_rules_floating"):
        info = conn.execute(f"PRAGMA table_info({tbl})").fetchall()
        existing = {row[1] for row in info}
        if "log_enabled" in existing:
            continue
        try:
            conn.execute(
                f"ALTER TABLE {tbl} ADD COLUMN log_enabled INTEGER DEFAULT 0"
            )
        except Exception:
            pass


def _migration_v37(conn):
    """
    Phase 37: persistent SOC alerts lifecycle (Wave C foundations).

    ``siem_alert_actions`` / ``siem_alert_assignments`` (v18/v31) tracked
    analyst decisions but kept the alerts themselves implicit — the SOC
    portal kept re-deriving them from raw events on every refresh. There
    was no deduplication, no stable severity escalation, no suppression,
    and no count of how many times a noisy detection had fired.

    This migration adds four tables:

      ``alerts`` — one row per logical incident. Detectors call
                   ``alert_service.create_or_update_alert(...)`` and the
                   row is either inserted new or its ``count``/``last_seen``
                   bumped (deduplication is by ``dedup_key``).

      ``alert_actions`` — every analyst action on an alert (ack, assign,
                          escalate, close, false_positive, suppress, note,
                          reopen) for the audit trail.

      ``alert_suppressions`` — operator-defined rules that auto-close or
                               hide future alerts matching a key/IP/domain
                               for a window of time.

      ``case_alerts`` — many-to-many between siem_cases and alerts so one
                        case can roll up several deduplicated alerts.
    """
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS alerts (
        id                 INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_uuid         TEXT UNIQUE NOT NULL,
        first_seen         TEXT NOT NULL,
        last_seen          TEXT NOT NULL,
        status             TEXT NOT NULL DEFAULT 'new',     -- new|acknowledged|in_progress|escalated|case_opened|closed|false_positive|suppressed
        severity           TEXT NOT NULL DEFAULT 'medium',  -- critical|high|medium|low|info
        category           TEXT,
        alert_type         TEXT,
        title              TEXT,
        description        TEXT,
        source_event_id    INTEGER,
        source_event_uuid  TEXT,
        dedup_key          TEXT NOT NULL,
        count              INTEGER NOT NULL DEFAULT 1,
        src_ip             TEXT,
        dst_ip             TEXT,
        username           TEXT,
        hostname           TEXT,
        mac                TEXT,
        domain             TEXT,
        rule_id            TEXT,
        rule_name          TEXT,
        signature_id       TEXT,
        mitre_tactic       TEXT,
        mitre_technique    TEXT,
        risk_score         REAL NOT NULL DEFAULT 0,
        assigned_to        INTEGER,
        assigned_name      TEXT,
        assigned_by        TEXT,
        assigned_at        TEXT,
        acknowledged_by    TEXT,
        acknowledged_at    TEXT,
        closed_by          TEXT,
        closed_at          TEXT,
        closure_type       TEXT,                            -- resolved|false_positive|duplicate|benign
        suppression_id     INTEGER,
        case_id            INTEGER,
        details            TEXT,                            -- JSON-encoded extras
        created_at         TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at         TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_alerts_status      ON alerts(status);
    CREATE INDEX IF NOT EXISTS idx_alerts_severity    ON alerts(severity);
    CREATE INDEX IF NOT EXISTS idx_alerts_last_seen   ON alerts(last_seen);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_dedup_open
        ON alerts(dedup_key)
        WHERE status NOT IN ('closed','false_positive','suppressed');
    CREATE INDEX IF NOT EXISTS idx_alerts_src_ip      ON alerts(src_ip);
    CREATE INDEX IF NOT EXISTS idx_alerts_dst_ip      ON alerts(dst_ip);
    CREATE INDEX IF NOT EXISTS idx_alerts_assigned_to ON alerts(assigned_to);
    CREATE INDEX IF NOT EXISTS idx_alerts_case_id     ON alerts(case_id);

    CREATE TABLE IF NOT EXISTS alert_actions (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_id    INTEGER NOT NULL,
        action      TEXT NOT NULL,    -- ack|assign|unassign|escalate|case_created|case_linked|close|false_positive|suppress|reopen|comment|note
        actor       TEXT NOT NULL,
        note        TEXT,
        old_status  TEXT,
        new_status  TEXT,
        details     TEXT,             -- JSON-encoded extras
        created_at  TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(alert_id) REFERENCES alerts(id)
    );
    CREATE INDEX IF NOT EXISTS idx_alert_actions_alert_id   ON alert_actions(alert_id);
    CREATE INDEX IF NOT EXISTS idx_alert_actions_created_at ON alert_actions(created_at);

    CREATE TABLE IF NOT EXISTS alert_suppressions (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        name        TEXT NOT NULL,
        enabled     INTEGER NOT NULL DEFAULT 1,
        match_type  TEXT NOT NULL,    -- dedup_key|signature_id|src_ip|dst_ip|domain|username|rule_id|alert_type
        match_value TEXT NOT NULL,
        reason      TEXT,
        created_by  TEXT,
        created_at  TEXT DEFAULT CURRENT_TIMESTAMP,
        expires_at  TEXT,
        details     TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_alert_supp_enabled ON alert_suppressions(enabled);
    CREATE INDEX IF NOT EXISTS idx_alert_supp_match   ON alert_suppressions(match_type, match_value);

    CREATE TABLE IF NOT EXISTS case_alerts (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id   INTEGER NOT NULL,
        alert_id  INTEGER NOT NULL,
        added_by  TEXT,
        added_at  TEXT DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(case_id, alert_id),
        FOREIGN KEY(case_id)  REFERENCES siem_cases(id),
        FOREIGN KEY(alert_id) REFERENCES alerts(id)
    );
    CREATE INDEX IF NOT EXISTS idx_case_alerts_case_id  ON case_alerts(case_id);
    CREATE INDEX IF NOT EXISTS idx_case_alerts_alert_id ON case_alerts(alert_id);
    """)


def _migration_v38(conn):
    """
    Phase 38: collector reliability — health table + dead-letter queue
              (Wave D foundations).

    Until now collector parse failures were silently dropped (four ``except:
    continue`` sites across ``siem_collector.py``) and collector state was
    a flat key/value soup in ``siem_state``.  The new tables give us:

      ``collector_state`` — one row per source name (pflog0, eve.json,
        unbound, …) with the current tail offset, last error, drop counts,
        and a heartbeat. The /status/collector-health page reads this.

      ``event_dead_letter`` — every parse failure or queue-full drop lands
        here so an operator can post-mortem the raw payload that broke the
        collector instead of guessing from the log.
    """
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS collector_state (
        source_name        TEXT PRIMARY KEY,
        source_type        TEXT,
        enabled            INTEGER NOT NULL DEFAULT 1,
        path               TEXT,
        inode              TEXT,
        offset             INTEGER NOT NULL DEFAULT 0,
        file_size          INTEGER NOT NULL DEFAULT 0,
        last_seen          TEXT,
        last_event_ts      TEXT,
        last_error         TEXT,
        events_collected   INTEGER NOT NULL DEFAULT 0,
        events_dropped     INTEGER NOT NULL DEFAULT 0,
        restart_count      INTEGER NOT NULL DEFAULT 0,
        updated_at         TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS event_dead_letter (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        ts          TEXT NOT NULL,
        source_type TEXT,
        source_name TEXT,
        reason      TEXT,
        raw_payload TEXT,
        details     TEXT,
        created_at  TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_dlq_ts     ON event_dead_letter(ts);
    CREATE INDEX IF NOT EXISTS idx_dlq_source ON event_dead_letter(source_type, source_name);
    """)


def _migration_v39(conn):
    """
    Phase 39: dns_events specialised table (Wave E).

    Mirrors firewall_events for DNS — the DNS collector dual-writes parsed
    Unbound log lines into this table so the upcoming DNS Logs page can
    filter on client IP / query / policy / blocked-flag without LIKE-scan
    of the JSON details column.

    Default DNS query logging mode lives in ``siem_state`` under
    ``dns_logging_mode`` (values: off | blocked_only | all). The collector
    reads it each tick — operators can flip the mode from a settings page
    without restarting the service.
    """
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS dns_events (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id      INTEGER,
        event_uuid    TEXT,
        ts            TEXT NOT NULL,
        client_ip     TEXT,
        client_port   INTEGER,
        query         TEXT NOT NULL,
        qtype         TEXT,
        rcode         TEXT,
        action        TEXT,                 -- allow | block_all | redirect | allow_whitelist_only
        blocked       INTEGER DEFAULT 0,
        redirected    INTEGER DEFAULT 0,
        policy_id     TEXT,
        policy_name   TEXT,
        matched_domain TEXT,
        category      TEXT,
        resolver      TEXT,
        hostname      TEXT,
        mac           TEXT,
        raw_line      TEXT,
        created_at    TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_dns_ts          ON dns_events(ts);
    CREATE INDEX IF NOT EXISTS idx_dns_client_ip   ON dns_events(client_ip);
    CREATE INDEX IF NOT EXISTS idx_dns_query       ON dns_events(query);
    CREATE INDEX IF NOT EXISTS idx_dns_blocked     ON dns_events(blocked);
    CREATE INDEX IF NOT EXISTS idx_dns_action      ON dns_events(action);
    CREATE INDEX IF NOT EXISTS idx_dns_matched     ON dns_events(matched_domain);
    CREATE INDEX IF NOT EXISTS idx_dns_event_uuid  ON dns_events(event_uuid);
    """)

    # Seed the default DNS query logging mode (blocked_only). Operators can
    # override by writing a different value to siem_state['dns_logging_mode'].
    try:
        conn.execute(
            "INSERT INTO siem_state (key, value) VALUES ('dns_logging_mode', 'blocked_only') "
            "ON CONFLICT(key) DO NOTHING"
        )
    except Exception:
        # On SQLite versions without ON CONFLICT — best-effort fallback.
        row = conn.execute(
            "SELECT value FROM siem_state WHERE key = 'dns_logging_mode'"
        ).fetchone()
        if not row:
            conn.execute(
                "INSERT INTO siem_state (key, value) VALUES (?, ?)",
                ("dns_logging_mode", "blocked_only"),
            )


def _migration_v40(conn):
    """v40 — dns_events.policy_source for log classification via the unified
    domain-policy resolver (Wave J of the Fv5 plan).

    Before this column landed, ``dns_events.action`` was the only hint about
    which filter blocked a query — and the DNS collector populated it from
    parsing Unbound text instead of consulting the policy resolver. The new
    column carries the *source* (``dns`` / ``web`` / ``app`` / ``soc``) so the
    DNS Logs UI can answer "which filter blocked this domain?" without a
    second lookup.
    """
    # Defensive: ALTER TABLE ... ADD COLUMN is non-transactional in SQLite,
    # so guard against re-adding on a partially-applied install by reading
    # PRAGMA table_info first.
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(dns_events)").fetchall()}
    if "policy_source" not in cols:
        conn.execute("ALTER TABLE dns_events ADD COLUMN policy_source TEXT")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_dns_policy_source "
        "ON dns_events(policy_source)"
    )


def _migration_v41(conn):
    """v41 — ``alert_observations`` so dedup doesn't hide per-event evidence
    (Wave K of the Fv5 plan).

    The ``alerts`` table (v37) collapses repeated alerts into a single row
    with a count. Useful for the queue, but it loses the per-occurrence
    detail an analyst needs: which exact src/dst, which domain, which
    event_uuid. ``alert_observations`` is the append-only history of every
    occurrence so the detail page can show the timeline without rerunning
    correlations.
    """
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS alert_observations (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_id      INTEGER NOT NULL,
        event_uuid    TEXT,
        observed_at   TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        src_ip        TEXT,
        dst_ip        TEXT,
        domain        TEXT,
        url           TEXT,
        username      TEXT,
        hostname      TEXT,
        summary       TEXT,
        raw_json      TEXT,
        FOREIGN KEY(alert_id) REFERENCES alerts(id)
    );
    CREATE INDEX IF NOT EXISTS idx_alert_obs_alert
        ON alert_observations(alert_id);
    CREATE INDEX IF NOT EXISTS idx_alert_obs_time
        ON alert_observations(observed_at);
    CREATE INDEX IF NOT EXISTS idx_alert_obs_event_uuid
        ON alert_observations(event_uuid);
    """)


def _migration_v42(conn):
    """v42 — richer firewall_events columns (Wave L of the Fv5 plan).

    Adds optional ``policy_id``, ``policy_name``, ``zone_in``, ``zone_out``,
    ``nat_translated_src``, and ``nat_translated_dst``. These let the
    firewall-log row-detail drawer surface the matching policy name and
    NAT translation without parsing the raw line again.

    All columns nullable, all populated best-effort by the collector — old
    rows simply have ``NULL`` in the new fields.
    """
    cols = {r["name"] for r in conn.execute(
        "PRAGMA table_info(firewall_events)"
    ).fetchall()}
    for new_col in ("policy_id", "policy_name", "zone_in", "zone_out",
                    "nat_translated_src", "nat_translated_dst"):
        if new_col not in cols:
            conn.execute(
                f"ALTER TABLE firewall_events ADD COLUMN {new_col} TEXT"
            )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_firewall_events_policy_id "
        "ON firewall_events(policy_id)"
    )


def _migration_v43(conn):
    """v43 — default abuse.ch threat feeds to safe dry-run mode.

    Earlier fresh installs seeded ``ids_threat_feeds.abusech_dry_run = 0``
    (live), so the app reported "live" mode even with no Auth-Key configured —
    every recent/lookup call then failed with "ABUSECH_AUTH_KEY is required"
    instead of staying offline-safe. Flip any unconfigured row (no key) back to
    dry-run. Idempotent: rows that already have a key, or are already dry-run,
    are left untouched.
    """
    conn.execute(
        "UPDATE ids_threat_feeds SET abusech_dry_run = 1 "
        "WHERE COALESCE(abusech_auth_key, '') = '' AND abusech_dry_run = 0"
    )


def _migration_v44(conn):
    """v44 — turn mail alerts on by default when the admin hasn't configured SMTP.

    The Smart Shield ships with a built-in fallback Gmail account (see
    ``_DEFAULT_SMTP_USERNAME`` / ``_DEFAULT_SMTP_APP_PASSWORD`` in
    ``app/services/mail_alerts.py``) so a fresh install can email alerts
    without any GUI setup. Existing installs created before that change
    have ``mail_alerts_config.enabled = 0`` and blank credentials — flip
    them to ``enabled = 1`` so the fallback actually takes effect.

    Idempotent and conservative: only fires when the row is still in its
    untouched factory state (no username, no app password). Any admin who
    has already saved their own credentials, or deliberately disabled
    mail with their own credentials in place, is left alone.
    """
    conn.execute(
        "UPDATE mail_alerts_config "
        "SET enabled = 1 "
        "WHERE id = 1 "
        "  AND COALESCE(enabled, 0) = 0 "
        "  AND COALESCE(TRIM(smtp_username), '') = '' "
        "  AND COALESCE(TRIM(smtp_app_password), '') = ''"
    )


def _migration_v45(conn):
    """v45 — IPS inline peer interface + degraded-rules opt-in for the IDS.

    Two new ids_config columns back the IDS/IPS hardening work:

    * ``ips_peer_interface`` — netmap IPS bridges traffic between the capture
      interface and a *second* inline interface. Without a distinct peer the
      generated suricata.yaml used ``copy-iface == interface``, which is not a
      valid inline bridge. The Configuration UI now exposes a peer selector and
      ``generate_suricata_yaml`` requires the two to differ for IPS mode.

    * ``allow_degraded_rules`` — Suricata will happily start with zero
      signatures, but that is no detection coverage. ``_rules_ready`` now blocks
      enable when the merged rules file is empty unless this opt-in flag is set,
      so operators are steered to run "Update Rules" first.
    """
    for ddl in (
        "ALTER TABLE ids_config ADD COLUMN ips_peer_interface TEXT DEFAULT ''",
        "ALTER TABLE ids_config ADD COLUMN allow_degraded_rules INTEGER NOT NULL DEFAULT 0",
    ):
        try:
            conn.execute(ddl)
        except Exception:
            pass  # column already exists


def _migration_v46(conn):
    """v46 — store the full source log on a SOC case so it can be investigated.

    ``siem_case_events`` previously held only a one-line ``event_summary``, so a
    case opened from an alert kept no detail of the originating log — the case
    page had nothing for the analyst to investigate. Two columns back the new
    "Linked Logs / Evidence" view:

    * ``event_uuid``    — the collision-safe join key to the audit-log event.
    * ``event_details`` — a JSON snapshot of the full event, captured at
      case-open time so the evidence survives audit-log retention eviction.

    Idempotent: the ALTERs no-op when the columns already exist (fresh installs
    create them inline in database.py / the v17 mirror).
    """
    for ddl in (
        "ALTER TABLE siem_case_events ADD COLUMN event_uuid TEXT DEFAULT ''",
        "ALTER TABLE siem_case_events ADD COLUMN event_details TEXT DEFAULT ''",
    ):
        try:
            conn.execute(ddl)
        except Exception:
            pass  # column already exists


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
    (16, _migration_v16),
    (17, _migration_v17),
    (18, _migration_v18),
    (19, _migration_v19),
    (20, _migration_v20),
    (21, _migration_v21),
    (22, _migration_v22),
    (23, _migration_v23),
    (24, _migration_v24),
    (25, _migration_v25),
    (26, _migration_v26),
    (27, _migration_v27),
    (28, _migration_v28),
    (29, _migration_v29),
    (30, _migration_v30),
    (31, _migration_v31),
    (32, _migration_v32),
    (33, _migration_v33),
    (34, _migration_v34),
    (35, _migration_v35),
    (36, _migration_v36),
    (37, _migration_v37),
    (38, _migration_v38),
    (39, _migration_v39),
    (40, _migration_v40),
    (41, _migration_v41),
    (42, _migration_v42),
    (43, _migration_v43),
    (44, _migration_v44),
    (45, _migration_v45),
    (46, _migration_v46),
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


def _log_migration_event(message: str) -> None:
    # Stdlib logging only. Writing to the audit log here would open a second
    # DB connection during schema-mutating transactions and deadlock against
    # the in-memory SQLite DB used by tests.
    try:
        _log.info("[migrations] %s", message)
    except Exception:
        pass
