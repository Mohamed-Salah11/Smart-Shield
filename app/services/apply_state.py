"""
apply_state.py
--------------
Applied-state tracking for every Smart Shield configuration feature.

Every time a feature config is saved or applied, a row is written to
config_apply_jobs and the feature_applied_state summary is updated.

The UI reads feature_applied_state to show accurate status badges:
  saved        stored in DB, not yet applied to the OS
  pending      apply has been queued but not started
  applying     apply is in progress
  applied      successfully written to disk and service reloaded
  failed       apply was attempted and failed; OS may have rolled back
  rolled_back  apply failed and previous config was restored
  dry-run      config generated but not applied (non-FreeBSD or dry-run mode)
  unsupported  feature cannot run on this platform
"""

import hashlib
import time
from typing import Optional


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VALID_STATES = frozenset([
    "saved", "pending", "applying", "applied",
    "failed", "rolled_back", "dry-run", "unsupported",
])

STATE_COLORS = {
    "saved":       "blue",
    "pending":     "yellow",
    "applying":    "yellow",
    "applied":     "green",
    "failed":      "red",
    "rolled_back": "orange",
    "dry-run":     "gray",
    "unsupported": "gray",
}

STATE_LABELS = {
    "saved":       "Saved",
    "pending":     "Pending Apply",
    "applying":    "Applying…",
    "applied":     "Applied",
    "failed":      "Failed",
    "rolled_back": "Rolled Back",
    "dry-run":     "Dry-Run",
    "unsupported": "Unsupported",
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _now() -> float:
    return time.time()


def _hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]


def _update_feature_summary(conn, feature_key: str, state: str,
                             message: str, job_id: Optional[int]) -> None:
    """Keep feature_applied_state in sync after every job state change."""
    conn.execute(
        """
        INSERT OR REPLACE INTO feature_applied_state
            (feature_key, state, message, last_job_id, updated_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (feature_key, state, message or "", job_id, _now()),
    )
    conn.commit()


# ---------------------------------------------------------------------------
# Write functions
# ---------------------------------------------------------------------------

def record_save(conn, feature_key: str, config_hash: str = "",
                applied_by: str = "system", notes: str = "") -> int:
    """
    Record that a feature config was saved to the DB but not yet applied.
    Returns the new job row id.
    """
    cur = conn.execute(
        """
        INSERT INTO config_apply_jobs
            (feature_key, state, config_hash, applied_by, notes, message, created_at, updated_at)
        VALUES (?, 'saved', ?, ?, ?, '', ?, ?)
        """,
        (feature_key, config_hash, applied_by, notes, _now(), _now()),
    )
    conn.commit()
    job_id = cur.lastrowid
    _update_feature_summary(conn, feature_key, "saved", "Saved — not yet applied", job_id)
    return job_id


def record_apply_start(conn, feature_key: str, config_hash: str = "",
                       applied_by: str = "system", notes: str = "") -> int:
    """Mark that an apply operation has started. Returns the job id."""
    cur = conn.execute(
        """
        INSERT INTO config_apply_jobs
            (feature_key, state, config_hash, applied_by, notes, message, created_at, updated_at)
        VALUES (?, 'applying', ?, ?, ?, '', ?, ?)
        """,
        (feature_key, config_hash, applied_by, notes, _now(), _now()),
    )
    conn.commit()
    job_id = cur.lastrowid
    _update_feature_summary(conn, feature_key, "applying", "Apply in progress…", job_id)
    return job_id


def record_apply_result(conn, job_id: int, ok: bool, message: str = "",
                        rollback_ok: Optional[bool] = None) -> None:
    """
    Update a job row with the final apply result.

    ok=True           → state becomes "applied"
    ok=False + rollback_ok=True  → state becomes "rolled_back"
    ok=False + rollback_ok=False → state becomes "failed"
    ok=False + rollback_ok=None  → state becomes "failed"
    """
    if ok:
        state = "applied"
    elif rollback_ok is True:
        state = "rolled_back"
    else:
        state = "failed"

    conn.execute(
        """
        UPDATE config_apply_jobs
        SET state=?, message=?, updated_at=?
        WHERE id=?
        """,
        (state, message or "", _now(), job_id),
    )
    conn.commit()

    # Propagate to feature summary
    row = conn.execute(
        "SELECT feature_key FROM config_apply_jobs WHERE id=?", (job_id,)
    ).fetchone()
    if row:
        _update_feature_summary(conn, row["feature_key"], state, message or "", job_id)


def record_dry_run(conn, feature_key: str, config_preview: str = "",
                   applied_by: str = "system") -> int:
    """Record a dry-run: config was generated but not written to disk."""
    chash = _hash(config_preview) if config_preview else ""
    cur = conn.execute(
        """
        INSERT INTO config_apply_jobs
            (feature_key, state, config_hash, applied_by, notes, message, created_at, updated_at)
        VALUES (?, 'dry-run', ?, ?, 'dry-run: config generated, not applied', '', ?, ?)
        """,
        (feature_key, chash, applied_by, _now(), _now()),
    )
    conn.commit()
    job_id = cur.lastrowid
    _update_feature_summary(conn, feature_key, "dry-run",
                            "Dry-run — config generated but not applied to OS", job_id)
    return job_id


def record_unsupported(conn, feature_key: str, reason: str = "") -> None:
    """Record that a feature is unsupported on this platform."""
    conn.execute(
        """
        INSERT OR REPLACE INTO feature_applied_state
            (feature_key, state, message, last_job_id, updated_at)
        VALUES (?, 'unsupported', ?, NULL, ?)
        """,
        (feature_key, reason or "Not supported on this platform", _now()),
    )
    conn.commit()


# ---------------------------------------------------------------------------
# Read functions
# ---------------------------------------------------------------------------

def get_feature_state(conn, feature_key: str) -> Optional[dict]:
    """Return the current applied-state record for a feature, or None."""
    row = conn.execute(
        """
        SELECT fs.feature_key, fs.state, fs.message, fs.updated_at,
               j.config_hash, j.applied_by, j.notes
        FROM feature_applied_state fs
        LEFT JOIN config_apply_jobs j ON j.id = fs.last_job_id
        WHERE fs.feature_key = ?
        """,
        (feature_key,),
    ).fetchone()
    if not row:
        return None
    d = dict(row)
    d["color"] = STATE_COLORS.get(d.get("state", ""), "gray")
    d["label"] = STATE_LABELS.get(d.get("state", ""), d.get("state", ""))
    return d


def get_all_feature_states(conn) -> dict:
    """Return {feature_key: state_dict} for every recorded feature."""
    rows = conn.execute(
        """
        SELECT fs.feature_key, fs.state, fs.message, fs.updated_at,
               j.config_hash, j.applied_by
        FROM feature_applied_state fs
        LEFT JOIN config_apply_jobs j ON j.id = fs.last_job_id
        """
    ).fetchall()
    result = {}
    for r in rows:
        d = dict(r)
        d["color"] = STATE_COLORS.get(d.get("state", ""), "gray")
        d["label"] = STATE_LABELS.get(d.get("state", ""), d.get("state", ""))
        result[d["feature_key"]] = d
    return result


def get_recent_jobs(conn, feature_key: str = None, limit: int = 20) -> list:
    """Return recent apply jobs, optionally filtered to one feature."""
    if feature_key:
        rows = conn.execute(
            """
            SELECT * FROM config_apply_jobs
            WHERE feature_key = ?
            ORDER BY created_at DESC LIMIT ?
            """,
            (feature_key, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT * FROM config_apply_jobs
            ORDER BY created_at DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d["color"] = STATE_COLORS.get(d.get("state", ""), "gray")
        d["label"] = STATE_LABELS.get(d.get("state", ""), d.get("state", ""))
        result.append(d)
    return result


def has_pending_changes(conn, feature_key: str) -> bool:
    """Return True if the feature has been saved but not yet applied."""
    row = conn.execute(
        "SELECT state FROM feature_applied_state WHERE feature_key=?",
        (feature_key,),
    ).fetchone()
    return row is not None and row["state"] == "saved"


def get_pending_features(conn) -> list:
    """Return list of feature_keys whose state is 'saved' (applied not yet)."""
    rows = conn.execute(
        "SELECT feature_key FROM feature_applied_state WHERE state='saved'"
    ).fetchall()
    return [r["feature_key"] for r in rows]
