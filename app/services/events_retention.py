"""
app/services/events_retention.py
--------------------------------
Background pruner for the indexed `events` table.

The audit-log file is rotated by newsyslog (default 90-day retention), but
its SQLite mirror used by every query in the SOC portal grew forever. This
module trims rows older than the configured retention window on a fixed
cadence, so search and dashboards stay fast and disk usage stays bounded.

Config lives in `siem_state` under the `events_retention` key:
  {"enabled": true, "days": 90}
"""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timedelta, timezone


_STARTED    = threading.Event()
_CONFIG_KEY = "events_retention"
_TICK_SECS  = 3600   # evaluate once per hour


# Per-category retention overrides. Empty dict = use the global window for
# every event. Operators set these via the retention settings page or by
# editing siem_state['events_retention']. Each value is the number of days
# rows in that category should be kept before pruning.
#
# Sensible defaults (kept commented for documentation; the dict starts empty
# so unchanged installs behave identically to pre-Wave-E):
#   "firewall":     30      # high-volume packet logs roll fast
#   "connection":   7       # DNS allow-mode is the noisiest if enabled
#   "ids":          180     # signatures matter long after the event
#   "security":     365     # admin/auth/SOC events kept a year
#   "admin_audit":  365     # config changes — compliance window
#   "system":       30
#   "vpn":          90
# Wave N: per-table retention windows. Older snapshots only handled the
# generic ``events`` table; specialised tables grew without a cap because the
# pruner never touched them. Keys here line up with sibling tables; default
# windows are sensible production values, ``0`` means "disabled, do not prune".
_PRUNE_DEFAULTS = {
    "firewall_events":     30,
    "dns_events":          30,
    "alerts":             180,
    "alert_observations":  30,
    "event_dead_letter":   14,
}


def _default_config() -> dict:
    return {
        "enabled":      True,
        "days":         90,
        "per_category": {},
        "per_table":    dict(_PRUNE_DEFAULTS),
    }


def load_config(conn) -> dict:
    cfg = _default_config()
    try:
        row = conn.execute(
            "SELECT value FROM siem_state WHERE key = ?", (_CONFIG_KEY,)
        ).fetchone()
        if row and row[0]:
            cfg.update(json.loads(row[0]))
    except Exception:
        pass
    # sanity-clamp the global window
    try:
        cfg["days"] = max(1, min(int(cfg.get("days", 90)), 3650))
    except (TypeError, ValueError):
        cfg["days"] = 90
    cfg["enabled"] = bool(cfg.get("enabled", True))
    # sanity-clamp per-category overrides
    pc_in = cfg.get("per_category") or {}
    pc_out: dict = {}
    if isinstance(pc_in, dict):
        for cat, days in pc_in.items():
            if not cat or not isinstance(cat, str):
                continue
            try:
                pc_out[cat] = max(1, min(int(days), 3650))
            except (TypeError, ValueError):
                continue
    cfg["per_category"] = pc_out
    # Wave N — clamp per-table overrides too. Defaults supply the sensible
    # production windows; operators can override any/all in the settings page.
    pt_in = cfg.get("per_table") or {}
    pt_out: dict = dict(_PRUNE_DEFAULTS)
    if isinstance(pt_in, dict):
        for tbl, days in pt_in.items():
            if not tbl or not isinstance(tbl, str):
                continue
            if tbl not in _PRUNE_DEFAULTS:
                continue
            try:
                # 0 = disabled (do not prune); otherwise clamp to a sane range
                v = int(days)
                pt_out[tbl] = 0 if v <= 0 else min(v, 3650)
            except (TypeError, ValueError):
                continue
    cfg["per_table"] = pt_out
    return cfg


def save_config(conn, cfg: dict) -> dict:
    merged = _default_config()
    try:
        days = int(cfg.get("days", 90))
    except (TypeError, ValueError):
        days = 90
    pc_in  = cfg.get("per_category") or {}
    pc_out: dict = {}
    if isinstance(pc_in, dict):
        for cat, days_v in pc_in.items():
            if not cat or not isinstance(cat, str):
                continue
            try:
                pc_out[cat] = max(1, min(int(days_v), 3650))
            except (TypeError, ValueError):
                continue
    pt_in = cfg.get("per_table") or {}
    pt_out: dict = dict(_PRUNE_DEFAULTS)
    if isinstance(pt_in, dict):
        for tbl, days_v in pt_in.items():
            if not tbl or not isinstance(tbl, str) or tbl not in _PRUNE_DEFAULTS:
                continue
            try:
                v = int(days_v)
                pt_out[tbl] = 0 if v <= 0 else min(v, 3650)
            except (TypeError, ValueError):
                continue
    merged.update({
        "enabled":      bool(cfg.get("enabled", True)),
        "days":         max(1, min(days, 3650)),
        "per_category": pc_out,
        "per_table":    pt_out,
    })
    conn.execute(
        "INSERT INTO siem_state (key, value, updated_at) "
        "VALUES (?, ?, CURRENT_TIMESTAMP) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value, "
        "updated_at = CURRENT_TIMESTAMP",
        (_CONFIG_KEY, json.dumps(merged)),
    )
    conn.commit()
    return merged


def _cutoff_for(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def prune_once() -> dict:
    """
    Delete events older than the configured retention window.

    Honours per-category overrides — categories listed in
    ``cfg['per_category']`` use their own window; everything else falls back
    to the global ``cfg['days']``.

    Returns ``{"ok": bool, "deleted": int, "details": {...}, "message": str}``.
    Safe to call from any thread; uses its own short-lived connection.
    """
    from app.audit_log import _events_db
    conn = _events_db()
    if conn is None:
        return {"ok": False, "deleted": 0, "cutoff": "", "message": "events DB unavailable"}
    try:
        cfg = load_config(conn)
        if not cfg["enabled"]:
            return {"ok": True, "deleted": 0, "cutoff": "",
                    "message": "retention disabled"}

        per_cat = cfg.get("per_category") or {}
        per_cat_deleted: dict = {}
        total_deleted = 0

        # Per-category sweeps first.
        for category, days in per_cat.items():
            cutoff = _cutoff_for(days)
            cur = conn.execute(
                "DELETE FROM events WHERE category = ? AND ts < ?",
                (category, cutoff),
            )
            n = cur.rowcount or 0
            per_cat_deleted[category] = n
            total_deleted += n

        # Global sweep — exclude any category that has its own window so we
        # do not double-trim categories with a longer override.
        global_cutoff = _cutoff_for(cfg["days"])
        if per_cat:
            placeholders = ",".join("?" * len(per_cat))
            cur = conn.execute(
                f"DELETE FROM events WHERE ts < ? "
                f"AND (category IS NULL OR category NOT IN ({placeholders}))",
                [global_cutoff] + list(per_cat.keys()),
            )
        else:
            cur = conn.execute("DELETE FROM events WHERE ts < ?", (global_cutoff,))
        global_deleted = cur.rowcount or 0
        total_deleted += global_deleted

        # Wave N — sweep the sibling tables with their own windows. Skip a
        # table when its configured window is 0 (operator disabled) or when
        # the table does not exist on this DB (fresh installs that haven't
        # migrated yet).
        per_table_deleted: dict = {}
        per_table_cfg = cfg.get("per_table") or {}
        for tbl, days in per_table_cfg.items():
            try:
                days_i = int(days)
            except (TypeError, ValueError):
                continue
            if days_i <= 0:
                continue
            ts_col = "observed_at" if tbl == "alert_observations" else "ts"
            try:
                cutoff_t = _cutoff_for(days_i)
                cur_t = conn.execute(
                    f"DELETE FROM {tbl} WHERE {ts_col} < ?", (cutoff_t,)
                )
                deleted_t = cur_t.rowcount or 0
                per_table_deleted[tbl] = deleted_t
                total_deleted += deleted_t
            except Exception:
                # Best-effort: a missing table or column is logged in audit
                # via the standard run_migrations path, not surfaced here.
                continue

        conn.commit()

        return {
            "ok":            True,
            "deleted":       total_deleted,
            "cutoff":        global_cutoff,
            "per_category":  per_cat_deleted,
            "per_table":     per_table_deleted,
            "global_window": cfg["days"],
            "message":       (
                f"Pruned {total_deleted} row(s) "
                f"({global_deleted} events global; "
                f"{sum(per_cat_deleted.values())} per-category; "
                f"{sum(per_table_deleted.values())} per-table)."
            ),
        }
    except Exception as exc:
        return {"ok": False, "deleted": 0, "cutoff": "",
                "message": f"Prune failed: {exc}"}
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _retention_loop():
    # Stagger the first run so it doesn't pile onto boot-time work.
    time.sleep(60)
    while True:
        try:
            prune_once()
        except Exception:
            pass
        time.sleep(_TICK_SECS)


def start_retention_pruner():
    """Start the background retention thread (idempotent per process)."""
    if _STARTED.is_set():
        return
    _STARTED.set()
    threading.Thread(target=_retention_loop, name="events-retention",
                     daemon=True).start()
