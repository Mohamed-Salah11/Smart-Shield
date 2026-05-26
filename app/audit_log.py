import json
import logging
import os
import re
import sqlite3
import sys
import uuid
from datetime import datetime, timezone


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Secret redaction
#
# Used by the live terminal audit path so passwords / tokens / private keys
# that operators type at the shell never reach the durable audit log. The
# patterns deliberately bias towards over-redaction: false positives here
# only obscure a value in the audit trail, while a miss leaks a credential.
# ---------------------------------------------------------------------------
_SECRET_PATTERNS = [
    re.compile(r"(?i)\b(password\s*=\s*)(\S+)"),
    re.compile(r"(?i)\b(passwd\s*=\s*)(\S+)"),
    re.compile(r"(?i)\b(secret(?:_key)?\s*=\s*)(\S+)"),
    re.compile(r"(?i)\b(token\s*=\s*)(\S+)"),
    re.compile(r"(?i)\b(api[_-]?key\s*=\s*)(\S+)"),
    re.compile(r"(?i)(authorization:\s*bearer\s+)(\S+)"),
    re.compile(
        r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----)"
        r"([\s\S]+?)"
        r"(-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----)"
    ),
]


def redact_secrets(text: str) -> str:
    """Return ``text`` with anything that looks like a secret replaced by
    ``[REDACTED]``. Safe to call on arbitrary command strings."""
    if not text:
        return text
    out = text
    for pat in _SECRET_PATTERNS:
        if pat.groups == 3:
            out = pat.sub(r"\1[REDACTED]\3", out)
        else:
            out = pat.sub(r"\1[REDACTED]", out)
    return out


def _default_audit_path():
    if sys.platform.startswith("freebsd"):
        from app.config import _ss_dir
        return os.path.join(_ss_dir("/var/log"), "audit.log")
    return "logs/audit.log"


def _audit_log_path():
    return os.getenv("SMARTSHIELD_AUDIT_LOG_PATH", _default_audit_path())


def _ensure_parent_dir(path: str):
    parent_dir = os.path.dirname(os.path.abspath(path))
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)


# ---------------------------------------------------------------------------
# Indexed event store
#
# Every audit event is written to two places:
#   1. the audit.log NDJSON file  — durable, append-only forensic record
#      (rotated by newsyslog; never removed)
#   2. the `events` SQLite table  — indexed mirror used for all queries,
#      stats and charts, so callers never re-scan the whole file
#
# log_event() and the readers below open a short-lived dedicated SQLite
# connection (NOT get_db()) so they are safe from background collector
# threads and from contexts without a Flask app context.
# ---------------------------------------------------------------------------

def _events_db():
    """Open a short-lived connection to the event store, or None on failure."""
    try:
        from app.database import _database_path  # lazy import — avoids cycles
        path = _database_path()
        is_uri = path.startswith("file:")
        conn = sqlite3.connect(path, uri=is_uri, timeout=5)
        conn.row_factory = sqlite3.Row
        return conn
    except Exception:
        return None


def _row_to_event(row) -> dict:
    """Convert an `events` table row to the legacy NDJSON event shape."""
    try:
        details = json.loads(row["details"]) if row["details"] else {}
    except Exception:
        details = {}
    out = {
        "timestamp":   row["ts"],
        "severity":    row["severity"] or "info",
        "category":    row["category"] or "",
        "action":      row["action"] or "",
        "username":    row["username"] or "anonymous",
        "remote_addr": row["remote_addr"] or "",
        "details":     details,
    }
    # Surface the stable event_uuid alongside details so consumers can join
    # against alert-action / case-event tables by uuid instead of timestamp.
    # The column is added in migration v34 and may be absent on rows older
    # than that migration if the backfill skipped them.
    try:
        out["event_uuid"] = row["event_uuid"] or ""
    except (IndexError, KeyError):
        out["event_uuid"] = ""
    return out


_EVENT_COLS = (
    "ts, severity, category, action, username, remote_addr, details, "
    "event_uuid, source_type, source_name, src_ip, src_port, dst_ip, dst_port, "
    "protocol, interface, direction, hostname, mac, domain, url, "
    "rule_id, rule_name, policy_id, policy_name, "
    "mitre_tactic, mitre_technique, soc_origin, raw"
)

# Legacy 7-column shape, used as a fallback when log_event() runs against a
# DB whose `events` table has not yet been migrated to v34. The mirror write
# then loses the normalized columns but the audit.log file still has the full
# detail, so dashboards keep working.
_EVENT_LEGACY_COLS = (
    "ts, severity, category, action, username, remote_addr, details"
)

# Subset selected by readers that only care about the legacy NDJSON shape.
# Keeping this distinct from _EVENT_COLS lets us add more normalized columns
# later without touching every reader.
_EVENT_READ_COLS = (
    "ts, severity, category, action, username, remote_addr, details, event_uuid"
)


def _events_columns(conn) -> set:
    """Return the set of column names currently on the `events` table.

    Used by log_event() to choose between the modern 28-column INSERT and
    the legacy 7-column INSERT during the brief window where a pre-v34 DB
    has not yet been upgraded. Returns an empty set on any error so the
    caller falls through to its own swallow-everything handler.
    """
    try:
        return {str(r[1]) for r in conn.execute("PRAGMA table_info(events)").fetchall()}
    except Exception:
        return set()


# Module-level guard so a sustained DB-mirror failure logs a single warning
# instead of one traceback per audit event. The full traceback is kept on
# the first hit; subsequent failures within the same process are silent.
_DB_MIRROR_WARNED = False


def _truncate_raw(value, limit: int = 4096):
    """Cap the ``raw`` column so a single 1 MB syslog line cannot bloat the DB."""
    if value is None:
        return None
    text = value if isinstance(value, str) else str(value)
    if len(text) <= limit:
        return text
    return text[:limit]


def _int_or_none(value):
    """Coerce a JSON-ish port/number value into INTEGER or NULL."""
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _extract_normalized_fields(category: str, action: str, details: dict) -> dict:
    """Lift commonly-queried fields out of the ``details`` JSON blob so the
    `events` table can be filtered on indexed columns instead of LIKE-scans.

    Pure function: never raises, never mutates ``details``.  Unknown fields are
    returned as None so the SQL bind list stays a fixed shape.
    """
    d = details if isinstance(details, dict) else {}

    def pick(*keys):
        for k in keys:
            v = d.get(k)
            if v not in (None, ""):
                return v
        return None

    return {
        "source_type":     pick("source_type", "collector"),
        "source_name":     pick("source_name"),
        "src_ip":          pick("src_ip", "source_ip", "client_ip"),
        "src_port":        _int_or_none(pick("src_port", "source_port")),
        "dst_ip":          pick("dst_ip", "dest_ip", "destination_ip"),
        "dst_port":        _int_or_none(pick("dst_port", "dest_port",
                                             "destination_port")),
        "protocol":        pick("protocol", "proto"),
        "interface":       pick("interface", "iface"),
        "direction":       pick("direction"),
        "hostname":        pick("hostname", "host"),
        "mac":             pick("mac", "mac_address"),
        "domain":          pick("domain", "query"),
        "url":             pick("url"),
        "rule_id":         pick("rule_id"),
        "rule_name":       pick("rule_name", "rule_label"),
        "policy_id":       pick("policy_id"),
        "policy_name":     pick("policy_name"),
        "mitre_tactic":    pick("mitre_tactic"),
        "mitre_technique": pick("mitre_technique"),
        "soc_origin":      1 if d.get("soc_origin") else 0,
        "raw":             _truncate_raw(pick("raw", "raw_line")),
    }


def log_event(category: str, action: str, username=None, remote_addr=None,
              details=None, severity: str = "info"):
    """
    Append one audit event to the audit.log file AND mirror it into the
    indexed `events` table.  Never raises.

    Returns the event's ``event_uuid`` so callers that need to correlate
    (alert lifecycle, case event links, correlation engine output) can join
    by uuid instead of timestamp.  Returns "" if the row write was skipped
    because the DB was unavailable.
    """
    ts = datetime.now(timezone.utc).isoformat()
    event_uuid = uuid.uuid4().hex
    safe_details = details or {}
    # Inline TI enrichment — annotates events whose IP fields match the
    # ThreatFox cache. Pure function, swallow any failure so an enrichment
    # bug can never block the audit-log write.
    try:
        from app.services.ti_enrichment import enrich_details
        safe_details = enrich_details(safe_details)
    except Exception:
        # Enrichment is best-effort, but logging the miss lets ops trace why
        # the ThreatFox/abuse.ch tags disappeared from events (Fv11 §P1-07).
        logger.debug("ti_enrichment failed for audit event", exc_info=True)
    # Asset/identity catalog enrichment — annotates events whose src_ip /
    # username match an inventory entry. Same swallow-everything contract.
    try:
        from app.services.inventory import annotate_details
        # Pick the most specific IP field present, falling back to the
        # request's remote_addr when none is in the details payload.
        ip_field = None
        for f in ("src_ip", "source_ip", "remote_addr", "dest_ip", "dst_ip"):
            if (safe_details or {}).get(f):
                ip_field = f
                break
        if ip_field is None and remote_addr:
            safe_details = dict(safe_details)
            safe_details["remote_addr"] = remote_addr
            ip_field = "remote_addr"
        annotate_details(safe_details, ip_field=ip_field, username=username or "")
    except Exception:
        logger.debug("inventory annotate_details failed", exc_info=True)

    # Lift normalized fields out of details so the events table can be
    # filtered/sorted on indexed columns. Done AFTER enrichment so any
    # IP/hostname/MAC added by enrichment is captured too.
    norm = _extract_normalized_fields(category, action, safe_details)

    entry = {
        "timestamp":   ts,
        "event_uuid":  event_uuid,
        "severity":    severity,
        "category":    category,
        "action":      action,
        "username":    username or "anonymous",
        "remote_addr": remote_addr or "",
        "details":     safe_details,
    }

    file_ok = True
    try:
        path = _audit_log_path()
        _ensure_parent_dir(path)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=True) + "\n")
    except OSError:
        file_ok = False

    # Mirror into the indexed event store (best-effort — the file write above
    # is the durability guarantee, so a DB failure here is swallowed).
    conn = _events_db()
    if conn is not None:
        try:
            cols = _events_columns(conn)
            if "event_uuid" in cols:
                conn.execute(
                    f"INSERT INTO events ({_EVENT_COLS}) VALUES ("
                    "?,?,?,?,?,?,?,"          # ts, severity, category, action,
                                              # username, remote_addr, details
                    "?,?,?,?,?,?,?,"          # event_uuid, source_type,
                                              # source_name, src_ip, src_port,
                                              # dst_ip, dst_port
                    "?,?,?,?,?,?,?,"          # protocol, interface, direction,
                                              # hostname, mac, domain, url
                    "?,?,?,?,?,?,?,?)",       # rule_id, rule_name, policy_id,
                                              # policy_name, mitre_tactic,
                                              # mitre_technique, soc_origin, raw
                    (
                        ts, severity, category, action, entry["username"],
                        entry["remote_addr"],
                        json.dumps(entry["details"], ensure_ascii=True),
                        event_uuid,
                        norm["source_type"], norm["source_name"],
                        norm["src_ip"], norm["src_port"],
                        norm["dst_ip"], norm["dst_port"],
                        norm["protocol"], norm["interface"], norm["direction"],
                        norm["hostname"], norm["mac"],
                        norm["domain"], norm["url"],
                        norm["rule_id"], norm["rule_name"],
                        norm["policy_id"], norm["policy_name"],
                        norm["mitre_tactic"], norm["mitre_technique"],
                        norm["soc_origin"], norm["raw"],
                    ),
                )
            else:
                # Pre-v34 DB — fall back to the legacy 7-column INSERT so the
                # mirror still works during the brief window before migration
                # v34 ALTER TABLEs the new columns in. Normalized fields are
                # dropped here; the audit.log file above retains them.
                conn.execute(
                    f"INSERT INTO events ({_EVENT_LEGACY_COLS}) VALUES "
                    "(?,?,?,?,?,?,?)",
                    (
                        ts, severity, category, action, entry["username"],
                        entry["remote_addr"],
                        json.dumps(entry["details"], ensure_ascii=True),
                    ),
                )
            conn.commit()
        except Exception:
            # The JSONL file write above is the durability guarantee; the
            # indexed-DB mirror is a query convenience. Log the first miss
            # at WARNING with traceback (Fv11 §P1-07), then stay quiet for
            # the rest of the process so repeated failures don't drown the
            # log during release_check.py / runtime_preflight.py.
            global _DB_MIRROR_WARNED
            if not _DB_MIRROR_WARNED:
                logger.warning("events DB mirror insert failed", exc_info=True)
                _DB_MIRROR_WARNED = True
            else:
                logger.debug("events DB mirror insert failed", exc_info=True)
        finally:
            try:
                conn.close()
            except Exception:
                logger.debug("events DB close failed", exc_info=True)

    # Trigger any matching playbooks. The dispatcher has a re-entry guard so
    # a playbook's own emitted events cannot recursively re-fire it.
    try:
        from app.services.playbooks import on_event
        on_event(entry)
    except Exception:
        logger.warning("playbook dispatch failed for event", exc_info=True)

    # Outbound mail-alert hook. notify_event applies the severity/category
    # filter, cooldown, and hourly cap, and ignores its own category="mail"
    # events so it cannot recursively re-fire. Best-effort — a mail failure
    # never affects the audit write.
    try:
        from app.services.mail_alerts import notify_event
        notify_event(entry)
    except Exception:
        logger.warning("mail_alerts notify_event failed", exc_info=True)
    return event_uuid if file_ok else ""


def log_soc_event(category: str, action: str, username=None, remote_addr=None,
                  details=None, severity: str = "info"):
    """
    Log a SOC-portal-originated audit event.

    Identical to :func:`log_event` but stamps ``details.soc_origin = True`` so
    firewall-facing log views (which pass ``hide_soc=1``) and the firewall
    dashboard can exclude SOC team activity. SOC investigation work therefore
    stays out of the SmartShield Core firewall log while still sharing the one
    indexed event store.
    """
    soc_details = dict(details or {})
    soc_details["soc_origin"] = True
    return log_event(category=category, action=action, username=username,
                     remote_addr=remote_addr, details=soc_details,
                     severity=severity)


def tail_events(limit=200, category=None):
    """Return the most-recent `limit` events, newest first."""
    conn = _events_db()
    if conn is None:
        return []
    try:
        sql = f"SELECT {_EVENT_COLS} FROM events"
        params = []
        if category:
            sql += " WHERE category = ?"
            params.append(category)
        sql += " ORDER BY id DESC"
        if limit and limit > 0:
            sql += " LIMIT ?"
            params.append(limit)
        rows = conn.execute(sql, params).fetchall()
        return [_row_to_event(r) for r in rows]
    except Exception:
        return []
    finally:
        conn.close()


def tail_events_since(after_ts: str = "", limit: int = 200,
                      categories=None, severities=None,
                      start_ts: str = "", end_ts: str = "") -> list:
    """
    Return events whose timestamp is strictly greater than `after_ts`.
    Results are ordered newest-first.  Pass after_ts="" to get the most
    recent `limit` events across all time.

    Optional filters:
      categories  — list of category strings to include
      severities  — list of severity strings to include ("critical","high",...)
      start_ts    — ISO-8601 lower bound (inclusive)
      end_ts      — ISO-8601 upper bound (inclusive)
    """
    conn = _events_db()
    if conn is None:
        return []
    try:
        sql = f"SELECT {_EVENT_COLS} FROM events WHERE 1=1"
        params = []
        if after_ts:
            sql += " AND ts > ?"
            params.append(after_ts)
        if start_ts:
            sql += " AND ts >= ?"
            params.append(start_ts)
        if end_ts:
            sql += " AND ts <= ?"
            params.append(end_ts)
        if categories:
            cats = list(categories)
            sql += " AND category IN (%s)" % ",".join("?" * len(cats))
            params += cats
        if severities:
            sevs = list(severities)
            sql += " AND severity IN (%s)" % ",".join("?" * len(sevs))
            params += sevs
        sql += " ORDER BY id DESC"
        if limit and limit > 0:
            sql += " LIMIT ?"
            params.append(limit)
        rows = conn.execute(sql, params).fetchall()
        return [_row_to_event(r) for r in rows]
    except Exception:
        return []
    finally:
        conn.close()


def get_event_by_uuid(event_uuid: str = "", timestamp: str = ""):
    """Return a single audit-log event in the legacy NDJSON shape, or ``None``.

    Looks the event up by its stable ``event_uuid`` (preferred); falls back to
    an exact ``ts`` match for callers that only have the timestamp key (e.g. a
    pre-v34 alert). Used to snapshot the full source log onto a SOC case so the
    evidence survives audit-log retention eviction.
    """
    event_uuid = (event_uuid or "").strip()
    timestamp  = (timestamp or "").strip()
    if not (event_uuid or timestamp):
        return None
    conn = _events_db()
    if conn is None:
        return None
    try:
        if event_uuid:
            where, param = "event_uuid = ?", event_uuid
        else:
            where, param = "ts = ?", timestamp
        row = conn.execute(
            f"SELECT {_EVENT_READ_COLS} FROM events WHERE {where} "
            f"ORDER BY id DESC LIMIT 1",
            (param,),
        ).fetchone()
        return _row_to_event(row) if row else None
    except Exception:
        return None
    finally:
        conn.close()


def search_events_fts(query: str, limit: int = 200, categories=None,
                      severities=None, start_ts: str = "",
                      end_ts: str = "") -> list:
    """
    Full-text-index-backed search over events.{category,action,username,
    remote_addr,details}.

    Falls back to a LIKE-substring scan when the FTS5 virtual table isn't
    available (older sqlite, never-migrated DB). Result rows have the same
    legacy NDJSON shape as ``tail_events_since`` so callers can drop this
    in transparently.

    *query* uses FTS5 MATCH syntax. A plain term like ``alice`` searches
    the union of every column; ``details:alice`` restricts to one column;
    ``"alice bob"`` matches the phrase. Empty/None query returns [].
    """
    if not query or not query.strip():
        return []
    conn = _events_db()
    if conn is None:
        return []
    fts_available = False
    try:
        conn.execute("SELECT 1 FROM events_fts LIMIT 1").fetchone()
        fts_available = True
    except Exception:
        fts_available = False

    try:
        if fts_available:
            sql = (
                "SELECT e." + _EVENT_COLS + " FROM events e "
                "JOIN events_fts f ON f.rowid = e.id "
                "WHERE events_fts MATCH ?"
            )
            params: list = [query.strip()]
        else:
            like = f"%{query.strip()}%"
            sql = (
                f"SELECT {_EVENT_COLS} FROM events "
                "WHERE (category LIKE ? OR action LIKE ? OR username LIKE ? "
                "       OR remote_addr LIKE ? OR details LIKE ?)"
            )
            params = [like, like, like, like, like]
        if categories:
            cats = list(categories)
            sql += " AND e.category IN (%s)" % ",".join("?" * len(cats)) \
                   if fts_available else \
                   " AND category IN (%s)" % ",".join("?" * len(cats))
            params += cats
        if severities:
            sevs = list(severities)
            sql += " AND e.severity IN (%s)" % ",".join("?" * len(sevs)) \
                   if fts_available else \
                   " AND severity IN (%s)" % ",".join("?" * len(sevs))
            params += sevs
        if start_ts:
            sql += (" AND e.ts >= ?" if fts_available else " AND ts >= ?")
            params.append(start_ts)
        if end_ts:
            sql += (" AND e.ts <= ?" if fts_available else " AND ts <= ?")
            params.append(end_ts)
        sql += (" ORDER BY e.id DESC LIMIT ?" if fts_available
                else " ORDER BY id DESC LIMIT ?")
        params.append(int(limit) if limit and limit > 0 else 200)
        rows = conn.execute(sql, params).fetchall()
        return [_row_to_event(r) for r in rows]
    except Exception:
        return []
    finally:
        try:
            conn.close()
        except Exception:
            pass


def log_stats() -> dict:
    """
    Return per-category event counts for the entire event store.
    Also includes special keys: _total, _login_failed, _critical, _high.
    """
    conn = _events_db()
    stats: dict = {}
    if conn is None:
        return stats
    try:
        for row in conn.execute(
            "SELECT category, COUNT(*) AS c FROM events GROUP BY category"
        ):
            stats[row["category"] or "unknown"] = row["c"]
        stats["_total"] = conn.execute(
            "SELECT COUNT(*) AS c FROM events"
        ).fetchone()["c"]
        stats["_login_failed"] = conn.execute(
            "SELECT COUNT(*) AS c FROM events WHERE action = 'login_failed'"
        ).fetchone()["c"]
        stats["_critical"] = conn.execute(
            "SELECT COUNT(*) AS c FROM events WHERE severity = 'critical'"
        ).fetchone()["c"]
        stats["_high"] = conn.execute(
            "SELECT COUNT(*) AS c FROM events WHERE severity = 'high'"
        ).fetchone()["c"]
    except Exception:
        pass
    finally:
        conn.close()
    return stats


def events_timeseries(bucket: str = "hour", categories=None, severities=None,
                      start_ts: str = "", end_ts: str = "",
                      limit_buckets: int = 168) -> dict:
    """
    Return event counts grouped by time bucket and severity, for charting.

    bucket: "hour" or "day".
    Returns {"buckets": ["2026-05-18T12:00", ...],
             "series": {"info": [counts...], "high": [...], ...}}.
    """
    empty = {"buckets": [], "series": {}}
    conn = _events_db()
    if conn is None:
        return empty
    fmt = "%Y-%m-%dT%H:00" if bucket != "day" else "%Y-%m-%d"
    try:
        sql = "SELECT strftime(?, ts) AS b, severity, COUNT(*) AS c FROM events WHERE 1=1"
        params = [fmt]
        if start_ts:
            sql += " AND ts >= ?"
            params.append(start_ts)
        if end_ts:
            sql += " AND ts <= ?"
            params.append(end_ts)
        if categories:
            cats = list(categories)
            sql += " AND category IN (%s)" % ",".join("?" * len(cats))
            params += cats
        if severities:
            sevs = list(severities)
            sql += " AND severity IN (%s)" % ",".join("?" * len(sevs))
            params += sevs
        sql += " GROUP BY b, severity ORDER BY b"
        rows = conn.execute(sql, params).fetchall()
    except Exception:
        return empty
    finally:
        conn.close()

    buckets: list = []
    counts: dict = {}
    sevs: set = set()
    for r in rows:
        b = r["b"]
        if not b:
            continue
        if b not in buckets:
            buckets.append(b)
        sev = r["severity"] or "info"
        sevs.add(sev)
        counts[(b, sev)] = r["c"]

    if limit_buckets and len(buckets) > limit_buckets:
        buckets = buckets[-limit_buckets:]

    series = {sev: [counts.get((b, sev), 0) for b in buckets]
              for sev in sorted(sevs)}
    return {"buckets": buckets, "series": series}
