"""
correlation_engine.py
----------------------
A small, user-configurable rule engine that turns volumetric patterns in the
event store into security events.

Rules live in the `correlation_rules` table.  Each rule counts events that
match a category/action filter within a sliding time window, grouped by a
field; when a group's count crosses the rule's threshold, a
`correlation_match` security event is emitted — tagged with the rule's MITRE
ATT&CK technique.

Optional rule fields (v26):
  * prerequisite_action — when set, only count events whose group_value has
    also seen this preceding action in the same window. Lets analysts write
    chained detections like "successful_login after login_failed from same
    IP" without inventing a whole new rule type.
  * auto_case — when 1, also open a row in `siem_cases` tied to the firing
    event so the SOC team gets an investigation queue automatically.

This replaces the two formerly hard-coded detectors (brute-force login,
IDS-alert flood), which are seeded as the default rules by migration v23.
The siem-anomaly collector thread calls evaluate() every 60 s.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

# (rule_id, group_value) -> last-fired epoch.  Suppresses duplicate matches.
_FIRED: dict = {}
_COOLDOWN = 600          # seconds — do not re-fire the same match within 10 min


def _enabled_rules(conn) -> list:
    try:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM correlation_rules WHERE enabled = 1"
        )]
    except Exception:
        return []


def _group_value(event: dict, group_by: str) -> str:
    """Resolve a rule's group-by key against an event (supports details.*)."""
    if not group_by:
        return "*"
    if group_by.startswith("details."):
        return str((event.get("details") or {}).get(group_by[8:], "") or "")
    return str(event.get(group_by, "") or "")


def _filter_events(events: list, rule: dict) -> tuple:
    """
    Return (counts, prerequisite_groups) for *events* under *rule*.

    counts                — {group_value: int} of matches to action_filter
    prerequisite_groups   — set of group_values that have seen
                            rule['prerequisite_action'] in the window
                            (empty set when prerequisite_action is unset)
    """
    group_by = rule.get("group_by") or ""
    acts = {a.strip() for a in (rule.get("action_filter") or "").split(",")
            if a.strip()}
    prereq = (rule.get("prerequisite_action") or "").strip()

    counts: dict = {}
    prereq_groups: set = set()

    for e in events:
        action = e.get("action") or ""
        if action == "correlation_match":
            continue                           # never correlate on our own output
        gv = _group_value(e, group_by)

        if prereq and action == prereq:
            prereq_groups.add(gv)

        if acts and action not in acts:
            continue
        if not acts and prereq and action == prereq:
            # When the rule has no positive action_filter, prerequisite-only
            # events should not double-count as the matched action.
            continue
        counts[gv] = counts.get(gv, 0) + 1

    return counts, prereq_groups


def _maybe_open_case(conn, rule: dict, group_value: str, count: int,
                     fired_ts: str) -> None:
    """When the rule has auto_case=1, open a siem_cases row for SOC triage."""
    if not rule.get("auto_case"):
        return
    title = f"[Auto] {rule.get('name') or 'Correlation match'}"
    if group_value and group_value != "*":
        title += f" — {group_value}"
    description = (
        f"Correlation rule '{rule.get('name')}' fired automatically.\n"
        f"group_by={rule.get('group_by') or '*'}; group_value={group_value};\n"
        f"matches={count} within {rule.get('window_seconds') or 300}s;\n"
        f"MITRE technique: {rule.get('mitre_technique') or '-'}\n\n"
        f"Investigate the events near {fired_ts} for this group and decide "
        f"whether to escalate or mark as a false positive."
    )
    try:
        cur = conn.execute(
            "INSERT INTO siem_cases (title, description, severity, status, "
            "created_by, source_event, tags) VALUES (?,?,?,?,?,?,?)",
            (
                title,
                description,
                (rule.get("severity") or "high").lower(),
                "open",
                "correlation_engine",
                fired_ts,
                f"auto,correlation,rule:{rule.get('id')}",
            ),
        )
        case_id = cur.lastrowid
        conn.execute(
            "INSERT INTO siem_case_events (case_id, event_timestamp, event_action, "
            "event_category, event_summary) VALUES (?,?,?,?,?)",
            (case_id, fired_ts, "correlation_match", "security",
             f"{rule.get('name')} fired for {group_value} ({count} matches)"),
        )
        conn.commit()
    except Exception:
        pass


def evaluate() -> int:
    """
    Evaluate every enabled correlation rule once.
    Returns the number of `correlation_match` events fired.
    """
    from app.audit_log import _events_db, tail_events_since, log_event

    conn = _events_db()
    if conn is None:
        return 0
    try:
        rules = _enabled_rules(conn)
    except Exception:
        rules = []

    if not rules:
        try:
            conn.close()
        except Exception:
            pass
        return 0

    now   = time.time()
    fired = 0
    try:
        for rule in rules:
            try:
                window    = int(rule.get("window_seconds") or 300)
                threshold = int(rule.get("threshold") or 5)
                start_ts  = (datetime.now(timezone.utc)
                             - timedelta(seconds=window)).isoformat()
                cats = [c.strip() for c in (rule.get("category_filter") or "").split(",")
                        if c.strip()]
                # When the rule has a prerequisite action we may need it from a
                # different category than the trigger — pull events from all
                # categories the rule cares about.
                if (rule.get("prerequisite_action") or "").strip():
                    cats = cats or None

                events = tail_events_since(start_ts=start_ts, limit=5000,
                                           categories=cats or None)
                counts, prereq_groups = _filter_events(events, rule)

                prereq = (rule.get("prerequisite_action") or "").strip()
                for gv, count in counts.items():
                    if count < threshold:
                        continue
                    if prereq and gv not in prereq_groups:
                        continue
                    key = (rule["id"], gv)
                    if now - _FIRED.get(key, 0) < _COOLDOWN:
                        continue
                    _FIRED[key] = now
                    fired_ts = datetime.now(timezone.utc).isoformat()
                    event_uuid = log_event(
                        category="security",
                        action="correlation_match",
                        username="siem",
                        remote_addr=gv if rule.get("group_by") == "remote_addr" else "",
                        severity=rule.get("severity") or "high",
                        details={
                            "rule":               rule.get("name"),
                            "rule_id":            rule["id"],
                            "mitre_technique":    rule.get("mitre_technique") or "",
                            "group_by":           rule.get("group_by") or "",
                            "group_value":        gv,
                            "count":              count,
                            "threshold":          threshold,
                            "window_seconds":     window,
                            "prerequisite_action": prereq or None,
                            "auto_case":          bool(rule.get("auto_case")),
                        },
                    ) or ""
                    _maybe_open_case(conn, rule, gv, count, fired_ts)

                    # Create / update the persistent SOC alert. Detectors
                    # used to drive the SOC queue by re-deriving alerts
                    # from raw events; now every correlation match is a
                    # first-class deduplicated alert.
                    try:
                        from app.services.alert_service import create_or_update_alert
                        gb = (rule.get("group_by") or "").lower()
                        src_ip   = gv if (gb == "remote_addr" or
                                          gb.endswith(("ip", "src_ip"))) else ""
                        username = gv if gb in ("username", "user")    else ""
                        create_or_update_alert(
                            conn,
                            dedup_key=f"corr:{rule['id']}:{gv}",
                            title=rule.get("name") or "Correlation match",
                            severity=rule.get("severity") or "high",
                            category="security",
                            alert_type="correlation_match",
                            description=(
                                f"{rule.get('name')} fired for "
                                f"{gv} ({count} matches in "
                                f"{window}s)"
                            ),
                            source_event_uuid=event_uuid,
                            src_ip=src_ip,
                            username=username,
                            rule_id=str(rule.get("id") or ""),
                            rule_name=rule.get("name") or "",
                            mitre_technique=rule.get("mitre_technique") or "",
                            risk_score=float(count or 0),
                            details={
                                "group_by":    rule.get("group_by") or "",
                                "group_value": gv,
                                "count":       count,
                                "threshold":   threshold,
                                "window_seconds": window,
                            },
                        )
                        conn.commit()
                    except Exception:
                        pass
                    # Risk-based alerting: bump the score for whichever
                    # entity the rule groups by, so repeated low-grade
                    # detections roll up into a top-risky entity.
                    try:
                        from app.services.risk_scoring import bump as _bump_risk
                        gb = (rule.get("group_by") or "").lower()
                        if gb == "remote_addr" or gb.endswith(("ip", "src_ip", "dest_ip")):
                            _bump_risk("ip", gv, rule.get("severity") or "high",
                                       reason=rule.get("name") or "")
                        elif gb in ("username", "user"):
                            _bump_risk("username", gv,
                                       rule.get("severity") or "high",
                                       reason=rule.get("name") or "")
                    except Exception:
                        pass
                    fired += 1
            except Exception:
                continue
    finally:
        try:
            conn.close()
        except Exception:
            pass

    # Bound the cooldown map.
    if len(_FIRED) > 5000:
        for k, t in list(_FIRED.items()):
            if now - t > _COOLDOWN:
                _FIRED.pop(k, None)
    return fired


# ---------------------------------------------------------------------------
# Simulator — backtest a (saved or draft) rule without firing events.
# ---------------------------------------------------------------------------

def simulate(rule: dict, hours: int = 24, sample_limit: int = 20) -> dict:
    """
    Run *rule* against historical events without writing anything.

    rule is a dict with the same keys as a row in `correlation_rules`
    (category_filter, action_filter, group_by, threshold, window_seconds,
    severity, mitre_technique, prerequisite_action, auto_case). Anything
    missing falls back to safe defaults.

    Returns:
        {
          "ok":           True,
          "evaluated":    int,   # how many candidate events were scanned
          "would_fire":   int,   # group-windows that would cross the threshold
          "matches":      [      # up to `sample_limit` example fired groups
              {"group_value": str, "count": int, "first_ts": str,
               "last_ts": str, "would_open_case": bool},
              ...
          ],
          "rule_summary": {...}  # echo of normalized rule
        }
    """
    from app.audit_log import tail_events_since

    try:
        hours    = max(1, min(int(hours or 24), 720))   # cap at 30 days
    except (TypeError, ValueError):
        hours    = 24
    try:
        window    = int(rule.get("window_seconds") or 300)
        threshold = int(rule.get("threshold") or 5)
    except (TypeError, ValueError):
        window, threshold = 300, 5

    cats = [c.strip() for c in (rule.get("category_filter") or "").split(",")
            if c.strip()]
    start_ts = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

    events = tail_events_since(start_ts=start_ts, limit=20000,
                               categories=cats or None)

    # Bucket by floor(ts / window) so we evaluate non-overlapping windows.
    # This is an approximation of the sliding-window engine, fast enough for
    # the dry-run preview.
    group_by = rule.get("group_by") or ""
    acts = {a.strip() for a in (rule.get("action_filter") or "").split(",")
            if a.strip()}
    prereq = (rule.get("prerequisite_action") or "").strip()

    buckets: dict = {}     # (bucket, group_value) -> [count, first_ts, last_ts]
    # Prereq is tracked per-group across the whole scan window — the live
    # engine looks only inside one window, so this is slightly more permissive
    # by design (a backtest is an upper bound on what would have fired).
    prereq_groups: set = set()

    for e in events:
        ts_raw = e.get("timestamp") or ""
        try:
            ts = datetime.fromisoformat(ts_raw).timestamp()
        except (TypeError, ValueError):
            continue
        bucket = int(ts) // max(window, 1)
        gv     = _group_value(e, group_by)
        action = e.get("action") or ""
        if action == "correlation_match":
            continue
        if prereq and action == prereq:
            prereq_groups.add(gv)
        if acts and action not in acts:
            continue
        if not acts and prereq and action == prereq:
            continue
        key = (bucket, gv)
        if key not in buckets:
            buckets[key] = [0, ts_raw, ts_raw]
        buckets[key][0] += 1
        if ts_raw < buckets[key][1]:
            buckets[key][1] = ts_raw
        if ts_raw > buckets[key][2]:
            buckets[key][2] = ts_raw

    matches: list = []
    for (bucket, gv), (count, first_ts, last_ts) in buckets.items():
        if count < threshold:
            continue
        if prereq and gv not in prereq_groups:
            continue
        matches.append({
            "group_value":     gv,
            "count":           count,
            "first_ts":        first_ts,
            "last_ts":         last_ts,
            "would_open_case": bool(rule.get("auto_case")),
        })
    matches.sort(key=lambda m: m["count"], reverse=True)

    return {
        "ok":         True,
        "evaluated":  len(events),
        "would_fire": len(matches),
        "matches":    matches[:max(0, int(sample_limit or 20))],
        "rule_summary": {
            "category_filter":     ",".join(cats) if cats else "",
            "action_filter":       ",".join(sorted(acts)) if acts else "",
            "group_by":            group_by,
            "threshold":           threshold,
            "window_seconds":      window,
            "severity":            (rule.get("severity") or "high"),
            "mitre_technique":     rule.get("mitre_technique") or "",
            "prerequisite_action": prereq,
            "auto_case":           bool(rule.get("auto_case")),
            "scan_hours":          hours,
        },
    }
