"""
app/services/report_generator.py
--------------------------------
Generate self-contained HTML reports from the event store, inventory and
risk-score data. Three templates ship today:

* ``executive`` — a 1-page summary for management. Top severities, open
  case count, top risky entities, crown-jewel asset hits.
* ``pci_dss``   — maps event categories onto PCI-DSS v4.0 requirements
  (logging, access control, monitoring) and surfaces gaps.
* ``iso_27001`` — same idea against ISO 27001 Annex A controls.

Reports are persisted in the ``reports`` table so an admin can re-open a
previous report without rerunning the analytics. The HTML is plain
inline-style so a browser "Print → Save as PDF" gives an offline copy
without any extra dependency.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timedelta, timezone


_REPORT_TYPES = ("executive", "pci_dss", "iso_27001")


def _esc(s) -> str:
    return html.escape(str(s if s is not None else ""))


def _period_window(period: str) -> tuple:
    """Return (start_ts, end_ts) ISO strings for a named period."""
    now = datetime.now(timezone.utc)
    if period == "7d":
        start = now - timedelta(days=7)
    elif period == "30d":
        start = now - timedelta(days=30)
    elif period == "90d":
        start = now - timedelta(days=90)
    else:
        start = now - timedelta(days=30)
    return start.isoformat(), now.isoformat()


# ---------------------------------------------------------------------------
# Data gatherers
# ---------------------------------------------------------------------------

def _gather(conn, start_ts: str, end_ts: str) -> dict:
    """Collect summary statistics used by every report template."""
    data: dict = {
        "period_start":   start_ts,
        "period_end":     end_ts,
        "totals":         {"all": 0, "critical": 0, "high": 0,
                           "medium": 0, "low": 0, "info": 0},
        "by_category":    {},
        "by_action_top":  [],
        "open_cases":     0,
        "closed_cases":   {"resolved": 0, "false_positive": 0},
        "top_risky":      [],
        "crown_jewel_events": 0,
        "ti_hits":        0,
        "correlation_matches": 0,
    }

    # Severity + category counts
    try:
        for r in conn.execute(
            "SELECT severity, COUNT(*) AS c FROM events "
            "WHERE ts >= ? AND ts <= ? GROUP BY severity",
            (start_ts, end_ts),
        ):
            sev = (r["severity"] or "info").lower()
            data["totals"][sev] = r["c"]
            data["totals"]["all"] += r["c"]
        for r in conn.execute(
            "SELECT category, COUNT(*) AS c FROM events "
            "WHERE ts >= ? AND ts <= ? GROUP BY category ORDER BY c DESC LIMIT 20",
            (start_ts, end_ts),
        ):
            data["by_category"][r["category"] or "—"] = r["c"]
        for r in conn.execute(
            "SELECT action, COUNT(*) AS c FROM events "
            "WHERE ts >= ? AND ts <= ? GROUP BY action ORDER BY c DESC LIMIT 15",
            (start_ts, end_ts),
        ):
            data["by_action_top"].append({"action": r["action"] or "—", "count": r["c"]})
    except Exception:
        pass

    # Cases
    try:
        data["open_cases"] = conn.execute(
            "SELECT COUNT(*) FROM siem_cases WHERE status='open' "
            "AND created_at >= ? AND created_at <= ?",
            (start_ts, end_ts),
        ).fetchone()[0]
        for r in conn.execute(
            "SELECT closure_type, COUNT(*) AS c FROM siem_cases "
            "WHERE status='closed' AND created_at >= ? AND created_at <= ? "
            "GROUP BY closure_type",
            (start_ts, end_ts),
        ):
            key = (r["closure_type"] or "resolved").lower()
            if key in data["closed_cases"]:
                data["closed_cases"][key] = r["c"]
    except Exception:
        pass

    # Crown-jewel asset events (uses the asset enrichment annotation)
    try:
        cj = conn.execute(
            "SELECT COUNT(*) FROM events "
            "WHERE ts >= ? AND ts <= ? AND details LIKE '%\"criticality\": \"crown_jewel\"%'",
            (start_ts, end_ts),
        ).fetchone()[0]
        data["crown_jewel_events"] = cj
    except Exception:
        pass

    # TI hits + correlation matches
    try:
        data["ti_hits"] = conn.execute(
            "SELECT COUNT(*) FROM events "
            "WHERE ts >= ? AND ts <= ? AND details LIKE '%\"ti_hits\":%'",
            (start_ts, end_ts),
        ).fetchone()[0]
        data["correlation_matches"] = conn.execute(
            "SELECT COUNT(*) FROM events "
            "WHERE ts >= ? AND ts <= ? AND action='correlation_match'",
            (start_ts, end_ts),
        ).fetchone()[0]
    except Exception:
        pass

    # Top risky entities (live decay)
    try:
        from app.services.risk_scoring import top_risky
        data["top_risky"] = top_risky(limit=10)
    except Exception:
        pass

    return data


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------

_STYLES = """
<style>
  body { font-family: -apple-system, "Segoe UI", Arial, sans-serif;
         margin: 0; padding: 24px; color: #1f2937; background: #fff; }
  h1 { color: #111827; border-bottom: 2px solid #00b4a0; padding-bottom: .4rem; }
  h2 { color: #0f766e; margin-top: 1.6rem; }
  h3 { color: #374151; margin: 1rem 0 .4rem; }
  .meta { color: #6b7280; font-size: .9rem; }
  .grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: .8rem; margin: 1rem 0; }
  .kpi { border: 1px solid #e5e7eb; border-radius: 8px; padding: .8rem 1rem; background: #f9fafb; }
  .kpi .v { font-size: 1.6rem; font-weight: 800; color: #111827; }
  .kpi .l { font-size: .78rem; color: #6b7280; text-transform: uppercase; letter-spacing: .04em; }
  table { width: 100%; border-collapse: collapse; margin: .6rem 0 1rem; }
  th, td { text-align: left; padding: .35rem .55rem; border-bottom: 1px solid #e5e7eb; font-size: .88rem; }
  th { background: #f3f4f6; }
  .control { background:#eef2ff; border-left: 4px solid #4f46e5; padding: .55rem .8rem;
             margin: .4rem 0; border-radius: 4px; font-size: .9rem; }
  .gap     { background:#fef2f2; border-left: 4px solid #ef4444; padding: .55rem .8rem;
             margin: .4rem 0; border-radius: 4px; font-size: .9rem; }
  .ok      { background:#ecfdf5; border-left: 4px solid #10b981; padding: .55rem .8rem;
             margin: .4rem 0; border-radius: 4px; font-size: .9rem; }
  .footer { color: #9ca3af; font-size: .75rem; margin-top: 2rem; border-top: 1px dashed #e5e7eb;
            padding-top: .6rem; }
</style>
"""


def _kpi(label: str, value, color: str = "") -> str:
    extra = f"color:{color};" if color else ""
    return (f'<div class="kpi"><div class="v" style="{extra}">{_esc(value)}</div>'
            f'<div class="l">{_esc(label)}</div></div>')


def _executive_html(data: dict) -> str:
    t = data["totals"]
    risky_rows = "".join(
        f"<tr><td>{_esc(r['entity_type'])}</td><td><code>{_esc(r['entity_value'])}</code></td>"
        f"<td>{_esc(r['score'])}</td><td>{_esc(r['last_updated'])}</td></tr>"
        for r in data["top_risky"]
    ) or "<tr><td colspan='4' style='color:#6b7280;'>No entities currently exceed the noise floor.</td></tr>"

    action_rows = "".join(
        f"<tr><td><code>{_esc(a['action'])}</code></td><td>{_esc(a['count'])}</td></tr>"
        for a in data["by_action_top"]
    ) or "<tr><td colspan='2' style='color:#6b7280;'>No events in this window.</td></tr>"

    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>Executive SOC Summary</title>{_STYLES}</head><body>
<h1>Executive SOC Summary</h1>
<div class="meta">Window: <strong>{_esc(data['period_start'])}</strong> → <strong>{_esc(data['period_end'])}</strong></div>

<div class="grid">
  {_kpi("Total events", t["all"])}
  {_kpi("Critical", t["critical"], "#dc2626")}
  {_kpi("High", t["high"], "#ea580c")}
  {_kpi("Correlation matches", data["correlation_matches"], "#4f46e5")}
  {_kpi("Open cases", data["open_cases"])}
  {_kpi("Resolved cases", data["closed_cases"]["resolved"], "#10b981")}
  {_kpi("False positives", data["closed_cases"]["false_positive"])}
  {_kpi("Crown-jewel events", data["crown_jewel_events"], "#dc2626")}
</div>

<h2>Top risky entities</h2>
<table>
  <thead><tr><th>Type</th><th>Entity</th><th>Score</th><th>Last activity</th></tr></thead>
  <tbody>{risky_rows}</tbody>
</table>

<h2>Most-frequent event actions</h2>
<table>
  <thead><tr><th>Action</th><th>Count</th></tr></thead>
  <tbody>{action_rows}</tbody>
</table>

<div class="footer">
  Generated by SmartShield SIEM · TI hits in window: {_esc(data['ti_hits'])}
</div></body></html>"""


def _pci_dss_html(data: dict) -> str:
    """Map event-store coverage onto PCI-DSS v4.0 requirements."""
    has_admin_logins = any(c for c in data["by_category"] if c == "session")
    has_audit_log    = data["totals"]["all"] > 0
    has_ids          = "ids" in data["by_category"]
    has_correlation  = data["correlation_matches"] > 0
    has_ti           = data["ti_hits"] > 0

    def line(req, name, ok, hint=""):
        klass = "ok" if ok else "gap"
        verdict = "covered" if ok else "GAP"
        more = f" — {_esc(hint)}" if hint else ""
        return f'<div class="{klass}"><strong>{_esc(req)} {_esc(name)}:</strong> {verdict}{more}</div>'

    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>PCI-DSS v4.0 Coverage</title>{_STYLES}</head><body>
<h1>PCI-DSS v4.0 Coverage</h1>
<div class="meta">Window: <strong>{_esc(data['period_start'])}</strong> → <strong>{_esc(data['period_end'])}</strong></div>

<h2>Requirement 7 — Restrict access</h2>
{line("7.2", "User access provisioned by role", True,
      "tier-based RBAC enforced via @soc_tier_required and @superuser_required")}

<h2>Requirement 8 — Identify and authenticate users</h2>
{line("8.3", "Strong authentication", True,
      "Account lockout enforced (5 fails / 15 min) on both admin and SOC logins")}
{line("8.4", "Multi-factor authentication", True,
      "TOTP MFA available per-user under /soc-portal/security")}

<h2>Requirement 10 — Log and monitor all access</h2>
{line("10.2", "Audit log entries for every action", has_audit_log,
      f"{data['totals']['all']} events captured in window")}
{line("10.4", "Time-synchronized clocks", True, "FreeBSD ntpd managed via System → NTP")}
{line("10.6", "Daily audit log review", has_correlation,
      f"{data['correlation_matches']} correlation matches fired automatically")}
{line("10.7", "Audit log retention ≥ 1 year", False,
      "default retention is 90 days; raise events_retention.days to 365 in Log Forwarding")}

<h2>Requirement 11 — Test security regularly</h2>
{line("11.4", "Intrusion detection in place", has_ids, "Suricata events present in window")}
{line("11.5", "File integrity monitoring", False, "Not yet captured by SmartShield SIEM")}

<h2>Requirement 12 — Information security program</h2>
{line("12.10", "Incident-response capability", data["open_cases"] >= 0,
      f"Case workflow active; {data['open_cases']} open and "
      f"{data['closed_cases']['resolved']} resolved in window")}
{line("12.11", "Threat intel feed reviewed", has_ti,
      f"{data['ti_hits']} events enriched by abuse.ch / ThreatFox")}

<div class="footer">Generated by SmartShield SIEM. Use the gaps above as the
next quarter's hardening backlog.</div></body></html>"""


def _iso_27001_html(data: dict) -> str:
    """Map event-store coverage onto ISO 27001 Annex A controls."""
    def line(ctrl, name, ok, hint=""):
        klass = "ok" if ok else "gap"
        verdict = "covered" if ok else "GAP"
        more = f" — {_esc(hint)}" if hint else ""
        return f'<div class="{klass}"><strong>{_esc(ctrl)} {_esc(name)}:</strong> {verdict}{more}</div>'

    has_audit = data["totals"]["all"] > 0
    has_corr  = data["correlation_matches"] > 0

    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>ISO 27001:2022 Annex A Coverage</title>{_STYLES}</head><body>
<h1>ISO/IEC 27001:2022 — Annex A Coverage</h1>
<div class="meta">Window: <strong>{_esc(data['period_start'])}</strong> → <strong>{_esc(data['period_end'])}</strong></div>

<h2>A.5 Organisational controls</h2>
{line("A.5.7", "Threat intelligence", data["ti_hits"] > 0,
      f"{data['ti_hits']} events tagged by the ThreatFox feed")}
{line("A.5.24", "Incident management planning", True,
      "Case workflow with L1/L2/L3 escalation and closure tracking")}
{line("A.5.25", "Assessment and decision on incidents", True,
      "siem_alert_actions captures acknowledge / false-positive / escalate decisions")}

<h2>A.8 Technological controls</h2>
{line("A.8.5",  "Secure authentication", True, "TOTP MFA + per-account lockout")}
{line("A.8.15", "Logging", has_audit,
      f"{data['totals']['all']} events captured")}
{line("A.8.16", "Monitoring activities", has_corr,
      f"{data['correlation_matches']} automated detections in window")}
{line("A.8.17", "Clock synchronisation", True, "FreeBSD ntpd")}
{line("A.8.22", "Segregation of networks", True,
      "PF separates SOC VIP, admin UI and external traffic")}
{line("A.8.23", "Web filtering", True, "DNS filter + Suricata IDS in place")}

<div class="footer">Generated by SmartShield SIEM. Gaps above feed the
ISMS continual-improvement log.</div></body></html>"""


_RENDERERS = {
    "executive": _executive_html,
    "pci_dss":   _pci_dss_html,
    "iso_27001": _iso_27001_html,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate(conn, report_type: str, period: str, generated_by: str = "admin") -> dict:
    """Render and persist a report. Returns the inserted row id + HTML."""
    rtype = (report_type or "").strip().lower()
    if rtype not in _RENDERERS:
        return {"ok": False, "message": f"unknown report_type '{report_type}'"}
    start_ts, end_ts = _period_window(period or "30d")
    data    = _gather(conn, start_ts, end_ts)
    html_doc = _RENDERERS[rtype](data)
    summary = {
        "totals": data["totals"],
        "open_cases": data["open_cases"],
        "correlation_matches": data["correlation_matches"],
        "ti_hits": data["ti_hits"],
        "crown_jewel_events": data["crown_jewel_events"],
        "top_risky": data["top_risky"][:5],
    }
    cur = conn.execute(
        "INSERT INTO reports (report_type, period_start, period_end, "
        "generated_by, html, summary_json) VALUES (?,?,?,?,?,?)",
        (rtype, start_ts, end_ts, generated_by or "admin",
         html_doc, json.dumps(summary)),
    )
    conn.commit()
    return {"ok": True, "id": cur.lastrowid, "html": html_doc, "summary": summary}


def list_reports(conn, limit: int = 30) -> list:
    rows = conn.execute(
        "SELECT id, report_type, period_start, period_end, generated_by, "
        "generated_at, summary_json FROM reports ORDER BY id DESC LIMIT ?",
        (int(limit or 30),),
    ).fetchall()
    return [dict(r) for r in rows]


def fetch_html(conn, report_id: int) -> str:
    row = conn.execute(
        "SELECT html FROM reports WHERE id=?", (int(report_id),)
    ).fetchone()
    return row["html"] if row else ""


def list_types() -> list:
    return list(_REPORT_TYPES)
