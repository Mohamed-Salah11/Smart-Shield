"""
app/services/incident_report.py
-------------------------------
PDF incident-report generation for SmartShield mail alerts.

``build_incident_pdf(incident)`` renders a one/two-page branded PDF and
returns the raw bytes — no temp file. It is attached to an alert email
when an incident was automatically mitigated by a playbook, or to a
follow-up email when a SOC analyst escalates or closes it.

The renderer is plain ``fpdf2`` (pure-Python, no native dependencies)
and takes a normalized ``incident`` dict assembled by ``mail_alerts`` so
this module never touches the database or Flask.

incident = {
    "reference":   str,          # e.g. the event timestamp
    "title":       str,          # human-readable incident title
    "severity":    str,          # info|low|medium|high|critical
    "category":    str,
    "action":      str,
    "timestamp":   str,          # ISO detected-at
    "source_ip":   str,
    "username":    str,
    "details":     dict,         # event details payload
    "disposition": dict | None,  # see below
    "timeline":    [ (when, text), ... ],   # optional
}

disposition = {
    "kind":    "auto" | "soc",
    "summary": str,              # one-line outcome
    "actor":   str,              # playbook name or analyst username
    "tier":    str,              # SOC tier, when relevant
    "outcome": str,              # closure_type / "escalated" / actions taken
    "notes":   str,
}
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone


_LOGO_CANDIDATES = (
    "static/images/ss-email-logo.png",
    "static/images/SS.png",
)

# Severity → (R, G, B) for the banner.
_SEV_RGB = {
    "critical": (185, 28, 28),
    "high":     (217, 90, 20),
    "medium":   (202, 138, 4),
    "low":      (37, 99, 235),
    "info":     (100, 116, 139),
}

_INK   = (31, 41, 55)
_MUTED = (107, 114, 128)
_LINE  = (209, 213, 219)


def _logo_path() -> str:
    for rel in _LOGO_CANDIDATES:
        if os.path.isfile(rel):
            return rel
    return ""


def _clean(text) -> str:
    """Coerce to a string fpdf2's core fonts can render (latin-1 safe)."""
    s = "" if text is None else str(text)
    return s.encode("latin-1", "replace").decode("latin-1")


def build_incident_pdf(incident: dict) -> bytes:
    """Render the incident report and return PDF bytes."""
    from fpdf import FPDF

    sev = (incident.get("severity") or "info").lower()
    rgb = _SEV_RGB.get(sev, _SEV_RGB["info"])

    pdf = FPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()
    epw = pdf.epw  # effective page width

    # ── Header band ────────────────────────────────────────────────
    logo = _logo_path()
    if logo:
        try:
            pdf.image(logo, x=pdf.l_margin, y=12, w=16)
        except Exception:
            pass
    pdf.set_xy(pdf.l_margin + (20 if logo else 0), 12)
    pdf.set_font("Helvetica", "B", 17)
    pdf.set_text_color(*_INK)
    pdf.cell(0, 8, "SmartShield", ln=1)
    pdf.set_x(pdf.l_margin + (20 if logo else 0))
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(*_MUTED)
    pdf.cell(0, 6, "Security Incident Report", ln=1)
    pdf.ln(4)

    # ── Severity banner ────────────────────────────────────────────
    pdf.set_fill_color(*rgb)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 11, _clean(f"  {sev.upper()}  -  {incident.get('title', 'Security Incident')}"),
             ln=1, fill=True)
    pdf.ln(5)

    # ── Incident summary ───────────────────────────────────────────
    _section(pdf, "Incident Summary")
    _kv(pdf, epw, "Reference",   incident.get("reference", ""))
    _kv(pdf, epw, "Detected at", incident.get("timestamp", ""))
    _kv(pdf, epw, "Category",    incident.get("category", ""))
    _kv(pdf, epw, "Event",       incident.get("action", ""))
    _kv(pdf, epw, "Source IP",   incident.get("source_ip", "") or "-")
    _kv(pdf, epw, "User",        incident.get("username", "") or "-")
    pdf.ln(3)

    # ── Disposition ────────────────────────────────────────────────
    disp = incident.get("disposition") or {}
    five_w = _parse_five_w((disp or {}).get("notes") or "")
    if disp:
        if disp.get("kind") == "auto":
            _section(pdf, "Automatic Mitigation")
        else:
            _section(pdf, "SOC Disposition")
        if disp.get("summary"):
            _para(pdf, disp["summary"])
        if disp.get("actor"):
            _kv(pdf, epw, "Handled by", disp.get("actor"))
        if disp.get("tier"):
            _kv(pdf, epw, "Tier", disp.get("tier"))
        if disp.get("outcome"):
            _kv(pdf, epw, "Outcome", disp.get("outcome"))
        # Skip the generic "Notes" row when the note is the structured 5W
        # report — it gets its own section below.
        if disp.get("notes") and not five_w:
            _kv(pdf, epw, "Notes", disp.get("notes"))
        pdf.ln(3)

    # ── Incident Report (5W) ───────────────────────────────────────
    if five_w:
        from fpdf.enums import XPos, YPos
        _section(pdf, "Incident Report")
        if five_w["verdict"]:
            label, rgb = five_w["verdict"]
            pdf.set_x(pdf.l_margin)
            pdf.set_fill_color(*rgb)
            pdf.set_text_color(255, 255, 255)
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(70, 7, _clean(f"  {label}"), fill=True,
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_text_color(*_INK)
            pdf.ln(2)
        for k in ("WHO", "WHAT", "WHEN", "WHERE", "WHY"):
            _kv(pdf, epw, k.title(), five_w["fields"].get(k, ""))
        if five_w["extra"]:
            _kv(pdf, epw, "Additional", five_w["extra"])
        pdf.ln(3)

    # ── Event details ──────────────────────────────────────────────
    details = incident.get("details") or {}
    if isinstance(details, dict) and details:
        _section(pdf, "Event Details")
        for key in sorted(details.keys()):
            val = details[key]
            if isinstance(val, (dict, list)):
                val = json.dumps(val, ensure_ascii=False)
            _kv(pdf, epw, str(key), val)
        pdf.ln(3)

    # ── Timeline ───────────────────────────────────────────────────
    timeline = incident.get("timeline") or []
    if timeline:
        from fpdf.enums import XPos, YPos
        _section(pdf, "Timeline")
        pdf.set_font("Helvetica", "", 9)
        for when, text in timeline:
            pdf.set_x(pdf.l_margin)
            y0 = pdf.get_y()
            pdf.set_text_color(*_MUTED)
            pdf.set_font("Helvetica", "B", 9)
            pdf.cell(42, 5, _clean(when), border=0,
                     new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(*_INK)
            pdf.set_xy(pdf.l_margin + 42, y0)
            pdf.multi_cell(epw - 42, 5, _clean(text),
                           new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(3)

    # ── Footer ─────────────────────────────────────────────────────
    pdf.set_y(-16)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(*_MUTED)
    gen = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    pdf.cell(0, 5, _clean(f"Generated by SmartShield - {gen} - automated report"),
             align="C")

    out = pdf.output()
    return bytes(out)


# ---------------------------------------------------------------------------
# Layout helpers
# ---------------------------------------------------------------------------

def _section(pdf, title: str) -> None:
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(*_INK)
    pdf.cell(0, 7, _clean(title), ln=1)
    pdf.set_draw_color(*_LINE)
    y = pdf.get_y()
    pdf.line(pdf.l_margin, y, pdf.l_margin + pdf.epw, y)
    pdf.ln(2)


def _kv(pdf, epw: float, key: str, value) -> None:
    from fpdf.enums import XPos, YPos
    label_w = 42.0
    pdf.set_x(pdf.l_margin)
    y0 = pdf.get_y()
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(*_MUTED)
    pdf.cell(label_w, 5, _clean(key), border=0,
             new_x=XPos.RIGHT, new_y=YPos.TOP)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*_INK)
    pdf.set_xy(pdf.l_margin + label_w, y0)
    pdf.multi_cell(epw - label_w, 5,
                   _clean(value if value not in (None, "") else "-"),
                   new_x=XPos.LMARGIN, new_y=YPos.NEXT)


def _para(pdf, text: str) -> None:
    from fpdf.enums import XPos, YPos
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*_INK)
    pdf.multi_cell(pdf.epw, 5, _clean(text),
                   new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(1)


def _parse_five_w(note: str):
    """Pick WHO/WHAT/WHEN/WHERE/WHY rows out of a structured note string.
    Returns a dict {verdict, fields, extra} or None when the note isn't a
    5W report (legacy or free-form notes pass through untouched)."""
    if not note:
        return None
    import re
    fields = {}
    for key in ("WHO", "WHAT", "WHEN", "WHERE", "WHY"):
        m = re.search(rf"^{key}:\s*(.+?)(?=\n[A-Z]+:|\nAdditional:|\Z)",
                      note, re.MULTILINE | re.DOTALL)
        if m:
            fields[key] = m.group(1).strip()
    verdict = None
    first = note.splitlines()[0].strip() if note else ""
    if first.startswith("[CLOSED") and "TRUE POSITIVE" in first:
        verdict = ("TRUE POSITIVE", (16, 185, 129))
    elif first.startswith("[CLOSED") and "FALSE POSITIVE" in first:
        verdict = ("FALSE POSITIVE", (239, 68, 68))
    elif first.startswith("[ESCALATED"):
        verdict = (first.strip("[]").strip(), (59, 130, 246))
    extra = ""
    m_extra = re.search(r"\nAdditional:\s*(.+)\Z", note, re.DOTALL)
    if m_extra:
        extra = m_extra.group(1).strip()
    if not fields and not verdict:
        return None
    return {"verdict": verdict, "fields": fields, "extra": extra}
