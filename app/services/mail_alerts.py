"""
app/services/mail_alerts.py
---------------------------
Outbound email alerting for SmartShield.

Every security event flows through ``audit_log.log_event``; that function
calls :func:`notify_event` here right after it persists the event. This
module decides — cheaply, inline — whether the event deserves an email,
and if so hands it to a background worker thread that does the actual
(slow) SMTP so the audit write is never blocked.

Two kinds of mail go out:

* **Alert** — a branded HTML email for any event that passes the
  severity/category filter. If a playbook *automatically* mitigated the
  threat (knowable synchronously, before this hook runs), a PDF incident
  report is attached.
* **Follow-up** — when a SOC analyst escalates or closes an alert, the
  SOC disposition routes call :func:`send_incident_followup`, which emails
  a branded "incident handled" message with the PDF report. Escalations
  are routed to the SOC users of the tier the incident moved to.

Authentication is a Gmail **app password** stored AES-GCM-encrypted in
``mail_alerts_config.smtp_app_password`` via ``secret_store``.

Flood control (alerts only): a per-``(category, action, remote_addr)``
cooldown and a hard hourly cap. The module never raises out of
:func:`notify_event` — a mail problem can never break event logging.
"""

from __future__ import annotations

import json
import os
import queue
import smtplib
import threading
import time
from email.message import EmailMessage


# Built-in mail account used when the operator hasn't configured one in the
# UI. Lets a fresh install send alerts immediately. Either column-level
# value in `mail_alerts_config` (smtp_username / smtp_app_password) takes
# precedence if set, so an admin can still override via the Mail Alerts UI
# without editing this file. See `get_config()` below.
_DEFAULT_SMTP_USERNAME     = "SmartShieldAlerts@gmail.com"
_DEFAULT_SMTP_APP_PASSWORD = "ytnmnzbthtqphepz"


# Severity ranking — matches app/services/playbooks.py:_SEV_ORDER.
_SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Severity → hex colour for the HTML banner.
_SEV_HEX = {
    "critical": "#b91c1c",
    "high":     "#d95a14",
    "medium":   "#ca8a04",
    "low":      "#2563eb",
    "info":     "#64748b",
}

# Human-readable titles for known event actions — used in subjects + HTML.
_SUBJECT_TITLES = {
    "correlation_match":          "Correlation Rule Triggered",
    "ids_alert":                  "Intrusion Detection Alert",
    "ids_flood_detected":         "IDS Alert Flood",
    "brute_force_detected":       "Brute-Force Attack Detected",
    "ssh_login_failed":           "Failed SSH Login",
    "su_attempt_failed":          "Failed Privilege Escalation",
    "insecure_protocol_detected": "Insecure Protocol In Use",
    "exe_download_detected":      "Executable Download Detected",
    "exe_url_detected":           "Executable URL Detected",
    "c2_agent_detected":          "Command-and-Control Agent Detected",
    "service_down":               "Service Outage",
    "service_recovered":          "Service Recovered",
    "kernel_panic":               "Kernel Panic",
    "out_of_memory":              "Out-Of-Memory Condition",
    "pf_table_overload":          "Firewall Table Overload",
    "link_state_change":          "Network Link State Change",
    "wan_ip_changed":             "WAN IP Address Changed",
    "cert_expired":               "Certificate Expired",
    "cert_expiring":              "Certificate Expiring Soon",
    "vpn_auth_fail":              "VPN Authentication Failure",
    "vpn_connect":                "VPN Client Connected",
    "vpn_disconnect":             "VPN Client Disconnected",
    "ids_auto_recovered":         "IDS Auto-Recovered",
    "ids_auto_recovery_failed":   "IDS Auto-Recovery Failed",
}

# Cooldown bookkeeping — (category, action, remote_addr) -> last-sent epoch.
_FIRED: dict = {}
_FIRED_CAP = 5000

# Config cache so notify_event does not hit the DB on every single event.
_CFG_CACHE: dict = {"cfg": None, "ts": 0.0}
_CFG_TTL = 30.0

# Cached email logo bytes.
_LOGO_CACHE: dict = {"bytes": None}
_LOGO_CANDIDATES = ("static/images/ss-email-logo.png", "static/images/SS.png")

# Background sender.
_QUEUE: "queue.Queue" = queue.Queue(maxsize=200)
_WORKER_STARTED = threading.Event()

_HOUR_KEY = "mail_alert_hour_count"

# Phase 2.2: per-source cooldown ring (separate from the global
# (category, action, remote_addr) ring above so a noisy src_ip can be
# squashed without hiding distinct alert kinds).
_PER_SOURCE_FIRED: dict = {}

# Phase 2.2: digest buffer + lock. Each entry is {"ts": int, "event": dict};
# the digest ticker drains the buffer and enqueues a single ``kind=digest``
# job whenever the configured window has elapsed.
_DIGEST_BUFFER: list = []
_DIGEST_LOCK = threading.Lock()
_DIGEST_LAST_FLUSH: list = [0]
_DIGEST_TICK_STARTED = threading.Event()
_DIGEST_TICK_INTERVAL = 60   # poll the buffer once per minute


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def _now() -> int:
    return int(time.time())


def _open_conn():
    """Short-lived connection to the main DB (events + mail tables live here)."""
    from app.audit_log import _events_db
    return _events_db()


def _state_read(conn, key: str, default: str = "") -> str:
    try:
        row = conn.execute(
            "SELECT value FROM siem_state WHERE key = ?", (key,)
        ).fetchone()
        return row["value"] if row else default
    except Exception:
        return default


def _state_write(conn, key: str, value: str) -> None:
    try:
        conn.execute(
            "INSERT INTO siem_state (key, value, updated_at) "
            "VALUES (?, ?, CURRENT_TIMESTAMP) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value, "
            "updated_at = CURRENT_TIMESTAMP",
            (key, value),
        )
        conn.commit()
    except Exception:
        pass


def _hour_counter(conn) -> dict:
    """Return ``{"hour_bucket": int, "count": int}`` for the current hour."""
    raw = _state_read(conn, _HOUR_KEY, "")
    try:
        data = json.loads(raw) if raw else {}
    except Exception:
        data = {}
    bucket = _now() // 3600
    if data.get("hour_bucket") != bucket:
        data = {"hour_bucket": bucket, "count": 0}
    return data


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def get_config(conn) -> dict:
    """Read the singleton config row; decrypt the app password.

    When the DB row's smtp_username or smtp_app_password is blank, fall back
    to the built-in defaults at the top of this module so a fresh install
    can send mail without any GUI configuration. Any value the admin saves
    via the Mail Alerts UI still wins — the fallback only fills the gap.
    """
    row = conn.execute("SELECT * FROM mail_alerts_config WHERE id = 1").fetchone()
    if not row:
        return {}
    cfg = dict(row)
    enc = cfg.get("smtp_app_password") or ""
    if enc:
        try:
            from app.secret_store import decrypt_secret
            cfg["smtp_app_password"] = decrypt_secret(enc) or ""
        except Exception:
            cfg["smtp_app_password"] = ""

    if not (cfg.get("smtp_username") or "").strip():
        cfg["smtp_username"] = _DEFAULT_SMTP_USERNAME
    if not (cfg.get("smtp_app_password") or "").strip():
        cfg["smtp_app_password"] = _DEFAULT_SMTP_APP_PASSWORD
    return cfg


def _cached_config() -> dict:
    """Config with a 30 s TTL — keeps notify_event off the DB on the hot path."""
    now = time.time()
    if _CFG_CACHE["cfg"] is not None and (now - _CFG_CACHE["ts"]) < _CFG_TTL:
        return _CFG_CACHE["cfg"]
    conn = _open_conn()
    cfg = {}
    if conn is not None:
        try:
            cfg = get_config(conn)
        except Exception:
            cfg = {}
        finally:
            try:
                conn.close()
            except Exception:
                pass
    _CFG_CACHE["cfg"] = cfg
    _CFG_CACHE["ts"] = now
    return cfg


def invalidate_config_cache() -> None:
    """Drop the cached config — call after the settings route saves changes."""
    _CFG_CACHE["cfg"] = None
    _CFG_CACHE["ts"] = 0.0


# ---------------------------------------------------------------------------
# Recipients
# ---------------------------------------------------------------------------

def resolve_recipients(conn) -> list:
    """
    Return the de-duplicated list of recipient email addresses.

    A user-linked row (``user_id`` set) resolves to that user's *current*
    ``users.email``; a free-text row uses its own ``email`` column.
    """
    try:
        rows = conn.execute(
            "SELECT COALESCE(NULLIF(TRIM(u.email), ''), TRIM(r.email)) AS addr "
            "FROM mail_alert_recipients r "
            "LEFT JOIN users u ON u.id = r.user_id "
            "WHERE COALESCE(r.disabled, 0) = 0"
        ).fetchall()
    except Exception:
        return []
    return _dedupe_emails(row["addr"] for row in rows)


def _users_at_tier(conn, tier: str) -> list:
    """
    Emails of SOC users at *tier* (L1/L2/L3).

    A user is at a tier via ``users.soc_tier`` or via a group whose
    ``groups.soc_tier`` matches. Superusers are implicitly L3.
    """
    tier = (tier or "").strip().upper()
    if tier not in ("L1", "L2", "L3"):
        return []
    found = []
    try:
        for r in conn.execute(
            "SELECT email FROM users WHERE soc_tier = ? "
            "AND COALESCE(status,'active') = 'active'", (tier,)
        ):
            found.append(r["email"])
        for r in conn.execute(
            "SELECT u.email FROM users u "
            "JOIN user_groups ug ON ug.user_id = u.id "
            "JOIN groups g ON g.id = ug.group_id "
            "WHERE g.soc_tier = ? AND COALESCE(u.status,'active') = 'active'",
            (tier,)
        ):
            found.append(r["email"])
        if tier == "L3":
            for r in conn.execute(
                "SELECT email FROM users WHERE COALESCE(is_superuser,0) = 1 "
                "AND COALESCE(status,'active') = 'active'"
            ):
                found.append(r["email"])
    except Exception:
        pass
    return _dedupe_emails(found)


def _dedupe_emails(values) -> list:
    seen, out = set(), []
    for v in values:
        addr = (v or "").strip()
        if addr and "@" in addr and addr.lower() not in seen:
            seen.add(addr.lower())
            out.append(addr)
    return out


# ---------------------------------------------------------------------------
# Filtering (alerts only)
# ---------------------------------------------------------------------------

def _passes_filter(cfg: dict, event: dict) -> bool:
    """Severity threshold + category filter + loop guard. No side effects."""
    if (event.get("category") or "").lower() == "mail":
        return False  # loop guard — never alert on our own audit events
    min_sev = (cfg.get("min_severity") or "high").lower()
    ev_sev  = (event.get("severity") or "info").lower()
    if _SEV_ORDER.get(ev_sev, 0) < _SEV_ORDER.get(min_sev, 3):
        return False
    cat_filter = (cfg.get("category_filter") or "").strip()
    if cat_filter:
        allowed = {c.strip().lower() for c in cat_filter.split(",") if c.strip()}
        if (event.get("category") or "").lower() not in allowed:
            return False
    return True


def _cooldown_ok(event: dict, cooldown_minutes: int) -> bool:
    """True if this (category, action, remote_addr) is outside its cooldown."""
    if cooldown_minutes <= 0:
        return True
    key = (event.get("category") or "", event.get("action") or "",
           event.get("remote_addr") or "")
    now = _now()
    if now - _FIRED.get(key, 0) < cooldown_minutes * 60:
        return False
    _FIRED[key] = now
    if len(_FIRED) > _FIRED_CAP:
        for k in [k for k, t in _FIRED.items() if now - t > 3600]:
            _FIRED.pop(k, None)
    return True


# ---------------------------------------------------------------------------
# Phase 2.2: per-source cooldown + digest buffering
# ---------------------------------------------------------------------------

def _per_source_key(event: dict) -> str:
    """Return the identifier used for per-source cooldown — prefer
    ``details.src_ip`` (a single noisy attacker), then ``details.signature``
    (a single noisy rule). Empty string means "no usable key, don't suppress"."""
    details = event.get("details") or {}
    if not isinstance(details, dict):
        return ""
    src = (details.get("src_ip") or "").strip()
    if src:
        return f"src:{src}"
    sig = (details.get("signature") or "").strip()
    if sig:
        return f"sig:{sig}"
    return ""


def _per_source_cooldown_ok(event: dict, cooldown_minutes: int) -> bool:
    """True if the event's per-source key is outside its cooldown window.

    No-op (always True) when ``cooldown_minutes`` is 0 or the event has no
    usable src_ip / signature — so disabling the feature or alerting on
    sourceless events both still go through.
    """
    if cooldown_minutes <= 0:
        return True
    key = _per_source_key(event)
    if not key:
        return True
    now = _now()
    if now - _PER_SOURCE_FIRED.get(key, 0) < cooldown_minutes * 60:
        return False
    _PER_SOURCE_FIRED[key] = now
    if len(_PER_SOURCE_FIRED) > _FIRED_CAP:
        for k in [k for k, t in _PER_SOURCE_FIRED.items() if now - t > 3600]:
            _PER_SOURCE_FIRED.pop(k, None)
    return True


def _buffer_for_digest(event: dict) -> None:
    """Append an event to the digest buffer. Called instead of immediate enqueue
    when ``digest_window_minutes`` > 0."""
    with _DIGEST_LOCK:
        _DIGEST_BUFFER.append({"ts": _now(), "event": dict(event)})


def _digest_flush_due(window_minutes: int, now: int) -> bool:
    """True iff the digest window has elapsed AND there's something buffered."""
    if window_minutes <= 0:
        return False
    with _DIGEST_LOCK:
        if not _DIGEST_BUFFER:
            return False
        # Seed the timer on the FIRST event so a digest fires reliably window
        # minutes after the first buffered alert, not "first poll after startup".
        if _DIGEST_LAST_FLUSH[0] == 0:
            _DIGEST_LAST_FLUSH[0] = _DIGEST_BUFFER[0]["ts"]
        return (now - _DIGEST_LAST_FLUSH[0]) >= window_minutes * 60


def _flush_digest() -> int:
    """Atomically drain the digest buffer and enqueue ONE digest job covering
    every buffered event. Returns the number of events flushed."""
    with _DIGEST_LOCK:
        if not _DIGEST_BUFFER:
            return 0
        batch = [b["event"] for b in _DIGEST_BUFFER]
        _DIGEST_BUFFER.clear()
        _DIGEST_LAST_FLUSH[0] = _now()
    try:
        _QUEUE.put_nowait({"kind": "digest", "events": batch})
    except queue.Full:
        pass
    return len(batch)


def _digest_ticker() -> None:
    """Background timer: every ``_DIGEST_TICK_INTERVAL`` seconds, flush the
    digest buffer if the configured window has elapsed."""
    while True:
        time.sleep(_DIGEST_TICK_INTERVAL)
        try:
            cfg = _cached_config()
            if not cfg or not cfg.get("enabled"):
                continue
            window = int(cfg.get("digest_window_minutes") or 0)
            if _digest_flush_due(window, _now()):
                _flush_digest()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Titles + content
# ---------------------------------------------------------------------------

def _event_title(event: dict) -> str:
    action = (event.get("action") or "event").strip()
    return _SUBJECT_TITLES.get(action) or action.replace("_", " ").title()


def _logo_bytes() -> bytes:
    """Read and cache the email logo PNG. Empty bytes if none found."""
    if _LOGO_CACHE["bytes"] is not None:
        return _LOGO_CACHE["bytes"]
    data = b""
    for rel in _LOGO_CANDIDATES:
        if os.path.isfile(rel):
            try:
                with open(rel, "rb") as fh:
                    data = fh.read()
                break
            except Exception:
                data = b""
    _LOGO_CACHE["bytes"] = data
    return data


def _esc(text) -> str:
    s = "" if text is None else str(text)
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;"))


def _alert_subject(event: dict, disposition: dict | None) -> str:
    sev   = (event.get("severity") or "info").upper()
    title = _event_title(event)
    if disposition and disposition.get("kind") == "auto":
        return f"[SmartShield] {sev} · {title} — Auto-Mitigated"
    return f"[SmartShield] {sev} · {title}"


def _build_text(incident: dict) -> str:
    """Plain-text fallback body for the multipart/alternative message."""
    d = incident
    lines = [
        "SmartShield Security Alert",
        "=" * 32, "",
        f"  Incident  : {d.get('title','')}",
        f"  Severity  : {(d.get('severity') or 'info').upper()}",
        f"  Detected  : {d.get('timestamp','')}",
        f"  Category  : {d.get('category','')}",
        f"  Event     : {d.get('action','')}",
        f"  Source IP : {d.get('source_ip','') or '-'}",
        f"  User      : {d.get('username','') or '-'}",
        "",
    ]
    disp = d.get("disposition") or {}
    if disp:
        header = ("Automatic Mitigation" if disp.get("kind") == "auto"
                  else "SOC Disposition")
        lines += [header, "-" * len(header)]
        if disp.get("summary"):
            lines.append(f"  {disp['summary']}")
        if disp.get("actor"):
            lines.append(f"  Handled by : {disp['actor']}")
        if disp.get("tier"):
            lines.append(f"  Tier       : {disp['tier']}")
        if disp.get("outcome"):
            lines.append(f"  Outcome    : {disp['outcome']}")
        if disp.get("notes"):
            lines.append(f"  Notes      : {disp['notes']}")
        lines.append("")
    details = d.get("details") or {}
    if isinstance(details, dict) and details:
        lines.append("Event details:")
        try:
            lines.append(json.dumps(details, indent=2, ensure_ascii=False))
        except Exception:
            lines.append(str(details))
        lines.append("")
    lines += ["Review this incident in the SmartShield SOC portal.",
              "— This is an automated message from SmartShield."]
    return "\n".join(lines)


def _parse_five_w(note: str):
    """Pick WHO/WHAT/WHEN/WHERE/WHY rows out of a structured close/escalate note.
    Returns {verdict, fields, extra} or None when the note isn't 5W formatted."""
    if not note:
        return None
    import re as _re
    fields = {}
    for key in ("WHO", "WHAT", "WHEN", "WHERE", "WHY"):
        m = _re.search(rf"^{key}:\s*(.+?)(?=\n[A-Z]+:|\nAdditional:|\Z)",
                       note, _re.MULTILINE | _re.DOTALL)
        if m:
            fields[key] = m.group(1).strip()
    verdict = None
    first = note.splitlines()[0].strip() if note else ""
    if first.startswith("[CLOSED") and "TRUE POSITIVE" in first:
        verdict = ("TRUE POSITIVE", "#10b981")
    elif first.startswith("[CLOSED") and "FALSE POSITIVE" in first:
        verdict = ("FALSE POSITIVE", "#ef4444")
    elif first.startswith("[ESCALATED"):
        verdict = (first.strip("[]").strip(), "#3b82f6")
    extra = ""
    m_extra = _re.search(r"\nAdditional:\s*(.+)\Z", note, _re.DOTALL)
    if m_extra:
        extra = m_extra.group(1).strip()
    if not fields and not verdict:
        return None
    return {"verdict": verdict, "fields": fields, "extra": extra}


def render_alert_html(incident: dict, portal_url: str = "") -> str:
    """Branded, email-client-safe HTML body. References the logo via cid:ss-logo.

    Layout is table-based + inline styles only — survives every mainstream
    client (Gmail, Outlook, Apple Mail, Thunderbird). No @media, @keyframes,
    flex, grid, or SVG.
    """
    d        = incident
    sev      = (d.get("severity") or "info").lower()
    sev_hex  = _SEV_HEX.get(sev, _SEV_HEX["info"])
    sev_tint = {
        "critical": "#fef2f2", "high": "#fff7ed", "medium": "#fffbeb",
        "low":      "#eff6ff", "info": "#f1f5f9",
    }.get(sev, "#f1f5f9")
    title    = _esc(d.get("title", "Security Incident"))
    action   = d.get("action") or "-"
    category = d.get("category") or "-"
    src_ip   = d.get("source_ip") or "-"
    user     = d.get("username") or "-"
    detected = d.get("timestamp") or "-"
    logo_tag = ('<img src="cid:ss-logo" width="44" height="44" '
                'alt="SmartShield" style="display:block;border:0;border-radius:6px;">'
                if _logo_bytes() else
                '<div style="width:44px;height:44px;background:rgba(255,255,255,.15);'
                'border:1px solid rgba(255,255,255,.25);border-radius:6px;"></div>')

    # Disposition panel + 5W parse.
    disp = d.get("disposition") or {}
    five_w = _parse_five_w((disp or {}).get("notes") or "")
    if disp.get("kind") == "auto":
        status_label = "Auto-Mitigated"
        status_bg, status_fg = "#ecfdf5", "#047857"
    elif disp.get("kind") == "soc":
        status_label = "Handled by SOC"
        status_bg, status_fg = "#eff6ff", "#1d4ed8"
    else:
        status_label = "Live Incident"
        status_bg, status_fg = sev_tint, sev_hex

    # ── Info cards (2×2 grid via two table rows of two cells each).
    def _info_card(label, value, mono=False, tint=False):
        v_html = _esc(value)
        if mono:
            v_html = (
                f'<span style="font-family:Consolas,Menlo,monospace;font-size:13px;'
                f'background:#fff7ed;color:#c43409;border:1px solid #fed7aa;'
                f'border-radius:4px;padding:2px 6px;">{v_html}</span>'
            )
        elif tint:
            v_html = (
                f'<span style="font-family:Consolas,Menlo,monospace;font-size:12px;'
                f'background:#f3f4f6;color:#374151;border:1px solid #e5e7eb;'
                f'border-radius:4px;padding:2px 6px;">{v_html}</span>'
            )
        return (
            f'<td valign="top" style="padding:6px;width:50%;">'
            f'<table width="100%" cellpadding="0" cellspacing="0" '
            f'style="background:#f7f8fa;border:1px solid #e5e7eb;'
            f'border-radius:8px;">'
            f'<tr><td style="padding:12px 14px;">'
            f'<div style="font-size:11px;color:#6b7280;font-weight:700;'
            f'letter-spacing:.06em;text-transform:uppercase;margin-bottom:4px;">'
            f'{_esc(label)}</div>'
            f'<div style="font-size:14px;color:#111827;font-weight:600;'
            f'word-break:break-all;">{v_html}</div>'
            f'</td></tr></table></td>'
        )

    info_grid = (
        '<table width="100%" cellpadding="0" cellspacing="0" '
        'style="margin:8px 0 4px;"><tr>'
        + _info_card("Category", category, tint=True)
        + _info_card("Event",    action,   tint=True)
        + '</tr><tr>'
        + _info_card("Source IP", src_ip, mono=True)
        + _info_card("User",      user)
        + '</tr></table>'
    )

    # ── Disposition box (omit Notes row when 5W is being rendered separately).
    disp_html = ""
    if disp:
        is_auto = disp.get("kind") == "auto"
        accent  = "#059669" if is_auto else "#1d4ed8"
        bg      = "#ecfdf5" if is_auto else "#eff6ff"
        heading = "Automatic Mitigation" if is_auto else "SOC Disposition"
        bits = []
        if disp.get("summary"):
            bits.append(
                f'<div style="font-size:13px;color:#1f2937;'
                f'margin-bottom:6px;">{_esc(disp["summary"])}</div>'
            )
        for label, pretty in (("actor", "Handled by"), ("tier", "Tier"),
                              ("outcome", "Outcome"), ("notes", "Notes")):
            if label == "notes" and five_w:
                continue  # rendered as its own 5W card below
            if disp.get(label):
                bits.append(
                    f'<div style="font-size:12px;color:#374151;'
                    f'margin-top:4px;line-height:1.5;">'
                    f'<span style="color:#6b7280;font-weight:600;">{pretty}:</span> '
                    f'{_esc(disp[label])}</div>'
                )
        disp_html = (
            f'<tr><td style="padding:0 24px 12px;">'
            f'<table width="100%" cellpadding="0" cellspacing="0" '
            f'style="background:{bg};border-left:4px solid {accent};'
            f'border-radius:8px;"><tr><td style="padding:12px 14px;">'
            f'<div style="font-size:11px;font-weight:700;color:{accent};'
            f'text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px;">'
            f'{heading}</div>{"".join(bits)}</td></tr></table>'
            f'</td></tr>'
        )

    # ── 5W "Incident Report" card.
    five_w_html = ""
    if five_w:
        verdict_chip = ""
        if five_w["verdict"]:
            label, rgb = five_w["verdict"]
            verdict_chip = (
                f'<div style="margin-bottom:8px;"><span style="display:inline-block;'
                f'background:{rgb};color:#ffffff;font-weight:700;font-size:12px;'
                f'padding:4px 10px;border-radius:4px;text-transform:uppercase;'
                f'letter-spacing:.05em;">{_esc(label)}</span></div>'
            )
        w_rows = ""
        for k in ("WHO", "WHAT", "WHEN", "WHERE", "WHY"):
            v = five_w["fields"].get(k, "")
            w_rows += (
                f'<tr><td valign="top" style="padding:5px 0;width:80px;color:#6b7280;'
                f'font-size:12px;font-weight:700;text-transform:uppercase;'
                f'letter-spacing:.05em;">{k}</td>'
                f'<td valign="top" style="padding:5px 10px;color:#111827;'
                f'font-size:13px;line-height:1.5;">{_esc(v) or "&mdash;"}</td></tr>'
            )
        extra_html = ""
        if five_w["extra"]:
            extra_html = (
                f'<tr><td valign="top" style="padding:5px 0;color:#6b7280;'
                f'font-size:12px;font-weight:700;text-transform:uppercase;'
                f'letter-spacing:.05em;">Additional</td>'
                f'<td valign="top" style="padding:5px 10px;color:#374151;'
                f'font-size:13px;line-height:1.5;">{_esc(five_w["extra"])}</td></tr>'
            )
        five_w_html = (
            f'<tr><td style="padding:0 24px 14px;">'
            f'<table width="100%" cellpadding="0" cellspacing="0" '
            f'style="background:#ffffff;border:1px solid #e5e7eb;'
            f'border-radius:8px;"><tr><td style="padding:14px 16px;">'
            f'<div style="font-size:11px;color:#6b7280;font-weight:700;'
            f'letter-spacing:.06em;text-transform:uppercase;margin-bottom:8px;">'
            f'Incident Report &mdash; 5W</div>{verdict_chip}'
            f'<table width="100%" cellpadding="0" cellspacing="0">'
            f'{w_rows}{extra_html}</table>'
            f'</td></tr></table>'
            f'</td></tr>'
        )

    # ── Event details rows (only if non-empty).
    details_html = ""
    details = d.get("details") or {}
    if isinstance(details, dict) and details:
        drows = ""
        for k in sorted(details.keys()):
            v = details[k]
            if isinstance(v, (dict, list)):
                v = json.dumps(v, ensure_ascii=False)
            drows += (
                f'<tr><td valign="top" style="padding:8px 12px;color:#6b7280;'
                f'font-size:12px;border-bottom:1px solid #f3f4f6;width:42%;'
                f'word-break:break-all;">{_esc(k)}</td>'
                f'<td valign="top" style="padding:8px 12px;color:#111827;'
                f'font-size:12px;font-family:Consolas,Menlo,monospace;'
                f'border-bottom:1px solid #f3f4f6;word-break:break-all;">'
                f'{_esc(v)}</td></tr>'
            )
        details_html = (
            f'<tr><td style="padding:0 24px 14px;">'
            f'<div style="font-size:11px;color:#6b7280;font-weight:700;'
            f'letter-spacing:.1em;text-transform:uppercase;margin:4px 0 6px;">'
            f'Event Details</div>'
            f'<table width="100%" cellpadding="0" cellspacing="0" '
            f'style="border:1px solid #e5e7eb;border-radius:8px;'
            f'border-collapse:separate;border-spacing:0;background:#ffffff;">'
            f'{drows}</table>'
            f'</td></tr>'
        )

    # ── Timeline (only on follow-up emails with prior notes).
    timeline = d.get("timeline") or []
    timeline_html = ""
    if timeline:
        rows = ""
        for when, text in timeline:
            rows += (
                f'<tr><td valign="top" style="padding:6px 10px 6px 0;color:#6b7280;'
                f'font-family:Consolas,Menlo,monospace;font-size:11px;width:140px;'
                f'white-space:nowrap;">{_esc(when)}</td>'
                f'<td valign="top" style="padding:6px 0;color:#374151;'
                f'font-size:12px;line-height:1.5;white-space:pre-line;">'
                f'{_esc(text)}</td></tr>'
            )
        timeline_html = (
            f'<tr><td style="padding:0 24px 14px;">'
            f'<div style="font-size:11px;color:#6b7280;font-weight:700;'
            f'letter-spacing:.1em;text-transform:uppercase;margin:4px 0 6px;">'
            f'Timeline</div>'
            f'<table width="100%" cellpadding="0" cellspacing="0">{rows}</table>'
            f'</td></tr>'
        )

    section_sub = (
        "An automated correlation rule has matched suspicious activity. "
        "Review the details below and take action immediately."
        if disp.get("kind") != "soc"
        else "A SOC analyst has updated this incident. Review the disposition below."
    )

    return f"""\
<!DOCTYPE html>
<html><body style="margin:0;padding:0;background:#f0f2f5;font-family:Segoe UI,Helvetica,Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f0f2f5;padding:32px 16px;">
<tr><td align="center">
<table width="620" cellpadding="0" cellspacing="0" style="max-width:620px;width:100%;
 background:#ffffff;border-radius:16px;overflow:hidden;
 box-shadow:0 2px 8px rgba(0,0,0,.06),0 16px 48px rgba(0,0,0,.08);
 font-family:Segoe UI,Helvetica,Arial,sans-serif;">

  <!-- Header -->
  <tr><td style="background:#5a0a0a;background:linear-gradient(135deg,#5a0a0a,#7f1010,#5a0a0a);padding:20px 28px;">
    <table width="100%" cellpadding="0" cellspacing="0"><tr>
      <td width="44" style="vertical-align:middle;">{logo_tag}</td>
      <td style="padding-left:12px;vertical-align:middle;">
        <div style="color:#ffffff;font-size:17px;font-weight:700;letter-spacing:-0.01em;line-height:1.2;">SmartShield</div>
        <div style="color:rgba(255,255,255,0.75);font-size:11px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;margin-top:2px;">Security Operations</div>
      </td>
      <td align="right" style="vertical-align:middle;">
        <span style="display:inline-block;background:rgba(255,255,255,0.15);border:1px solid rgba(255,255,255,0.28);border-radius:999px;padding:4px 12px;color:rgba(255,255,255,0.92);font-size:11px;font-weight:600;letter-spacing:.05em;text-transform:uppercase;">Security Alert</span>
      </td>
    </tr></table>
  </td></tr>

  <!-- Severity banner -->
  <tr><td style="background:{sev_tint};border-bottom:1px solid #e5e7eb;padding:10px 28px;">
    <table width="100%" cellpadding="0" cellspacing="0"><tr>
      <td style="vertical-align:middle;">
        <span style="display:inline-block;background:#ffffff;color:{sev_hex};
          border:1.5px solid {sev_hex};border-radius:999px;padding:3px 10px;
          font-size:11px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;">
          <span style="display:inline-block;width:6px;height:6px;border-radius:50%;background:{sev_hex};margin-right:6px;vertical-align:middle;"></span>
          {_esc(sev)}
        </span>
        <span style="margin-left:10px;color:{sev_hex};font-size:13px;font-weight:700;vertical-align:middle;">Security Event Triggered</span>
      </td>
    </tr></table>
  </td></tr>

  <!-- Body -->
  <tr><td style="padding:24px 28px 8px;">
    <div style="font-size:20px;font-weight:700;color:#111827;letter-spacing:-0.01em;line-height:1.2;margin:0 0 6px;">{title}</div>
    <div style="font-size:12px;color:#6b7280;margin:0 0 18px;line-height:1.5;">{_esc(section_sub)}</div>

    <!-- Timeline strip -->
    <table width="100%" cellpadding="0" cellspacing="0" style="background:#f7f8fa;border:1px solid #e5e7eb;border-radius:10px;margin-bottom:14px;"><tr>
      <td width="44" style="padding:12px 0 12px 14px;vertical-align:middle;">
        <div style="width:32px;height:32px;background:#fff2ee;border-radius:6px;text-align:center;line-height:32px;color:#e8400a;font-size:16px;font-weight:700;">&#x29D6;</div>
      </td>
      <td style="padding:12px;vertical-align:middle;">
        <div style="font-size:10px;color:#6b7280;font-weight:600;letter-spacing:.06em;text-transform:uppercase;">Detected at</div>
        <div style="font-family:Consolas,Menlo,monospace;font-size:12px;color:#111827;font-weight:700;margin-top:2px;">{_esc(detected)}</div>
      </td>
      <td align="right" style="padding:12px 14px 12px 0;vertical-align:middle;">
        <span style="display:inline-block;background:{status_bg};color:{status_fg};border:1px solid {status_fg};border-radius:999px;padding:3px 10px;font-size:11px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;">{_esc(status_label)}</span>
      </td>
    </tr></table>

    {info_grid}
  </td></tr>

  {disp_html}
  {five_w_html}
  {details_html}
  {timeline_html}

  <!-- Footer -->
  <tr><td style="background:#f0f2f5;border-top:1px solid #e5e7eb;padding:16px 28px;">
    <table width="100%" cellpadding="0" cellspacing="0"><tr>
      <td style="font-size:11px;color:#6b7280;font-weight:600;">
        <span style="color:#e8400a;">&#x1F6E1;</span> SmartShield &middot; Security Operations
      </td>
      <td align="right" style="font-size:11px;color:#9ca3af;">
        Automated &middot; do not reply
      </td>
    </tr></table>
    <div style="font-size:10px;color:#9ca3af;text-align:center;border-top:1px solid #e5e7eb;padding-top:10px;margin-top:10px;">
      Automated message from SmartShield &mdash; do not reply directly to this email.
    </div>
  </td></tr>

</table>
</td></tr></table>
</body></html>"""


# ---------------------------------------------------------------------------
# SMTP send
# ---------------------------------------------------------------------------

def send_mail(cfg: dict, to_list: list, subject: str, text_body: str,
              html_body: str = "", pdf_bytes: bytes = b"",
              pdf_name: str = "incident-report.pdf") -> tuple:
    """
    Send one email (plain-text, or multipart with HTML + inline logo +
    optional PDF attachment). Returns ``(ok, message)``.

    *cfg* must carry a **decrypted** ``smtp_app_password``.
    """
    host = (cfg.get("smtp_host") or "smtp.gmail.com").strip()
    port = int(cfg.get("smtp_port") or 587)
    security = (cfg.get("smtp_security") or "starttls").lower()
    username = (cfg.get("smtp_username") or "").strip()
    password = cfg.get("smtp_app_password") or ""
    from_name = (cfg.get("from_name") or "SmartShield").strip()

    if not username or not password:
        return False, "SMTP username / app password not configured."
    recipients = [a for a in (to_list or []) if a]
    if not recipients:
        return False, "No recipients."

    msg = EmailMessage()
    msg["Subject"] = subject
    # Gmail rewrites any From that is not the authenticated account.
    msg["From"] = f"{from_name} <{username}>" if from_name else username
    msg["To"] = ", ".join(recipients)
    msg.set_content(text_body)

    if html_body:
        msg.add_alternative(html_body, subtype="html")
        # Inline the logo into the HTML part (must happen before add_attachment).
        logo = _logo_bytes()
        if logo and "cid:ss-logo" in html_body:
            try:
                html_part = msg.get_payload()[-1]
                html_part.add_related(logo, maintype="image", subtype="png",
                                      cid="<ss-logo>")
            except Exception:
                pass

    if pdf_bytes:
        try:
            msg.add_attachment(pdf_bytes, maintype="application",
                               subtype="pdf", filename=pdf_name)
        except Exception:
            pass

    try:
        if security == "ssl":
            with smtplib.SMTP_SSL(host, port, timeout=20) as smtp:
                smtp.login(username, password)
                smtp.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=20) as smtp:
                smtp.ehlo()
                smtp.starttls()
                smtp.ehlo()
                smtp.login(username, password)
                smtp.send_message(msg)
        return True, f"Sent to {len(recipients)} recipient(s)."
    except smtplib.SMTPAuthenticationError:
        return False, ("SMTP authentication failed — check the Gmail address "
                       "and app password (not your normal account password).")
    except Exception as exc:
        return False, f"SMTP send failed: {exc}"


def send_test(cfg: dict, to_address: str) -> tuple:
    """Send a one-off test email. Returns ``(ok, message)``."""
    to_address = (to_address or "").strip()
    if not to_address or "@" not in to_address:
        return False, "Enter a valid destination address."
    ok, message = send_mail(
        cfg, [to_address],
        "[SmartShield] Test alert",
        "This is a test email from SmartShield's mail alert service.\n\n"
        "If you received this, SMTP is configured correctly.\n",
    )
    try:
        from app.audit_log import log_event
        log_event(category="mail", action="mail_test_sent",
                  severity="info", username="system", remote_addr="",
                  details={"to": to_address, "ok": ok, "message": message})
    except Exception:
        pass
    return ok, message


# ---------------------------------------------------------------------------
# Disposition detection + incident assembly
# ---------------------------------------------------------------------------

def _detect_auto_disposition(conn, event: dict) -> dict | None:
    """
    Decide whether *event* was automatically mitigated.

    A playbook that ran to completion against this event, or an
    ``ids_auto_recovered`` event, counts as automatic handling. Playbooks
    run synchronously before the mail worker, so the run record exists by
    the time this is called.
    """
    action = (event.get("action") or "").lower()
    if action == "ids_auto_recovered":
        return {"kind": "auto", "actor": "IDS watchdog",
                "summary": "Suricata IDS was automatically restarted.",
                "outcome": "Service recovered"}

    ts = event.get("timestamp") or ""
    if not ts:
        return None
    try:
        run = conn.execute(
            "SELECT pr.id, pr.playbook_id, pr.steps_log_json, p.name AS pname "
            "FROM playbook_runs pr "
            "LEFT JOIN playbooks p ON p.id = pr.playbook_id "
            "WHERE pr.trigger_event_ts = ? AND pr.status = 'done' "
            "ORDER BY pr.id DESC LIMIT 1",
            (ts,),
        ).fetchone()
    except Exception:
        return None
    if not run:
        return None

    actions_taken = []
    try:
        for step in json.loads(run["steps_log_json"] or "[]"):
            if (step.get("status") == "ok") and step.get("message"):
                actions_taken.append(str(step["message"]))
    except Exception:
        pass
    name = run["pname"] or f"Playbook #{run['playbook_id']}"
    return {
        "kind": "auto",
        "actor": name,
        "summary": f"Automatically mitigated by playbook “{name}”.",
        "outcome": "; ".join(actions_taken) if actions_taken else "Playbook completed",
    }


def _build_incident(event: dict, disposition: dict | None) -> dict:
    """Normalize an event (+ disposition) into the incident dict the
    HTML renderer and PDF builder both consume."""
    details = event.get("details") or {}
    src = (event.get("remote_addr") or "")
    if not src and isinstance(details, dict):
        src = details.get("src_ip") or details.get("source_ip") or ""
    return {
        "reference":   event.get("timestamp", ""),
        "title":       _event_title(event),
        "severity":    event.get("severity", "info"),
        "category":    event.get("category", ""),
        "action":      event.get("action", ""),
        "timestamp":   event.get("timestamp", ""),
        "source_ip":   src,
        "username":    event.get("username", ""),
        "details":     details if isinstance(details, dict) else {},
        "disposition": disposition,
        "timeline":    [],
    }


def _safe_pdf(incident: dict) -> bytes:
    """Build the incident PDF; never raise."""
    try:
        from app.services.incident_report import build_incident_pdf
        return build_incident_pdf(incident)
    except Exception:
        return b""


# ---------------------------------------------------------------------------
# Inbound hooks
# ---------------------------------------------------------------------------

def notify_event(event: dict) -> None:
    """
    Inline gate called by ``log_event`` for every event. Cheap when the
    feature is disabled. Events passing the filter/cooldown/cap are queued
    for the background worker.
    """
    cfg = _cached_config()
    if not cfg or not cfg.get("enabled"):
        return
    if not _passes_filter(cfg, event):
        return
    if not _cooldown_ok(event, int(cfg.get("cooldown_minutes") or 0)):
        return
    # Phase 2.2: per-source cooldown — a single noisy attacker / signature
    # can't burn the global budget and starve other alerts.
    if not _per_source_cooldown_ok(
        event, int(cfg.get("per_source_cooldown_minutes") or 0)
    ):
        return

    # Phase 2.2: digest mode — buffer matching events and let the digest
    # ticker emit a single mail per window. The window itself is the rate
    # limit, so we skip the per-event hour cap on this branch.
    digest_window = int(cfg.get("digest_window_minutes") or 0)
    if digest_window > 0:
        _buffer_for_digest(event)
        start_mail_alert_worker()
        return

    conn = _open_conn()
    if conn is None:
        return
    try:
        cap = int(cfg.get("max_per_hour") or 0)
        hc = _hour_counter(conn)
        count = int(hc.get("count") or 0)
        if cap > 0 and count >= cap:
            if count == cap:  # log the "capped" notice exactly once per hour
                hc["count"] = count + 1
                _state_write(conn, _HOUR_KEY, json.dumps(hc))
                try:
                    from app.audit_log import log_event
                    log_event(category="mail", action="mail_alert_capped",
                              severity="medium", username="system",
                              remote_addr="", details={"max_per_hour": cap})
                except Exception:
                    pass
            return
        hc["count"] = count + 1
        _state_write(conn, _HOUR_KEY, json.dumps(hc))
    finally:
        try:
            conn.close()
        except Exception:
            pass

    try:
        _QUEUE.put_nowait({"kind": "alert", "event": dict(event)})
    except queue.Full:
        pass
    start_mail_alert_worker()


def send_incident_followup(kind: str, case_id=None, event_key: str = "",
                           target_tier: str = "", actor: str = "",
                           note: str = "") -> None:
    """
    Enqueue a follow-up incident email after a SOC analyst dispositions an
    alert. Called from the SOC routes (request context) — enqueue only, the
    worker does the SMTP. *kind* is ``"escalated"`` or ``"closed"``.
    """
    try:
        _QUEUE.put_nowait({
            "kind":        "followup",
            "followup":    kind,
            "case_id":     case_id,
            "event_key":   event_key or "",
            "target_tier": target_tier or "",
            "actor":       actor or "",
            "note":        note or "",
        })
        start_mail_alert_worker()
    except queue.Full:
        pass
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Background worker
# ---------------------------------------------------------------------------

def _worker() -> None:
    while True:
        job = _QUEUE.get()
        try:
            kind = job.get("kind") if isinstance(job, dict) else None
            if kind == "followup":
                _deliver_followup(job)
            elif kind == "digest":
                _deliver_digest((job or {}).get("events") or [])
            else:
                _deliver_alert((job or {}).get("event") or {})
        except Exception:
            pass
        finally:
            _QUEUE.task_done()


def _deliver_digest(events: list) -> None:
    """Send a single mail summarizing every event in ``events``. Called by
    ``_worker`` when ``digest_window_minutes`` > 0 batched matching alerts."""
    if not events:
        return
    conn = _open_conn()
    if conn is None:
        return
    try:
        cfg = get_config(conn)
        if not cfg or not cfg.get("enabled"):
            return
        recipients = resolve_recipients(conn)
        if not recipients:
            return
        subject = f"[SmartShield] Alert digest — {len(events)} event(s)"
        lines = [f"Smart Shield alert digest ({len(events)} events):", ""]
        for ev in events:
            title = _event_title(ev)
            sev   = (ev.get("severity") or "info").upper()
            ts    = ev.get("timestamp") or ev.get("created_at") or ""
            src   = (ev.get("details") or {}).get("src_ip", "") if isinstance(ev.get("details"), dict) else ""
            lines.append(f"  [{sev}] {ts} {title}" + (f" from {src}" if src else ""))
        text = "\n".join(lines) + "\n"
        ok, message = send_mail(cfg, recipients, subject, text)
    finally:
        try:
            conn.close()
        except Exception:
            pass
    _audit("mail_alert_digest_sent" if ok else "mail_alert_digest_failed", ok,
           {"recipients": len(recipients), "events": len(events),
            "message": message})


def _deliver_alert(event: dict) -> None:
    """Send the branded alert email; attach a PDF when auto-mitigated."""
    conn = _open_conn()
    if conn is None:
        return
    try:
        cfg = get_config(conn)
        if not cfg or not cfg.get("enabled"):
            return
        recipients = resolve_recipients(conn)
        if not recipients:
            return
        disposition = _detect_auto_disposition(conn, event)
        incident = _build_incident(event, disposition)
        subject  = _alert_subject(event, disposition)
        text     = _build_text(incident)
        html     = render_alert_html(incident, portal_url=cfg.get("portal_base_url", ""))
        pdf = _safe_pdf(incident) if disposition else b""
        ok, message = send_mail(cfg, recipients, subject, text, html_body=html,
                                pdf_bytes=pdf)
    finally:
        try:
            conn.close()
        except Exception:
            pass
    _audit("mail_alert_sent" if ok else "mail_alert_failed", ok,
           {"recipients": len(recipients), "message": message,
            "for_action": event.get("action"),
            "auto_mitigated": bool(disposition), "pdf": bool(pdf)})


def _deliver_followup(job: dict) -> None:
    """Send the 'incident handled' follow-up email after a SOC disposition."""
    conn = _open_conn()
    if conn is None:
        return
    try:
        cfg = get_config(conn)
        if not cfg or not cfg.get("enabled"):
            return

        incident, case = _load_case_incident(conn, job)
        if incident is None:
            return

        followup = job.get("followup")
        if followup == "escalated":
            tier = (job.get("target_tier") or "").upper()
            recipients = _users_at_tier(conn, tier)
            subject = (f"[SmartShield] Escalated to {tier} · "
                       f"{incident['title']}")
        else:  # closed
            recipients = resolve_recipients(conn)
            closure = (case or {}).get("closure_type") or "resolved"
            label = ("Closed (False Positive)"
                     if closure == "false_positive" else "Resolved")
            subject = f"[SmartShield] {label} · {incident['title']}"

        if not recipients:
            return
        text = _build_text(incident)
        html = render_alert_html(incident, portal_url=cfg.get("portal_base_url", ""))
        pdf  = _safe_pdf(incident)
        ok, message = send_mail(cfg, recipients, subject, text, html_body=html,
                                pdf_bytes=pdf, pdf_name="incident-report.pdf")
    finally:
        try:
            conn.close()
        except Exception:
            pass
    _audit("mail_followup_sent" if ok else "mail_followup_failed", ok,
           {"recipients": len(recipients) if recipients else 0,
            "message": message, "followup": job.get("followup"),
            "case_id": job.get("case_id")})


def _load_case_incident(conn, job: dict):
    """
    Build the incident dict for a follow-up email from the SIEM case (and,
    if available, the original event embedded in ``siem_cases.source_event``).
    Returns ``(incident, case_row_dict)`` or ``(None, None)``.
    """
    case = None
    case_id = job.get("case_id")
    if case_id:
        try:
            row = conn.execute(
                "SELECT * FROM siem_cases WHERE id = ?", (case_id,)
            ).fetchone()
            case = dict(row) if row else None
        except Exception:
            case = None

    # The original event — embedded in the case, or the events table.
    event = {}
    src = (case or {}).get("source_event") or ""
    if src:
        # New path: source_event holds the full event JSON.
        try:
            parsed = json.loads(src)
            if isinstance(parsed, dict) and parsed:
                event = parsed
        except Exception:
            event = {}
        # Fallback: SOC alerts-page case-open stores only the alert's `ts`
        # timestamp string. Look it up in the events table.
        if not event:
            try:
                row = conn.execute(
                    "SELECT ts, severity, category, action, username, "
                    "remote_addr, details FROM events WHERE ts = ? LIMIT 1",
                    (src,),
                ).fetchone()
                if row:
                    event = dict(row)
                    event["timestamp"] = event.get("ts", "")
                    try:
                        event["details"] = json.loads(event.get("details") or "{}")
                    except Exception:
                        event["details"] = {}
            except Exception:
                pass
    if not event and job.get("event_key"):
        # event_key may be either a legacy ISO timestamp or a v34+ event_uuid;
        # the escalate route now sends whichever it has. Try the uuid column
        # first since the timestamp column is not unique.
        handle = job["event_key"]
        try:
            row = conn.execute(
                "SELECT ts, severity, category, action, username, remote_addr, "
                "details, event_uuid FROM events WHERE event_uuid = ? LIMIT 1",
                (handle,),
            ).fetchone()
            if not row:
                row = conn.execute(
                    "SELECT ts, severity, category, action, username, "
                    "remote_addr, details, event_uuid "
                    "FROM events WHERE ts = ? ORDER BY id DESC LIMIT 1",
                    (handle,),
                ).fetchone()
            if row:
                event = dict(row)
                event["timestamp"] = event.get("ts", "")
                try:
                    event["details"] = json.loads(event.get("details") or "{}")
                except Exception:
                    event["details"] = {}
        except Exception:
            event = {}

    if not event and not case:
        return None, None

    # Normalize event-shape keys (source_event may use ts or timestamp).
    if event and "timestamp" not in event:
        event["timestamp"] = event.get("ts", "")

    actor = job.get("actor") or "SOC analyst"
    if job.get("followup") == "escalated":
        tier = (job.get("target_tier") or "").upper()
        disposition = {
            "kind": "soc", "actor": actor, "tier": tier,
            "outcome": f"Escalated to {tier}",
            "summary": f"Escalated to the {tier} response tier by {actor}.",
            "notes": job.get("note") or "",
        }
    else:
        closure = (case or {}).get("closure_type") or "resolved"
        outcome = ("False positive" if closure == "false_positive"
                   else "Resolved")
        disposition = {
            "kind": "soc", "actor": actor,
            "outcome": outcome,
            "summary": f"Case closed by {actor} — {outcome.lower()}.",
            "notes": job.get("note") or "",
        }

    # Prefer the original event's fields; fall back to the case.
    incident = _build_incident(event, disposition) if event else {
        "reference": str(case_id or ""), "title": "", "severity": "info",
        "category": "", "action": "", "timestamp": "", "source_ip": "",
        "username": "", "details": {}, "disposition": disposition,
        "timeline": [],
    }
    if case:
        incident["title"] = case.get("title") or incident.get("title") or "Security Incident"
        incident["severity"] = case.get("severity") or incident.get("severity")
        incident["reference"] = f"Case #{case_id}"
        incident["timeline"] = _case_timeline(conn, case_id)
    if not incident.get("title"):
        incident["title"] = "Security Incident"
    return incident, case


def _case_timeline(conn, case_id) -> list:
    """Return [(created_at, 'user: note'), ...] from siem_case_notes."""
    out = []
    try:
        for r in conn.execute(
            "SELECT created_at, created_by, note FROM siem_case_notes "
            "WHERE case_id = ? ORDER BY id", (case_id,)
        ):
            who = r["created_by"] or "system"
            out.append((str(r["created_at"] or ""), f"{who}: {r['note'] or ''}"))
    except Exception:
        pass
    return out


def _audit(action: str, ok: bool, details: dict) -> None:
    try:
        from app.audit_log import log_event
        log_event(category="mail", action=action,
                  severity="info" if ok else "medium",
                  username="system", remote_addr="", details=details)
    except Exception:
        pass


def start_mail_alert_worker() -> None:
    """Start the background sender thread + digest flush ticker (idempotent
    per process). The digest ticker is a no-op until an operator sets
    ``digest_window_minutes`` > 0 in mail_alerts_config."""
    if not _WORKER_STARTED.is_set():
        _WORKER_STARTED.set()
        threading.Thread(target=_worker, name="mail-alert-sender",
                         daemon=True).start()
    if not _DIGEST_TICK_STARTED.is_set():
        _DIGEST_TICK_STARTED.set()
        threading.Thread(target=_digest_ticker, name="mail-alert-digest",
                         daemon=True).start()
