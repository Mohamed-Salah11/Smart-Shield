#!/usr/bin/env python3
"""
tools/send_welcome_email.py
---------------------------
Send the post-install welcome email containing the setup claim code.

Invoked by bsd/install.sh after the final banner, only when the operator
typed an admin email at the install-time prompt. Stays self-contained: no
Flask app context, no DB writes beyond an audit-log row. Reuses
``app.services.mail_alerts.get_config`` (which carries the built-in
Gmail fallback) and ``send_mail`` for the actual SMTP send.

Exit codes
----------
0  success
2  bad arguments (missing --to / --lan-ip)
3  recipient validation failed
4  token file missing or empty
5  template render failure
6  SMTP send failed (config or transport)

The script prints a short human-readable line to stdout on success and
to stderr on failure — install.sh surfaces both verbatim.
"""

from __future__ import annotations

import argparse
import os
import re
import sys


# Project root resolves to two levels up (tools/ → app root).
_HERE      = os.path.dirname(os.path.abspath(__file__))
_PROJ_ROOT = os.path.dirname(_HERE)


def _eprint(msg: str) -> None:
    print(msg, file=sys.stderr)


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Send the Smart Shield welcome email (claim code).",
    )
    p.add_argument("--to", required=True, help="Recipient email address.")
    p.add_argument("--lan-ip", required=True,
                   help="Appliance LAN IP for the setup URL.")
    p.add_argument("--token-file",
                   default="/var/db/smartshield/setup_claim_token",
                   help="Path to the setup-claim-token file "
                        "(default: %(default)s).")
    p.add_argument("--dry-run", action="store_true",
                   help="Render bodies + print to stdout without sending.")
    return p.parse_args()


def _read_token(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as fh:
            tok = (fh.read() or "").strip()
    except OSError as exc:
        _eprint(f"Cannot read token file {path!r}: {exc}")
        sys.exit(4)
    if not tok:
        _eprint(f"Token file {path!r} is empty.")
        sys.exit(4)
    return tok


def _valid_email(addr: str) -> bool:
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", addr))


def _render(template_dir: str, claim_token: str, lan_ip: str,
            setup_url: str, support_email: str) -> tuple:
    """Render (html, text) bodies. Exits with code 5 on template error."""
    try:
        from jinja2 import Environment, FileSystemLoader, select_autoescape
    except ImportError as exc:
        _eprint(f"Jinja2 not available: {exc}")
        sys.exit(5)

    env = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(["html"]),
    )
    ctx = {
        "claim_token":   claim_token,
        "lan_ip":        lan_ip,
        "setup_url":     setup_url,
        "support_email": support_email,
    }
    try:
        html = env.get_template("email/welcome.html").render(**ctx)
        text = env.get_template("email/welcome.txt").render(**ctx)
    except Exception as exc:
        _eprint(f"Template render failed: {exc}")
        sys.exit(5)
    return html, text


def _log_send(recipient: str, ok: bool, message: str) -> None:
    """Best-effort audit-log row. Failure is non-fatal — we still exit
    with the SMTP outcome the caller cares about."""
    try:
        from app.audit_log import log_event
        log_event(
            category="mail",
            action="welcome_email_sent" if ok else "welcome_email_failed",
            severity="low" if ok else "medium",
            username="installer",
            remote_addr="",
            details={"recipient": recipient, "message": message[:400]},
        )
    except Exception:
        pass


def main() -> int:
    # Make the project importable BEFORE we import any app.* modules.
    if _PROJ_ROOT not in sys.path:
        sys.path.insert(0, _PROJ_ROOT)

    args = _parse_args()

    recipient = (args.to or "").strip()
    if not _valid_email(recipient):
        _eprint(f"Invalid recipient address: {recipient!r}")
        return 3

    token = _read_token(args.token_file)
    lan_ip = (args.lan_ip or "").strip() or "your-appliance"
    setup_url = f"https://{lan_ip}/setup"

    # Dry-run short-circuits the entire mail backend (no DB, no SMTP, no
    # audit-log import). Useful for editing the template on dev machines
    # that don't have the full appliance env (.env, dotenv, etc.).
    if args.dry_run:
        html, text = _render(
            template_dir=os.path.join(_PROJ_ROOT, "templates"),
            claim_token=token,
            lan_ip=lan_ip,
            setup_url=setup_url,
            support_email="dry-run@example.com",
        )
        print("=== welcome.txt ===")
        print(text)
        print("\n=== welcome.html (first 400 chars) ===")
        print(html[:400] + ("..." if len(html) > 400 else ""))
        print(f"\n[dry-run] Would send to: {recipient}")
        return 0

    # Resolve SMTP config (built-in fallback fills in when DB is blank).
    try:
        from app.audit_log import _events_db
        from app.services.mail_alerts import get_config, send_mail
    except Exception as exc:
        _eprint(f"Cannot import mail backend: {exc}")
        return 6

    conn = _events_db()
    cfg = {}
    if conn is not None:
        try:
            cfg = get_config(conn) or {}
        finally:
            try:
                conn.close()
            except Exception:
                pass
    if not cfg.get("smtp_username") or not cfg.get("smtp_app_password"):
        _eprint("SMTP credentials are not available (no UI config and no "
                "built-in fallback).")
        return 6

    support_email = (cfg.get("smtp_username") or "").strip()

    html, text = _render(
        template_dir=os.path.join(_PROJ_ROOT, "templates"),
        claim_token=token,
        lan_ip=lan_ip,
        setup_url=setup_url,
        support_email=support_email,
    )

    ok, message = send_mail(
        cfg,
        [recipient],
        "Welcome to Smart Shield — your setup claim code",
        text,
        html,
    )
    _log_send(recipient, ok, message)
    if ok:
        print(f"Welcome email sent to {recipient}: {message}")
        return 0
    _eprint(f"Welcome email to {recipient} failed: {message}")
    return 6


if __name__ == "__main__":
    sys.exit(main())
