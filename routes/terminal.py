"""
routes/terminal.py
------------------
Smart Shield Live CLI Terminal.

Two endpoints plus a token issuer:
  POST /terminal/api/exec        — legacy single-command executor (kept for compat)
  GET  /terminal/api/ws-ticket   — short-lived signed ticket for the WS upgrade
  WS   /terminal/ws              — live PTY WebSocket session

Hardening (Phase 6):
  1. ``terminal_enabled`` setting on advanced_admin_access — off by default.
     All routes 404 when off so the feature is not even probable.
  2. Superuser-only.
  3. Recent reauth (last 300s) required before opening a session.
  4. WS upgrade requires a single-use signed ticket (max 60s old) bound to
     the user-id + remote IP. Origin check stays.
  5. Commands and session events are audit-logged with secrets redacted.
  6. UI banner in the floating CLI panel (templates/base.html) explains the
     privilege model so operators are not surprised by audit lines.
"""

import hmac
import hashlib
import json
import logging
import os
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone

from flask import Blueprint, abort, current_app, jsonify, request, session

from app.audit_log import log_event, redact_secrets
from app.auth_utils import login_required
from app.database import get_db

logger = logging.getLogger(__name__)

terminal_bp = Blueprint("terminal", __name__, url_prefix="/terminal")


# ---------------------------------------------------------------------------
# Settings helpers
# ---------------------------------------------------------------------------

def terminal_is_enabled() -> bool:
    """Return True only when both the deployment-time env flag
    (SMARTSHIELD_TERMINAL_ENABLED=1) **and** the runtime DB toggle
    (advanced_admin_access.terminal_enabled) are on. The env flag lets an
    operator harden a deployment by removing the feature entirely; the DB
    toggle remains the day-to-day on/off switch a superuser sees in the UI."""
    if not current_app.config.get("TERMINAL_ENABLED"):
        return False
    try:
        row = get_db().execute(
            "SELECT terminal_enabled FROM advanced_admin_access LIMIT 1"
        ).fetchone()
        return bool(row and row["terminal_enabled"])
    except Exception:
        logger.warning("Failed to read terminal_enabled DB flag; defaulting to off", exc_info=True)
        return False


def _reauth_age_seconds() -> float:
    """How long ago the current session re-authenticated. Returns +inf when
    no reauth has happened in this session yet."""
    raw = session.get("reauth_time")
    if not raw:
        return float("inf")
    try:
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt).total_seconds()
    except (ValueError, TypeError):
        return float("inf")


TERMINAL_REAUTH_TTL = 300        # seconds — same as global reauth window
TERMINAL_TICKET_TTL = 60         # seconds — WS handshake must follow promptly
_TERMINAL_TICKET_VERSION = "v1"


def _ticket_key() -> bytes:
    """Derive a per-app HMAC key for terminal tickets. Reuses Flask's
    SECRET_KEY so tickets stay valid across worker processes and rotate on
    secret rotation."""
    secret = current_app.config.get("SECRET_KEY") or ""
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    return secret


def _issue_ticket(user_id: int, remote_addr: str) -> str:
    """Return ``v1.<user_id>.<issued_at>.<sig>`` — a single-use ticket that
    the browser must present on the WS upgrade. Bound to user-id + IP so a
    leaked ticket is useless from another network."""
    issued = int(time.time())
    payload = f"{_TERMINAL_TICKET_VERSION}.{user_id}.{issued}.{remote_addr}"
    sig = hmac.new(_ticket_key(), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{_TERMINAL_TICKET_VERSION}.{user_id}.{issued}.{sig}"


def _validate_ticket(ticket: str, user_id: int, remote_addr: str) -> bool:
    if not ticket:
        return False
    parts = ticket.split(".")
    if len(parts) != 4:
        return False
    version, tk_user, issued, sig = parts
    if version != _TERMINAL_TICKET_VERSION:
        return False
    try:
        if int(tk_user) != int(user_id):
            return False
        issued_i = int(issued)
    except ValueError:
        return False
    if (time.time() - issued_i) > TERMINAL_TICKET_TTL:
        return False
    expected = hmac.new(
        _ticket_key(),
        f"{version}.{tk_user}.{issued}.{remote_addr}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, sig)


# Tickets are single-use across ALL gunicorn workers. The unique ticket
# signature is recorded in a shared SQLite table; the atomic INSERT (PRIMARY
# KEY collision = already consumed) is the cross-process replay guard. A
# process-local dict would let a ticket be replayed against another worker
# within its 60s TTL, so it is not sufficient.
def _ensure_ticket_table(conn) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS terminal_ticket_nonces (
            nonce       TEXT PRIMARY KEY,
            user_id     INTEGER NOT NULL,
            issued_at   INTEGER NOT NULL,
            consumed_at INTEGER NOT NULL
        )
        """
    )


def _claim_ticket(user_id: int, ticket: str) -> bool:
    parts = ticket.split(".")
    if len(parts) != 4:
        return False
    sig = parts[3]
    try:
        issued_i = int(parts[2])
    except ValueError:
        return False

    now = int(time.time())
    conn = get_db()
    try:
        _ensure_ticket_table(conn)
        # Opportunistic cleanup of expired nonces so the table stays small.
        conn.execute(
            "DELETE FROM terminal_ticket_nonces WHERE consumed_at < ?",
            (now - TERMINAL_TICKET_TTL,),
        )
        # The signature is globally unique per ticket; INSERT-or-fail is the
        # atomic single-use claim.
        conn.execute(
            "INSERT INTO terminal_ticket_nonces (nonce, user_id, issued_at, consumed_at) "
            "VALUES (?, ?, ?, ?)",
            (sig, user_id, issued_i, now),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        # PRIMARY KEY collision → ticket already consumed by some worker.
        try:
            conn.rollback()
        except Exception:
            pass
        return False
    except Exception:
        logger.warning("terminal ticket claim failed", exc_info=True)
        try:
            conn.rollback()
        except Exception:
            pass
        return False


def _abort_if_disabled():
    """404 when the appliance console feature is turned off — chosen over
    403 so the endpoint is indistinguishable from a missing route to anyone
    without the enable flag."""
    if not terminal_is_enabled():
        abort(404)


# ---------------------------------------------------------------------------
# HTTP endpoints
# ---------------------------------------------------------------------------

@terminal_bp.route("/check", methods=["GET"])
@login_required
def terminal_check():
    """Probe used by the CLI panel JS to distinguish nginx WS misconfig from a
    plain backend-down condition. Returns terminal_enabled so the UI can hide
    the console button when the feature is off."""
    return jsonify({
        "ok": True,
        "platform": sys.platform,
        "ws_path": "/terminal/ws",
        "superuser": bool(session.get("is_superuser")),
        "terminal_enabled": terminal_is_enabled(),
        "reauth_age": _reauth_age_seconds(),
        "reauth_ttl": TERMINAL_REAUTH_TTL,
    })


@terminal_bp.route("/api/ws-ticket", methods=["POST"])
@login_required
def terminal_ws_ticket():
    """Issue a single-use ticket for the WS upgrade. The browser must hit
    this endpoint after re-authenticating and present the returned ticket
    on the WS query string within TERMINAL_TICKET_TTL seconds."""
    _abort_if_disabled()
    if not session.get("is_superuser"):
        return jsonify({"ok": False, "error": "Permission denied"}), 403
    if _reauth_age_seconds() > TERMINAL_REAUTH_TTL:
        return jsonify({
            "ok": False,
            "reauth_required": True,
            "message": "Re-authenticate to open the appliance console.",
        }), 403

    user_id = session.get("user_id") or 0
    ticket = _issue_ticket(user_id, request.remote_addr or "")
    log_event(
        category="privileged", action="terminal_ticket_issued",
        username=session.get("username"), remote_addr=request.remote_addr,
        details={"ttl": TERMINAL_TICKET_TTL},
    )
    return jsonify({
        "ok": True,
        "ticket": ticket,
        "ttl": TERMINAL_TICKET_TTL,
    })


@terminal_bp.route("/api/exec", methods=["POST"])
@login_required
def terminal_exec():
    """REMOVED (Phase 4.1): the legacy one-shot ``sh -c`` executor is gone.

    The live PTY WebSocket at /terminal/ws supersedes it and carries the
    full hardening stack (enable flag, superuser, recent-reauth, signed
    ticket, Origin check, per-command audit). This endpoint always 404s now
    so old clients fail loudly instead of silently falling back to a
    less-audited code path. Audit-log every attempt so SOC can spot any
    client still calling it.
    """
    log_event(
        category="security",
        action="terminal_exec_legacy_blocked",
        username=session.get("username"),
        remote_addr=request.remote_addr,
        details={"path": "/terminal/api/exec"},
    )
    abort(404)


# ---------------------------------------------------------------------------
# Live PTY WebSocket handler — registered via Sock in app/__init__.py
# ---------------------------------------------------------------------------

def terminal_ws(ws):
    """
    Live interactive terminal over WebSocket. See module docstring for the
    layered hardening. The handshake order is deliberately:
        enable flag → superuser → reauth → Origin → ticket
    so an attacker probing each layer only sees the most generic failure
    that still lets a legitimate operator self-diagnose.
    """
    if not terminal_is_enabled():
        try:
            ws.send("\r\n\x1b[31m[Appliance console is disabled]\x1b[0m\r\n")
        except Exception:
            pass
        return

    if not session.get("is_superuser"):
        ws.send("\r\n\x1b[31m[Permission denied — superuser only]\x1b[0m\r\n")
        return

    if _reauth_age_seconds() > TERMINAL_REAUTH_TTL:
        ws.send("\r\n\x1b[31m[Re-authentication required — close the console "
                "and reopen after entering your password]\x1b[0m\r\n")
        return

    # WebSocket Origin check — reject cross-site WebSocket hijacking. A browser
    # always sends Origin on a WS handshake; it must match the page's own host.
    from urllib.parse import urlparse
    _origin = request.headers.get("Origin", "")
    if _origin:
        _origin_host = urlparse(_origin).netloc
        if _origin_host and _origin_host != request.host:
            ws.send("\r\n\x1b[31m[Rejected — WebSocket Origin mismatch]\x1b[0m\r\n")
            log_event(
                category="security", action="terminal_origin_rejected",
                username=session.get("username"), remote_addr="ws",
                details={"origin": _origin[:200], "host": request.host},
            )
            return

    # Single-use signed ticket. The page must POST /terminal/api/ws-ticket
    # immediately before opening the socket and send the result back as
    # ?t=<ticket> on the upgrade URL.
    user_id = session.get("user_id") or 0
    ticket = request.args.get("t", "")
    if not _validate_ticket(ticket, user_id, request.remote_addr or ""):
        ws.send("\r\n\x1b[31m[Rejected — invalid or expired console ticket]\x1b[0m\r\n")
        log_event(
            category="security", action="terminal_ticket_rejected",
            username=session.get("username"), remote_addr="ws",
            details={"reason": "invalid_or_expired"},
        )
        return
    if not _claim_ticket(user_id, ticket):
        ws.send("\r\n\x1b[31m[Rejected — console ticket already used]\x1b[0m\r\n")
        log_event(
            category="security", action="terminal_ticket_rejected",
            username=session.get("username"), remote_addr="ws",
            details={"reason": "replay"},
        )
        return

    # PTY is a Unix-only feature
    if sys.platform == "win32":
        ws.send("\r\n\x1b[33m[Live PTY terminal not available on Windows dev host. "
                "Deploy on FreeBSD for full functionality.]\x1b[0m\r\n")
        _run_win32_fallback(ws)
        return

    import fcntl
    import pty
    import select
    import struct
    import termios
    import threading

    _term_user = session.get("username")
    log_event(
        category="privileged", action="terminal_session_opened",
        username=_term_user, remote_addr="ws",
        details={"shell": "/bin/tcsh" if sys.platform.startswith("freebsd") else "/bin/sh"},
    )

    # Per-session command buffer. Each typed shell line is emitted as a single
    # audit event on Enter so the SOC can see exactly what the operator ran in
    # the live PTY (handles backspace, Ctrl-U, Ctrl-C, and skips ESC/arrow
    # sequences so the recorded text matches what the shell actually executed).
    _cmd_buf = []  # list of chars; using a list avoids repeated str slicing

    def _emit_cmd(action: str):
        cmd_str = "".join(_cmd_buf).rstrip("\r\n").strip()
        _cmd_buf.clear()
        if not cmd_str:
            return
        try:
            log_event(
                category="privileged", action=action,
                username=_term_user, remote_addr="ws",
                details={"cmd": redact_secrets(cmd_str[:1000])},
            )
        except Exception:
            logger.exception("Failed to audit terminal command (action=%s)", action)

    def _feed_keystrokes(data: bytes):
        """Update the command buffer from raw PTY input bytes."""
        i = 0
        while i < len(data):
            b = data[i]
            # ESC / CSI sequences (arrow keys, history navigation, function keys)
            if b == 0x1b:
                # Skip the ESC byte and any following CSI/SS3 sequence so we
                # don't pollute the buffer with control codes.
                i += 1
                if i < len(data) and data[i] in (0x5b, 0x4f):  # '[' or 'O'
                    i += 1
                    while i < len(data) and not (0x40 <= data[i] <= 0x7e):
                        i += 1
                    if i < len(data):
                        i += 1  # consume final byte of the CSI sequence
                continue
            # Newline → flush as executed command
            if b in (0x0d, 0x0a):
                _emit_cmd("terminal_command")
                i += 1
                continue
            # Backspace / DEL → pop last char
            if b in (0x08, 0x7f):
                if _cmd_buf:
                    _cmd_buf.pop()
                i += 1
                continue
            # Ctrl-U → clear current line
            if b == 0x15:
                _cmd_buf.clear()
                i += 1
                continue
            # Ctrl-C → flush whatever was buffered as an aborted command
            if b == 0x03:
                _emit_cmd("terminal_command_aborted")
                i += 1
                continue
            # Drop any other non-printable control bytes (except TAB)
            if b < 0x20 and b != 0x09:
                i += 1
                continue
            _cmd_buf.append(chr(b))
            i += 1

    shell = "/bin/tcsh" if sys.platform.startswith("freebsd") else "/bin/sh"
    master_fd, slave_fd = pty.openpty()

    # Set a sensible default window size
    fcntl.ioctl(master_fd, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))

    env = {**os.environ, "TERM": "xterm-256color", "SHELL": shell}
    if sys.platform.startswith("freebsd"):
        env.setdefault("HOME", "/root")

    proc = subprocess.Popen(
        [shell],
        stdin=slave_fd, stdout=slave_fd, stderr=slave_fd,
        close_fds=True, env=env,
    )
    os.close(slave_fd)

    stop = threading.Event()

    def _read_pty():
        """Background thread: read PTY output and forward to WebSocket."""
        while not stop.is_set():
            try:
                r, _, _ = select.select([master_fd], [], [], 0.05)
                if master_fd in r:
                    data = os.read(master_fd, 4096)
                    if data:
                        ws.send(data.decode("utf-8", errors="replace"))
                if proc.poll() is not None:
                    # Shell exited
                    try:
                        ws.send("\r\n\x1b[33m[Shell exited]\x1b[0m\r\n")
                    except Exception:
                        pass
                    break
            except Exception:
                break

    reader = threading.Thread(target=_read_pty, daemon=True)
    reader.start()

    try:
        while True:
            msg = ws.receive()
            if msg is None:
                break

            # Resize event from XTerm.js FitAddon
            try:
                evt = json.loads(msg)
                if evt.get("type") == "resize":
                    rows = max(1, int(evt.get("rows", 24)))
                    cols = max(1, int(evt.get("cols", 80)))
                    fcntl.ioctl(master_fd, termios.TIOCSWINSZ,
                                struct.pack("HHHH", rows, cols, 0, 0))
                    continue
            except (json.JSONDecodeError, TypeError, KeyError, ValueError):
                pass

            # Raw keystroke → PTY, with a parallel command-audit buffer.
            raw = msg if isinstance(msg, bytes) else msg.encode()
            try:
                _feed_keystrokes(raw)
            except Exception:
                pass  # never let audit logic break the terminal
            try:
                os.write(master_fd, raw)
            except OSError:
                break

    except Exception:
        pass

    finally:
        stop.set()
        # Flush any in-progress command line on disconnect so a half-typed
        # but never-Enter'd line still leaves a record.
        try:
            if _cmd_buf:
                _emit_cmd("terminal_command_aborted")
        except Exception:
            pass
        log_event(
            category="privileged", action="terminal_session_closed",
            username=_term_user, remote_addr="ws", details={},
        )
        try:
            proc.terminate()
        except Exception:
            pass
        try:
            os.close(master_fd)
        except Exception:
            pass


def _run_win32_fallback(ws):
    """Minimal command-runner over WebSocket for Windows dev host (no PTY)."""
    ws.send("SmartShield Root Console — Windows dev mode (no PTY). "
            "Type a command and press Enter.\r\n\r\n$ ")
    buf = ""
    while True:
        try:
            msg = ws.receive()
        except Exception:
            break
        if msg is None:
            break
        buf += msg if isinstance(msg, str) else msg.decode("utf-8", errors="replace")
        # Echo character back
        ws.send(msg if isinstance(msg, str) else msg.decode("utf-8", errors="replace"))
        if "\r" in buf or "\n" in buf:
            cmd = buf.strip().replace("\r\n", "").replace("\r", "").replace("\n", "")
            buf = ""
            if cmd.lower() in ("exit", "quit"):
                ws.send("\r\nGoodbye.\r\n")
                break
            try:
                res = subprocess.run(
                    ["cmd", "/c", cmd] if sys.platform == "win32" else ["sh", "-c", cmd],
                    capture_output=True, text=True, timeout=30,
                )
                out = (res.stdout or "") + (res.stderr or "")
                ws.send("\r\n" + out.replace("\n", "\r\n"))
            except Exception as e:
                ws.send(f"\r\nError: {e}\r\n")
            ws.send("$ ")
