"""
app/services/ids_blocker.py
---------------------------
IDS block-on-alert: turn high-severity Suricata alerts into live PF blocks.

When the SIEM collector processes a Suricata alert, :func:`maybe_block` adds the
attacker's source IP to the persistent ``<ss_ids_blocks>`` PF table — already
declared and enforced by ``pf_generator`` (``block in log quick from
<ss_ids_blocks>`` at the top of the hardening section) — so the firewall drops
it immediately, and records a bookkeeping row in ``ids_blocked_ips`` so the
block can expire on a TTL and be listed / cleared from the UI. The
``ids_blocker_expirer`` background thread ages entries out every 60s.

Policy (all configurable on ``ids_config``):
  * Block only when severity is in {high, critical} OR the alert's
    ``signature_id`` is in ``auto_block_sids`` (comma-separated).
  * TTL = ``auto_block_ttl_seconds`` (default 3600s).
  * Per-process rate limit: <= 60 *new* blocks / 5 min, so a noisy ruleset
    can't blow the PF table. Re-alerts for an already-blocked IP are free
    no-ops (no PF churn, no rate-budget spend).

The DB bookkeeping is written on every platform so the UI and tests see it; the
PF mutation is best-effort and FreeBSD-only (``pfctl`` is absent elsewhere).
"""

import ipaddress
import logging
import sys
import threading
import time

_log = logging.getLogger(__name__)

# Reuse the PF table pf_generator already declares + blocks on, and that
# priv_helper already allowlists. (See pf_generator hardening section.)
_PF_TABLE = "ss_ids_blocks"

_DEFAULT_TTL = 3600       # seconds
_RATE_MAX = 60            # max new blocks ...
_RATE_WINDOW = 300        # ... per 5-minute window
_EXPIRE_INTERVAL = 60     # expirer tick (seconds)

_BLOCK_SEVERITIES = ("high", "critical")

_rate_lock = threading.Lock()
_rate_events: list = []   # epoch timestamps of recent *new* block actions


# ---------------------------------------------------------------------------
# Policy helpers
# ---------------------------------------------------------------------------

def _rate_ok(now: float) -> bool:
    """True if a new block is within the per-process rate budget (and records it)."""
    with _rate_lock:
        cutoff = now - _RATE_WINDOW
        while _rate_events and _rate_events[0] < cutoff:
            _rate_events.pop(0)
        if len(_rate_events) >= _RATE_MAX:
            return False
        _rate_events.append(now)
        return True


def _auto_block_policy(conn) -> "tuple[int, set]":
    """Return ``(ttl_seconds, sid_set)`` from ids_config. Safe defaults on error."""
    ttl = _DEFAULT_TTL
    sids: set = set()
    try:
        row = conn.execute(
            "SELECT auto_block_ttl_seconds, auto_block_sids FROM ids_config WHERE id=1"
        ).fetchone()
        if row:
            try:
                ttl = int((row["auto_block_ttl_seconds"] if hasattr(row, "keys")
                           else row[0]) or _DEFAULT_TTL)
            except (TypeError, ValueError):
                ttl = _DEFAULT_TTL
            raw = (row["auto_block_sids"] if hasattr(row, "keys") else row[1]) or ""
            sids = {s.strip() for s in str(raw).split(",") if s.strip()}
    except Exception:
        pass
    if ttl <= 0:
        ttl = _DEFAULT_TTL
    return ttl, sids


def _should_block(severity: str, signature_id: str, sid_set: set) -> bool:
    if (severity or "").lower() in _BLOCK_SEVERITIES:
        return True
    sid = (signature_id or "").strip()
    return bool(sid and sid in sid_set)


# ---------------------------------------------------------------------------
# PF table mutation (FreeBSD-only, best-effort)
# ---------------------------------------------------------------------------

def _pf_add(ip: str) -> bool:
    if not sys.platform.startswith("freebsd"):
        return False
    try:
        from app.services.priv_helper import run_privileged
        r = run_privileged("pf.table_add", table=_PF_TABLE, ip=ip)
        return r.returncode == 0
    except Exception as exc:
        _log.warning("ids_blocker: pf.table_add failed for %s: %s", ip, exc)
        return False


def _pf_delete(ip: str) -> bool:
    if not sys.platform.startswith("freebsd"):
        return False
    try:
        from app.services.priv_helper import run_privileged
        r = run_privileged("pf.table_delete", table=_PF_TABLE, ip=ip)
        return r.returncode == 0
    except Exception as exc:
        _log.warning("ids_blocker: pf.table_delete failed for %s: %s", ip, exc)
        return False


def _is_active(conn, ip: str, now: float) -> bool:
    try:
        row = conn.execute(
            "SELECT 1 FROM ids_blocked_ips WHERE ip=? AND expires_at > ? LIMIT 1",
            (ip, now),
        ).fetchone()
        return row is not None
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def maybe_block(conn, *, src_ip: str, severity: str = "", signature: str = "",
                signature_id: str = "", source_alert_id: str = "") -> "dict | None":
    """Block ``src_ip`` if policy allows. Returns a result dict on block, else None.

    Idempotent per IP: an already-active block is a free no-op (no PF add, no
    rate-budget spend). Never raises — a failure here must not break the
    collector loop.
    """
    ip = (src_ip or "").strip()
    if not ip:
        return None
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return None

    ttl, sids = _auto_block_policy(conn)
    if not _should_block(severity, signature_id, sids):
        return None

    now = time.time()
    if _is_active(conn, ip, now):
        return None  # already blocked — don't churn PF or burn the rate budget

    if not _rate_ok(now):
        _log.warning("ids_blocker: rate limit hit (%d/%ds) — skipping block of %s",
                     _RATE_MAX, _RATE_WINDOW, ip)
        return None

    expires_at = now + ttl
    try:
        conn.execute(
            "INSERT INTO ids_blocked_ips (ip, source_alert_id, signature, severity, "
            "added_at, expires_at) VALUES (?,?,?,?,?,?)",
            (ip, source_alert_id or "", signature or "", (severity or "").lower(),
             now, expires_at),
        )
        conn.commit()
    except Exception as exc:
        _log.warning("ids_blocker: DB insert failed for %s: %s", ip, exc)
        return None

    pf_ok = _pf_add(ip)

    try:
        from app.audit_log import log_event
        log_event(category="security", action="ids_auto_block", severity="high",
                  username="system", remote_addr=ip,
                  details={"ip": ip, "signature": signature,
                           "signature_id": signature_id, "severity": severity,
                           "ttl_seconds": ttl, "pf_ok": pf_ok,
                           "source_alert_id": source_alert_id})
    except Exception:
        pass

    return {"ok": True, "ip": ip, "expires_at": expires_at,
            "ttl_seconds": ttl, "pf_ok": pf_ok}


def list_blocked(conn) -> list:
    """Active blocks (``expires_at`` in the future), newest first."""
    now = time.time()
    try:
        rows = conn.execute(
            "SELECT ip, source_alert_id, signature, severity, added_at, expires_at "
            "FROM ids_blocked_ips WHERE expires_at > ? ORDER BY added_at DESC",
            (now,),
        ).fetchall()
        return [dict(r) for r in rows]
    except Exception:
        return []


def unblock(conn, ip: str, actor: str = "admin") -> dict:
    """Manually remove an IP from the block table + the live PF table."""
    ip = (ip or "").strip()
    if not ip:
        return {"ok": False, "message": "ip is required"}
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {"ok": False, "message": "invalid IP"}
    try:
        conn.execute("DELETE FROM ids_blocked_ips WHERE ip=?", (ip,))
        conn.commit()
    except Exception as exc:
        return {"ok": False, "message": f"DB delete failed: {exc}"}
    _pf_delete(ip)
    try:
        from app.audit_log import log_event
        log_event(category="security", action="ids_unblock", severity="medium",
                  username=actor, remote_addr=ip, details={"ip": ip})
    except Exception:
        pass
    return {"ok": True, "ip": ip, "message": f"{ip} unblocked"}


def expire_blocks(conn, ttl_hint: "int | None" = None) -> dict:
    """Drop expired blocks: bulk-expire the PF table by age + delete stale DB rows.

    Returns ``{"ok": bool, "expired": int}`` (``expired`` = DB rows removed).
    """
    now = time.time()

    # PF-side: expire table entries older than the configured TTL (FreeBSD-only).
    if sys.platform.startswith("freebsd"):
        ttl = ttl_hint if ttl_hint is not None else _auto_block_policy(conn)[0]
        try:
            from app.services.priv_helper import run_privileged
            run_privileged("pf.table_expire", table=_PF_TABLE, seconds=str(int(ttl)))
        except Exception as exc:
            _log.warning("ids_blocker: pf.table_expire failed: %s", exc)

    # DB-side: delete rows whose TTL has passed.
    try:
        cur = conn.execute("DELETE FROM ids_blocked_ips WHERE expires_at < ?", (now,))
        conn.commit()
        expired = cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
    except Exception as exc:
        return {"ok": False, "expired": 0, "message": str(exc)}
    return {"ok": True, "expired": expired}


# ---------------------------------------------------------------------------
# Background expirer thread
# ---------------------------------------------------------------------------

_EXPIRER_STARTED = False
_EXPIRER_LOCK = threading.Lock()


def _expirer_loop():
    while True:
        try:
            from app.audit_log import _events_db
            conn = _events_db()
            if conn is not None:
                try:
                    expire_blocks(conn)
                finally:
                    try:
                        conn.close()
                    except Exception:
                        pass
        except Exception as exc:
            _log.warning("ids_blocker_expirer: loop error: %s", exc)
        time.sleep(_EXPIRE_INTERVAL)


def start_ids_blocker_expirer() -> None:
    """Start the 60s expirer daemon thread (idempotent; FreeBSD-only)."""
    global _EXPIRER_STARTED
    if not sys.platform.startswith("freebsd"):
        _log.debug("ids_blocker: non-FreeBSD — expirer not started")
        return
    with _EXPIRER_LOCK:
        if _EXPIRER_STARTED:
            return
        _EXPIRER_STARTED = True
    t = threading.Thread(target=_expirer_loop, name="ids-blocker-expirer", daemon=True)
    t.start()
    _log.info("ids_blocker_expirer: daemon started (interval=%ds)", _EXPIRE_INTERVAL)
