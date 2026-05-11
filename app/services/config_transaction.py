"""
config_transaction.py
----------------------
Global configuration transaction manager for Smart Shield.

A ConfigTransaction groups one or more service apply operations into a
best-effort atomic unit.  If any step fails, all previously-applied steps
in the same transaction are rolled back in reverse dependency order.

Usage
-----
    from app.services.config_transaction import ConfigTransaction
    from app.services.pf_generator import reload_pf_rules, rollback_pf

    with ConfigTransaction(conn, "firewall_change", applied_by="admin") as txn:
        txn.apply("pf_firewall", reload_pf_rules, conn,
                  rollback_fn=rollback_pf)
    # if reload_pf_rules returns ok=False or raises, rollback_pf() is called

Design notes
------------
- apply_fn must return {"ok": bool, "message": str} or raise on failure.
- rollback_fn, if provided, is called with no arguments.
- Rollback handlers can also be pre-registered via register_rollback().
- The transaction does not use database locking — it is cooperative.
- On non-FreeBSD the transaction runs in dry-run mode automatically.
"""

import sys
import time
import logging
from typing import Callable, Optional

_log = logging.getLogger(__name__)

_ON_FREEBSD = sys.platform.startswith("freebsd")

# ---------------------------------------------------------------------------
# Global rollback registry
# ---------------------------------------------------------------------------

_ROLLBACK_HANDLERS: dict = {}


def register_rollback(feature_key: str, handler: Callable) -> None:
    """Pre-register a rollback function for a feature key."""
    _ROLLBACK_HANDLERS[feature_key] = handler


# ---------------------------------------------------------------------------
# Dependency order — services applied in this order, rolled back in reverse
# ---------------------------------------------------------------------------

DEPENDENCY_ORDER = [
    "network_interfaces",
    "routing",
    "virtual_ips",
    "high_availability",
    "nat",
    "pf_firewall",
    "firewall_schedules",
    "dns_resolver",
    "dns_filtering",
    "dhcpv4",
    "dhcpv6",
    "captive_portal",
    "openvpn",
    "ipsec",
    "l2tp",
    "suricata_ids",
    "suricata_ips",
    "ddns",
    "ntp",
    "snmp",
    "upnp",
    "igmp_proxy",
    "mrtg",
    "siem",
]


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class TransactionError(RuntimeError):
    """Raised when a transaction step fails after rollback was attempted."""


# ---------------------------------------------------------------------------
# ConfigTransaction
# ---------------------------------------------------------------------------

class ConfigTransaction:
    """
    Context manager that applies service configs in dependency order and
    rolls back all completed steps if any step fails.

    Parameters
    ----------
    conn         SQLite connection for apply-state tracking
    name         Human-readable transaction label (logged and stored)
    applied_by   Username or identifier for audit trail
    dry_run      Force dry-run mode regardless of runtime_mode
    """

    def __init__(self, conn, name: str = "config_change",
                 applied_by: str = "system", dry_run: bool = False):
        self.conn        = conn
        self.name        = name
        self.applied_by  = applied_by
        self._dry_run    = dry_run or not _ON_FREEBSD
        self._steps: list = []          # [(feature_key, rollback_fn), ...]
        self._errors: list = []
        self.transaction_id = f"{name}_{int(time.time())}"

        _log.info("[txn:%s] started (dry_run=%s)", self.transaction_id, self._dry_run)

    # ------------------------------------------------------------------
    # apply() — execute one step of the transaction
    # ------------------------------------------------------------------

    def apply(self, feature_key: str, apply_fn: Callable,
              *args, rollback_fn: Optional[Callable] = None, **kwargs) -> dict:
        """
        Apply one service step within this transaction.

        Returns {"ok": bool, "message": str, "feature": feature_key}.
        On failure, all previously-completed steps are rolled back and
        TransactionError is raised.
        """
        from app.services.apply_state import (
            record_apply_start, record_apply_result, record_dry_run,
        )

        if self._dry_run:
            if self.conn is not None:
                record_dry_run(self.conn, feature_key, applied_by=self.applied_by)
            _log.info("[txn:%s] dry-run %s", self.transaction_id, feature_key)
            return {"ok": True, "message": "dry-run", "feature": feature_key}

        job_id = None
        if self.conn is not None:
            job_id = record_apply_start(
                self.conn, feature_key,
                applied_by=self.applied_by,
                notes=f"transaction:{self.transaction_id}",
            )

        try:
            result = apply_fn(*args, **kwargs)
            if not isinstance(result, dict):
                raise TypeError(
                    f"apply_fn for '{feature_key}' returned {type(result).__name__}, expected dict"
                )
            ok      = result.get("ok", False)
            message = result.get("message", "")

            if not ok:
                raise RuntimeError(message or f"{feature_key} apply returned ok=False")

            if self.conn is not None and job_id is not None:
                record_apply_result(self.conn, job_id, ok=True, message=message)
            rb = rollback_fn or _ROLLBACK_HANDLERS.get(feature_key)
            self._steps.append((feature_key, rb))
            _log.info("[txn:%s] applied %s", self.transaction_id, feature_key)
            return {"ok": True, "message": message, "feature": feature_key}

        except Exception as exc:
            if self.conn is not None and job_id is not None:
                record_apply_result(self.conn, job_id, ok=False, message=str(exc))
            self._errors.append({"feature": feature_key, "error": str(exc)})
            _log.error("[txn:%s] failed %s: %s", self.transaction_id, feature_key, exc)
            rb_count = self._rollback_all()
            raise TransactionError(
                f"Step '{feature_key}' failed: {exc}. "
                f"Rolled back {rb_count} prior step(s)."
            ) from exc

    # ------------------------------------------------------------------
    # Internal rollback
    # ------------------------------------------------------------------

    def _rollback_all(self) -> int:
        """Roll back every applied step in reverse order. Returns count attempted."""
        count = 0
        for feature_key, rb_fn in reversed(self._steps):
            count += 1
            if rb_fn is None:
                _log.warning("[txn:%s] no rollback handler for %s", self.transaction_id, feature_key)
                continue
            try:
                rb_fn()
                _log.info("[txn:%s] rolled back %s", self.transaction_id, feature_key)
            except Exception as exc:
                self._errors.append({"feature": feature_key, "error": f"rollback: {exc}"})
                _log.error("[txn:%s] rollback failed for %s: %s",
                           self.transaction_id, feature_key, exc)
        return count

    # ------------------------------------------------------------------
    # Context manager protocol
    # ------------------------------------------------------------------

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None and exc_type is not TransactionError:
            # Unexpected exception outside apply() — roll back what we have
            self._rollback_all()
        return False   # never suppress exceptions

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    @property
    def errors(self) -> list:
        return list(self._errors)

    @property
    def success(self) -> bool:
        return len(self._errors) == 0

    @property
    def dry_run(self) -> bool:
        return self._dry_run

    def summary(self) -> dict:
        return {
            "transaction_id": self.transaction_id,
            "name":           self.name,
            "applied_by":     self.applied_by,
            "dry_run":        self._dry_run,
            "steps_applied":  len(self._steps),
            "errors":         self._errors,
            "ok":             self.success,
        }
