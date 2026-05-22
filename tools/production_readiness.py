#!/usr/bin/env python3
"""
production_readiness.py
-----------------------
Production *deployment-configuration* gate.

``release_check.py`` validates the build (deps importable, schema consistent,
routes register). This tool validates the running configuration of an actual
appliance: secrets are set and strong, the encryption master key is persisted,
debug is off, and an admin account exists. It is the gate that prevents a box
from going live with ephemeral key material or default secrets.

REQUIRED checks contribute to the exit code (non-zero blocks deploy).
OPTIONAL integrations only warn — the appliance runs fine without them.

Usage:
    python tools/production_readiness.py
    python tools/production_readiness.py --json
"""

from __future__ import annotations

import json
import os
import sys
from typing import Callable, List, Tuple


_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)


# (ok, message, required)
CheckResult = Tuple[bool, str, bool]
CheckFn = Callable[[], CheckResult]

_WEAK_MARKERS = {
    "change-me", "replace-this", "changeme", "secret", "dev", "test",
    "flask-secret", "insecure", "please-change", "default",
}


def check_secret_key() -> CheckResult:
    sk = os.getenv("SECRET_KEY") or os.getenv("SMARTSHIELD_SECRET_KEY") or ""
    if not sk:
        return (False, "SECRET_KEY / SMARTSHIELD_SECRET_KEY is not set", True)
    if len(sk) < 32:
        return (False, f"SECRET_KEY too short ({len(sk)} chars; need >= 32 random)", True)
    if any(m in sk.lower() for m in _WEAK_MARKERS):
        return (False, "SECRET_KEY looks like a placeholder/default value", True)
    return (True, "strong SECRET_KEY set", True)


def check_master_key() -> CheckResult:
    try:
        from app.secret_store import has_master_key
    except Exception as exc:
        return (False, f"could not import secret_store: {exc}", True)
    if not has_master_key():
        return (
            False,
            "no persisted master key (SMARTSHIELD_MASTER_KEY unset and no key "
            "file) — encrypted secrets (VPN keys, PSKs) will not survive reboot",
            True,
        )
    return (True, "encryption master key is persisted", True)


def check_debug_off() -> CheckResult:
    if os.getenv("FLASK_DEBUG", "0").strip() == "1":
        return (False, "FLASK_DEBUG=1 must be disabled in production", True)
    return (True, "FLASK_DEBUG is off", True)


def check_admin_user() -> CheckResult:
    """An appliance exposed before the setup wizard creates the first admin is
    a takeover risk. Confirm at least one account exists."""
    try:
        from app import create_app
        from app.database import get_db
        app = create_app()
        with app.app_context():
            conn = get_db()
            count = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
    except Exception as exc:
        return (False, f"could not query users table: {exc}", True)
    if count == 0:
        return (
            False,
            "no admin account yet — finish the setup wizard before exposing the appliance",
            True,
        )
    return (True, f"{count} user account(s) present", True)


def check_optional_integrations() -> List[Tuple[str, str]]:
    """Return (env_var, feature) pairs for optional integrations that are off.
    These never block deployment — they are reported as informational WARNs."""
    out: List[Tuple[str, str]] = []
    for env, feature in (
        ("GROQ_API_KEY", "AI chatbot assistant"),
        ("ABUSECH_AUTH_KEY", "abuse.ch threat-intel feeds"),
        ("SMARTSHIELD_SMTP_HOST", "outbound mail alerts (SMTP)"),
    ):
        if not os.getenv(env):
            out.append((env, feature))
    return out


_CHECKS: List[Tuple[str, CheckFn]] = [
    ("secret key strength",   check_secret_key),
    ("encryption master key", check_master_key),
    ("debug disabled",        check_debug_off),
    ("admin account exists",  check_admin_user),
]


def main() -> int:
    json_output = "--json" in sys.argv

    results = []
    fail_count = 0
    for label, fn in _CHECKS:
        try:
            ok, message, required = fn()
        except Exception as exc:
            ok, message, required = False, f"check raised: {exc}", True
        results.append({"name": label, "ok": ok, "required": required, "message": message})
        if not ok and required:
            fail_count += 1

    optional = check_optional_integrations()

    if json_output:
        print(json.dumps({
            "ok": fail_count == 0,
            "checks": results,
            "optional_disabled": [{"env": e, "feature": f} for e, f in optional],
        }, indent=2))
    else:
        for r in results:
            tag = "PASS" if r["ok"] else "FAIL"
            print(f"{tag:4s}  {r['name']:24s}  — {r['message']}")
        for env, feature in optional:
            print(f"WARN  {('optional: ' + env):24s}  — {feature} disabled (set {env} to enable)")
        print()
        if fail_count == 0:
            print("OK — production configuration checks passed.")
        else:
            print(f"BLOCK — {fail_count} required production check(s) failed; do not deploy.")
    return 0 if fail_count == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
