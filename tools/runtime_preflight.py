#!/usr/bin/env python3
"""
runtime_preflight.py
--------------------
Production-safe `create_app()` smoke test, run from inside the project venv.

Distinct from siblings:
  * tools/smoke_startup.py   — bare app.create_app() boot check (no env
                                guards). Suitable for CI; not safe to run on a
                                live appliance because it could touch network
                                state or spawn background workers.
  * tools/release_check.py   — battery of static checks (dependencies,
                                version consistency, template references).
  * tools/runtime_preflight  — *this file*. Forces the network-apply and
                                background-worker kill switches BEFORE
                                importing the app so a misconfigured env file
                                can't cause real PF/network mutation while the
                                installer is just verifying the import path.

Fv11 review §P0-06 asked for this script to be wired into bsd/install.sh as
the final production check, and into the release manifest so an operator can
re-run it after upgrade.

Usage:
    cd /usr/local/share/smartshield
    .venv/bin/python tools/runtime_preflight.py
    .venv/bin/python tools/runtime_preflight.py --json
"""

from __future__ import annotations

import argparse
import json
import os
import sys


def _force_safe_env() -> None:
    """Override the env vars that would otherwise let create_app() touch the
    network or spin up background threads. These are os.environ overrides
    (not setdefaults) on purpose — a misconfigured smartshield.env that sets
    SMARTSHIELD_ENABLE_NETWORK_APPLY=1 must not bleed into a preflight run."""
    os.environ["FLASK_DEBUG"]                       = "0"
    os.environ["SMARTSHIELD_ENABLE_NETWORK_APPLY"]  = "0"
    os.environ["SMARTSHIELD_NETWORK_DRY_RUN"]       = "1"
    os.environ["SMARTSHIELD_DISABLE_BACKGROUND"]    = "1"


def run(json_output: bool = False) -> int:
    _force_safe_env()

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if root not in sys.path:
        sys.path.insert(0, root)

    result = {
        "ok": False,
        "blueprints": 0,
        "routes": 0,
        "error": None,
    }

    try:
        from app import create_app
        app = create_app()
        with app.app_context():
            result["blueprints"] = len(app.blueprints)
            result["routes"]     = sum(1 for _ in app.url_map.iter_rules())
        result["ok"] = result["blueprints"] > 0 and result["routes"] > 0
        if not result["ok"]:
            result["error"] = (
                f"app booted but registered nothing (blueprints={result['blueprints']}, "
                f"routes={result['routes']})"
            )
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"

    if json_output:
        print(json.dumps(result, indent=2))
    else:
        if result["ok"]:
            print(
                f"runtime_preflight: OK  "
                f"blueprints={result['blueprints']}  routes={result['routes']}"
            )
        else:
            sys.stderr.write(f"runtime_preflight: FAIL — {result['error']}\n")

    return 0 if result["ok"] else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Smart Shield runtime preflight")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args()
    return run(json_output=args.json)


if __name__ == "__main__":
    raise SystemExit(main())
