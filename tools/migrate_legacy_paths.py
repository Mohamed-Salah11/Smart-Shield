#!/usr/bin/env python3
"""
migrate_legacy_paths.py — one-shot helper that moves Smart Shield runtime
state from the legacy `smart-shield` paths to the canonical `smartshield`
paths introduced in Phase 11.

Idempotent: skips a pair when the destination already exists or the legacy
path is already a symlink (created by install.sh §2).

Run as root on FreeBSD:
    python3 tools/migrate_legacy_paths.py --apply

Without --apply the script prints what it would do (default safety).
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys


_PAIRS = [
    # (legacy, canonical)
    ("/usr/local/share/smart-shield", "/usr/local/share/smartshield"),
    ("/usr/local/etc/smart-shield",   "/usr/local/etc/smartshield"),
    ("/var/db/smart-shield",          "/var/db/smartshield"),
    ("/var/log/smart-shield",         "/var/log/smartshield"),
    ("/var/run/smart-shield",         "/var/run/smartshield"),
]


def _migrate_one(legacy: str, canonical: str, apply: bool) -> str:
    if not os.path.exists(legacy):
        return f"skip: legacy {legacy} not present"
    if os.path.islink(legacy):
        return f"skip: {legacy} is already a symlink"
    if os.path.exists(canonical) and not os.path.islink(canonical):
        return f"skip: canonical {canonical} already exists — manual reconcile needed"

    if not apply:
        return f"would move {legacy} → {canonical}"

    # If canonical is a stale symlink from a half-finished install, remove it
    # so we can move the real directory into place.
    if os.path.islink(canonical):
        os.unlink(canonical)

    os.makedirs(os.path.dirname(canonical), exist_ok=True)
    shutil.move(legacy, canonical)
    # Leave a symlink at the legacy path so operator shell aliases that
    # still reference smart-shield keep resolving until the next reboot.
    os.symlink(canonical, legacy)
    return f"moved {legacy} → {canonical} (symlink left at {legacy})"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apply", action="store_true",
        help="Actually perform the moves (default: dry-run).",
    )
    args = parser.parse_args()

    if not sys.platform.startswith("freebsd"):
        sys.stderr.write("This migrator is intended for FreeBSD only.\n")
        return 1
    if args.apply and os.geteuid() != 0:
        sys.stderr.write("--apply requires root.\n")
        return 2

    for legacy, canonical in _PAIRS:
        print(_migrate_one(legacy, canonical, args.apply))
    return 0


if __name__ == "__main__":
    sys.exit(main())
