#!/usr/bin/env python3
"""
release_check.py
----------------
Appliance release-readiness checker.

Runs a battery of independent checks and prints a PASS/FAIL line for each.
Exits non-zero when any required check fails. Used as the last
acceptance gate after install.sh has finished and before the appliance is
declared "ready to operate."

Check coverage:
  * Python dependencies              — every entry in requirements.txt importable
  * Database migrations              — CURRENT_SCHEMA_VERSION matches the DB
  * Template references              — every render_template() target exists
  * Route registration               — create_app() succeeds, blueprints register
  * pfctl availability               — on FreeBSD only
  * Required FreeBSD commands        — service, sysrc, ifconfig, route, sudo
  * Writable paths                   — DB dir, log dir, run dir
  * Nginx config                     — `nginx -t` passes (when nginx is present)

Each check is best-effort and isolated: a failure in one does not short-circuit
the rest. The exit code is the count of failed required checks, capped at 1
(so CI sees a simple boolean).

Usage:
    python tools/release_check.py
    python tools/release_check.py --json     # machine-readable output
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from typing import Callable, List, Tuple


_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)


# Each check returns (ok: bool, message: str, required: bool). When `required`
# is False, a FAIL still prints but does not contribute to the exit code.
CheckResult = Tuple[bool, str, bool]
CheckFn = Callable[[], CheckResult]


# PyPI distribution name → import name, for the cases that genuinely differ.
# Keyed by the lowercased distribution name (the lookup lowercases ``pkg``).
PACKAGE_IMPORT_MAP = {
    "flask":         "flask",
    "jinja2":        "jinja2",
    "markupsafe":    "markupsafe",
    "werkzeug":      "werkzeug",
    "python-dotenv": "dotenv",
    "pyyaml":        "yaml",
    "flask-login":   "flask_login",
    "flask-wtf":     "flask_wtf",
    "fpdf2":         "fpdf",
}


def check_dependencies() -> CheckResult:
    req_path = os.path.join(_REPO_ROOT, "requirements.txt")
    if not os.path.isfile(req_path):
        return (False, "requirements.txt not found", True)

    missing: List[str] = []
    with open(req_path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Strip extras / version pins to get the bare package name.
            pkg = re.split(r"[<>=!~;\[]", line, maxsplit=1)[0].strip()
            if not pkg:
                continue
            # Map PyPI distribution names to their import names. Keyed by the
            # lowercased dist name. The fallback lowercases too, so case-only
            # differences (Flask→flask, Jinja2→jinja2, MarkupSafe→markupsafe)
            # resolve without an explicit entry; only genuinely different names
            # (python-dotenv→dotenv, fpdf2→fpdf) need listing.
            import_name = PACKAGE_IMPORT_MAP.get(
                pkg.lower(), pkg.replace("-", "_").lower()
            )
            try:
                __import__(import_name)
            except Exception:
                missing.append(pkg)
    if missing:
        return (False, f"missing imports: {', '.join(missing)}", True)
    return (True, "all requirements importable", True)


def check_version_consistency() -> CheckResult:
    """version.json must exist, carry a non-empty version, and agree with the
    code's CURRENT_SCHEMA_VERSION. Catches the class of bug where the schema is
    bumped in migrations.py but version.json is left stale (or vice versa)."""
    vj_path = os.path.join(_REPO_ROOT, "version.json")
    if not os.path.isfile(vj_path):
        return (False, "version.json not found", True)
    try:
        with open(vj_path, "r", encoding="utf-8") as fh:
            meta = json.load(fh)
    except (ValueError, OSError) as exc:
        return (False, f"version.json unreadable: {exc}", True)

    version = str(meta.get("version") or "").strip()
    if not version:
        return (False, "version.json has no 'version'", True)

    try:
        from app.migrations import CURRENT_SCHEMA_VERSION
    except Exception as exc:
        return (False, f"could not import CURRENT_SCHEMA_VERSION: {exc}", True)

    vj_schema = meta.get("schema_version")
    if vj_schema != CURRENT_SCHEMA_VERSION:
        return (
            False,
            f"version.json schema_version {vj_schema} != "
            f"CURRENT_SCHEMA_VERSION {CURRENT_SCHEMA_VERSION}",
            True,
        )
    return (True, f"version {version}, schema_version {vj_schema}", True)


def check_database_migrations() -> CheckResult:
    try:
        from app.migrations import CURRENT_SCHEMA_VERSION
        from app import create_app
        from app.database import get_db
    except Exception as exc:
        return (False, f"could not import migration helpers: {exc}", True)

    try:
        app = create_app()
        with app.app_context():
            conn = get_db()
            row = conn.execute(
                "SELECT MAX(version) AS v FROM schema_version"
            ).fetchone()
            db_version = (row["v"] if row else None) or 0
    except Exception as exc:
        return (False, f"could not read schema_version: {exc}", True)

    if db_version != CURRENT_SCHEMA_VERSION:
        return (
            False,
            f"DB version {db_version} != CURRENT_SCHEMA_VERSION {CURRENT_SCHEMA_VERSION}",
            True,
        )
    return (True, f"schema_version = {db_version}", True)


def check_template_references() -> CheckResult:
    """Walk the route modules, find every render_template("X") call, confirm X exists."""
    template_root = os.path.join(_REPO_ROOT, "templates")
    if not os.path.isdir(template_root):
        return (False, "templates/ directory missing", True)

    referenced: set = set()
    pattern = re.compile(r"render_template\(\s*['\"]([^'\"]+\.html)['\"]")
    for dirpath, _dirs, files in os.walk(os.path.join(_REPO_ROOT, "routes")):
        for name in files:
            if not name.endswith(".py"):
                continue
            try:
                with open(os.path.join(dirpath, name), "r", encoding="utf-8") as fh:
                    referenced.update(pattern.findall(fh.read()))
            except OSError:
                continue

    missing = [t for t in sorted(referenced) if not os.path.isfile(os.path.join(template_root, t))]
    if missing:
        return (False, f"missing templates: {', '.join(missing[:5])}{' …' if len(missing) > 5 else ''}", True)
    return (True, f"{len(referenced)} template references resolved", True)


def check_routes_register() -> CheckResult:
    try:
        from app import create_app
        app = create_app()
        bp_count = len(app.blueprints)
        route_count = sum(1 for _ in app.url_map.iter_rules())
    except Exception as exc:
        return (False, f"create_app() failed: {exc}", True)
    if bp_count == 0 or route_count == 0:
        return (False, f"no blueprints or routes registered (bp={bp_count}, routes={route_count})", True)
    return (True, f"{bp_count} blueprints, {route_count} routes", True)


def check_pfctl_available() -> CheckResult:
    required_on_freebsd = sys.platform.startswith("freebsd")
    if not shutil.which("pfctl"):
        return (False, "pfctl not on PATH", required_on_freebsd)
    return (True, "pfctl present", required_on_freebsd)


def check_required_freebsd_commands() -> CheckResult:
    if not sys.platform.startswith("freebsd"):
        return (True, "not FreeBSD — skipped", False)
    commands = ["service", "sysrc", "ifconfig", "route", "sockstat"]
    missing = [c for c in commands if not shutil.which(c)]
    if missing:
        return (False, f"missing: {', '.join(missing)}", True)
    return (True, f"all present ({', '.join(commands)})", True)


def check_writable_paths() -> CheckResult:
    try:
        from app.config import get_config
        cfg = get_config()
        paths = [
            os.path.dirname(cfg.DB_PATH) or ".",
            os.path.dirname(cfg.AUDIT_LOG_PATH) or ".",
            os.path.dirname(cfg.APP_LOG_PATH) or ".",
            cfg.UPLOAD_DIR,
        ]
    except Exception as exc:
        return (False, f"could not load config: {exc}", True)

    not_writable = []
    for path in paths:
        if path.startswith("file:") or path.startswith(":memory:"):
            continue
        try:
            if not os.path.isdir(path):
                not_writable.append(f"{path} (missing)")
                continue
            if not os.access(path, os.W_OK):
                not_writable.append(f"{path} (not writable)")
        except OSError as exc:
            not_writable.append(f"{path} ({exc})")
    if not_writable:
        return (False, "; ".join(not_writable), True)
    return (True, f"{len(paths)} paths writable", True)


def check_nginx_config() -> CheckResult:
    required_on_freebsd = sys.platform.startswith("freebsd")
    if not shutil.which("nginx"):
        return (True, "nginx not installed — skipped", False)
    try:
        result = subprocess.run(
            ["nginx", "-t"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return (False, f"nginx -t failed to run: {exc}", required_on_freebsd)
    if result.returncode != 0:
        first_err = (result.stderr or result.stdout or "").strip().splitlines()[-1:]
        return (False, "nginx -t failed: " + (first_err[0] if first_err else "unknown"), required_on_freebsd)
    return (True, "nginx -t passed", required_on_freebsd)


_CHECKS: List[Tuple[str, CheckFn]] = [
    ("dependencies",              check_dependencies),
    ("version consistency",       check_version_consistency),
    ("database schema",           check_database_migrations),
    ("template references",       check_template_references),
    ("route registration",        check_routes_register),
    ("pfctl available",           check_pfctl_available),
    ("required FreeBSD commands", check_required_freebsd_commands),
    ("writable paths",            check_writable_paths),
    ("nginx config",              check_nginx_config),
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
        results.append({
            "name": label,
            "ok": ok,
            "required": required,
            "message": message,
        })
        if not ok and required:
            fail_count += 1

    if json_output:
        print(json.dumps({"ok": fail_count == 0, "checks": results}, indent=2))
    else:
        for r in results:
            tag = "PASS" if r["ok"] else ("FAIL" if r["required"] else "WARN")
            print(f"{tag:4s}  {r['name']:30s}  — {r['message']}")
        print()
        if fail_count == 0:
            print("OK — appliance is release-ready.")
        else:
            print(f"FAIL — {fail_count} required check(s) failed; do not ship.")
    return 0 if fail_count == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
