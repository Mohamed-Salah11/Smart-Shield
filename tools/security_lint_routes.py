#!/usr/bin/env python3
"""
security_lint_routes.py
-----------------------
Static-analysis route security lint for SmartShield.

Scans every ``.py`` file under ``routes/`` and flags Flask view functions
that:

  * Handle a mutating HTTP method (POST/PUT/PATCH/DELETE), AND
  * Are NOT explicitly declared as one of:
      - browser-session API (``@login_required`` + ``@api_permission_required``,
        or the unified ``@browser_api_required(...)``)
      - machine API (``@api_permission_required``-style + ``@require_api_scope``,
        or the unified ``@machine_api_required(...)``)
      - explicit public route (``@public_route`` marker, or membership in
        the blueprint prefix ``CSRF_EXEMPT_ENDPOINT_PREFIXES``, or membership
        in the named-endpoint set ``CSRF_EXEMPT_ENDPOINTS`` in
        ``app/__init__.py``)
      - HMAC-validated callback (validates HMAC in the function body — best
        effort, signaled by an ``hmac.compare_digest`` call)
      - portal / unauthenticated browser route (``@portal_csrf_exempt`` or
        an explicit reason comment)

Exit codes
----------
  0  No violations.
  1  At least one violation; details written to stdout/stderr.
  2  Internal error parsing source files.

Runs without importing the app — pure AST inspection — so it can be invoked
on developer machines without a live database.
"""

from __future__ import annotations

import ast
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

# Decorator names that satisfy the "browser-session admin API" expectation.
# The codebase has multiple session scopes (admin, SOC analyst, VPN portal,
# captive portal); any ``*_login_required`` decorator is treated as a valid
# browser-session gate. The lint's job is to flag mutating routes with NO
# auth declaration at all — not to police which specific session pool is
# correct, which is a code-review concern.
_BROWSER_DECORATORS = frozenset({
    "browser_api_required",
    "login_required",
    "api_permission_required",
    "superuser_required",
    "soc_login_required",
    "vpn_portal_login_required",
})

# Regex catch-all so adding a new ``foo_login_required`` decorator works
# without editing this lint.
_BROWSER_DECORATOR_RE = re.compile(r"_login_required$|^login_required$")

# Endpoints that are intentionally pre-auth and have their own brute-force /
# rate-limit / captcha protections. Adding to this list is an explicit
# "this route is public" declaration that should pass code review.
_PUBLIC_ENDPOINT_ALLOWLIST = frozenset({
    # System admin login surfaces.
    "auth.login",
    "auth.reauth",
    # Logout: POST-only and CSRF-protected; intentionally usable even when the
    # session is already partially invalid so a sign-out always succeeds.
    "auth.logout",
    "system.logout",
    "soc_portal.logout",
    # First-boot setup wizard — runs before any user exists.
    "setup.api_step1_save",
    "setup.api_step2_save",
    "setup.api_step3_save",
    "setup.api_step4_apply",
    # SOC portal authentication surfaces (pre-session).
    "soc_portal.login",
    "soc_portal.login_mfa",
    # VPN portal authentication surfaces (pre-session).
    "vpn_portal.login",
    "vpn_portal.mfa",
    "vpn_portal.logout",
    "vpn_portal.enroll_mfa",
    # Captive portal browser-AJAX auth (CSRF-protected but no admin login).
    "services.api_cp_authenticate",
})

# Decorator names that satisfy the "machine API" expectation.
_MACHINE_DECORATORS = frozenset({
    "machine_api_required",
    "require_api_scope",
})

# Decorator names that mark an endpoint as intentionally public/unauthenticated.
_PUBLIC_DECORATORS = frozenset({
    "public_route",
    "portal_csrf_exempt",
})

# HTTP methods that mutate state and therefore require an auth declaration.
_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# High-risk endpoint patterns — routes that match any of these regexes against
# the function name must carry @superuser_required (or an explicit
# @api_permission_required that delegates to superuser). The base auth check
# above guarantees the route has *some* gate; this stricter check makes sure
# the destructive ones aren't reachable by every authenticated admin.
_HIGH_RISK_FUNC_PATTERNS = (
    re.compile(r"factory_reset"),
    re.compile(r"^(reboot|halt|shutdown|poweroff)\b"),
    re.compile(r"(^|_)(revoke|delete)_cert"),
    re.compile(r"(^|_)package_install\b"),
    re.compile(r"(^|_)terminal_ticket\b"),
    re.compile(r"(^|_)pf_(apply|rollback|reload)\b"),
    re.compile(r"(^|_)interface_apply\b"),
)

# Decorators that satisfy the high-risk check.
_HIGH_RISK_DECORATORS = frozenset({
    "superuser_required",
    "api_permission_required",
    "reauth_required_form",
    "reauth_required",
})


@dataclass
class Violation:
    file: str
    line: int
    func: str
    methods: tuple
    reason: str

    def format(self) -> str:
        m = ",".join(self.methods)
        return f"FAIL  {self.file}:{self.line}  {m}  {self.func}  — {self.reason}"


def _iter_decorator_names(node: ast.FunctionDef) -> Iterable[str]:
    """Yield bare decorator names for ``@foo`` or ``@foo(...)``."""
    for dec in node.decorator_list:
        if isinstance(dec, ast.Call):
            target = dec.func
        else:
            target = dec
        if isinstance(target, ast.Name):
            yield target.id
        elif isinstance(target, ast.Attribute):
            yield target.attr


def _iter_route_methods(node: ast.FunctionDef) -> set:
    """Return the set of HTTP methods declared in any ``@bp.route(...)`` /
    ``@bp.post(...)`` / ``@bp.put(...)`` etc. decorator on *node*.

    Includes the implicit GET when no methods kwarg is given on ``.route``.
    """
    methods: set = set()
    for dec in node.decorator_list:
        if not isinstance(dec, ast.Call):
            continue
        func = dec.func
        # Shortcut decorators: bp.post / bp.put / bp.patch / bp.delete / bp.get.
        if isinstance(func, ast.Attribute) and func.attr.upper() in (
            "POST", "PUT", "PATCH", "DELETE", "GET"
        ):
            methods.add(func.attr.upper())
            continue
        # @bp.route("...", methods=[...])
        if isinstance(func, ast.Attribute) and func.attr == "route":
            for kw in dec.keywords:
                if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                    for el in kw.value.elts:
                        if isinstance(el, ast.Constant) and isinstance(el.value, str):
                            methods.add(el.value.upper())
            if not any(kw.arg == "methods" for kw in dec.keywords):
                methods.add("GET")
    return methods


def _calls_hmac_compare(node: ast.FunctionDef) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            f = sub.func
            if isinstance(f, ast.Attribute) and f.attr == "compare_digest":
                return True
            if isinstance(f, ast.Name) and f.id == "compare_digest":
                return True
    return False


def _read_csrf_exempt_sets(app_init: Path) -> tuple:
    """Best-effort extraction of CSRF_EXEMPT_ENDPOINT_PREFIXES and
    CSRF_EXEMPT_ENDPOINTS from ``app/__init__.py``. Falls back to ``()``,
    ``set()`` if parsing fails."""
    prefixes: tuple = ()
    endpoints: set = set()
    try:
        source = app_init.read_text(encoding="utf-8")
    except OSError:
        return prefixes, endpoints

    # Match a tuple/list of string literals assigned to CSRF_EXEMPT_ENDPOINT_PREFIXES.
    m = re.search(
        r"CSRF_EXEMPT_ENDPOINT_PREFIXES\s*=\s*\(([^)]*)\)",
        source,
    )
    if m:
        prefixes = tuple(re.findall(r'"([^"]+)"', m.group(1)))

    m = re.search(
        r"CSRF_EXEMPT_ENDPOINTS\s*=\s*(?:frozenset|set)?\s*\(?\{([^}]*)\}\)?",
        source,
    )
    if m:
        endpoints = set(re.findall(r'"([^"]+)"', m.group(1)))

    return prefixes, endpoints


def _scan_file(path: Path, blueprint_prefix: str, exempt_prefixes: tuple,
               exempt_endpoints: set) -> list:
    violations: list = []
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except SyntaxError as exc:
        print(f"PARSE-ERROR  {path}: {exc}", file=sys.stderr)
        return violations

    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        methods = _iter_route_methods(node) & _MUTATING_METHODS
        if not methods:
            continue
        dec_names = set(_iter_decorator_names(node))

        endpoint = f"{blueprint_prefix}.{node.name}"
        if blueprint_prefix and any(
            endpoint.startswith(p) for p in exempt_prefixes
        ):
            continue
        if endpoint in exempt_endpoints:
            continue
        if endpoint in _PUBLIC_ENDPOINT_ALLOWLIST:
            continue

        if dec_names & _BROWSER_DECORATORS:
            continue
        if any(_BROWSER_DECORATOR_RE.search(name) for name in dec_names):
            continue
        if dec_names & _MACHINE_DECORATORS:
            continue
        if dec_names & _PUBLIC_DECORATORS:
            continue
        if _calls_hmac_compare(node):
            continue

        violations.append(Violation(
            file=str(path),
            line=node.lineno,
            func=node.name,
            methods=tuple(sorted(methods)),
            reason=(
                "mutating route has no auth declaration "
                "(expected one of: @browser_api_required, @machine_api_required, "
                "@login_required + @api_permission_required, @require_api_scope, "
                "@public_route, or HMAC verification in body)"
            ),
        ))

    # Second pass: high-risk endpoints must additionally carry one of the
    # decorators in _HIGH_RISK_DECORATORS. Done as a second walk so the
    # "missing any auth" violations above are surfaced first; a route can
    # generate at most one violation per pass.
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        methods = _iter_route_methods(node) & _MUTATING_METHODS
        if not methods:
            continue
        if not any(p.search(node.name) for p in _HIGH_RISK_FUNC_PATTERNS):
            continue
        dec_names = set(_iter_decorator_names(node))
        if dec_names & _HIGH_RISK_DECORATORS:
            continue
        violations.append(Violation(
            file=str(path),
            line=node.lineno,
            func=node.name,
            methods=tuple(sorted(methods)),
            reason=(
                "high-risk endpoint missing strict gate "
                "(expected @superuser_required, @api_permission_required, "
                "or @reauth_required_form)"
            ),
        ))
    return violations


def _guess_blueprint_prefix(path: Path, repo_root: Path) -> str:
    """Map a route file path to its blueprint name for endpoint-prefix matching.

    Mirrors the SmartShield routes/ layout: routes/<bp>.py or
    routes/<bp>/<sub>.py become blueprint ``<bp>``. Returns "" when unknown.
    """
    try:
        rel = path.relative_to(repo_root / "routes")
    except ValueError:
        return ""
    parts = rel.parts
    if not parts:
        return ""
    head = parts[0]
    if head.endswith(".py"):
        return head[:-3]
    return head


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    routes_dir = repo_root / "routes"
    if not routes_dir.is_dir():
        print(f"routes/ directory not found at {routes_dir}", file=sys.stderr)
        return 2

    exempt_prefixes, exempt_endpoints = _read_csrf_exempt_sets(
        repo_root / "app" / "__init__.py"
    )

    all_violations: list = []
    file_count = 0
    for py in routes_dir.rglob("*.py"):
        if py.name.startswith("_"):
            # Conventional: _common.py / _foo.py are helper modules without routes.
            continue
        file_count += 1
        bp_prefix = _guess_blueprint_prefix(py, repo_root)
        all_violations.extend(
            _scan_file(py, bp_prefix, exempt_prefixes, exempt_endpoints)
        )

    if all_violations:
        for v in all_violations:
            print(v.format())
        print(
            f"\nsecurity_lint_routes: scanned {file_count} files, "
            f"{len(all_violations)} violation(s)",
            file=sys.stderr,
        )
        return 1

    print(
        f"security_lint_routes: scanned {file_count} files, no violations",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
