#!/usr/bin/env python3
"""
scripts/soc_template_lint.py
----------------------------
Phase 2.8 — stored-XSS gate for the SOC portal.

Background
~~~~~~~~~~
``templates/soc_portal/base.html`` defines ``SOC.esc(value)``, a shared HTML
escaper. Every dynamic field interpolated into a template literal that ends
up in ``innerHTML`` on a SOC page MUST go through it: a SIEM event whose
``details.signature`` contains ``<img src=x onerror=…>`` would otherwise
land in an analyst's browser unescaped.

What this script does
~~~~~~~~~~~~~~~~~~~~~
Scans ``templates/soc_portal/*.html`` for JavaScript template-literal
interpolations of the form ``${EXPR}``. For each one, if ``EXPR``:

  * references ``.details.<field>`` or ``[...].details[...]``, OR
  * references one of the four dangerous fields (``signature``,
    ``action``, ``username``, ``details``) as an object property
    (``.action``, ``['action']``, ``.signature``, etc.)

…and is **not** already wrapped in ``SOC.esc(…)``, the script fails with
the file/line/snippet so a CI run blocks the merge.

Safe forms recognised
~~~~~~~~~~~~~~~~~~~~~
* ``${SOC.esc(<anything>)}`` — the prescribed escaper.
* ``${encodeURIComponent(<anything>)}`` — URL component escaping (used in
  ``href`` interpolations where HTML escaping would break the URL).

Out of scope
~~~~~~~~~~~~
* ``{{ jinja }}`` — Jinja autoescape handles those at render time.
* Numbers, indexes, hard-coded strings, ternary literals — operators
  never type those.
* HTML attribute values built by ``SOC.esc()`` or ``encodeURIComponent()``
  — both are safe.

Usage
~~~~~
    python scripts/soc_template_lint.py            # human-readable
    python scripts/soc_template_lint.py --json     # CI-friendly
"""

from __future__ import annotations

import glob
import json
import os
import re
import sys
from typing import Dict, List, Tuple


_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE_GLOB = os.path.join(_REPO_ROOT, "templates", "soc_portal", "*.html")

# Fields that must never reach innerHTML unescaped. These were the four
# called out in the Phase 2.8 audit prompt: SIEM events under operator
# control can carry attacker-supplied HTML in any of them.
DANGEROUS_FIELDS = ("signature", "action", "username", "details")

# Regex catches both dot access (``.signature``) and bracketed access
# (``['signature']`` / ``["signature"]``). The leading word boundary stops
# ``transaction`` from matching ``action``.
_DANGER_PATTERN = re.compile(
    r"(?:\.(?:" + "|".join(DANGEROUS_FIELDS) + r")\b)"
    r"|"
    r"(?:\[\s*['\"](?:" + "|".join(DANGEROUS_FIELDS) + r")['\"]\s*\])"
)

# Matches a single ``${...}`` interpolation. Greedy-not-newline, because in
# practice the SOC templates use one-line interpolations even inside
# multi-line template literals (each ${…} stays on its own line).
_INTERP_PATTERN = re.compile(r"\$\{([^{}\n]+)\}")

# Permitted wrappers — if the WHOLE expression is wrapped in one of these,
# the value is escaped (or URL-component-encoded) at the boundary, so the
# inner expression is allowed to reference dangerous fields.
_SAFE_WRAPPER = re.compile(
    r"^\s*(?:SOC\.esc|encodeURIComponent)\s*\(.*\)\s*$"
)

Violation = Tuple[str, int, str, str]  # (path, line_no, snippet, expr)


def _line_number(text: str, offset: int) -> int:
    """1-indexed line number for a byte offset into ``text``."""
    return text.count("\n", 0, offset) + 1


def _scan_file(path: str) -> List[Violation]:
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()

    violations: List[Violation] = []
    for match in _INTERP_PATTERN.finditer(text):
        expr = match.group(1)
        if not _DANGER_PATTERN.search(expr):
            continue
        if _SAFE_WRAPPER.match(expr):
            continue

        line_no = _line_number(text, match.start())
        # Pull the full source line so the operator sees context, not just
        # the bare interpolation.
        line_start = text.rfind("\n", 0, match.start()) + 1
        line_end = text.find("\n", match.start())
        if line_end == -1:
            line_end = len(text)
        snippet = text[line_start:line_end].strip()
        rel_path = os.path.relpath(path, _REPO_ROOT)
        violations.append((rel_path, line_no, snippet, expr.strip()))

    return violations


def scan(glob_pattern: str | None = None) -> List[Violation]:
    glob_pattern = glob_pattern if glob_pattern is not None else TEMPLATE_GLOB
    violations: List[Violation] = []
    for path in sorted(glob.glob(glob_pattern)):
        violations.extend(_scan_file(path))
    return violations


def _format_human(violations: List[Violation]) -> str:
    if not violations:
        return f"OK — no unescaped dangerous-field interpolations under templates/soc_portal/."
    lines = [
        f"SOC template lint failed — {len(violations)} dangerous-field "
        f"interpolation(s) not wrapped in SOC.esc():",
        "",
    ]
    for path, line_no, snippet, expr in violations:
        lines.append(f"  {path}:{line_no}")
        lines.append(f"      ${{{expr}}}")
        lines.append(f"      {snippet}")
        lines.append("")
    lines.append(
        "  Fix: wrap each interpolation in SOC.esc(...) "
        "(or encodeURIComponent for URL-component positions)."
    )
    return "\n".join(lines)


def main(argv: List[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    want_json = "--json" in argv

    violations = scan()

    if want_json:
        print(json.dumps({
            "ok": not violations,
            "violations": [
                {"file": p, "line": ln, "expr": e, "snippet": s}
                for (p, ln, s, e) in violations
            ],
        }))
    else:
        if violations:
            print(_format_human(violations), file=sys.stderr)
        else:
            print(_format_human(violations))

    return 0 if not violations else 1


if __name__ == "__main__":
    sys.exit(main())
