#!/usr/bin/env python3
"""
check_manifest.py
-----------------
Fail fast when ``app/manifests/python_runtime.json`` drifts from
``requirements.txt``.

Why this exists
---------------
``bsd/install.sh`` runs a post-venv import check that iterates the manifest's
``imports`` list and calls ``__import__`` on each entry. If a new package is
added to ``requirements.txt`` but the manifest is forgotten, the import check
silently passes anyway — the package is installed in the venv but never
exercised, so a real-world boot may still blow up on
``ModuleNotFoundError``. Conversely, a removed dep stays in the manifest as
an orphan and the next install fails on a phantom import.

What it does
------------
1. Parse ``requirements.txt`` the same way ``tools/release_check.py`` does
   (strip comments, version pins, extras, environment markers).
2. Translate each PyPI distribution name to its import name using
   ``release_check.PACKAGE_IMPORT_MAP``, falling back to the lowercased
   ``dist.replace("-", "_")`` rule.
3. Compare the resulting set against ``manifest["imports"]``.
4. Exit 0 when they match. Exit 1 with a unified diff when they don't.

Usage
-----
    python tools/check_manifest.py            # human-readable
    python tools/check_manifest.py --json     # CI-friendly
"""

from __future__ import annotations

import json
import os
import re
import sys
from typing import List, Set, Tuple


_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

# Re-use the canonical dist→import map so a single edit propagates everywhere
# in the release-gating toolchain (release_check, install.sh import check,
# this script).
from tools.release_check import PACKAGE_IMPORT_MAP  # noqa: E402


REQUIREMENTS_PATH = os.path.join(_REPO_ROOT, "requirements.txt")
MANIFEST_PATH = os.path.join(_REPO_ROOT, "app", "manifests", "python_runtime.json")


def _dist_to_import(dist: str) -> str:
    """Map ``dist`` (the PyPI distribution name) to its import name using the
    same rule as :func:`release_check.check_dependencies`."""
    return PACKAGE_IMPORT_MAP.get(
        dist.lower(),
        dist.replace("-", "_").lower(),
    )


def parse_requirements(path: str | None = None) -> Set[str]:
    """Return the set of import names implied by ``requirements.txt``.

    Mirrors ``release_check.check_dependencies`` so the two cannot disagree
    on what's "required". Comments, blank lines, ``-e``/``-r`` directives,
    and VCS URLs are skipped. Extras (``foo[bar]``) and version pins are
    stripped.
    """
    path = path if path is not None else REQUIREMENTS_PATH
    imports: Set[str] = set()
    with open(path, "r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            # Skip pip directives — they don't name a single dist.
            if line.startswith(("-", "--", "git+", "http:", "https:")):
                continue
            # Strip extras, version pins, env markers.
            dist = re.split(r"[<>=!~;\[]", line, maxsplit=1)[0].strip()
            if not dist:
                continue
            imports.add(_dist_to_import(dist))
    return imports


def parse_manifest(path: str | None = None) -> Set[str]:
    """Return the set of import names listed in ``python_runtime.json``."""
    path = path if path is not None else MANIFEST_PATH
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    imports = data.get("imports") or []
    return set(imports)


def _diff(expected: Set[str], actual: Set[str]) -> Tuple[List[str], List[str]]:
    """Return ``(missing_from_manifest, extra_in_manifest)``."""
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    return missing, extra


def check(req_path: str | None = None,
          manifest_path: str | None = None) -> Tuple[bool, List[str], List[str]]:
    """Programmatic entry point — useful for unit tests.

    Returns ``(ok, missing_from_manifest, extra_in_manifest)``.
    """
    expected = parse_requirements(req_path)
    actual = parse_manifest(manifest_path)
    missing, extra = _diff(expected, actual)
    return (not missing and not extra), missing, extra


def _format_human(missing: List[str], extra: List[str]) -> str:
    lines = []
    lines.append("python_runtime.json is out of sync with requirements.txt:")
    if missing:
        lines.append("")
        lines.append("  Missing from manifest (in requirements.txt but not the manifest):")
        for name in missing:
            lines.append(f"    + {name}")
    if extra:
        lines.append("")
        lines.append("  Extra in manifest (in the manifest but not requirements.txt):")
        for name in extra:
            lines.append(f"    - {name}")
    lines.append("")
    lines.append(f"  Edit {os.path.relpath(MANIFEST_PATH, _REPO_ROOT)} to match.")
    return "\n".join(lines)


def main(argv: List[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    want_json = "--json" in argv

    try:
        ok, missing, extra = check()
    except FileNotFoundError as exc:
        msg = f"check_manifest: cannot read {exc.filename}: {exc.strerror}"
        if want_json:
            print(json.dumps({"ok": False, "error": msg}))
        else:
            print(msg, file=sys.stderr)
        return 1
    except (json.JSONDecodeError, OSError) as exc:
        msg = f"check_manifest: manifest unreadable: {exc}"
        if want_json:
            print(json.dumps({"ok": False, "error": msg}))
        else:
            print(msg, file=sys.stderr)
        return 1

    if want_json:
        print(json.dumps({
            "ok": ok,
            "missing_from_manifest": missing,
            "extra_in_manifest": extra,
        }))
    else:
        if ok:
            print(f"OK — python_runtime.json matches requirements.txt "
                  f"({len(parse_manifest())} imports).")
        else:
            print(_format_human(missing, extra), file=sys.stderr)

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
