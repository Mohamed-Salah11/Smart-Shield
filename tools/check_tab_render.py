#!/usr/bin/env python3
"""
check_tab_render.py
-------------------
Deterministic lint that guards against the "blank tab panel" antipattern.

Revealing a panel with `element.style.display = ''` only clears the INLINE
display style; the element then falls back to the stylesheet. When the panel
carries a class that resolves to `display:none` (e.g. `.ext-cb458930`,
`.ss-hidden`), clearing the inline style silently re-hides it, so the panel
renders blank. Reveals must use an explicit display value (e.g. 'block',
'inline-block', 'table-row') or toggle the hiding class instead.

This checker walks templates/**/*.html and fails (exit 1) if any line assigns
an empty string to `.style.display`.

Run from the repo root:

    python tools/check_tab_render.py
"""

import os
import re
import sys

# Matches `<anything>.style.display = ''` or `... = ""` (any whitespace).
_EMPTY_DISPLAY = re.compile(r"""\.style\.display\s*=\s*(''|"")""")


def main() -> int:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    templates_dir = os.path.join(root, "templates")

    offenders = []
    for dirpath, _dirnames, filenames in os.walk(templates_dir):
        for name in filenames:
            if not name.endswith(".html"):
                continue
            path = os.path.join(dirpath, name)
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    lines = fh.readlines()
            except OSError as exc:
                sys.stderr.write(f"warning: could not read {path}: {exc}\n")
                continue
            for lineno, line in enumerate(lines, start=1):
                if _EMPTY_DISPLAY.search(line):
                    rel = os.path.relpath(path, root)
                    offenders.append((rel, lineno, line.rstrip()))

    if offenders:
        sys.stderr.write(
            "check_tab_render: empty-string display assignments found.\n"
            "Clearing inline display falls back to the stylesheet and silently "
            "re-hides panels controlled by a display:none class.\n"
            "Fix: use an explicit display value (e.g. 'block', 'inline-block', "
            "'table-row') or toggle the hiding class.\n\n"
        )
        for rel, lineno, text in offenders:
            sys.stderr.write(f"  {rel}:{lineno}: {text.strip()}\n")
        sys.stderr.write(f"\ncheck_tab_render: {len(offenders)} offender(s)\n")
        return 1

    sys.stderr.write("check_tab_render: no empty-string display reveals\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
