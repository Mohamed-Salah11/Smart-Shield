#!/usr/bin/env python3
"""
One-off migration: move the generated ``<!-- inline-handlers:auto -->`` blocks
that the original CSP migration appended *after* the final ``{% endblock %}`` of
each child template into a rendered ``{% block scripts %}`` (or the soc_portal
``{% block extra_js %}``).

Why: in Jinja inheritance, any text outside ``{% block %}`` in a template that
``{% extends %}`` a parent is discarded — so those trailing blocks never render
and their handlers are never registered. This script relocates them in place.

It reuses the placement helpers from ``migrate_handlers.py`` so the result is
identical to what a corrected migration run would produce. Idempotent: a block
that already lives inside a rendered block is left untouched.

Run from the repo root:  python scripts/relocate_handlers.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from migrate_handlers import (  # noqa: E402
    ENDBLOCK_RE,
    INLINE_HANDLERS_MARKER_CLOSE,
    INLINE_HANDLERS_MARKER_OPEN,
    ROOT,
    TEMPLATES,
    _emit_block,
    _extends_parent,
)

# Whole marked region, plus any surrounding blank lines, so we can lift it cleanly.
BLOCK_RE = re.compile(
    r"\n*"
    + re.escape(INLINE_HANDLERS_MARKER_OPEN)
    + r".*?"
    + re.escape(INLINE_HANDLERS_MARKER_CLOSE)
    + r"\n*",
    re.DOTALL,
)


def _last_endblock_start(text: str):
    last = None
    for m in ENDBLOCK_RE.finditer(text):
        last = m
    return last.start() if last else None


def relocate_file(path: Path) -> str:
    """Return 'moved' | 'skip-noblock' | 'skip-standalone' | 'skip-inplace'."""
    with path.open(encoding="utf-8", newline="") as fh:
        text = fh.read()
    open_idx = text.find(INLINE_HANDLERS_MARKER_OPEN)
    if open_idx == -1:
        return "skip-noblock"

    parent = _extends_parent(text)
    if parent is None:
        # Standalone page / partial — its trailing block renders fine.
        return "skip-standalone"

    last_eb = _last_endblock_start(text)
    if last_eb is not None and open_idx < last_eb:
        # Already inside a rendered block.
        return "skip-inplace"

    m = BLOCK_RE.search(text)
    if not m:
        return "skip-noblock"

    # Reconstruct a tidy block string (strip the surrounding blank-line padding
    # the regex consumed) and lift it out of the body.
    block = text[m.start(): m.end()].strip("\n")
    body = (text[: m.start()] + text[m.end():]).rstrip() + "\n"
    new_text = _emit_block(body, block, parent)
    if not new_text.endswith("\n"):
        new_text += "\n"
    with path.open("w", encoding="utf-8", newline="") as fh:
        fh.write(new_text)
    return "moved"


def main() -> int:
    counts: dict[str, int] = {}
    moved: list[str] = []
    for path in sorted(TEMPLATES.rglob("*.html")):
        status = relocate_file(path)
        counts[status] = counts.get(status, 0) + 1
        if status == "moved":
            moved.append(str(path.relative_to(ROOT)).replace("\\", "/"))

    print("Relocation summary:")
    for k in sorted(counts):
        print(f"  {k:18s}: {counts[k]}")
    print(f"\nMoved {len(moved)} template(s):")
    for f in moved:
        print(f"  - {f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
