#!/usr/bin/env python3
"""
Idempotent migration of inline assets in templates/ for strict-CSP compatibility.

Three passes per template:

  1A. Add `nonce="{{ csp_nonce() }}"` to every inline `<script>` (no src, no nonce yet).
  1C. Extract every `style="..."` to a hashed class in static/css/ext-inline.css,
      and rewrite the attribute as a `class="..."` reference (merged into any
      existing class attribute on the same tag).
  #3. Rewrite `url_for('static', filename='X')` to `static_v('X')` so cache-bust
      hashes get injected by the context processor in app/__init__.py.

Re-running this script is a no-op for already-migrated content.
"""
from __future__ import annotations

import hashlib
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / "templates"
EXT_CSS = ROOT / "static" / "css" / "ext-inline.css"

# Anything inside these wrappers is left alone (raw blocks, comments).
RAW_RE = re.compile(r"({%\s*raw\s*%}.*?{%\s*endraw\s*%}|{#.*?#})", re.DOTALL)


def _mask(text: str):
    """Replace raw/comment regions with sentinels so regexes don't touch them."""
    holes: list[str] = []

    def repl(m):
        holes.append(m.group(0))
        return f"\x00H{len(holes)-1}\x00"

    return RAW_RE.sub(repl, text), holes


def _unmask(text: str, holes: list[str]) -> str:
    for i, h in enumerate(holes):
        text = text.replace(f"\x00H{i}\x00", h)
    return text


# ─── 1A: nonce attribute on inline <script> and <style> ───────────────────────
SCRIPT_OPEN_RE = re.compile(
    r"<script(?P<attrs>(?:\s+[^>]*)?)>",
    re.IGNORECASE,
)
STYLE_OPEN_RE = re.compile(
    r"<style(?P<attrs>(?:\s+[^>]*)?)>",
    re.IGNORECASE,
)


def _add_nonce(text: str) -> tuple[str, int]:
    count = 0

    def script_repl(m: re.Match) -> str:
        nonlocal count
        attrs = m.group("attrs") or ""
        if re.search(r"\bsrc\s*=", attrs, re.IGNORECASE):
            return m.group(0)
        if re.search(r"\bnonce\s*=", attrs, re.IGNORECASE):
            return m.group(0)
        count += 1
        return f"<script{attrs} nonce=\"{{{{ csp_nonce() }}}}\">"

    def style_repl(m: re.Match) -> str:
        nonlocal count
        attrs = m.group("attrs") or ""
        if re.search(r"\bnonce\s*=", attrs, re.IGNORECASE):
            return m.group(0)
        count += 1
        return f"<style{attrs} nonce=\"{{{{ csp_nonce() }}}}\">"

    text = SCRIPT_OPEN_RE.sub(script_repl, text)
    text = STYLE_OPEN_RE.sub(style_repl, text)
    return text, count


# ─── #3: url_for('static', filename='X') → static_v('X') ──────────────────────
STATIC_URL_RE = re.compile(
    r"url_for\(\s*(['\"])static\1\s*,\s*filename\s*=\s*(['\"])([^'\"]+)\2\s*\)",
)


def _migrate_static_v(text: str) -> tuple[str, int]:
    count = 0

    def repl(m: re.Match) -> str:
        nonlocal count
        count += 1
        q = m.group(2)
        path = m.group(3)
        return f"static_v({q}{path}{q})"

    return STATIC_URL_RE.sub(repl, text), count


# ─── 1C: style="..." → class="ext-XXXXXXXX" ───────────────────────────────────
# Match a single tag and rewrite its style attribute. We match the full tag so
# we can merge with an existing class attribute on the same element.
TAG_RE = re.compile(r"<(?P<name>[a-zA-Z][\w:-]*)(?P<attrs>(?:\s+[^>]*?)?)\s*(?P<slash>/?)>")
STYLE_ATTR_RE = re.compile(r"""\sstyle\s*=\s*(['"])(?P<val>.*?)\1""", re.DOTALL)
CLASS_ATTR_RE = re.compile(r"""\sclass\s*=\s*(?P<q>['"])(?P<val>.*?)(?P=q)""", re.DOTALL)


def _class_token_for(style_value: str) -> str:
    # 8-char hex of normalized style (collapse whitespace) → deterministic.
    norm = re.sub(r"\s+", " ", style_value).strip().rstrip(";")
    return "ext-" + hashlib.md5(norm.encode("utf-8")).hexdigest()[:8]


# Catalog of (token, normalized style) collected across the whole run.
_STYLE_CATALOG: dict[str, str] = {}


def _extract_styles(text: str) -> tuple[str, int]:
    count = 0

    def per_tag(m: re.Match) -> str:
        nonlocal count
        tag = m.group(0)
        sm = STYLE_ATTR_RE.search(tag)
        if not sm:
            return tag
        style_val = sm.group("val")
        # Skip if style contains Jinja expression — can't hash variable output.
        if "{{" in style_val or "{%" in style_val:
            return tag
        # Skip empty.
        if not style_val.strip():
            # Just drop the attribute.
            cleaned = (tag[: sm.start()] + tag[sm.end():])
            return cleaned
        norm = re.sub(r"\s+", " ", style_val).strip().rstrip(";")
        if not norm:
            cleaned = (tag[: sm.start()] + tag[sm.end():])
            return cleaned
        token = _class_token_for(norm)
        _STYLE_CATALOG[token] = norm

        # Remove the style attribute.
        without_style = tag[: sm.start()] + tag[sm.end():]

        # Merge into existing class, or add a new class attribute.
        cm = CLASS_ATTR_RE.search(without_style)
        if cm:
            existing = cm.group("val")
            # Avoid double-adding if already present (idempotent re-run).
            tokens = existing.split()
            if token in tokens:
                merged = existing
            else:
                merged = (existing + " " + token).strip()
            q = cm.group("q")
            new_attr = f' class={q}{merged}{q}'
            merged_tag = without_style[: cm.start()] + new_attr + without_style[cm.end():]
        else:
            # Insert class attribute right after the tag name.
            name_end = len(m.group("name")) + 1  # past "<name"
            merged_tag = (
                without_style[:name_end]
                + f' class="{token}"'
                + without_style[name_end:]
            )
        count += 1
        return merged_tag

    return TAG_RE.sub(per_tag, text), count


# ─── Driver ───────────────────────────────────────────────────────────────────
def process_file(path: Path) -> dict:
    original = path.read_text(encoding="utf-8")
    masked, holes = _mask(original)
    masked, n_nonce = _add_nonce(masked)
    masked, n_static = _migrate_static_v(masked)
    masked, n_style = _extract_styles(masked)
    text = _unmask(masked, holes)
    if text != original:
        path.write_text(text, encoding="utf-8")
    return {"nonce": n_nonce, "static_v": n_static, "style": n_style}


_CSS_RULE_RE = re.compile(r"^\.(ext-[0-9a-f]{8})\s*\{\s*(.*?)\s*\}\s*$")


def _load_existing_css() -> None:
    """Seed the catalog from a previously generated ext-inline.css so re-runs
    don't lose rules whose source `style=` attributes were already migrated."""
    if not EXT_CSS.exists():
        return
    for raw in EXT_CSS.read_text(encoding="utf-8").splitlines():
        m = _CSS_RULE_RE.match(raw.strip())
        if m:
            token = m.group(1)
            body = m.group(2).strip()
            if body.endswith(";"):
                body = body[:-1].rstrip()
            _STYLE_CATALOG.setdefault(token, body)


def write_ext_css() -> int:
    EXT_CSS.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "/* Auto-generated by scripts/migrate_inline.py — DO NOT EDIT BY HAND. */",
        "/* Each rule corresponds to an extracted inline style=\"...\" attribute. */",
        "",
    ]
    for token in sorted(_STYLE_CATALOG):
        body = _STYLE_CATALOG[token]
        if not body.endswith(";"):
            body += ";"
        lines.append(f".{token} {{ {body} }}")
    EXT_CSS.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return len(_STYLE_CATALOG)


def main() -> int:
    if not TEMPLATES.is_dir():
        print(f"ERROR: templates dir not found at {TEMPLATES}", file=sys.stderr)
        return 1

    _load_existing_css()

    totals = {"nonce": 0, "static_v": 0, "style": 0, "files": 0}
    for path in sorted(TEMPLATES.rglob("*.html")):
        stats = process_file(path)
        if any(v for v in stats.values()):
            totals["files"] += 1
            for k in ("nonce", "static_v", "style"):
                totals[k] += stats[k]

    n_rules = write_ext_css()

    print(f"Files modified : {totals['files']}")
    print(f"Nonces added   : {totals['nonce']}")
    print(f"static_v subs  : {totals['static_v']}")
    print(f"Styles hashed  : {totals['style']}  (unique classes: {n_rules})")
    print(f"CSS written to : {EXT_CSS.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
