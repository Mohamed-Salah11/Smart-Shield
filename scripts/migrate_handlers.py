#!/usr/bin/env python3
"""
Idempotent migration of inline event handlers (onclick=..., onchange=..., etc.)
in templates/ for strict-CSP compatibility.

Per template:

  1. Find every attribute matching ``on<event>="<body>"`` (and single-quoted form).
  2. Replace with a ``data-action-<event>="<deterministic-id>"`` attribute (or
     just ``data-action`` for click handlers, which the delegator falls back
     to when no event-specific key is set).
  3. Append a single ``<script nonce="{{ csp_nonce() }}">`` registration block
     at the end of the template that wires every handler:

         SSActions['<id>'] = function (event, el) { /* original body */ };

  The handler body is kept verbatim, so any Jinja-interpolated values inside
  (``{{ thing }}``) still render at request time. The id is deterministic
  (sha8 of template path + body) so re-running the script is a no-op for
  already-migrated content.
"""
from __future__ import annotations

import hashlib
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / "templates"

RAW_RE = re.compile(r"({%\s*raw\s*%}.*?{%\s*endraw\s*%}|{#.*?#})", re.DOTALL)
INLINE_HANDLERS_MARKER_OPEN = "<!-- inline-handlers:auto -->"
INLINE_HANDLERS_MARKER_CLOSE = "<!-- /inline-handlers:auto -->"

# Jinja structural markers used to place the registration block inheritance-correctly.
EXTENDS_RE = re.compile(r"{%-?\s*extends\s+['\"](?P<parent>[^'\"]+)['\"]\s*-?%}")
ENDBLOCK_RE = re.compile(r"{%-?\s*endblock[^%]*%}")
SCRIPTS_OPEN_RE = re.compile(r"{%-?\s*block\s+scripts\s*-?%}")
EXTRA_JS_BLOCK_RE = re.compile(
    r"({%-?\s*block\s+extra_js\s*-?%})(?P<inner>.*?)({%-?\s*endblock[^%]*%})", re.DOTALL
)
# An empty scripts wrapper left behind after the marker region is stripped on re-run.
EMPTY_SCRIPTS_WRAPPER_RE = re.compile(
    r"\n?{%-?\s*block\s+scripts\s*-?%}(?:\s*{{\s*super\(\)\s*}})?\s*{%-?\s*endblock[^%]*%}\n?",
    re.DOTALL,
)

# Recognized DOM events we will migrate. Anything else stays inline (rare).
EVENTS = (
    "click", "change", "submit", "input", "focus", "blur",
    "keydown", "keyup", "keypress", "mouseover", "mouseout",
    "dblclick", "contextmenu", "mousedown", "mouseup",
)
# Build the attribute regex once. Matches: on<event>="..."  or  on<event>='...'
HANDLER_RE = re.compile(
    r"""\son(?P<event>""" + "|".join(EVENTS) + r""")\s*=\s*(?P<q>['"])(?P<body>.*?)(?P=q)""",
    re.DOTALL | re.IGNORECASE,
)


def _mask_raw(text: str):
    holes: list[str] = []

    def repl(m):
        holes.append(m.group(0))
        return f"\x00H{len(holes)-1}\x00"

    return RAW_RE.sub(repl, text), holes


def _unmask(text: str, holes: list[str]) -> str:
    for i, h in enumerate(holes):
        text = text.replace(f"\x00H{i}\x00", h)
    return text


def _strip_old_block(text: str) -> str:
    """Remove a previously-generated registration block so re-runs are clean."""
    pattern = re.compile(
        re.escape(INLINE_HANDLERS_MARKER_OPEN)
        + r".*?"
        + re.escape(INLINE_HANDLERS_MARKER_CLOSE),
        re.DOTALL,
    )
    return pattern.sub("", text)


def _extends_parent(text: str):
    """Return the parent template path of an ``{% extends %}`` template, or None."""
    m = EXTENDS_RE.search(text)
    return m.group("parent") if m else None


def _emit_block(text: str, block: str, parent) -> str:
    """
    Insert the registration ``block`` into ``text`` in an inheritance-correct spot.

    - No ``{% extends %}`` (standalone page / partial): append at end (legacy).
    - Extends ``soc_portal/base.html``: merge inside the existing ``{% block extra_js %}``.
    - Extends any other base: merge into an existing ``{% block scripts %}`` if present,
      else append a new ``{% block scripts %}{{ super() }} … {% endblock %}`` after the
      last ``{% endblock %}``.
    """
    if parent is None:
        return text.rstrip() + "\n" + block

    if parent.replace("\\", "/").endswith("soc_portal/base.html"):
        m = EXTRA_JS_BLOCK_RE.search(text)
        if m:
            inner = m.group("inner").rstrip()
            merged = m.group(1) + ("\n" + inner if inner else "") + "\n" + block + "\n" + m.group(3)
            return text[: m.start()] + merged + text[m.end():]
        return _append_wrapper(text, block, "extra_js", super_call=False)

    # base.html family.
    so = SCRIPTS_OPEN_RE.search(text)
    if so:
        em = ENDBLOCK_RE.search(text, so.end())
        if em:
            return text[: em.start()] + block + "\n" + text[em.start():]
    return _append_wrapper(text, block, "scripts", super_call=True)


def _append_wrapper(text: str, block: str, block_name: str, super_call: bool) -> str:
    """Append a fresh ``{% block <name> %}…{% endblock %}`` after the last endblock."""
    last = None
    for m in ENDBLOCK_RE.finditer(text):
        last = m
    opener = "{%% block %s %%}" % block_name
    if super_call:
        opener += "{{ super() }}"
    wrapper = "\n" + opener + "\n" + block + "\n{% endblock %}\n"
    if last:
        return text[: last.end()] + wrapper + text[last.end():]
    return text.rstrip() + "\n" + wrapper


def _action_id(template_rel: str, event: str, body: str, idx: int) -> str:
    """
    Deterministic id from (path, event, body, ordinal). The ordinal disambiguates
    multiple identical handlers in the same file (e.g. five buttons each
    `onclick="confirmDelete()"`). Hash is short for readable HTML.
    """
    norm_body = re.sub(r"\s+", " ", body).strip()
    seed = f"{template_rel}|{event}|{norm_body}|{idx}"
    return f"h_{hashlib.sha1(seed.encode('utf-8')).hexdigest()[:10]}"


def _escape_js(body: str) -> str:
    """Body goes inside a JS function. We embed it verbatim and let Jinja
    interpolation run; the only thing we must protect is the literal sequence
    `</script>` which would otherwise close our wrapping <script> tag."""
    return body.replace("</", "<\\/")


def process_file(path: Path) -> int:
    original = path.read_text(encoding="utf-8")
    text = _strip_old_block(original)
    masked, holes = _mask_raw(text)

    # ord_seq: per-(event,body) counter for deterministic idx disambiguation.
    ord_seq: dict[tuple[str, str], int] = defaultdict(int)
    # Collected registrations in source order.
    registrations: list[tuple[str, str, str]] = []  # (id, event, body)

    template_rel = str(path.relative_to(ROOT)).replace("\\", "/")

    def repl(m: re.Match) -> str:
        event = m.group("event").lower()
        body  = m.group("body")
        if not body.strip():
            return ""  # drop empty handler
        key = (event, re.sub(r"\s+", " ", body).strip())
        idx = ord_seq[key]
        ord_seq[key] += 1
        aid = _action_id(template_rel, event, body, idx)
        registrations.append((aid, event, body))
        # `data-action` (no suffix) is the click fallback; for other events
        # use `data-action-<event>` (camelCased via dataset) so the delegator
        # routes the right event to the right handler.
        attr_name = "data-action" if event == "click" else f"data-action-{event}"
        return f' {attr_name}="{aid}"'

    new_masked = HANDLER_RE.sub(repl, masked)
    new_text = _unmask(new_masked, holes)

    if not registrations:
        # No new inline handlers to migrate. Leave any existing registration
        # block intact — re-runs must be non-destructive (the stripped block is
        # only re-emitted when there is something to wire).
        return 0

    # Drop any empty wrapper left behind once the marker region was stripped, so
    # we don't accumulate duplicate `{% block scripts %}` shells on re-run.
    new_text = EMPTY_SCRIPTS_WRAPPER_RE.sub("\n", new_text)

    # Build the registration block. One IIFE keeps lint clean and avoids
    # leaking helper names into the global scope.
    lines = [
        "",
        INLINE_HANDLERS_MARKER_OPEN,
        '<script nonce="{{ csp_nonce() }}">',
        "/* Auto-generated by scripts/migrate_handlers.py — DO NOT EDIT BY HAND. */",
        "(function () {",
        "  var R = window.SSActions || (window.SSActions = {});",
    ]
    for aid, _event, body in registrations:
        safe_body = _escape_js(body)
        lines.append(f"  R[{aid!r}] = function (event, el) {{ {safe_body} }};")
    lines.append("})();")
    lines.append("</script>")
    lines.append(INLINE_HANDLERS_MARKER_CLOSE)
    block = "\n".join(lines)

    # Place the block inheritance-correctly: inside `{% block scripts %}` (or the
    # soc_portal `extra_js` block) for child templates, so it actually renders.
    new_text = _emit_block(new_text, block, _extends_parent(original))
    path.write_text(new_text, encoding="utf-8")
    return len(registrations)


_REG_LINE_RE = re.compile(r"R\[")
# A backslash-escaped quote in a registration body is invalid JS (it only made
# sense inside the JS template-literal string the handler was extracted from).
_ESCAPED_QUOTE_RE = re.compile(r"\\['\"]")


def check_file(path: Path) -> list[str]:
    """Return a list of problems for one template (empty = clean)."""
    text = path.read_text(encoding="utf-8")
    rel = str(path.relative_to(ROOT)).replace("\\", "/")
    problems: list[str] = []

    open_idx = text.find(INLINE_HANDLERS_MARKER_OPEN)
    if open_idx == -1:
        return problems  # no generated block — nothing to check

    # 1. A child template must not carry its generated block outside all blocks
    #    (i.e. after the last {% endblock %}), or it will never render.
    if _extends_parent(text) is not None:
        last_endblock = None
        for m in ENDBLOCK_RE.finditer(text):
            last_endblock = m
        if last_endblock is None or open_idx > last_endblock.start():
            problems.append(
                f"{rel}: inline-handlers block is outside any {{% block %}} "
                f"(after the last {{% endblock %}}) -- it will never render."
            )

    # 2. No registration line may contain an unresolved Jinja/JS template var.
    close_idx = text.find(INLINE_HANDLERS_MARKER_CLOSE, open_idx)
    region = text[open_idx: close_idx if close_idx != -1 else len(text)]
    for lineno, line in enumerate(region.splitlines(), start=1):
        if not _REG_LINE_RE.search(line):
            continue
        if "${" in line or "{{" in line:
            problems.append(
                f"{rel} (block line {lineno}): registration references an "
                f"out-of-scope template var: {line.strip()[:120]}"
            )
        elif _ESCAPED_QUOTE_RE.search(line):
            problems.append(
                f"{rel} (block line {lineno}): registration has an invalid "
                f"backslash-escaped quote: {line.strip()[:120]}"
            )
    return problems


def check_templates() -> int:
    problems: list[str] = []
    for path in sorted(TEMPLATES.rglob("*.html")):
        problems.extend(check_file(path))
    if problems:
        print("Template handler check FAILED:")
        for p in problems:
            print(f"  - {p}")
        print(f"\n{len(problems)} problem(s) found.")
        return 1
    print("Template handler check passed: no dead or invalid handler blocks.")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not TEMPLATES.is_dir():
        print(f"ERROR: templates dir not found at {TEMPLATES}", file=sys.stderr)
        return 1

    if "--check" in argv:
        return check_templates()

    total_handlers = 0
    files_modified = 0
    for path in sorted(TEMPLATES.rglob("*.html")):
        n = process_file(path)
        if n:
            files_modified += 1
            total_handlers += n

    print(f"Files modified : {files_modified}")
    print(f"Handlers wired : {total_handlers}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
