"""
tests/test_tab_render_lint.py
-----------------------------
Pins ``tools/check_tab_render.py`` — the guard against the "blank tab panel"
antipattern where a CSS-hidden panel is revealed with
``element.style.display = ''`` (which clears the inline style and falls back to
the ``display:none`` class, silently re-hiding the panel).

The headline invariant is that the committed templates/ tree is clean.
"""
import importlib.util
import os
import sys

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

_TOOL_PATH = os.path.join(_REPO_ROOT, "tools", "check_tab_render.py")
_spec = importlib.util.spec_from_file_location("check_tab_render", _TOOL_PATH)
check_tab_render = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_tab_render)


def test_no_empty_display_reveals():
    """The committed templates/ tree must contain no empty-string display
    assignments — the checker exits 0 on the current (fixed) tree."""
    assert check_tab_render.main() == 0


def test_regex_flags_empty_string_assignments():
    pattern = check_tab_render._EMPTY_DISPLAY
    assert pattern.search("el.style.display = '';")
    assert pattern.search('el.style.display = "";')
    assert pattern.search("x.style.display=''")


def test_regex_ignores_explicit_display_values():
    pattern = check_tab_render._EMPTY_DISPLAY
    assert not pattern.search("el.style.display = 'block';")
    assert not pattern.search("el.style.display = 'none';")
    assert not pattern.search("el.style.display = 'table-row';")
    assert not pattern.search("el.style.display = 'inline-block';")
