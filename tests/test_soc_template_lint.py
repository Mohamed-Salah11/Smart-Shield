"""
tests/test_soc_template_lint.py
-------------------------------
Phase 2.8: ``scripts/soc_template_lint.py`` blocks stored-XSS via the SOC
portal's dangerous-field interpolations. These tests pin every branch of
the scanner — what it flags, what it ignores, what the exit-code contract
looks like — so a future relaxation of the rule cannot slip through review.
"""
import json
import os
import sys

import pytest

os.environ.setdefault("SMARTSHIELD_DB_PATH", "file:soclint?mode=memory&cache=shared")
os.environ.setdefault("SECRET_KEY", "test-soclint-key")
os.environ.setdefault("SMARTSHIELD_MASTER_KEY",
    __import__("base64").b64encode(__import__("secrets").token_bytes(32)).decode())

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import scripts.soc_template_lint as lint


def _write(tmp_path, name, content):
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return str(path)


# ---------------------------------------------------------------------------
# Repo-level invariant — committed soc_portal templates must be clean.
# ---------------------------------------------------------------------------

def test_committed_soc_portal_templates_pass_lint():
    violations = lint.scan()
    assert violations == [], (
        f"SOC portal templates have unescaped dangerous-field interpolations: "
        f"{violations}"
    )


# ---------------------------------------------------------------------------
# Dangerous fields trigger a fail
# ---------------------------------------------------------------------------

class TestDangerousFieldsFail:

    @pytest.mark.parametrize("expr", [
        "${e.action}",
        "${aa.action}",
        "${event.signature}",
        "${e.username}",
        "${d.details}",
        "${e.details.signature}",
        "${e.details.action}",
        "${event['signature']}",
        "${event[\"action\"]}",
        "${e['username']}",
    ])
    def test_each_field_form_flagged(self, tmp_path, expr):
        path = _write(tmp_path, "x.html",
                      f"<script>html = `<div>{expr}</div>`;</script>\n")
        violations = lint.scan(str(tmp_path / "*.html"))
        assert len(violations) == 1, f"expected 1 violation for {expr!r}, got {violations}"
        assert expr.strip("${}") in violations[0][3]


# ---------------------------------------------------------------------------
# Safe wrappers — SOC.esc + encodeURIComponent — do NOT trigger a fail
# ---------------------------------------------------------------------------

class TestSafeWrappersPass:

    @pytest.mark.parametrize("expr", [
        "${SOC.esc(e.action)}",
        "${SOC.esc(aa.action)}",
        "${SOC.esc(event.details.signature)}",
        "${SOC.esc(event.username)}",
        "${SOC.esc(e.details.action || '—')}",
        "${encodeURIComponent(aa.case_id)}",
        # nested: the dangerous reference is inside an SOC.esc wrapper
        "${SOC.esc(timeFmt(e.action))}",
    ])
    def test_wrapped_interpolations_clean(self, tmp_path, expr):
        path = _write(tmp_path, "x.html",
                      f"<script>html = `<div>{expr}</div>`;</script>\n")
        violations = lint.scan(str(tmp_path / "*.html"))
        assert violations == [], f"safe wrapper falsely flagged: {expr!r} → {violations}"


# ---------------------------------------------------------------------------
# Non-dangerous interpolations are ignored entirely
# ---------------------------------------------------------------------------

class TestUnrelatedInterpolationsIgnored:

    @pytest.mark.parametrize("expr", [
        "${idx}",
        "${i}",
        "${ts}",
        "${SEV_COLOR[sev].color}",
        "${count}",
        # word-boundary check: `transaction` must NOT be matched as `action`.
        "${e.transaction_id}",
        # similar near-miss: `actions` (plural) should not match `action`.
        "${e.actions_taken}",
    ])
    def test_safe_expressions_not_flagged(self, tmp_path, expr):
        path = _write(tmp_path, "x.html",
                      f"<script>html = `<div>{expr}</div>`;</script>\n")
        violations = lint.scan(str(tmp_path / "*.html"))
        assert violations == [], f"unrelated interpolation falsely flagged: {expr!r} → {violations}"


# ---------------------------------------------------------------------------
# CLI / exit-code contract
# ---------------------------------------------------------------------------

class TestCli:

    def test_main_exits_zero_when_clean(self, monkeypatch, tmp_path, capsys):
        # Point lint at an empty fixture dir.
        monkeypatch.setattr(lint, "TEMPLATE_GLOB",
                            str(tmp_path / "*.html"))
        rc = lint.main([])
        assert rc == 0
        assert "OK" in capsys.readouterr().out

    def test_main_exits_one_on_violation(self, monkeypatch, tmp_path, capsys):
        _write(tmp_path, "bad.html",
               "<script>html = `<div>${e.signature}</div>`;</script>\n")
        monkeypatch.setattr(lint, "TEMPLATE_GLOB",
                            str(tmp_path / "*.html"))
        rc = lint.main([])
        assert rc == 1
        err = capsys.readouterr().err
        assert "e.signature" in err
        assert "SOC template lint failed" in err

    def test_main_json_output_round_trips(self, monkeypatch, tmp_path, capsys):
        _write(tmp_path, "bad.html",
               "<script>html = `<div>${e.signature}</div>`;</script>\n")
        monkeypatch.setattr(lint, "TEMPLATE_GLOB",
                            str(tmp_path / "*.html"))
        rc = lint.main(["--json"])
        assert rc == 1
        payload = json.loads(capsys.readouterr().out)
        assert payload["ok"] is False
        assert len(payload["violations"]) == 1
        v = payload["violations"][0]
        assert v["expr"] == "e.signature"
        assert v["line"] == 1


# ---------------------------------------------------------------------------
# Aggregate behaviour — multi-file, multi-violation reports
# ---------------------------------------------------------------------------

class TestAggregate:

    def test_multiple_files_each_contribute(self, tmp_path):
        _write(tmp_path, "a.html",
               "<script>html = `<div>${e.action}</div>`;</script>\n")
        _write(tmp_path, "b.html",
               "<script>html = `<div>${e.signature}</div>`;</script>\n")
        violations = lint.scan(str(tmp_path / "*.html"))
        files = {os.path.basename(v[0]) for v in violations}
        assert files == {"a.html", "b.html"}
