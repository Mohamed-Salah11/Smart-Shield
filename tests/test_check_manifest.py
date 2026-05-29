"""
tests/test_check_manifest.py
----------------------------
Phase 2.7: ``tools/check_manifest.py`` gates the install/release pipeline
on ``app/manifests/python_runtime.json`` matching ``requirements.txt``.
These tests pin every branch of the parser, the diff, and the exit-code
contract so a future refactor cannot silently weaken the check.
"""
import io
import json
import os
import sys

import pytest

# check_manifest doesn't touch the DB, but pytest's conftest does — keep it
# quiet by stamping the usual env vars.
os.environ.setdefault("SMARTSHIELD_DB_PATH", "file:cmtest?mode=memory&cache=shared")
os.environ.setdefault("SECRET_KEY", "test-cm-key")
os.environ.setdefault("SMARTSHIELD_MASTER_KEY",
    __import__("base64").b64encode(__import__("secrets").token_bytes(32)).decode())

# Ensure repo root is importable.
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import tools.check_manifest as cm


# ---------------------------------------------------------------------------
# Repo-level invariant — the committed manifest must match the committed
# requirements.txt. This is the test that will catch the original drift bug
# the moment it reappears.
# ---------------------------------------------------------------------------

def test_committed_manifest_matches_committed_requirements():
    ok, missing, extra = cm.check()
    assert ok, (
        f"python_runtime.json drift detected. "
        f"Missing from manifest: {missing}. Extra in manifest: {extra}"
    )


# ---------------------------------------------------------------------------
# Parser: requirements.txt
# ---------------------------------------------------------------------------

class TestParseRequirements:

    def test_strips_version_pin_extras_and_env_marker(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text(
            "flask==3.1.2\n"
            "requests>=2.32,<3.0\n"
            "gevent>=24.0,<26.0\n"
            "uvicorn[standard]==0.30; python_version >= '3.10'\n",
            encoding="utf-8",
        )
        result = cm.parse_requirements(str(req))
        assert "flask" in result
        assert "requests" in result
        assert "gevent" in result
        assert "uvicorn" in result  # extras + env marker stripped
        # Nothing leaked into the names.
        assert not any("[" in name or ";" in name or "=" in name for name in result)

    def test_skips_comments_blanks_and_pip_directives(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text(
            "# header comment\n"
            "\n"
            "flask==3.1.2\n"
            "-r other.txt\n"
            "-e git+https://example.com/foo.git\n"
            "--index-url https://example.com\n"
            "git+https://example.com/bar.git\n"
            "requests==2.32.3\n",
            encoding="utf-8",
        )
        result = cm.parse_requirements(str(req))
        assert result == {"flask", "requests"}

    def test_uses_package_import_map_for_known_renames(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text(
            "python-dotenv==1.0.1\n"
            "PyYAML==6.0.3\n"
            "fpdf2>=2.7.9\n",
            encoding="utf-8",
        )
        result = cm.parse_requirements(str(req))
        # Each dist name must be translated, NOT used verbatim.
        assert result == {"dotenv", "yaml", "fpdf"}

    def test_fallback_lowercases_and_underscores_unknown_dists(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("Flask-Sock>=0.7\nWerkzeug==3.1.3\n", encoding="utf-8")
        result = cm.parse_requirements(str(req))
        # `-` → `_` plus lowercased; matches install.sh's __import__ target.
        assert "flask_sock" in result
        assert "werkzeug" in result


# ---------------------------------------------------------------------------
# Parser: manifest
# ---------------------------------------------------------------------------

class TestParseManifest:

    def test_returns_imports_set(self, tmp_path):
        m = tmp_path / "manifest.json"
        m.write_text(json.dumps({"imports": ["flask", "requests"]}), encoding="utf-8")
        assert cm.parse_manifest(str(m)) == {"flask", "requests"}

    def test_missing_imports_key_returns_empty_set(self, tmp_path):
        m = tmp_path / "manifest.json"
        m.write_text(json.dumps({"_comment": "no list"}), encoding="utf-8")
        assert cm.parse_manifest(str(m)) == set()


# ---------------------------------------------------------------------------
# Diff & end-to-end check()
# ---------------------------------------------------------------------------

class TestCheck:

    def _write(self, tmp_path, req_text, manifest_obj):
        req = tmp_path / "requirements.txt"
        req.write_text(req_text, encoding="utf-8")
        manifest = tmp_path / "manifest.json"
        manifest.write_text(json.dumps(manifest_obj), encoding="utf-8")
        return str(req), str(manifest)

    def test_matching_returns_ok_with_empty_diff(self, tmp_path):
        req, manifest = self._write(
            tmp_path,
            "flask==3.1.2\nrequests==2.32.3\n",
            {"imports": ["flask", "requests"]},
        )
        ok, missing, extra = cm.check(req, manifest)
        assert ok is True
        assert missing == []
        assert extra == []

    def test_missing_from_manifest_reported(self, tmp_path):
        req, manifest = self._write(
            tmp_path,
            "flask==3.1.2\nrequests==2.32.3\nfpdf2>=2.7.9\n",
            {"imports": ["flask", "requests"]},
        )
        ok, missing, extra = cm.check(req, manifest)
        assert ok is False
        assert missing == ["fpdf"]
        assert extra == []

    def test_extra_in_manifest_reported(self, tmp_path):
        req, manifest = self._write(
            tmp_path,
            "flask==3.1.2\n",
            {"imports": ["flask", "ghost_module"]},
        )
        ok, missing, extra = cm.check(req, manifest)
        assert ok is False
        assert missing == []
        assert extra == ["ghost_module"]

    def test_both_sides_diverged_reported(self, tmp_path):
        req, manifest = self._write(
            tmp_path,
            "flask==3.1.2\nfpdf2>=2.7.9\n",
            {"imports": ["flask", "ghost_module"]},
        )
        ok, missing, extra = cm.check(req, manifest)
        assert ok is False
        assert missing == ["fpdf"]
        assert extra == ["ghost_module"]


# ---------------------------------------------------------------------------
# CLI / exit-code contract
# ---------------------------------------------------------------------------

class TestCliExitCode:

    def test_main_exits_zero_on_match(self, monkeypatch, capsys):
        # The committed repo is in-sync (verified above), so main() returns 0
        # without arguments.
        rc = cm.main([])
        assert rc == 0
        out = capsys.readouterr().out
        assert "OK" in out

    def test_main_exits_one_when_manifest_missing_entry(
        self, monkeypatch, tmp_path, capsys
    ):
        # Point check_manifest at a fake requirements.txt with an extra dep.
        req = tmp_path / "requirements.txt"
        req.write_text("flask==3.1.2\nfpdf2>=2.7.9\n", encoding="utf-8")
        manifest = tmp_path / "manifest.json"
        manifest.write_text(json.dumps({"imports": ["flask"]}), encoding="utf-8")

        monkeypatch.setattr(cm, "REQUIREMENTS_PATH", str(req))
        monkeypatch.setattr(cm, "MANIFEST_PATH", str(manifest))

        rc = cm.main([])
        assert rc == 1
        err = capsys.readouterr().err
        assert "fpdf" in err
        assert "out of sync" in err

    def test_main_json_output_round_trips(self, monkeypatch, tmp_path, capsys):
        req = tmp_path / "requirements.txt"
        req.write_text("flask==3.1.2\nfpdf2>=2.7.9\n", encoding="utf-8")
        manifest = tmp_path / "manifest.json"
        manifest.write_text(json.dumps({"imports": ["flask"]}), encoding="utf-8")
        monkeypatch.setattr(cm, "REQUIREMENTS_PATH", str(req))
        monkeypatch.setattr(cm, "MANIFEST_PATH", str(manifest))

        rc = cm.main(["--json"])
        assert rc == 1
        out = capsys.readouterr().out
        payload = json.loads(out)
        assert payload["ok"] is False
        assert payload["missing_from_manifest"] == ["fpdf"]
        assert payload["extra_in_manifest"] == []

    def test_main_handles_missing_files_gracefully(
        self, monkeypatch, tmp_path, capsys
    ):
        # Both files absent → exit 1, no traceback.
        monkeypatch.setattr(cm, "REQUIREMENTS_PATH",
                            str(tmp_path / "nope-req.txt"))
        monkeypatch.setattr(cm, "MANIFEST_PATH",
                            str(tmp_path / "nope-manifest.json"))
        rc = cm.main([])
        assert rc == 1
        err = capsys.readouterr().err
        assert "check_manifest" in err
