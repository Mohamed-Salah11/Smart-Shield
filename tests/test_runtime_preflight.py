"""
tests/test_runtime_preflight.py
-------------------------------
Phase 3.3 — prove ``tools/runtime_preflight.py`` actually neutralises a
misconfigured ``smartshield.env`` claiming live-mode.

The script's job is to verify that ``create_app()`` boots successfully on a
freshly installed appliance. Crucially, it must do so WITHOUT touching real
PF / network state — otherwise an operator running it post-install on a
production box could mutate the kernel ruleset.

Today's guard is ``_force_safe_env()``:
    SMARTSHIELD_ENABLE_NETWORK_APPLY = "0"
    SMARTSHIELD_NETWORK_DRY_RUN      = "1"
    SMARTSHIELD_DISABLE_BACKGROUND   = "1"
…written into ``os.environ`` *before* the ``from app import create_app``
line. The regression these tests pin: even when the surrounding env claims
the opposite, the preflight still boots cleanly AND nothing calls into
``network_service.run_command`` (which shells out to ``pfctl`` / ``ifconfig``
/ ``service`` etc.).
"""
import json
import os
import sys

import pytest

os.environ.setdefault("SMARTSHIELD_DB_PATH", "file:rpftest?mode=memory&cache=shared")
os.environ.setdefault("SECRET_KEY", "test-rpf-key")
os.environ.setdefault("SMARTSHIELD_MASTER_KEY",
    __import__("base64").b64encode(__import__("secrets").token_bytes(32)).decode())

# Ensure tools/ is importable.
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)


def _set_live_env(monkeypatch):
    """Simulate a smartshield.env that claims live mode. The preflight is
    supposed to override these — that's the entire point of the script."""
    monkeypatch.setenv("SMARTSHIELD_ENABLE_NETWORK_APPLY", "1")
    monkeypatch.setenv("SMARTSHIELD_NETWORK_DRY_RUN", "0")
    monkeypatch.setenv("SMARTSHIELD_DISABLE_BACKGROUND", "0")


def _trap_run_command(monkeypatch):
    """Replace ``network_service.run_command`` with a tripwire. If the
    preflight ever shells out to pfctl/ifconfig/service, this raises and
    the test fails with a useful traceback pointing at the call site."""
    import app.services.network_service as ns

    def _explode(cmd, *_a, **_kw):
        raise AssertionError(
            f"runtime_preflight tried to shell out to {list(cmd)!r} — "
            "_force_safe_env() did not neutralise the live env."
        )
    monkeypatch.setattr(ns, "run_command", _explode)


# ---------------------------------------------------------------------------
# Main regression — preflight survives a hostile env
# ---------------------------------------------------------------------------

class TestRuntimePreflightSafetyOverrides:

    def test_run_returns_ok_under_live_env(self, monkeypatch, capsys):
        # Live env *before* run() is called. _force_safe_env() must flip
        # these back inside run() before `from app import create_app`.
        _set_live_env(monkeypatch)
        _trap_run_command(monkeypatch)

        from tools import runtime_preflight
        rc = runtime_preflight.run(json_output=True)
        out = capsys.readouterr().out
        payload = json.loads(out)

        assert rc == 0, f"runtime_preflight reported non-zero: {payload!r}"
        assert payload["ok"] is True, payload
        assert payload["blueprints"] > 0
        assert payload["routes"] > 0
        assert payload.get("error") in (None, "", )

    def test_safe_env_actually_takes_effect_inside_run(self, monkeypatch):
        # After _force_safe_env() runs, os.environ must carry the safe
        # values regardless of what the test set before. This pins the
        # *mechanism*, not just its visible side effect.
        _set_live_env(monkeypatch)

        from tools import runtime_preflight
        runtime_preflight._force_safe_env()

        assert os.environ["SMARTSHIELD_ENABLE_NETWORK_APPLY"] == "0"
        assert os.environ["SMARTSHIELD_NETWORK_DRY_RUN"] == "1"
        assert os.environ["SMARTSHIELD_DISABLE_BACKGROUND"] == "1"
        assert os.environ["FLASK_DEBUG"] == "0"


# ---------------------------------------------------------------------------
# Negative — the tripwire is wired correctly (sanity check on the test)
# ---------------------------------------------------------------------------

class TestRunCommandTripwire:

    def test_tripwire_actually_raises_when_run_command_is_called(self, monkeypatch):
        # Catches the embarrassing failure mode where the tripwire silently
        # no-ops — then "preflight is safe" really means "the test does nothing".
        _trap_run_command(monkeypatch)
        import app.services.network_service as ns
        with pytest.raises(AssertionError, match="runtime_preflight tried to shell out"):
            ns.run_command(["pfctl", "-sr"], check=False)


# ---------------------------------------------------------------------------
# JSON contract — schema of run(json_output=True) output
# ---------------------------------------------------------------------------

class TestPreflightJsonContract:

    def test_json_output_has_required_keys(self, monkeypatch, capsys):
        _set_live_env(monkeypatch)
        _trap_run_command(monkeypatch)
        from tools import runtime_preflight
        runtime_preflight.run(json_output=True)
        payload = json.loads(capsys.readouterr().out)
        # Every key the install.sh wrapper parses must be present.
        for key in ("ok", "blueprints", "routes", "error"):
            assert key in payload, f"runtime_preflight JSON missing {key!r}"
