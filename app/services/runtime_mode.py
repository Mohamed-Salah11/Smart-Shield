"""
runtime_mode.py
---------------
Runtime mode detection for Smart Shield.

Exposes helpers that tell the application (and UI) whether it is running
on a live FreeBSD appliance, in dry-run mode, or in development mode.
"""

import logging
import os
import sys

_log = logging.getLogger(__name__)

_WEAK_SECRET_MARKERS = {
    "change-me", "replace-this", "changeme", "secret", "dev", "test",
    "flask-secret", "insecure", "please-change", "",
}


def is_freebsd() -> bool:
    return sys.platform.startswith("freebsd")


def network_apply_enabled() -> bool:
    return os.getenv("SMARTSHIELD_ENABLE_NETWORK_APPLY", "0") == "1"


def dry_run_enabled() -> bool:
    return os.getenv("SMARTSHIELD_NETWORK_DRY_RUN", "0") == "1"


def missing_dependencies() -> list:
    """Return names of required daemon binaries that are not installed."""
    try:
        from app.services.freebsd_setup import preflight_check
        report = preflight_check()
        return report.get("missing_required", [])
    except Exception:
        return []


def current_mode() -> str:
    """
    Return a single string describing the current operating mode.

    live        FreeBSD + network apply enabled + no missing required deps
    dry-run     FreeBSD + network apply disabled or dry-run flag set
    degraded    FreeBSD + required daemons missing
    development Non-FreeBSD (dev machine / Windows / macOS / Linux)
    """
    if not is_freebsd():
        return "development"

    if missing_dependencies():
        return "degraded"

    if dry_run_enabled() or not network_apply_enabled():
        return "dry-run"

    return "live"


def startup_warnings() -> list:
    """
    Return a list of warning dicts for missing or misconfigured keys/settings.
    Each dict has keys: level ('warning'|'critical'), feature, message.
    Warnings are logged automatically; callers may also display them in the UI.

    Production live-mode adds additional validation:
      - Weak / placeholder SECRET_KEY
      - FLASK_DEBUG=1 in production
      - Missing SMARTSHIELD_MASTER_KEY (secrets will not survive reboots)
    """
    mode = current_mode()
    warnings = []

    # ── Optional feature keys ──────────────────────────────────────────────

    if not os.getenv("GROQ_API_KEY"):
        warnings.append({
            "level":   "warning",
            "feature": "chatbot",
            "message": "GROQ_API_KEY is not set — AI chatbot will be unavailable.",
        })

    if not os.getenv("ABUSECH_AUTH_KEY"):
        warnings.append({
            "level":   "warning",
            "feature": "threat_intel",
            "message": "ABUSECH_AUTH_KEY is not set — abuse.ch threat intelligence feeds will be disabled.",
        })

    # ── Secrets encryption key ─────────────────────────────────────────────

    from app.secret_store import has_master_key

    if not has_master_key():
        msg   = ("No master key found (SMARTSHIELD_MASTER_KEY unset and no key "
                 "file present) — a key will be auto-generated.")
        level = "critical" if mode == "live" else "warning"
        if mode == "live":
            msg += (
                " On a production appliance this key must be set explicitly "
                "so encrypted secrets (VPN keys, PSKs) survive reboots."
            )
        warnings.append({"level": level, "feature": "secrets", "message": msg})

    # ── Production-only hardening checks ──────────────────────────────────

    if mode == "live":
        secret_key = os.getenv("SECRET_KEY", "")
        if any(m in secret_key.lower() for m in _WEAK_SECRET_MARKERS) or len(secret_key) < 24:
            warnings.append({
                "level":   "critical",
                "feature": "admin_security",
                "message": (
                    "SECRET_KEY appears to be weak or default. "
                    "Generate a strong random key: "
                    "python3 -c \"import secrets; print(secrets.token_hex(32))\""
                ),
            })

        if os.getenv("FLASK_DEBUG", "0").strip() == "1":
            warnings.append({
                "level":   "critical",
                "feature": "admin_security",
                "message": "FLASK_DEBUG=1 is set in production (live) mode — disable immediately.",
            })

        if os.getenv("SMARTSHIELD_ENABLE_NETWORK_APPLY", "0") != "1":
            warnings.append({
                "level":   "warning",
                "feature": "network_apply",
                "message": (
                    "SMARTSHIELD_ENABLE_NETWORK_APPLY is not set to 1 — "
                    "firewall and network changes will not be applied to the OS."
                ),
            })

        # ── Env file permissions check ─────────────────────────────────────
        import stat
        from app.config import _ss_dir
        env_dir = _ss_dir("/usr/local/etc")
        # `smartshield.env` is the canonical filename; check the legacy
        # `smart-shield.env` if the canonical one does not exist.
        env_path = os.path.join(env_dir, "smartshield.env")
        if not os.path.exists(env_path):
            legacy_env = os.path.join(env_dir, "smart-shield.env")
            if os.path.exists(legacy_env):
                env_path = legacy_env
        if sys.platform.startswith("freebsd") and os.path.exists(env_path):
            _mode = os.stat(env_path).st_mode
            if _mode & stat.S_IROTH:
                warnings.append({
                    "feature": "env_file_perms",
                    "level":   "critical",
                    "message": f"{env_path} is world-readable — fix: chmod 600",
                })

        # ── SECRET_KEY exact-match weak-value check ────────────────────────
        _secret = os.getenv("SECRET_KEY", "")
        if sys.platform.startswith("freebsd") and _secret.lower() in _WEAK_SECRET_MARKERS:
            warnings.append({
                "feature": "secret_key_default",
                "level":   "critical",
                "message": "SECRET_KEY is default or empty — set a strong random key",
            })

    for w in warnings:
        if w["level"] == "critical":
            _log.critical("[startup] %s", w["message"])
        else:
            _log.warning("[startup] %s", w["message"])

    return warnings


def production_ready() -> tuple:
    """
    Return (ok: bool, issues: list[str]) summarising whether the appliance
    is fit for production live mode.

    ok=True means all critical startup checks pass.
    """
    mode   = current_mode()
    warns  = startup_warnings()
    issues = [w["message"] for w in warns if w["level"] == "critical"]

    # Check mode itself
    if mode == "degraded":
        from app.services.freebsd_setup import preflight_check
        try:
            report = preflight_check()
            issues.extend(
                [f"Missing required tool: {t}" for t in report.get("missing_required", [])]
            )
        except Exception:
            pass

    return (len(issues) == 0, issues)


def env_file_world_readable() -> str:
    """Return the path of the smartshield env file when it exists and is
    world-readable, else "". FreeBSD-only — on a non-FreeBSD host the env file
    is a dev convenience and we never want to abort dev boots, so this returns
    "" off-platform.

    The env file holds ``SECRET_KEY`` and ``SMARTSHIELD_MASTER_KEY``; any
    ``S_IROTH`` bit means every local user can read the cookies-signing and
    secrets-encryption keys.
    """
    import stat
    if not sys.platform.startswith("freebsd"):
        return ""
    from app.config import _ss_dir
    env_dir = _ss_dir("/usr/local/etc")
    env_path = os.path.join(env_dir, "smartshield.env")
    if not os.path.exists(env_path):
        legacy = os.path.join(env_dir, "smart-shield.env")
        if os.path.exists(legacy):
            env_path = legacy
        else:
            return ""
    try:
        if os.stat(env_path).st_mode & stat.S_IROTH:
            return env_path
    except OSError:
        pass
    return ""


def assert_env_file_safe() -> None:
    """Refuse to boot in 'live' mode when the appliance env file is world-
    readable. Logged at CRITICAL and exits 78 (``EX_CONFIG``). Dev/dry-run /
    degraded keep booting — those modes don't run on a hardened appliance and
    the warning still surfaces through ``startup_warnings()``.

    Called from ``app/__init__.py::create_app`` after ``init_db()``.
    """
    if current_mode() != "live":
        return
    bad = env_file_world_readable()
    if not bad:
        return
    _log.critical(
        "[startup] refusing to boot in 'live' mode: %s is world-readable "
        "(holds SECRET_KEY / SMARTSHIELD_MASTER_KEY). Fix: chmod 600 %s",
        bad, bad,
    )
    raise SystemExit(78)


def mode_badge() -> dict:
    """Return display info for the UI mode banner."""
    mode = current_mode()
    _badges = {
        "live":        {"label": "Live",        "color": "green",  "icon": "shield-check"},
        "dry-run":     {"label": "Dry-Run",     "color": "yellow", "icon": "shield"},
        "degraded":    {"label": "Degraded",    "color": "red",    "icon": "shield-exclamation"},
        "development": {"label": "Development", "color": "gray",   "icon": "code-bracket"},
    }
    badge = _badges.get(mode, _badges["development"]).copy()
    badge["mode"] = mode
    return badge
