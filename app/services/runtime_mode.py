"""
runtime_mode.py
---------------
Runtime mode detection for Smart Shield.

Exposes helpers that tell the application (and UI) whether it is running
on a live FreeBSD appliance, in dry-run mode, or in development mode.
"""

import os
import sys


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
