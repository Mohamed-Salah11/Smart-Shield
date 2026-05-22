"""
soc_portal_auth.py
------------------
Authentication and authorization utilities for the SOC Team Portal.

The SOC portal uses a separate session namespace (keys prefixed with
``soc_``) so that logging out of the admin UI does not terminate an
active SOC analyst session and vice versa.

Tier ordering: L1 < L2 < L3.  An L3 user passes all @soc_tier_required
checks including those that require L1 or L2.
"""

import time
from functools import wraps
from flask import session, redirect, url_for, request, jsonify, render_template
from app.db_utils import db_cursor

_TIER_RANK = {"L1": 1, "L2": 2, "L3": 3}

# Pending-MFA state lifetime — analyst must finish the second factor within
# this window after a successful password, otherwise they restart the login.
_MFA_PENDING_TTL = 300  # 5 minutes


# ---------------------------------------------------------------------------
# MFA — pending second-factor state
# ---------------------------------------------------------------------------

def set_mfa_pending(user_id: int, username: str, tier: str) -> None:
    session["soc_pending_user_id"]  = int(user_id)
    session["soc_pending_username"] = username
    session["soc_pending_tier"]     = tier
    session["soc_pending_at"]       = int(time.time())


def get_mfa_pending():
    """Return (user_id, username, tier) of the pending login, or (None, None, None)."""
    started = session.get("soc_pending_at")
    if not started or (time.time() - int(started)) > _MFA_PENDING_TTL:
        clear_mfa_pending()
        return (None, None, None)
    return (
        session.get("soc_pending_user_id"),
        session.get("soc_pending_username"),
        session.get("soc_pending_tier"),
    )


def clear_mfa_pending() -> None:
    for k in ("soc_pending_user_id", "soc_pending_username",
              "soc_pending_tier", "soc_pending_at"):
        session.pop(k, None)


def user_has_mfa(user_id: int) -> bool:
    """True if the user has TOTP enrolled and enabled."""
    try:
        with db_cursor() as (_, cur):
            cur.execute(
                "SELECT totp_enabled, totp_secret FROM users WHERE id=?",
                (int(user_id),),
            )
            row = cur.fetchone()
            return bool(row and row["totp_enabled"] and (row["totp_secret"] or "").strip())
    except Exception:
        return False


def get_user_soc_tier(user_id: int):
    """
    Return the highest SOC tier assigned to a user — considering both the
    tier set directly on their account (users.soc_tier) and any tier
    inherited from their groups — or None if the user has no SOC tier.

    Superusers implicitly get L3 access regardless of group membership.
    """
    with db_cursor() as (_, cur):
        cur.execute(
            "SELECT COALESCE(is_superuser, 0) AS is_superuser, soc_tier "
            "FROM users WHERE id = ?",
            (user_id,),
        )
        row = cur.fetchone()
        if not row:
            return None
        if row["is_superuser"]:
            return "L3"

        tiers = []
        # Tier assigned directly to the user account.
        if row["soc_tier"] in _TIER_RANK:
            tiers.append(row["soc_tier"])

        # Tiers inherited from the user's groups.
        cur.execute(
            """
            SELECT g.soc_tier
            FROM groups g
            INNER JOIN user_groups ug ON ug.group_id = g.id
            WHERE ug.user_id = ? AND g.soc_tier IS NOT NULL
            """,
            (user_id,),
        )
        tiers += [r["soc_tier"] for r in cur.fetchall() if r["soc_tier"] in _TIER_RANK]

    if not tiers:
        return None
    return max(tiers, key=lambda t: _TIER_RANK[t])


def get_soc_session_user():
    """Return (user_id, username, tier) from the SOC session, or (None, None, None)."""
    return (
        session.get("soc_user_id"),
        session.get("soc_username"),
        session.get("soc_tier"),
    )


def soc_login_required(view_func):
    """Redirect to SOC login if there is no active SOC session."""
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        user_id, _, _ = get_soc_session_user()
        if not user_id:
            if request.is_json or request.path.startswith("/soc-portal/api/"):
                return jsonify({"ok": False, "message": "SOC session expired. Please log in."}), 401
            return redirect(url_for("soc_portal.login"))
        return view_func(*args, **kwargs)
    return wrapped


def soc_tier_required(min_tier: str):
    """
    Require the SOC user to have at least *min_tier* (L1, L2, or L3).
    Returns 403 for insufficient tier.  Must be used AFTER @soc_login_required.
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            _, _, tier = get_soc_session_user()
            if not tier or _TIER_RANK.get(tier, 0) < _TIER_RANK.get(min_tier, 99):
                if request.is_json or request.path.startswith("/soc-portal/api/"):
                    return jsonify({
                        "ok": False,
                        "message": f"This action requires SOC tier {min_tier} or higher.",
                    }), 403
                return render_template("soc_portal/forbidden.html", required_tier=min_tier), 403
            return view_func(*args, **kwargs)
        return wrapped
    return decorator


def soc_portal_enabled():
    """Return True if the SOC portal is enabled in soc_portal_config."""
    try:
        with db_cursor() as (_, cur):
            cur.execute("SELECT enabled FROM soc_portal_config WHERE id=1")
            row = cur.fetchone()
            return bool(row and row["enabled"])
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Analyst presence — which SOC analysts are currently logged in
# ---------------------------------------------------------------------------

# An analyst counts as "active" while their last request is within this window.
_PRESENCE_WINDOW_MIN = 15


def touch_soc_session(user_id, username, tier) -> None:
    """Heartbeat: record that this SOC analyst is currently active. Never raises."""
    if not user_id:
        return
    try:
        with db_cursor(commit=True) as (_, cur):
            cur.execute(
                "INSERT INTO soc_active_sessions (user_id, username, tier, last_seen) "
                "VALUES (?,?,?,CURRENT_TIMESTAMP) "
                "ON CONFLICT(user_id) DO UPDATE SET "
                "username=excluded.username, tier=excluded.tier, "
                "last_seen=CURRENT_TIMESTAMP",
                (int(user_id), username or "", tier or ""),
            )
    except Exception:
        pass


def drop_soc_session(user_id) -> None:
    """Remove an analyst's presence row (on logout). Never raises."""
    if not user_id:
        return
    try:
        with db_cursor(commit=True) as (_, cur):
            cur.execute("DELETE FROM soc_active_sessions WHERE user_id=?",
                        (int(user_id),))
    except Exception:
        pass


def active_soc_analysts(within_minutes: int = _PRESENCE_WINDOW_MIN) -> list:
    """Return [{user_id, username, tier}] for analysts seen within the window."""
    try:
        with db_cursor() as (_, cur):
            cur.execute(
                "SELECT user_id, username, tier FROM soc_active_sessions "
                "WHERE last_seen > datetime('now', ?) ORDER BY username",
                (f"-{int(within_minutes)} minutes",),
            )
            return [dict(r) for r in cur.fetchall()]
    except Exception:
        return []
