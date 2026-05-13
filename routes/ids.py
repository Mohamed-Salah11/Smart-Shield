import os

from flask import Blueprint, render_template, request, redirect, url_for, jsonify, session
from app.database import get_db
from app.auth_utils import login_required
from app.api_auth import api_permission_required
from app.audit_log import log_event

ids_bp = Blueprint("ids", __name__, url_prefix="/ids")


def _cfg(conn):
    cur = conn.cursor()
    cur.execute("SELECT * FROM ids_config WHERE id=1")
    row = cur.fetchone()
    return dict(row) if row else {}


def _rulesets(conn):
    cur = conn.cursor()
    cur.execute("SELECT * FROM ids_rulesets ORDER BY id")
    return [dict(r) for r in cur.fetchall()]


# ── Main IDS/IPS page ──────────────────────────────────────────────────────

def _feeds_has_key(conn) -> bool:
    if os.environ.get("ABUSECH_AUTH_KEY", "").strip():
        return True
    row = conn.execute(
        "SELECT abusech_auth_key FROM ids_threat_feeds WHERE id=1"
    ).fetchone()
    return bool(row and row["abusech_auth_key"])


@ids_bp.route("/", methods=["GET"])
@login_required
def ids_index():
    conn = get_db()
    cfg  = _cfg(conn)
    rulesets = _rulesets(conn)

    # Inject display-time WAN interface fallback so the status banner is never blank.
    # Empty string in DB means "auto (WAN)" — show the actual WAN interface name.
    if not cfg.get("interface"):
        wan_row = conn.execute(
            "SELECT assigned_port FROM wan_config LIMIT 1"
        ).fetchone()
        cfg = dict(cfg)
        cfg["interface"] = (wan_row["assigned_port"] if wan_row else None) or "em0"

    # Live status (non-blocking; returns quickly on non-FreeBSD)
    from app.services.ids_writer import get_ids_status
    status = get_ids_status()

    # Pull available interfaces for the dropdown
    from app.services.network_service import list_physical_nics
    nics = list_physical_nics()

    return render_template(
        "ids.html",
        cfg=cfg,
        rulesets=rulesets,
        status=status,
        nics=nics,
        feeds_has_key=_feeds_has_key(conn),
        active_tab=request.args.get("tab", "status"),
    )


# ── Save main configuration ────────────────────────────────────────────────

@ids_bp.route("/save", methods=["POST"])
@login_required
def ids_save():
    conn = get_db()
    cur  = conn.cursor()

    enabled      = 1 if request.form.get("enabled") else 0
    mode         = request.form.get("mode", "ids")
    interface    = request.form.get("interface", "")
    home_net     = request.form.get("home_net", "192.168.0.0/16").strip()
    ext_net      = request.form.get("external_net", "!$HOME_NET").strip()
    eve_json     = 1 if request.form.get("eve_json_enabled") else 0
    fast_log     = 1 if request.form.get("fast_log_enabled") else 0
    block_list   = 1 if request.form.get("block_list_enabled") else 0
    max_pending  = int(request.form.get("max_pending_packets") or 1024)

    if mode not in ("ids", "ips"):
        mode = "ids"

    cur.execute("""
        UPDATE ids_config SET
            enabled=?, mode=?, interface=?, home_net=?, external_net=?,
            eve_json_enabled=?, fast_log_enabled=?, block_list_enabled=?,
            max_pending_packets=?, updated_at=CURRENT_TIMESTAMP
        WHERE id=1
    """, (enabled, mode, interface, home_net, ext_net, eve_json, fast_log, block_list, max_pending))
    conn.commit()

    log_event(
        category="system", action="ids_config_save",
        username=session.get("username"),
        remote_addr=request.remote_addr,
        details={"mode": mode, "interface": interface, "enabled": enabled},
    )

    # If enabled, apply immediately
    if enabled:
        from app.services.ids_writer import write_suricata_config
        write_suricata_config(conn)

    return redirect(url_for("ids.ids_index", tab="config"))


# ── Toggle IDS on/off (AJAX) ───────────────────────────────────────────────

@ids_bp.route("/api/toggle", methods=["POST"])
@api_permission_required("api.ids.edit")
def ids_toggle():
    data = request.get_json(silent=True) or {}
    enabled = bool(data.get("enabled", False))
    conn = get_db()

    from app.services.ids_writer import toggle_ids
    result = toggle_ids(conn, enabled)

    log_event(
        category="system", action="ids_toggle",
        username=session.get("username"),
        remote_addr=request.remote_addr,
        details={"enabled": enabled, "result": result},
    )
    return jsonify(result)


# ── Ruleset CRUD ───────────────────────────────────────────────────────────

@ids_bp.route("/api/rulesets", methods=["GET"])
@login_required
def ids_rulesets_list():
    conn = get_db()
    return jsonify(_rulesets(conn))


@ids_bp.route("/api/rulesets", methods=["POST"])
@api_permission_required("api.ids.edit")
def ids_ruleset_add():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    url  = (data.get("url") or "").strip()
    desc = (data.get("description") or "").strip()
    if not name:
        return jsonify({"ok": False, "message": "Name is required"}), 400

    conn = get_db()
    cur  = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO ids_rulesets (name, enabled, url, description) VALUES (?,1,?,?)",
            (name, url, desc),
        )
        conn.commit()
        return jsonify({"ok": True, "id": cur.lastrowid})
    except Exception as exc:
        return jsonify({"ok": False, "message": str(exc)}), 400


@ids_bp.route("/api/rulesets/<int:rid>", methods=["PUT"])
@api_permission_required("api.ids.edit")
def ids_ruleset_update(rid):
    data    = request.get_json(silent=True) or {}
    enabled = 1 if data.get("enabled") else 0
    conn = get_db()
    conn.cursor().execute(
        "UPDATE ids_rulesets SET enabled=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
        (enabled, rid),
    )
    conn.commit()
    return jsonify({"ok": True})


@ids_bp.route("/api/rulesets/<int:rid>", methods=["DELETE"])
@api_permission_required("api.ids.edit")
def ids_ruleset_delete(rid):
    conn = get_db()
    conn.cursor().execute("DELETE FROM ids_rulesets WHERE id=?", (rid,))
    conn.commit()
    return jsonify({"ok": True})


# ── Update rules (trigger suricata-update) ────────────────────────────────

@ids_bp.route("/api/update-rules", methods=["POST"])
@api_permission_required("api.ids.edit")
def ids_update_rules():
    conn = get_db()
    from app.services.ids_writer import update_rules
    result = update_rules(conn)
    return jsonify(result)


# ── Status API ────────────────────────────────────────────────────────────

@ids_bp.route("/api/status", methods=["GET"])
@login_required
def ids_status():
    from app.services.ids_writer import get_ids_status
    return jsonify(get_ids_status())


# ── Threat Feeds (abuse.ch Auth-Key) ─────────────────────────────────────

@ids_bp.route("/api/feeds", methods=["GET"])
@login_required
def ids_feeds_get():
    conn = get_db()
    row = conn.execute(
        "SELECT abusech_dry_run FROM ids_threat_feeds WHERE id=1"
    ).fetchone()
    dry_run = bool(row["abusech_dry_run"]) if row else True
    return jsonify({"ok": True, "has_key": _feeds_has_key(conn), "dry_run": dry_run})


@ids_bp.route("/api/feeds", methods=["POST"])
@api_permission_required("api.ids.edit")
def ids_feeds_save():
    data    = request.get_json(silent=True) or {}
    raw_key = (data.get("abusech_auth_key") or "").strip()
    # When a key is provided default dry_run to 0 (live); allow explicit override
    dry_run = int(data.get("dry_run", 0 if raw_key else 1))

    from app.secret_store import encrypt_secret
    conn = get_db()
    conn.execute(
        "UPDATE ids_threat_feeds SET abusech_auth_key=?, abusech_dry_run=?, updated_at=CURRENT_TIMESTAMP WHERE id=1",
        (encrypt_secret(raw_key) if raw_key else "", dry_run),
    )
    conn.commit()

    log_event(
        category="system", action="abusech_key_update",
        username=session.get("username"),
        remote_addr=request.remote_addr,
        details={"key_set": bool(raw_key), "dry_run": dry_run},
    )
    return jsonify({"ok": True, "has_key": bool(raw_key), "dry_run": bool(dry_run)})

# -- abuse.ch live lookups --------------------------------------------------

@ids_bp.route("/api/feeds/abusech/recent", methods=["GET"])
@login_required
def ids_abusech_recent():
    """Fetch recent abuse.ch threat-intel samples for the IDS Threat Feeds tab."""
    try:
        limit = min(max(int(request.args.get("limit", 20)), 1), 100)
    except ValueError:
        limit = 20

    try:
        days = min(max(int(request.args.get("days", 1)), 1), 7)
    except ValueError:
        days = 1

    try:
        from app.services.abusech_client import (
            is_dry_run,
            malwarebazaar_recent,
            threatfox_recent_iocs,
            urlhaus_recent,
        )

        payload = {
            "ok": True,
            "dry_run": is_dry_run(),
            "urlhaus": urlhaus_recent(limit=limit),
            "malwarebazaar": malwarebazaar_recent(limit=limit),
            "threatfox": threatfox_recent_iocs(days=days),
        }
        return jsonify(payload)

    except RuntimeError as exc:
        return jsonify({"ok": False, "message": str(exc)}), 400

    except Exception as exc:
        return jsonify({"ok": False, "message": f"abuse.ch request failed: {exc}"}), 502


@ids_bp.route("/api/feeds/abusech/lookup", methods=["POST"])
@login_required
def ids_abusech_lookup():
    """Look up a URL, host/IP, hash, or generic IOC through abuse.ch services."""
    data = request.get_json(silent=True) or {}

    lookup_type = (data.get("type") or "").strip().lower()
    value = (data.get("value") or "").strip()

    if lookup_type not in {"url", "host", "hash", "ioc"}:
        return jsonify({
            "ok": False,
            "message": "type must be one of: url, host, hash, ioc",
        }), 400

    if not value:
        return jsonify({"ok": False, "message": "value is required"}), 400

    if len(value) > 2048:
        return jsonify({"ok": False, "message": "value is too long"}), 400

    try:
        from app.services.abusech_client import (
            is_dry_run,
            malwarebazaar_lookup_hash,
            threatfox_search_ioc,
            urlhaus_lookup_host,
            urlhaus_lookup_url,
        )

        if lookup_type == "url":
            result = urlhaus_lookup_url(value)
            service = "urlhaus"

        elif lookup_type == "host":
            result = urlhaus_lookup_host(value)
            service = "urlhaus"

        elif lookup_type == "hash":
            result = malwarebazaar_lookup_hash(value)
            service = "malwarebazaar"

        else:
            result = threatfox_search_ioc(value)
            service = "threatfox"

        log_event(
            category="system",
            action="abusech_lookup",
            username=session.get("username"),
            remote_addr=request.remote_addr,
            details={
                "type": lookup_type,
                "service": service,
                "dry_run": is_dry_run(),
            },
        )

        return jsonify({
            "ok": True,
            "service": service,
            "dry_run": is_dry_run(),
            "result": result,
        })

    except RuntimeError as exc:
        return jsonify({"ok": False, "message": str(exc)}), 400

    except Exception as exc:
        return jsonify({"ok": False, "message": f"abuse.ch lookup failed: {exc}"}), 502
# ── Alert log viewer (tail eve.json) ─────────────────────────────────────

@ids_bp.route("/api/alerts", methods=["GET"])
@login_required
def ids_alerts():
    import os, json as _json
    from datetime import datetime, timezone, timedelta

    try:
        limit = min(int(request.args.get("limit", 100)), 500)
    except (ValueError, TypeError):
        limit = 100

    search = (request.args.get("search") or "").lower().strip()
    try:
        severity = int(request.args.get("severity", 0))
    except (ValueError, TypeError):
        severity = 0
    try:
        hours = int(request.args.get("hours", 0))
    except (ValueError, TypeError):
        hours = 0

    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)) if hours > 0 else None

    eve_path = "/var/log/suricata/eve.json"
    alerts = []
    if os.path.exists(eve_path):
        try:
            with open(eve_path, "r", errors="replace") as f:
                lines = f.readlines()
            for line in reversed(lines):
                try:
                    obj = _json.loads(line)
                    if obj.get("event_type") != "alert":
                        continue
                    a = {
                        "timestamp": obj.get("timestamp", ""),
                        "src_ip":    obj.get("src_ip", ""),
                        "src_port":  obj.get("src_port", ""),
                        "dest_ip":   obj.get("dest_ip", ""),
                        "dest_port": obj.get("dest_port", ""),
                        "proto":     obj.get("proto", ""),
                        "signature": obj.get("alert", {}).get("signature", ""),
                        "category":  obj.get("alert", {}).get("category", ""),
                        "severity":  obj.get("alert", {}).get("severity", 3),
                        "action":    obj.get("alert", {}).get("action", "allowed"),
                    }
                    if severity and a["severity"] != severity:
                        continue
                    if cutoff and a["timestamp"]:
                        try:
                            ts = datetime.fromisoformat(a["timestamp"].replace("Z", "+00:00"))
                            if ts < cutoff:
                                continue
                        except Exception:
                            pass
                    if search and search not in (a["signature"] + a["src_ip"] + a["dest_ip"]).lower():
                        continue
                    alerts.append(a)
                    if len(alerts) >= limit:
                        break
                except Exception:
                    pass
        except OSError:
            pass

    return jsonify({"ok": True, "alerts": alerts, "total": len(alerts)})
