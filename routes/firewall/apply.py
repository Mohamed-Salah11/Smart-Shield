import sqlite3

from flask import render_template, request, jsonify, session
from app.database import get_db
from app.auth_utils import login_required
from app.api_auth import api_permission_required
from app.validators import (
    validate_ip, validate_cidr, validate_protocol,
    validate_description, validate_name, collect_errors,
    validate_port_list,
)

from routes.firewall import firewall_bp
from routes.firewall._common import _validate_rule


@firewall_bp.route("/api/apply", methods=["POST"])
@api_permission_required("api.firewall.edit")
def firewall_apply():
    """
    Compile all firewall rules, NAT rules, and aliases from the database
    into /etc/pf.conf and reload PF via pfctl.

    On non-FreeBSD the config is generated and returned but not applied.
    Returns {"ok": bool, "message": str, "conf": str}
    """
    from flask import session
    from app.audit_log import log_event
    conn = get_db()
    try:
        from app.services.pf_generator import reload_pf_rules
        result = reload_pf_rules(conn)
        # Sync Unbound DNS filter zones so DNS and PF stay consistent.
        if result.get("ok"):
            try:
                from app.services.dns_writer import apply_unbound
                dns_result = apply_unbound(conn)
                if not dns_result.get("ok"):
                    result["dns_warning"] = dns_result.get("message", "DNS sync failed")
            except Exception as dns_exc:
                result["dns_warning"] = str(dns_exc)
        log_event(
            category="system",
            action="firewall_apply",
            severity="high" if not result.get("ok") else "info",
            username=session.get("username", "system"),
            remote_addr=request.remote_addr,
            details={"ok": result["ok"], "message": result["message"]},
        )
        return jsonify(result)
    except Exception as exc:
        return jsonify({"ok": False, "message": str(exc), "conf": ""}), 500


@firewall_bp.route("/api/apply/status", methods=["GET"])
@login_required
def firewall_pf_status():
    """Return the live PF running state."""
    try:
        from app.services.pf_generator import get_pf_status
        return jsonify({"ok": True, **get_pf_status()})
    except Exception as exc:
        return jsonify({"ok": False, "message": str(exc)}), 500


@firewall_bp.route("/api/apply/rollback", methods=["POST"])
@api_permission_required("api.firewall.edit")
def firewall_rollback():
    """Restore the last known-good pf.conf."""
    from flask import session
    from app.audit_log import log_event
    try:
        from app.services.pf_generator import rollback_pf
        result = rollback_pf()
        log_event(
            category="system",
            action="firewall_rollback",
            username=session.get("username", "system"),
            remote_addr=request.remote_addr,
            details={"ok": result["ok"]},
        )
        return jsonify(result)
    except Exception as exc:
        return jsonify({"ok": False, "message": str(exc)}), 500


@firewall_bp.route("/api/apply/all", methods=["POST"])
@api_permission_required("api.firewall.edit")
def firewall_apply_all():
    """
    Apply all policy layers together: PF firewall, Unbound DNS filter zones,
    and Suricata IDS config (if running). Single endpoint to push all subsystems.
    Returns {"ok": bool, "results": {"pf": {...}, "dns": {...}, "ids": {...}}}
    """
    from flask import session
    from app.audit_log import log_event
    conn = get_db()
    results = {}
    overall_ok = True

    try:
        from app.services.pf_generator import reload_pf_rules
        pf = reload_pf_rules(conn)
        results["pf"] = {"ok": pf["ok"], "message": pf["message"]}
        if not pf["ok"]:
            overall_ok = False
    except Exception as exc:
        results["pf"] = {"ok": False, "message": str(exc)}
        overall_ok = False

    try:
        from app.services.dns_writer import apply_unbound
        dns = apply_unbound(conn)
        results["dns"] = {"ok": dns["ok"], "message": dns.get("message", "")}
        if not dns["ok"]:
            overall_ok = False
    except Exception as exc:
        results["dns"] = {"ok": False, "message": str(exc)}
        overall_ok = False

    try:
        from app.services.ids_writer import write_suricata_config, get_ids_status
        ids_status = get_ids_status(conn)
        if ids_status.get("running"):
            ids = write_suricata_config(conn)
            results["ids"] = {"ok": ids["ok"], "message": ids.get("message", "")}
        else:
            results["ids"] = {"ok": True, "message": "IDS not running — skipped"}
    except Exception as exc:
        results["ids"] = {"ok": False, "message": str(exc)}

    log_event(
        category="system",
        action="apply_all_policies",
        username=session.get("username", "system"),
        remote_addr=request.remote_addr,
        details={"ok": overall_ok, "results": results},
    )
    return jsonify({"ok": overall_ok, "results": results})


@firewall_bp.route("/api/apply/preview", methods=["GET"])
@login_required
def firewall_preview():
    """Return the pf.conf that *would* be applied without touching the OS."""
    conn = get_db()
    try:
        from app.services.pf_generator import generate_pf_conf
        conf = generate_pf_conf(conn)
        return jsonify({"ok": True, "conf": conf})
    except Exception as exc:
        return jsonify({"ok": False, "conf": "", "message": str(exc)}), 500


# ---------------------------------------------------------------------------
# RULE REORDER — update rule_order for drag-and-drop UI
# ---------------------------------------------------------------------------

_REORDER_TABLES = {
    "floating": "firewall_rules_floating",
    "wan":      "firewall_rules_wan",
    "lan":      "firewall_rules_lan",
}


@firewall_bp.route("/api/rules/<table>/reorder", methods=["POST"])
@api_permission_required("api.firewall.edit")
def reorder_rules(table):
    """
    Accept a JSON body ``{"order": [id1, id2, ...]}`` and update rule_order
    for the given rule table.  ``table`` must be one of floating/wan/lan.
    """
    if table not in _REORDER_TABLES:
        return jsonify({"success": False, "error": f"Unknown table: {table}"}), 400

    data = request.get_json(silent=True) or {}
    order = data.get("order", [])
    if not isinstance(order, list):
        return jsonify({"success": False, "error": "order must be a list of rule IDs"}), 400

    db = get_db()
    try:
        for position, rule_id in enumerate(order, start=1):
            db.execute(
                f"UPDATE {_REORDER_TABLES[table]} SET rule_order=? WHERE id=?",
                (position, int(rule_id)),
            )
        db.commit()
        return jsonify({"success": True, "message": f"{len(order)} rules reordered."})
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500
