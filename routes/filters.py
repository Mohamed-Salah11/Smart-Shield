"""
routes/filters.py
-----------------
DNS filter, Web filter, and Application filter management endpoints.

URL prefix: /filters

Pages
-----
GET  /filters/                         → filters.html (active tab from ?tab=dns|web|app)

DNS filter API
--------------
POST /filters/dns/add                  → add a DNS block rule
POST /filters/dns/<id>/toggle          → enable / disable
POST /filters/dns/<id>/delete          → delete
POST /filters/dns/apply                → write unbound.conf + reload

Web filter API
--------------
POST /filters/web/add
POST /filters/web/<id>/toggle
POST /filters/web/<id>/delete
POST /filters/web/apply

Application filter API
-----------------------
POST /filters/app/add                  → add custom rule
POST /filters/app/add-signature        → add from built-in library
POST /filters/app/<id>/toggle
POST /filters/app/<id>/delete
POST /filters/app/apply                → write unbound.conf + pf.conf + reload both
GET  /filters/api/signatures           → JSON list of built-in signatures
"""

from flask import Blueprint, jsonify, redirect, render_template, request, session, url_for

from app.audit_log import log_event
from app.auth_utils import login_required
from app.database import get_db
from app.validators import validate_ip
from app.services.app_filter import (
    APP_SIGNATURES,
    add_app_filter_rule,
    add_app_from_signature,
    apply_app_filter,
    delete_app_filter_rule,
    get_app_filter_rules,
    toggle_app_filter_rule,
    update_app_filter_rule,
)
from app.services.dns_filter import (
    add_dns_filter_rule,
    apply_dns_filter,
    delete_dns_filter_rule,
    get_dns_filter_rules,
    toggle_dns_filter_rule,
    update_dns_filter_rule,
)
from app.services.web_filter import (
    WEB_CATEGORIES,
    add_web_filter_rule,
    apply_web_filter,
    delete_web_filter_rule,
    get_web_filter_rules,
    toggle_web_filter_rule,
    update_web_filter_rule,
)

filters_bp = Blueprint("filters", __name__, url_prefix="/filters")


# ---------------------------------------------------------------------------
# Separate pages per filter type
# ---------------------------------------------------------------------------

@filters_bp.route("/")
@login_required
def filters_index():
    from flask import redirect
    return redirect(url_for("filters.dns_filter_page"))


@filters_bp.route("/dns")
@login_required
def dns_filter_page():
    conn = get_db()
    rules = get_dns_filter_rules(conn)
    return render_template("dns_filter.html", rules=rules, title="DNS Filter")


@filters_bp.route("/web")
@login_required
def web_filter_page():
    conn = get_db()
    rules = get_web_filter_rules(conn)
    return render_template(
        "web_filter.html",
        rules=rules,
        web_categories=WEB_CATEGORIES,
        title="Web Filter",
    )


@filters_bp.route("/app")
@login_required
def app_filter_page():
    conn = get_db()
    rules = get_app_filter_rules(conn)

    sig_by_category: dict = {}
    for key, sig in APP_SIGNATURES.items():
        cat = sig["category"]
        sig_by_category.setdefault(cat, []).append({"key": key, **sig})

    return render_template(
        "app_filter.html",
        rules=rules,
        sig_by_category=sig_by_category,
        title="Application Filter",
    )


# ---------------------------------------------------------------------------
# DNS filter endpoints
# ---------------------------------------------------------------------------

@filters_bp.route("/dns/add", methods=["POST"])
@login_required
def dns_add():
    data = request.get_json(force=True) or {}
    domain = (data.get("domain") or "").strip()
    action = (data.get("action") or "block").lower()
    redirect_ip = (data.get("redirect_ip") or "").strip()
    category = (data.get("category") or "custom").strip()
    description = (data.get("description") or "").strip()

    if not domain:
        return jsonify({"ok": False, "message": "Domain is required."}), 400
    if action not in ("block", "allow", "redirect"):
        return jsonify({"ok": False, "message": "Invalid action."}), 400
    if action == "redirect":
        if not redirect_ip:
            return jsonify({"ok": False, "message": "Redirect IP is required for redirect action."}), 400
        try:
            validate_ip(redirect_ip, allow_empty=False)
        except ValueError as exc:
            return jsonify({"ok": False, "message": str(exc)}), 400

    try:
        conn = get_db()
        row_id = add_dns_filter_rule(conn, domain, action, redirect_ip, category, description)
        log_event(
            category="system", action="dns_filter_add",
            username=session.get("username"), remote_addr=request.remote_addr,
            details={"domain": domain, "action": action, "id": row_id},
        )
        return jsonify({"ok": True, "message": f"DNS rule added for {domain}.", "id": row_id})
    except ValueError as exc:
        return jsonify({"ok": False, "message": str(exc)}), 400
    except Exception as exc:
        return jsonify({"ok": False, "message": str(exc)}), 500


@filters_bp.route("/dns/<int:rule_id>/toggle", methods=["POST"])
@login_required
def dns_toggle(rule_id):
    data = request.get_json(force=True) or {}
    enabled = bool(data.get("enabled", True))
    conn = get_db()
    toggle_dns_filter_rule(conn, rule_id, enabled)
    return jsonify({"ok": True, "message": f"Rule {'enabled' if enabled else 'disabled'}."})


@filters_bp.route("/dns/<int:rule_id>/edit", methods=["PUT"])
@login_required
def dns_edit(rule_id):
    data = request.get_json(force=True) or {}
    domain = (data.get("domain") or "").strip()
    action = (data.get("action") or "block").lower()
    redirect_ip = (data.get("redirect_ip") or "").strip()
    category = (data.get("category") or "custom").strip()
    description = (data.get("description") or "").strip()
    if not domain:
        return jsonify({"ok": False, "message": "Domain is required."}), 400
    if action == "redirect":
        if not redirect_ip:
            return jsonify({"ok": False, "message": "Redirect IP is required for redirect action."}), 400
        try:
            validate_ip(redirect_ip, allow_empty=False)
        except ValueError as exc:
            return jsonify({"ok": False, "message": str(exc)}), 400
    try:
        conn = get_db()
        update_dns_filter_rule(conn, rule_id, domain, action, redirect_ip, category, description)
        rule = dict(conn.execute("SELECT * FROM filter_dns_rules WHERE id=?", (rule_id,)).fetchone())
        log_event(category="system", action="dns_filter_edit",
                  username=session.get("username"), remote_addr=request.remote_addr,
                  details={"id": rule_id, "domain": domain})
        return jsonify({"ok": True, "message": "Rule updated.", "rule": rule})
    except ValueError as exc:
        return jsonify({"ok": False, "message": str(exc)}), 400
    except Exception as exc:
        return jsonify({"ok": False, "message": str(exc)}), 500


@filters_bp.route("/dns/<int:rule_id>/delete", methods=["POST"])
@login_required
def dns_delete(rule_id):
    conn = get_db()
    delete_dns_filter_rule(conn, rule_id)
    log_event(
        category="system", action="dns_filter_delete",
        username=session.get("username"), remote_addr=request.remote_addr,
        details={"id": rule_id},
    )
    return jsonify({"ok": True, "message": "Rule deleted."})


@filters_bp.route("/dns/apply", methods=["POST"])
@login_required
def dns_apply():
    conn = get_db()
    result = apply_dns_filter(conn)
    if result.get("ok"):
        try:
            from app.services.dns_writer import apply_unbound
            unbound_result = apply_unbound(conn)
            result["unbound"] = unbound_result.get("message", "")
            if not unbound_result.get("ok"):
                result["ok"] = False
                result["message"] = result.get("message", "") + " | Unbound: " + unbound_result.get("message", "")
        except Exception as exc:
            result["unbound_warning"] = str(exc)
    # Always apply captive portal PF anchor — independent of Unbound reload status
    try:
        from app.services.captive_portal import apply_captive_portal
        cp_result = apply_captive_portal(conn)
        result["captive_portal"] = cp_result.get("message", "")
    except Exception as exc:
        result["captive_portal_warning"] = str(exc)
    log_event(
        category="system", action="dns_filter_apply",
        username=session.get("username"), remote_addr=request.remote_addr,
        details=result,
    )
    return jsonify(result)


# ---------------------------------------------------------------------------
# Web filter endpoints
# ---------------------------------------------------------------------------

@filters_bp.route("/web/add", methods=["POST"])
@login_required
def web_add():
    data = request.get_json(force=True) or {}
    url_pattern = (data.get("url_pattern") or "").strip()
    action = (data.get("action") or "block").lower()
    category = (data.get("category") or "custom").strip()
    description = (data.get("description") or "").strip()

    if not url_pattern:
        return jsonify({"ok": False, "message": "URL/domain is required."}), 400
    if action not in ("block", "allow"):
        return jsonify({"ok": False, "message": "Invalid action."}), 400

    try:
        conn = get_db()
        row_id = add_web_filter_rule(conn, url_pattern, action, category, description)
        log_event(
            category="system", action="web_filter_add",
            username=session.get("username"), remote_addr=request.remote_addr,
            details={"url_pattern": url_pattern, "action": action, "id": row_id},
        )
        return jsonify({"ok": True, "message": f"Web filter rule added.", "id": row_id})
    except ValueError as exc:
        return jsonify({"ok": False, "message": str(exc)}), 400
    except Exception as exc:
        return jsonify({"ok": False, "message": str(exc)}), 500


@filters_bp.route("/web/<int:rule_id>/toggle", methods=["POST"])
@login_required
def web_toggle(rule_id):
    data = request.get_json(force=True) or {}
    enabled = bool(data.get("enabled", True))
    conn = get_db()
    toggle_web_filter_rule(conn, rule_id, enabled)
    return jsonify({"ok": True, "message": f"Rule {'enabled' if enabled else 'disabled'}."})


@filters_bp.route("/web/<int:rule_id>/edit", methods=["PUT"])
@login_required
def web_edit(rule_id):
    data = request.get_json(force=True) or {}
    url_pattern = (data.get("url_pattern") or "").strip()
    action = (data.get("action") or "block").lower()
    category = (data.get("category") or "custom").strip()
    description = (data.get("description") or "").strip()
    if not url_pattern:
        return jsonify({"ok": False, "message": "URL/domain is required."}), 400
    try:
        conn = get_db()
        update_web_filter_rule(conn, rule_id, url_pattern, action, category, description)
        rule = dict(conn.execute("SELECT * FROM filter_web_rules WHERE id=?", (rule_id,)).fetchone())
        log_event(category="system", action="web_filter_edit",
                  username=session.get("username"), remote_addr=request.remote_addr,
                  details={"id": rule_id, "url_pattern": url_pattern})
        return jsonify({"ok": True, "message": "Rule updated.", "rule": rule})
    except ValueError as exc:
        return jsonify({"ok": False, "message": str(exc)}), 400
    except Exception as exc:
        return jsonify({"ok": False, "message": str(exc)}), 500


@filters_bp.route("/web/<int:rule_id>/delete", methods=["POST"])
@login_required
def web_delete(rule_id):
    conn = get_db()
    delete_web_filter_rule(conn, rule_id)
    log_event(
        category="system", action="web_filter_delete",
        username=session.get("username"), remote_addr=request.remote_addr,
        details={"id": rule_id},
    )
    return jsonify({"ok": True, "message": "Rule deleted."})


@filters_bp.route("/web/apply", methods=["POST"])
@login_required
def web_apply():
    conn = get_db()
    result = apply_web_filter(conn)
    if result.get("ok"):
        try:
            from app.services.dns_writer import apply_unbound
            unbound_result = apply_unbound(conn)
            result["unbound"] = unbound_result.get("message", "")
            if not unbound_result.get("ok"):
                result["ok"] = False
                result["message"] = result.get("message", "") + " | Unbound: " + unbound_result.get("message", "")
        except Exception as exc:
            result["unbound_warning"] = str(exc)
    # Always apply captive portal PF anchor — independent of Unbound reload status
    try:
        from app.services.captive_portal import apply_captive_portal
        cp_result = apply_captive_portal(conn)
        result["captive_portal"] = cp_result.get("message", "")
    except Exception as exc:
        result["captive_portal_warning"] = str(exc)
    log_event(
        category="system", action="web_filter_apply",
        username=session.get("username"), remote_addr=request.remote_addr,
        details=result,
    )
    return jsonify(result)


# ---------------------------------------------------------------------------
# Application filter endpoints
# ---------------------------------------------------------------------------

@filters_bp.route("/app/add", methods=["POST"])
@login_required
def app_add():
    data = request.get_json(force=True) or {}
    app_name = (data.get("app_name") or "").strip()
    if not app_name:
        return jsonify({"ok": False, "message": "Application name is required."}), 400

    try:
        conn = get_db()
        row_id = add_app_filter_rule(
            conn,
            app_name=app_name,
            action=(data.get("action") or "block").lower(),
            block_dns=bool(data.get("block_dns", True)),
            block_ports=bool(data.get("block_ports", False)),
            ports=(data.get("ports") or "").strip(),
            protocol=(data.get("protocol") or "tcp+udp"),
            domains=(data.get("domains") or "").strip(),
            category=(data.get("category") or "custom").strip(),
            description=(data.get("description") or "").strip(),
        )
        log_event(
            category="system", action="app_filter_add",
            username=session.get("username"), remote_addr=request.remote_addr,
            details={"app_name": app_name, "id": row_id},
        )
        block_dns_val = bool(data.get("block_dns", True))
        block_ports_val = bool(data.get("block_ports", False))
        ports_val = (data.get("ports") or "").strip()
        return jsonify({
            "ok": True,
            "message": f"Application filter added for '{app_name}'.",
            "id": row_id,
            "rule": {
                "id": row_id,
                "app_name": app_name,
                "action": (data.get("action") or "block").lower(),
                "category": (data.get("category") or "custom").strip(),
                "block_dns": 1 if block_dns_val else 0,
                "block_ports": 1 if block_ports_val else 0,
                "ports": ports_val,
                "enabled": 1,
            },
        })
    except ValueError as exc:
        return jsonify({"ok": False, "message": str(exc)}), 400
    except Exception as exc:
        return jsonify({"ok": False, "message": str(exc)}), 500


@filters_bp.route("/app/add-signature", methods=["POST"])
@login_required
def app_add_signature():
    data = request.get_json(force=True) or {}
    sig_key = (data.get("sig_key") or "").strip().lower()
    action = (data.get("action") or "block").lower()

    if not sig_key:
        return jsonify({"ok": False, "message": "Signature key is required."}), 400

    try:
        conn = get_db()
        row_id = add_app_from_signature(conn, sig_key, action)
        sig_name = APP_SIGNATURES.get(sig_key, {}).get("name", sig_key)
        log_event(
            category="system", action="app_filter_add_signature",
            username=session.get("username"), remote_addr=request.remote_addr,
            details={"sig_key": sig_key, "name": sig_name, "id": row_id},
        )
        rule = dict(conn.execute(
            "SELECT * FROM filter_app_rules WHERE id=?", (row_id,)
        ).fetchone())
        return jsonify({"ok": True, "message": f"'{sig_name}' added from signature library.",
                        "id": row_id, "rule": rule})
    except ValueError as exc:
        return jsonify({"ok": False, "message": str(exc)}), 400
    except Exception as exc:
        return jsonify({"ok": False, "message": str(exc)}), 500


@filters_bp.route("/app/<int:rule_id>/toggle", methods=["POST"])
@login_required
def app_toggle(rule_id):
    data = request.get_json(force=True) or {}
    enabled = bool(data.get("enabled", True))
    conn = get_db()
    toggle_app_filter_rule(conn, rule_id, enabled)
    return jsonify({"ok": True, "message": f"Rule {'enabled' if enabled else 'disabled'}."})


@filters_bp.route("/app/<int:rule_id>/edit", methods=["PUT"])
@login_required
def app_edit(rule_id):
    data = request.get_json(force=True) or {}
    app_name = (data.get("app_name") or "").strip()
    if not app_name:
        return jsonify({"ok": False, "message": "Application name is required."}), 400
    try:
        conn = get_db()
        update_app_filter_rule(
            conn, rule_id,
            app_name=app_name,
            action=(data.get("action") or "block").lower(),
            block_dns=bool(data.get("block_dns", True)),
            block_ports=bool(data.get("block_ports", False)),
            ports=(data.get("ports") or "").strip(),
            protocol=(data.get("protocol") or "tcp+udp"),
            domains=(data.get("domains") or "").strip(),
            category=(data.get("category") or "custom").strip(),
            description=(data.get("description") or "").strip(),
        )
        rule = dict(conn.execute("SELECT * FROM filter_app_rules WHERE id=?", (rule_id,)).fetchone())
        log_event(category="system", action="app_filter_edit",
                  username=session.get("username"), remote_addr=request.remote_addr,
                  details={"id": rule_id, "app_name": app_name})
        return jsonify({"ok": True, "message": "Rule updated.", "rule": rule})
    except ValueError as exc:
        return jsonify({"ok": False, "message": str(exc)}), 400
    except Exception as exc:
        return jsonify({"ok": False, "message": str(exc)}), 500


@filters_bp.route("/app/<int:rule_id>/delete", methods=["POST"])
@login_required
def app_delete(rule_id):
    conn = get_db()
    delete_app_filter_rule(conn, rule_id)
    log_event(
        category="system", action="app_filter_delete",
        username=session.get("username"), remote_addr=request.remote_addr,
        details={"id": rule_id},
    )
    return jsonify({"ok": True, "message": "Rule deleted."})


@filters_bp.route("/app/apply", methods=["POST"])
@login_required
def app_apply():
    conn = get_db()
    # apply_app_filter() handles Unbound + PF internally and returns proper ok status
    result = apply_app_filter(conn)
    # Always apply captive portal PF anchor — independent of filter apply status
    try:
        from app.services.captive_portal import apply_captive_portal
        cp_result = apply_captive_portal(conn)
        result["captive_portal"] = cp_result.get("message", "")
    except Exception as exc:
        result["captive_portal_warning"] = str(exc)
    log_event(
        category="system", action="app_filter_apply",
        username=session.get("username"), remote_addr=request.remote_addr,
        details=result,
    )
    return jsonify(result)


# ---------------------------------------------------------------------------
# Signature library API
# ---------------------------------------------------------------------------

@filters_bp.route("/api/signatures")
@login_required
def api_signatures():
    """Return the built-in application signature library as JSON."""
    sigs = [
        {"key": k, **v}
        for k, v in sorted(APP_SIGNATURES.items(), key=lambda x: (x[1]["category"], x[1]["name"]))
    ]
    return jsonify({"ok": True, "signatures": sigs})


# ---------------------------------------------------------------------------
# Phase 3 — Conflict detection, preview, import/export
# ---------------------------------------------------------------------------

@filters_bp.route("/api/conflicts")
@login_required
def api_conflicts():
    """Detect conflicts across all enabled filter rules."""
    from app.services.filter_conflicts import detect_conflicts
    conn = get_db()
    result = detect_conflicts(conn)
    return jsonify({
        "ok": True,
        "has_errors":   bool(result["errors"]),
        "has_warnings": bool(result["warnings"]),
        **result,
    })


@filters_bp.route("/api/preview")
@login_required
def api_preview():
    """Return the combined DNS zone lines and PF rules all filters would generate."""
    from app.services.filter_conflicts import get_filter_preview
    conn   = get_db()
    result = get_filter_preview(conn)
    return jsonify({"ok": True, **result})


@filters_bp.route("/api/export/<filter_type>")
@login_required
def api_export(filter_type: str):
    """Export enabled rules as a newline-separated plain-text list."""
    from app.services.filter_conflicts import export_filter_list
    from flask import Response
    if filter_type not in ("dns", "web", "app"):
        return jsonify({"ok": False, "error": "filter_type must be dns, web, or app"}), 400
    conn = get_db()
    text = export_filter_list(conn, filter_type)
    return Response(
        text,
        mimetype="text/plain",
        headers={"Content-Disposition": f"attachment; filename={filter_type}_filter_export.txt"},
    )


@filters_bp.route("/api/import/<filter_type>", methods=["POST"])
@login_required
def api_import(filter_type: str):
    """
    Bulk-import a newline-separated list of domains/URLs.
    Body: plain text or JSON with {"text": "...", "action": "block", "category": "custom"}
    """
    from app.services.filter_conflicts import import_filter_list
    if filter_type not in ("dns", "web", "app"):
        return jsonify({"ok": False, "error": "filter_type must be dns, web, or app"}), 400

    ct   = request.content_type or ""
    if "json" in ct:
        data     = request.get_json(force=True) or {}
        text     = data.get("text", "")
        action   = data.get("action", "block")
        category = data.get("category", "custom")
    else:
        text     = request.get_data(as_text=True)
        action   = request.args.get("action", "block")
        category = request.args.get("category", "custom")

    if not text.strip():
        return jsonify({"ok": False, "error": "No content provided"}), 400

    conn   = get_db()
    result = import_filter_list(conn, text, filter_type, action, category)

    log_event(
        category="system", action=f"{filter_type}_filter_import",
        username=session.get("username"), remote_addr=request.remote_addr,
        details={"imported": result["imported"], "skipped": result["skipped"]},
    )
    return jsonify(result)
