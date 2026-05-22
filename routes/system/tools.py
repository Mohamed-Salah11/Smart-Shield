from routes.system import system_bp
from routes.system._common import *  # noqa: F401,F403
from routes.system._common import _general_config_path, _config_bool, _load_general_config, _safe_count, _build_dashboard_payload  # noqa: F401


@system_bp.route("/high-availability", methods=["GET", "POST"])
@login_required
def high_availability():
    import json as _json
    conn = get_db()
    if request.method == "POST":
        from app.secret_store import encrypt_secret
        raw_pw = request.form.get("remote_password", "").strip()
        pw_enc = encrypt_secret(raw_pw) if raw_pw else ""
        sync_options = _json.dumps(request.form.getlist("sync_options"))
        conn.execute("""
            INSERT INTO ha_settings (id, ss_sync_enabled, sync_interface, filter_host_id,
                peer_ip, xmlrpc_ip, remote_username, remote_password_enc,
                sync_admin, sync_options, updated_at)
            VALUES (1,?,?,?,?,?,?,?,?,?, CURRENT_TIMESTAMP)
            ON CONFLICT(id) DO UPDATE SET
                ss_sync_enabled=excluded.ss_sync_enabled,
                sync_interface=excluded.sync_interface,
                filter_host_id=excluded.filter_host_id,
                peer_ip=excluded.peer_ip,
                xmlrpc_ip=excluded.xmlrpc_ip,
                remote_username=excluded.remote_username,
                remote_password_enc=CASE WHEN excluded.remote_password_enc != ''
                    THEN excluded.remote_password_enc ELSE ha_settings.remote_password_enc END,
                sync_admin=excluded.sync_admin,
                sync_options=excluded.sync_options,
                updated_at=excluded.updated_at
        """, (
            1 if request.form.get("SS-Sync_enabled") else 0,
            request.form.get("sync_interface", "WAN"),
            request.form.get("filter_host_id", ""),
            request.form.get("SS-Sync_peer_ip", ""),
            request.form.get("sync_config_ip", ""),
            request.form.get("remote_username", ""),
            pw_enc,
            1 if request.form.get("sync_admin") else 0,
            sync_options,
        ))
        conn.commit()
        log_event(category="system", action="ha_settings_saved",
                  username=session.get("username"), remote_addr=request.remote_addr)
        return redirect(url_for("system.high_availability"))

    row = conn.execute("SELECT * FROM ha_settings WHERE id=1").fetchone()
    ha  = dict(row) if row else {}
    try:
        ha["sync_options_list"] = _json.loads(ha.get("sync_options") or "[]")
    except Exception:
        ha["sync_options_list"] = []
    return render_template("high_availability.html", ha=ha)


# ----------------------------
# PACKAGE MANAGER
# ----------------------------

@system_bp.route("/package-manager")
@login_required
def package_manager():
    return render_template("package_manager.html")


@system_bp.route("/api/packages", methods=["GET"])
@login_required
def api_packages_list():
    """List installed packages. Command logic lives in service_manager."""
    from app.services.service_manager import pkg_list_installed
    return jsonify(pkg_list_installed())


@system_bp.route("/api/packages/search", methods=["GET"])
@login_required
def api_packages_search():
    """Search available packages in the pkg repository."""
    from app.services.service_manager import pkg_search
    query = (request.args.get("q") or "").strip()
    if not query:
        return jsonify({"ok": False, "message": "q parameter required."}), 400
    return jsonify(pkg_search(query))


@system_bp.route("/api/packages/install", methods=["POST"])
@superuser_required
def api_packages_install():
    """Install a package via pkg install. FreeBSD + priv_helper only."""
    import sys, re
    if not sys.platform.startswith("freebsd"):
        return jsonify({"ok": False, "message": "pkg install is only available on FreeBSD."}), 400
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name or not re.match(r'^[A-Za-z0-9._+-]+$', name):
        return jsonify({"ok": False, "message": "Invalid package name."}), 400
    try:
        from app.services.priv_helper import run_privileged
        result = run_privileged("pkg.install", package_name=name)
        ok  = result.returncode == 0
        msg = (result.stdout or result.stderr or "").strip()
        from app.audit_log import log_event as _log_event
        _log_event(category="system", action="pkg_install",
                   username=session.get("username"), remote_addr=request.remote_addr,
                   details={"package": name, "ok": ok})
        return jsonify({"ok": ok, "message": msg or ("Installed" if ok else "Install failed")})
    except Exception as exc:
        return jsonify({"ok": False, "message": str(exc)})


# ----------------------------
# PREFLIGHT / SYSTEM HEALTH
# ----------------------------

@system_bp.route("/preflight")
@login_required
def preflight():
    from app.services.freebsd_setup import preflight_check
    report = preflight_check()
    return render_template("preflight.html", report=report)


@system_bp.route("/api/preflight", methods=["GET"])
@login_required
def preflight_api():
    from app.services.freebsd_setup import preflight_check
    return jsonify(preflight_check())


# ----------------------------
# SETUP WIZARD
# ----------------------------

@system_bp.route("/setup-wizard")
@login_required
def setup_wizard():
    # Legacy setup wizard — redirect to the canonical first-boot wizard at
    # /setup so operators land on one supported flow. The old template
    # (setup_wizard.html) is no longer rendered.
    from flask import redirect, url_for
    return redirect(url_for("setup.wizard_index"))


@system_bp.route("/setup-wizard/step/<int:step>")
@login_required
def setup_wizard_step(step):
    from flask import redirect, url_for
    return redirect(url_for("setup.wizard_index"))


@system_bp.route("/api/setup-wizard/general", methods=["POST"])
@login_required
@superuser_required
def api_setup_wizard_general():
    import os as _os
    data = request.get_json(force=True) or {}
    cfg  = _load_general_config()
    cfg["hostname"]   = (data.get("hostname") or cfg.get("hostname", "SmartShield")).strip()
    cfg["domain"]     = (data.get("domain")   or cfg.get("domain",   "home.arpa")).strip()
    dns1 = (data.get("primary_dns")   or "").strip()
    dns2 = (data.get("secondary_dns") or "").strip()
    cfg["dns_servers"]  = [d for d in [dns1, dns2] if d]
    cfg["dns_override"] = bool(data.get("override_dns", True))
    config_file = _general_config_path()
    _os.makedirs(_os.path.dirname(_os.path.abspath(config_file)), exist_ok=True)
    with open(config_file, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=4)
    return jsonify({"ok": True, "message": "General settings saved."})


@system_bp.route("/api/setup-wizard/time", methods=["POST"])
@login_required
@superuser_required
def api_setup_wizard_time():
    import os as _os
    data = request.get_json(force=True) or {}
    conn = get_db()

    cfg = _load_general_config()
    cfg["timezone"] = (data.get("timezone") or "Etc/UTC").strip()
    config_file = _general_config_path()
    _os.makedirs(_os.path.dirname(_os.path.abspath(config_file)), exist_ok=True)
    with open(config_file, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=4)

    ntp_row = conn.execute(
        "SELECT value_json FROM service_state WHERE key_name='ntp_settings'"
    ).fetchone()
    ntp_cfg = json.loads(ntp_row["value_json"]) if ntp_row else {}
    ntp_server = (data.get("ntp_server") or "").strip()
    if ntp_server:
        servers = ntp_cfg.get("servers", [])
        if ntp_server not in servers:
            servers = [ntp_server] + [s for s in servers if s]
        ntp_cfg["servers"] = servers[:4]
    ntp_cfg.setdefault("enabled", True)
    conn.execute(
        "INSERT INTO service_state (key_name, value_json, updated_at) VALUES ('ntp_settings',?,CURRENT_TIMESTAMP)"
        " ON CONFLICT(key_name) DO UPDATE SET value_json=excluded.value_json, updated_at=CURRENT_TIMESTAMP",
        (json.dumps(ntp_cfg),)
    )
    conn.commit()
    return jsonify({"ok": True, "message": "Time settings saved."})


# ----------------------------
# COPYRIGHT PAGE
# ----------------------------

@system_bp.route("/copyright", methods=["GET", "POST"])
@login_required
def copyright_page():
    if request.method == "POST":
        return redirect(url_for("system.dashboard"))
    return render_template("copyright.html")


# ----------------------------
# SYSTEM UPDATE PAGE
# ----------------------------

@system_bp.route("/update", methods=["GET", "POST"])
@login_required
def update_page():
    active_tab = "system"
    message = None

    if request.method == "POST":
        if "check_updates" in request.form:
            message = "Checking for updates..."
            active_tab = "system"

        elif "update_system" in request.form:
            message = "System update initiated..."
            active_tab = "system"

        elif "save_settings" in request.form:
            message = "Settings saved successfully"
            active_tab = "settings"

    return render_template("update.html", message=message, active_tab=active_tab)


# ----------------------------
# NOTIFICATIONS
# ----------------------------

_NOTIF_BOOL_FIELDS = {
    "certificate_expiration", "ignore_revoked", "disable_smtp",
    "secure_smtp_connection", "validate_ssl_tls",
    "console_bell", "startup_shutdown_sound", "enable_telegram",
}

@system_bp.route("/notifications", methods=["GET", "POST"])
@login_required
def notifications():
    conn = get_db()
    if request.method == "POST":
        data = {}
        for key, value in request.form.items():
            if key == "csrf_token":
                continue
            data[key] = value
        for field in _NOTIF_BOOL_FIELDS:
            data[field] = field in request.form
        conn.execute(
            "INSERT INTO service_state(key_name, value_json) VALUES('notification_settings', ?) "
            "ON CONFLICT(key_name) DO UPDATE SET value_json=excluded.value_json, updated_at=CURRENT_TIMESTAMP",
            (json.dumps(data),),
        )
        conn.commit()
        flash("Notification settings saved.", "success")
        return redirect(url_for("system.notifications"))

    row = conn.execute(
        "SELECT value_json FROM service_state WHERE key_name='notification_settings'"
    ).fetchone()
    settings = json.loads(row["value_json"]) if row else {}
    return render_template("notifications.html", settings=settings)


# ---------------------------------------------------------------------------
# Reports — executive / PCI-DSS / ISO 27001 HTML rollups
# ---------------------------------------------------------------------------

@system_bp.route("/reports", methods=["GET", "POST"])
@superuser_required
def reports():
    from app.services import report_generator as rg
    conn = get_db()
    if request.method == "POST":
        rtype  = request.form.get("report_type") or "executive"
        period = request.form.get("period") or "30d"
        result = rg.generate(conn, rtype, period,
                             generated_by=session.get("username") or "admin")
        if not result["ok"]:
            flash(result.get("message", "Failed to generate report."), "danger")
        else:
            log_event(category="system", action="report_generated",
                      username=session.get("username"), remote_addr=request.remote_addr,
                      details={"report_id": result["id"], "type": rtype, "period": period})
            return redirect(url_for("system.report_view", report_id=result["id"]))
        return redirect(url_for("system.reports"))

    return render_template("reports.html",
                           reports=rg.list_reports(conn),
                           types=rg.list_types())


@system_bp.route("/reports/<int:report_id>", methods=["GET"])
@superuser_required
def report_view(report_id):
    from app.services import report_generator as rg
    from flask import Response
    conn = get_db()
    html_doc = rg.fetch_html(conn, report_id)
    if not html_doc:
        flash("Report not found.", "warning")
        return redirect(url_for("system.reports"))
    return Response(html_doc, mimetype="text/html")


# ---------------------------------------------------------------------------
# Playbooks — trigger → ordered automated steps with optional approval gate
# ---------------------------------------------------------------------------

@system_bp.route("/playbooks", methods=["GET", "POST"])
@superuser_required
def playbooks():
    from app.services import playbooks as pb
    conn = get_db()

    if request.method == "POST":
        op = request.form.get("op", "")
        if op == "save":
            import json as _j
            try:
                steps = _j.loads(request.form.get("steps_json") or "[]")
            except Exception:
                steps = None
            if steps is None:
                flash("Steps must be valid JSON.", "danger")
                return redirect(url_for("system.playbooks"))
            result = pb.upsert_playbook(conn, {
                "id":               request.form.get("id"),
                "name":             request.form.get("name"),
                "description":      request.form.get("description"),
                "enabled":          request.form.get("enabled") == "on",
                "trigger_action":   request.form.get("trigger_action"),
                "trigger_category": request.form.get("trigger_category"),
                "trigger_min_sev":  request.form.get("trigger_min_sev"),
                "steps":            steps,
                "created_by":       session.get("username") or "admin",
            })
            if not result["ok"]:
                flash(result["message"], "danger")
            else:
                log_event(category="system", action="playbook_saved",
                          username=session.get("username"), remote_addr=request.remote_addr,
                          details={"name": request.form.get("name")})
                flash("Playbook saved.", "success")
        elif op == "delete":
            try:
                pb.delete_playbook(conn, int(request.form.get("id") or 0))
                flash("Playbook deleted.", "success")
            except Exception:
                flash("Failed to delete playbook.", "danger")
        elif op == "approve_run":
            try:
                rid = int(request.form.get("run_id") or 0)
            except (TypeError, ValueError):
                rid = 0
            res = pb.approve_run(conn, rid, session.get("username") or "admin")
            if res["ok"]:
                log_event(category="security", action="playbook_run_approved",
                          username=session.get("username"), remote_addr=request.remote_addr,
                          details={"run_id": rid, "status": res.get("status")})
                flash(f"Run {rid} resumed ({res.get('status')}).", "success")
            else:
                flash(res["message"], "warning")
        return redirect(url_for("system.playbooks"))

    return render_template(
        "playbooks.html",
        playbooks=pb.list_playbooks(conn),
        runs=pb.list_runs(conn, limit=30),
    )


# ---------------------------------------------------------------------------
# Asset & Identity inventory — used for per-event enrichment and reports
# ---------------------------------------------------------------------------

@system_bp.route("/inventory", methods=["GET", "POST"])
@superuser_required
def inventory():
    from app.services import inventory as inv
    conn = get_db()
    if request.method == "POST":
        op = request.form.get("op", "")
        if op == "asset_save":
            inv.upsert_asset(conn, {
                "id":            request.form.get("id"),
                "ip":            request.form.get("ip"),
                "hostname":      request.form.get("hostname"),
                "mac":           request.form.get("mac"),
                "owner":         request.form.get("owner"),
                "business_unit": request.form.get("business_unit"),
                "criticality":   request.form.get("criticality"),
                "tags":          request.form.get("tags"),
                "notes":         request.form.get("notes"),
            })
            log_event(category="system", action="asset_saved",
                      username=session.get("username"), remote_addr=request.remote_addr,
                      details={"ip": request.form.get("ip")})
            flash("Asset saved.", "success")
        elif op == "asset_delete":
            try:
                inv.delete_asset(conn, int(request.form.get("id") or 0))
                flash("Asset deleted.", "success")
            except Exception:
                flash("Failed to delete asset.", "danger")
        elif op == "identity_save":
            inv.upsert_identity(conn, {
                "id":            request.form.get("id"),
                "username":      request.form.get("username"),
                "full_name":     request.form.get("full_name"),
                "email":         request.form.get("email"),
                "role":          request.form.get("role"),
                "manager":       request.form.get("manager"),
                "business_unit": request.form.get("business_unit"),
                "sensitivity":   request.form.get("sensitivity"),
                "notes":         request.form.get("notes"),
            })
            log_event(category="system", action="identity_saved",
                      username=session.get("username"), remote_addr=request.remote_addr,
                      details={"target_user": request.form.get("username")})
            flash("Identity saved.", "success")
        elif op == "identity_delete":
            try:
                inv.delete_identity(conn, int(request.form.get("id") or 0))
                flash("Identity deleted.", "success")
            except Exception:
                flash("Failed to delete identity.", "danger")
        return redirect(url_for("system.inventory"))

    return render_template(
        "inventory.html",
        assets=inv.list_assets(conn),
        identities=inv.list_identities(conn),
    )


# ---------------------------------------------------------------------------
# API Tokens — service-account credentials for the HEC / SOC API surface
# ---------------------------------------------------------------------------

@system_bp.route("/api-tokens", methods=["GET", "POST"])
@superuser_required
def api_tokens():
    """Manage scoped API tokens used by external tools."""
    from app.api_tokens import create_token, list_tokens, revoke_token
    conn = get_db()
    new_plaintext = None

    if request.method == "POST":
        op = request.form.get("op", "create")
        if op == "create":
            name   = (request.form.get("name") or "").strip()
            # Build scopes from checkbox list + free-text fallback.
            checked = request.form.getlist("scope")
            extra   = (request.form.get("scopes_extra") or "").strip()
            scopes  = ",".join([s.strip() for s in checked if s.strip()])
            if extra:
                scopes = (scopes + "," + extra) if scopes else extra
            if not name or not scopes:
                flash("Name and at least one scope are required.", "danger")
                return redirect(url_for("system.api_tokens"))
            created = create_token(conn, name, scopes, session.get("username") or "admin")
            new_plaintext = created["token"]
            log_event(
                category="system", action="api_token_created",
                username=session.get("username"), remote_addr=request.remote_addr,
                details={"name": name, "scopes": scopes},
            )
            flash("Token created. Copy it now — it will not be shown again.", "success")
        elif op == "revoke":
            try:
                token_id = int(request.form.get("token_id") or 0)
            except (TypeError, ValueError):
                token_id = 0
            if token_id and revoke_token(conn, token_id):
                log_event(
                    category="system", action="api_token_revoked",
                    username=session.get("username"), remote_addr=request.remote_addr,
                    details={"token_id": token_id},
                )
                flash("Token revoked.", "success")
            else:
                flash("Token not found or already revoked.", "warning")

    return render_template("api_tokens.html",
                           tokens=list_tokens(conn),
                           new_plaintext=new_plaintext)


# ---------------------------------------------------------------------------
# SOC Team Portal Settings
# ---------------------------------------------------------------------------
