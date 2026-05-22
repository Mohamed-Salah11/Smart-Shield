from routes.system import system_bp
from routes.system._common import *  # noqa: F401,F403
from routes.system._common import _general_config_path, _config_bool, _load_general_config, _safe_count, _build_dashboard_payload  # noqa: F401


@system_bp.route("/soc-portal-settings", methods=["GET", "POST"])
@superuser_required
def soc_portal_settings():
    conn = get_db()

    if request.method == "POST":
        enabled     = 1 if request.form.get("enabled") else 0
        bind_ip     = request.form.get("bind_ip", "0.0.0.0").strip() or "0.0.0.0"
        bind_port   = request.form.get("bind_port", "8443").strip()
        ssl_cert_id = request.form.get("ssl_cert_id", "").strip() or None

        # SOC Portal Control runtime/access fields.
        public_url       = request.form.get("public_url", "").strip()
        allowed_networks = request.form.get("allowed_networks", "").strip()
        external_ingest  = 1 if request.form.get("external_ingest_enabled") else 0
        retention_days   = request.form.get("retention_days", "90").strip()
        try:
            retention_days = int(retention_days)
            if not (1 <= retention_days <= 3650):
                raise ValueError
        except ValueError:
            retention_days = 90

        try:
            bind_port = int(bind_port)
            if not (1 <= bind_port <= 65535):
                raise ValueError
        except ValueError:
            flash("Invalid port number.", "danger")
            return redirect(url_for("system.soc_portal_settings"))

        conn.execute(
            """UPDATE soc_portal_config
               SET enabled=?, bind_ip=?, bind_port=?, ssl_cert_id=?,
                   public_url=?, allowed_networks=?, external_ingest_enabled=?,
                   retention_days=?, updated_at=CURRENT_TIMESTAMP
               WHERE id=1""",
            (enabled, bind_ip, bind_port, ssl_cert_id,
             public_url, allowed_networks, external_ingest, retention_days),
        )

        # Save soc_tier for each group submitted as group_tier_<id>
        groups = conn.execute("SELECT id FROM groups").fetchall()
        for g in groups:
            tier = request.form.get(f"group_tier_{g['id']}", "").strip() or None
            if tier not in (None, "L1", "L2", "L3"):
                tier = None
            conn.execute(
                "UPDATE groups SET soc_tier=? WHERE id=?",
                (tier, g["id"]),
            )

        # Save soc_tier for each user submitted as user_tier_<id>
        # (superusers are implicitly L3 — their dropdown is disabled, so any
        # value submitted for them is ignored here).
        soc_users = conn.execute("SELECT id, is_superuser FROM users").fetchall()
        for u in soc_users:
            if u["is_superuser"]:
                continue
            tier = request.form.get(f"user_tier_{u['id']}", "").strip() or None
            if tier not in (None, "L1", "L2", "L3"):
                tier = None
            conn.execute(
                "UPDATE users SET soc_tier=? WHERE id=?",
                (tier, u["id"]),
            )

        conn.commit()
        log_event(
            category="system",
            action="soc_portal_settings_saved",
            username=session.get("username", "unknown"),
            remote_addr=request.remote_addr,
            details={"enabled": enabled, "bind_ip": bind_ip, "bind_port": bind_port},
        )
        from app.services.soc_portal_writer import write_soc_portal_nginx_config
        apply_result = write_soc_portal_nginx_config(conn)
        if not apply_result["ok"]:
            flash(f"Settings saved. Note: {apply_result['message']}", "warning")
        else:
            flash(f"Settings saved. {apply_result['message']}", "success")
        return redirect(url_for("system.soc_portal_settings"))

    try:
        conn.execute("INSERT OR IGNORE INTO soc_portal_config (id) VALUES (1)")
        conn.commit()
    except Exception:
        pass
    cfg = conn.execute("SELECT * FROM soc_portal_config WHERE id=1").fetchone()
    groups = conn.execute("SELECT id, name, description, soc_tier FROM groups ORDER BY name").fetchall()
    soc_users = conn.execute(
        "SELECT id, username, full_name, soc_tier, is_superuser, status "
        "FROM users ORDER BY username"
    ).fetchall()
    try:
        certs = conn.execute(
            "SELECT id, name FROM certificates WHERE cert_type='server' ORDER BY name"
        ).fetchall()
    except Exception:
        certs = []

    # LAN context for the bind-IP hint — the SOC portal binds to a VIP on LAN.
    lan_port = ""
    lan_subnet = ""
    lan_primary_ip = ""
    bind_ip_example = ""
    try:
        import ipaddress
        lan_row = conn.execute(
            "SELECT assigned_port, ipv4_address FROM lan_config WHERE id=1"
        ).fetchone()
        if lan_row:
            lan_port = (lan_row["assigned_port"] or "").strip().split()[0] if (lan_row["assigned_port"] or "").strip() else ""
            cidr = (lan_row["ipv4_address"] or "").strip()
            if cidr:
                lan_iface = ipaddress.ip_interface(cidr)
                lan_subnet = str(lan_iface.network)
                lan_primary_ip = str(lan_iface.ip)
                hosts = list(lan_iface.network.hosts())
                if hosts:
                    # Pick a likely-free host near the top of the subnet.
                    candidate = hosts[-6] if len(hosts) > 6 else hosts[-1]
                    if candidate == lan_iface.ip and len(hosts) > 1:
                        candidate = hosts[-1] if hosts[-1] != lan_iface.ip else hosts[-2]
                    bind_ip_example = str(candidate)
    except Exception:
        pass

    return render_template(
        "soc_portal_settings.html",
        cfg=cfg,
        groups=groups,
        users=soc_users,
        certs=certs,
        lan_port=lan_port,
        lan_subnet=lan_subnet,
        lan_primary_ip=lan_primary_ip,
        bind_ip_example=bind_ip_example,
    )


@system_bp.route("/soc-portal-settings/restart", methods=["POST"])
@superuser_required
def soc_portal_restart():
    """Re-apply the SOC Portal nginx vhost and reload the service."""
    conn = get_db()
    from app.services.soc_portal_writer import write_soc_portal_nginx_config
    result = write_soc_portal_nginx_config(conn)
    log_event(
        category="system",
        action="soc_portal_restart",
        username=session.get("username", "unknown"),
        remote_addr=request.remote_addr,
        details={"ok": result.get("ok"), "message": result.get("message", "")},
    )
    flash(("SOC Portal restarted. " if result.get("ok") else "SOC Portal restart issue: ")
          + result.get("message", ""),
          "success" if result.get("ok") else "warning")
    return redirect(url_for("system.soc_portal_settings"))


@system_bp.route("/soc-portal-settings/add-user", methods=["POST"])
@superuser_required
def soc_portal_add_user():
    """Create a new user account and assign it a SOC tier in one step."""
    from werkzeug.security import generate_password_hash

    conn     = get_db()
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    full_name = (request.form.get("full_name") or "").strip() or None
    tier      = (request.form.get("soc_tier") or "").strip() or None

    if not username:
        flash("Username is required.", "danger")
        return redirect(url_for("system.soc_portal_settings"))
    if len(password) < 8:
        flash("Password must be at least 8 characters.", "danger")
        return redirect(url_for("system.soc_portal_settings"))
    if tier not in ("L1", "L2", "L3"):
        flash("Select a valid SOC tier (L1, L2, or L3).", "danger")
        return redirect(url_for("system.soc_portal_settings"))

    existing = conn.execute(
        "SELECT id FROM users WHERE username=?", (username,)
    ).fetchone()
    if existing:
        flash(f"A user named '{username}' already exists.", "danger")
        return redirect(url_for("system.soc_portal_settings"))

    conn.execute(
        "INSERT INTO users (username, password, full_name, soc_tier) VALUES (?,?,?,?)",
        (username, generate_password_hash(password), full_name, tier),
    )
    conn.commit()
    log_event(
        category="system",
        action="soc_user_created",
        username=session.get("username", "unknown"),
        remote_addr=request.remote_addr,
        details={"new_user": username, "soc_tier": tier},
    )
    flash(f"SOC user '{username}' created with tier {tier}.", "success")
    return redirect(url_for("system.soc_portal_settings"))


# ===========================================================================
# Response Recommendations — Core review queue
#
# SOC analysts file recommendations inside the SOC Portal; once endorsed they
# arrive here (status 'sent_to_core'). SmartShield Core admin approves — which
# applies the firewall action — or rejects. SOC never changes firewall state
# directly (separation Rule 1).
# ===========================================================================

@system_bp.route("/soc-recommendations", methods=["GET"])
@superuser_required
def soc_recommendations_queue():
    conn = get_db()
    from app.services.soc_recommendations import list_recommendations
    pending = list_recommendations(conn, status="sent_to_core", limit=200)
    recent  = list_recommendations(conn, limit=100)
    return render_template("soc_recommendations.html",
                           pending=pending, recent=recent)


@system_bp.route("/soc-recommendations/<int:rec_id>/approve", methods=["POST"])
@superuser_required
def soc_recommendation_approve(rec_id):
    conn = get_db()
    from app.services.soc_recommendations import core_approve_and_apply
    admin = session.get("username", "unknown")
    res = core_approve_and_apply(conn, rec_id, admin)
    log_event(category="firewall", action="soc_recommendation_core_approved",
              username=admin, remote_addr=request.remote_addr,
              details={"recommendation_id": rec_id, "ok": res.get("ok"),
                       "status": res.get("status"), "message": res.get("message", "")})
    flash(res.get("message", ""), "success" if res.get("ok") else "warning")
    return redirect(url_for("system.soc_recommendations_queue"))


@system_bp.route("/soc-recommendations/<int:rec_id>/reject", methods=["POST"])
@superuser_required
def soc_recommendation_reject(rec_id):
    conn = get_db()
    from app.services.soc_recommendations import core_reject
    admin = session.get("username", "unknown")
    res = core_reject(conn, rec_id, admin)
    log_event(category="firewall", action="soc_recommendation_core_rejected",
              username=admin, remote_addr=request.remote_addr,
              details={"recommendation_id": rec_id, "message": res.get("message", "")})
    flash(res.get("message", ""), "success" if res.get("ok") else "warning")
    return redirect(url_for("system.soc_recommendations_queue"))


# ===========================================================================
# Mail Alerts — Gmail app-password SMTP alerting
# ===========================================================================

@system_bp.route("/mail-alerts", methods=["GET"])
@login_required
def mail_alerts_page():
    """Render the Mail Alerts settings page."""
    conn = get_db()
    cfg = conn.execute("SELECT * FROM mail_alerts_config WHERE id=1").fetchone()
    recipients = conn.execute(
        "SELECT r.id, r.user_id, r.email, r.label, r.disabled, "
        "       u.username AS user_username, u.email AS user_email "
        "FROM mail_alert_recipients r "
        "LEFT JOIN users u ON u.id = r.user_id "
        "ORDER BY r.id"
    ).fetchall()
    users = conn.execute(
        "SELECT id, username, email FROM users "
        "WHERE email IS NOT NULL AND TRIM(email) != '' ORDER BY username"
    ).fetchall()
    return render_template(
        "mail_alerts.html",
        cfg=dict(cfg) if cfg else {},
        recipients=[dict(r) for r in recipients],
        users=[dict(u) for u in users],
        has_password=bool(cfg and (cfg["smtp_app_password"] or "")),
    )


@system_bp.route("/api/mail-alerts/config", methods=["POST"])
@login_required
@superuser_required
def mail_alerts_save_config():
    """Save the singleton mail_alerts_config row."""
    from app.secret_store import encrypt_secret
    from app.services.mail_alerts import invalidate_config_cache

    data = request.get_json(silent=True) or {}
    conn = get_db()

    sec = (data.get("smtp_security") or "starttls").lower()
    if sec not in ("starttls", "ssl"):
        sec = "starttls"
    sev = (data.get("min_severity") or "high").lower()
    if sev not in ("info", "low", "medium", "high", "critical"):
        sev = "high"
    try:
        port = int(data.get("smtp_port") or 587)
    except (TypeError, ValueError):
        port = 587
    try:
        cooldown = max(0, int(data.get("cooldown_minutes") or 0))
    except (TypeError, ValueError):
        cooldown = 10
    try:
        cap = max(0, int(data.get("max_per_hour") or 0))
    except (TypeError, ValueError):
        cap = 20

    # App password: encrypt only when a new one is supplied; otherwise keep
    # whatever is stored ("leave blank to keep" pattern).
    raw_pw = (data.get("smtp_app_password") or "").strip()
    if raw_pw:
        pw_clause = ", smtp_app_password=?"
        pw_val = [encrypt_secret(raw_pw)]
    else:
        pw_clause = ""
        pw_val = []

    conn.execute(
        f"""UPDATE mail_alerts_config SET
            enabled=?, smtp_host=?, smtp_port=?, smtp_security=?,
            smtp_username=?, from_name=?, min_severity=?, category_filter=?,
            cooldown_minutes=?, max_per_hour=?{pw_clause},
            updated_at=CURRENT_TIMESTAMP
            WHERE id=1""",
        (
            1 if data.get("enabled") else 0,
            (data.get("smtp_host") or "smtp.gmail.com").strip(),
            port,
            sec,
            (data.get("smtp_username") or "").strip(),
            (data.get("from_name") or "Smart Shield").strip(),
            sev,
            (data.get("category_filter") or "").strip(),
            cooldown,
            cap,
            *pw_val,
        ),
    )
    conn.commit()
    invalidate_config_cache()
    log_event(category="mail", action="mail_alerts_config_saved",
              username=session.get("username", "unknown"),
              remote_addr=request.remote_addr,
              details={"enabled": bool(data.get("enabled")),
                       "min_severity": sev,
                       "password_changed": bool(raw_pw)})
    return jsonify({"ok": True})


@system_bp.route("/api/mail-alerts/recipients", methods=["GET"])
@login_required
def mail_alerts_recipients_list():
    conn = get_db()
    rows = conn.execute(
        "SELECT r.id, r.user_id, r.email, r.label, r.disabled, "
        "       u.username AS user_username, u.email AS user_email "
        "FROM mail_alert_recipients r "
        "LEFT JOIN users u ON u.id = r.user_id ORDER BY r.id"
    ).fetchall()
    return jsonify({"ok": True, "recipients": [dict(r) for r in rows]})


@system_bp.route("/api/mail-alerts/recipients", methods=["POST"])
@login_required
@superuser_required
def mail_alerts_recipients_add():
    """Add a recipient — either user-linked (user_id) or a free email."""
    data = request.get_json(silent=True) or {}
    conn = get_db()
    user_id = data.get("user_id")
    email   = (data.get("email") or "").strip()
    label   = (data.get("label") or "").strip()

    if user_id:
        try:
            user_id = int(user_id)
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "invalid user_id"}), 400
        urow = conn.execute("SELECT username FROM users WHERE id=?",
                            (user_id,)).fetchone()
        if not urow:
            return jsonify({"ok": False, "error": "user not found"}), 404
        conn.execute(
            "INSERT INTO mail_alert_recipients (user_id, label) VALUES (?,?)",
            (user_id, label or urow["username"]),
        )
    else:
        if not email or "@" not in email:
            return jsonify({"ok": False, "error": "valid email required"}), 400
        conn.execute(
            "INSERT INTO mail_alert_recipients (email, label) VALUES (?,?)",
            (email, label),
        )
    conn.commit()
    log_event(category="mail", action="mail_alert_recipient_added",
              username=session.get("username", "unknown"),
              remote_addr=request.remote_addr,
              details={"user_id": user_id, "email": email})
    return jsonify({"ok": True})


@system_bp.route("/api/mail-alerts/recipients/<int:rid>", methods=["DELETE"])
@login_required
@superuser_required
def mail_alerts_recipients_delete(rid):
    conn = get_db()
    conn.execute("DELETE FROM mail_alert_recipients WHERE id=?", (rid,))
    conn.commit()
    log_event(category="mail", action="mail_alert_recipient_removed",
              username=session.get("username", "unknown"),
              remote_addr=request.remote_addr, details={"id": rid})
    return jsonify({"ok": True})


@system_bp.route("/api/mail-alerts/test", methods=["POST"])
@login_required
@superuser_required
def mail_alerts_test():
    """
    Send a test email. Uses the submitted form values so the admin can test
    before saving; an empty app-password field falls back to the stored one.
    """
    from app.services.mail_alerts import get_config, send_test

    data = request.get_json(silent=True) or {}
    conn = get_db()
    stored = get_config(conn)  # carries the decrypted stored password

    cfg = {
        "smtp_host":     (data.get("smtp_host") or stored.get("smtp_host")
                          or "smtp.gmail.com").strip(),
        "smtp_port":      data.get("smtp_port") or stored.get("smtp_port") or 587,
        "smtp_security": (data.get("smtp_security")
                          or stored.get("smtp_security") or "starttls").lower(),
        "smtp_username": (data.get("smtp_username")
                          or stored.get("smtp_username") or "").strip(),
        "from_name":     (data.get("from_name")
                          or stored.get("from_name") or "Smart Shield").strip(),
        "smtp_app_password": (data.get("smtp_app_password") or "").strip()
                             or stored.get("smtp_app_password") or "",
    }
    to_address = (data.get("to") or cfg["smtp_username"]).strip()
    ok, message = send_test(cfg, to_address)
    return jsonify({"ok": ok, "message": message})
