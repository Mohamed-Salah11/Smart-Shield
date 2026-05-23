from routes.vpn import vpn_bp
from routes.vpn._common import *  # noqa: F401,F403
from routes.vpn._common import _payload_and_status  # noqa: F401


@vpn_bp.route("/")
@login_required
def vpn_home():
    return render_template("vpn.html")


# ----------------------------
# OPENVPN PAGE
# ----------------------------

@vpn_bp.route("/openvpn", methods=['GET', 'POST'])
@login_required
def openvpn():
    # OpenVPN Servers (default tab)
    return render_template("openvpn.html", active_tab="servers")


@vpn_bp.route("/openvpn/servers", methods=['GET', 'POST'])
@login_required
def openvpn_servers():
    return render_template("openvpn.html", active_tab="servers")


@vpn_bp.route("/openvpn/clients", methods=['GET', 'POST'])
@login_required
def openvpn_clients():
    return render_template("openvpn_clients.html", active_tab="clients")


@vpn_bp.route("/openvpn/cso", methods=['GET', 'POST'])
@login_required
def openvpn_cso():
    return render_template("openvpn_cso.html", active_tab="cso")


@vpn_bp.route("/openvpn/portal-users", methods=['GET'])
@login_required
def openvpn_portal_users():
    return render_template("openvpn_portal_users.html", active_tab="portal")


@vpn_bp.route("/openvpn/wizards", methods=['GET', 'POST'])
@login_required
def openvpn_wizards():
    return render_template("openvpn_wizards1.html", active_tab="wizards")


@vpn_bp.route("/openvpn/wizards/step2", methods=['GET', 'POST'])
@login_required
def openvpn_wizards_step2():
    return render_template("openvpn_wizards2.html", active_tab="wizards")


@vpn_bp.route("/openvpn/wizards/step3", methods=['GET', 'POST'])
@login_required
def openvpn_wizards_step3():
    return render_template("openvpn_wizards3.html", active_tab="wizards")


# ----------------------------
# IPsec PAGE
# ----------------------------

@vpn_bp.route("/ipsec", methods=['GET', 'POST'])
@login_required
def ipsec():
    active_tab = request.args.get("tab", "tunnels")
    if active_tab not in ("tunnels", "mobile_clients", "psk", "advanced"):
        active_tab = "tunnels"
    return render_template("ipsec.html", active_tab=active_tab)


# ----------------------------
# IPsec API (Phase 1)
# ----------------------------

@vpn_bp.route("/api/ipsec/p1", methods=["GET"])
@login_required
def ipsec_p1_list():
    from app.services import ipsec_service
    payload, status = ipsec_service.list_phase1(get_db())
    return jsonify(payload), status

@vpn_bp.route("/api/ipsec/p1", methods=["POST"])
@api_permission_required("api.vpn.edit")
def ipsec_p1_create():
    from app.services import ipsec_service
    payload, status = ipsec_service.create_phase1(get_db(), request.get_json(silent=True) or {})
    return jsonify(payload), status

@vpn_bp.route("/api/ipsec/p1/<int:p1_id>", methods=["DELETE"])
@api_permission_required("api.vpn.edit")
def ipsec_p1_delete(p1_id):
    from app.services import ipsec_service
    payload, status = ipsec_service.delete_phase1(get_db(), p1_id)
    return jsonify(payload), status

@vpn_bp.route("/ipsec/mobile-clients", methods=['GET', 'POST'])
@login_required
def ipsec_mobile_clients():
    return render_template("IPsec_mob_clients.html", active_tab="mobile_clients")


@vpn_bp.route("/ipsec/pre-shared-keys", methods=['GET', 'POST'])
@login_required
def ipsec_pre_shared_keys():
    return render_template("IPsec_pre_shared_keys.html", active_tab="psk")


@vpn_bp.route("/ipsec/advanced-settings", methods=['GET', 'POST'])
@login_required
def ipsec_advanced_settings():
    return render_template("IPsec_advanced_settings.html", active_tab="advanced")


# ----------------------------
# IPsec Mobile Clients API
# ----------------------------

@vpn_bp.route("/api/ipsec/mobile-clients", methods=["GET"])
@login_required
def ipsec_mobile_clients_get():
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute(
            """
            SELECT ike_extensions, group_auth, radius_accounting,
                   virtual_address_pool, virtual_ipv6_address_pool,
                   radius_ip_priority, radius_advanced_parameters,
                   network_list, save_xauth_password,
                   dns_default_domain, split_dns, dns_servers, wins_servers,
                   phase2_pfs_group, login_banner
            FROM ipsec_mobile_clients_settings WHERE id=1
            """
        )
        row = cur.fetchone()
        if not row:
            return jsonify({"success": True, "settings": {}})
        return jsonify({"success": True, "settings": dict(row)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@vpn_bp.route("/api/ipsec/mobile-clients", methods=["POST"])
@api_permission_required("api.vpn.edit")
def ipsec_mobile_clients_save():
    try:
        data = request.get_json(silent=True) or {}
        db = get_db()
        cur = db.cursor()

        def b(name, default=False):
            return 1 if bool(data.get(name, default)) else 0

        cur.execute(
            """
            UPDATE ipsec_mobile_clients_settings
            SET ike_extensions=?,
                group_auth=?,
                radius_accounting=?,
                virtual_address_pool=?,
                virtual_ipv6_address_pool=?,
                radius_ip_priority=?,
                radius_advanced_parameters=?,
                network_list=?,
                save_xauth_password=?,
                dns_default_domain=?,
                split_dns=?,
                dns_servers=?,
                wins_servers=?,
                phase2_pfs_group=?,
                login_banner=?,
                updated_at=CURRENT_TIMESTAMP
            WHERE id=1
            """,
            (
                b("ike_extensions"),
                b("group_auth"),
                b("radius_accounting"),
                b("virtual_address_pool", True),
                b("virtual_ipv6_address_pool"),
                b("radius_ip_priority"),
                b("radius_advanced_parameters"),
                b("network_list", True),
                b("save_xauth_password"),
                b("dns_default_domain"),
                b("split_dns"),
                b("dns_servers"),
                b("wins_servers"),
                b("phase2_pfs_group"),
                b("login_banner"),
            ),
        )
        db.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ----------------------------
# IPsec Pre-Shared Keys API
# ----------------------------

@vpn_bp.route("/api/ipsec/psk", methods=["GET"])
@login_required
def ipsec_psk_list():
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute(
            """
            SELECT id, identifier, secret_type
            FROM ipsec_pre_shared_keys
            ORDER BY id
            """
        )
        keys = [dict(r) for r in cur.fetchall()]
        return jsonify({"success": True, "keys": keys})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@vpn_bp.route("/api/ipsec/psk", methods=["POST"])
@api_permission_required("api.vpn.edit")
def ipsec_psk_create():
    try:
        data = request.get_json(silent=True) or {}
        identifier = (data.get("identifier") or "").strip()
        secret_type = (data.get("secret_type") or "psk").strip()
        pre_shared_key = (data.get("pre_shared_key") or "").strip()

        if not identifier:
            return jsonify({"success": False, "error": "identifier is required"}), 400
        if not pre_shared_key:
            return jsonify({"success": False, "error": "pre_shared_key is required"}), 400

        db = get_db()
        cur = db.cursor()
        try:
            cur.execute(
                """
                INSERT INTO ipsec_pre_shared_keys (identifier, secret_type, pre_shared_key)
                VALUES (?, ?, ?)
                """,
                (identifier, secret_type, seal(pre_shared_key)),
            )
        except sqlite3.IntegrityError:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": "A PSK with the same identifier already exists",
                    }
                ),
                409,
            )

        db.commit()
        return jsonify({"success": True, "id": cur.lastrowid})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@vpn_bp.route("/api/ipsec/psk/<int:psk_id>", methods=["DELETE"])
@api_permission_required("api.vpn.edit")
def ipsec_psk_delete(psk_id):
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute("DELETE FROM ipsec_pre_shared_keys WHERE id=?", (psk_id,))
        db.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ----------------------------
# IPsec Advanced Settings API
# ----------------------------

@vpn_bp.route("/api/ipsec/advanced-settings", methods=["GET"])
@login_required
def ipsec_advanced_settings_get():
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT * FROM ipsec_advanced_settings WHERE id=1")
        row = cur.fetchone()
        return jsonify({"success": True, "settings": dict(row) if row else {}})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@vpn_bp.route("/api/ipsec/advanced-settings", methods=["POST"])
@api_permission_required("api.vpn.edit")
def ipsec_advanced_settings_save():
    try:
        data = request.get_json(silent=True) or {}
        db = get_db()
        cur = db.cursor()

        def b(name, default=False):
            return 1 if bool(data.get(name, default)) else 0

        cur.execute(
            """
            UPDATE ipsec_advanced_settings
            SET log_daemon=?,
                log_sa_manager=?,
                log_ike_sa=?,
                log_ike_child_sa=?,
                log_job_processing=?,
                log_config_backend=?,
                log_kernel_interface=?,
                log_networking=?,
                log_asn_encoding=?,
                log_message_encoding=?,
                log_integrity_checker=?,
                log_integrity_verifier=?,
                log_platform_trust_service=?,
                log_tls_handler=?,
                log_ipsec_traffic=?,
                log_strongswan_lib=?,
                unique_ids=?,
                ipsec_filter_mode=?,
                ikev2_retransmission=?,
                ip_compression=?,
                pkcs11_support=?,
                strict_interface_binding=?,
                ikev1_unencrypted_payloads=?,
                max_ikev1_phase2_exchanges=?,
                enable_cisco_extensions=?,
                strict_crl_checking=?,
                fqdn_endpoints_resolve_interval=?,
                make_before_break=?,
                asynchronous_cryptography=?,
                custom_ike_port=?,
                custom_nat_t_port=?,
                auto_exclude_lan_address=?,
                additional_ipsec_bypass=?,
                updated_at=CURRENT_TIMESTAMP
            WHERE id=1
            """,
            (
                data.get("log_daemon", "Control"),
                data.get("log_sa_manager", "Control"),
                data.get("log_ike_sa", "Control"),
                data.get("log_ike_child_sa", "Control"),
                data.get("log_job_processing", "Control"),
                data.get("log_config_backend", "Control"),
                data.get("log_kernel_interface", "Control"),
                data.get("log_networking", "Control"),
                data.get("log_asn_encoding", "Control"),
                data.get("log_message_encoding", "Control"),
                data.get("log_integrity_checker", "Control"),
                data.get("log_integrity_verifier", "Control"),
                data.get("log_platform_trust_service", "Control"),
                data.get("log_tls_handler", "Control"),
                data.get("log_ipsec_traffic", "Control"),
                data.get("log_strongswan_lib", "Control"),
                data.get("unique_ids", "Yes (Replace)"),
                data.get(
                    "ipsec_filter_mode",
                    "Filter [IPsec Tunnel, Transport, and VTI] on IPsec tab (enc0)",
                ),
                b("ikev2_retransmission"),
                b("ip_compression"),
                b("pkcs11_support"),
                b("strict_interface_binding"),
                b("ikev1_unencrypted_payloads"),
                int(data.get("max_ikev1_phase2_exchanges", 3) or 3),
                b("enable_cisco_extensions"),
                b("strict_crl_checking"),
                int(data.get("fqdn_endpoints_resolve_interval", 60) or 60),
                b("make_before_break"),
                b("asynchronous_cryptography"),
                (data.get("custom_ike_port") or ""),
                (data.get("custom_nat_t_port") or ""),
                b("auto_exclude_lan_address"),
                b("additional_ipsec_bypass"),
            ),
        )

        db.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ----------------------------
# L2TP PAGE
# ----------------------------

@vpn_bp.route("/l2tp", methods=['GET', 'POST'])
@login_required
def l2tp():
    return render_template("l2tp.html")


@vpn_bp.route("/l2tp/users", methods=['GET', 'POST'])
@login_required
def l2tp_users():
    return render_template("l2tp_users.html")


# ----------------------------
# L2TP API (Configuration)
# ----------------------------

@vpn_bp.route("/api/l2tp/settings", methods=["GET"])
@login_required
def l2tp_settings_get():
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT enabled FROM l2tp_settings WHERE id=1")
        row = cur.fetchone()
        return jsonify({"success": True, "settings": dict(row) if row else {}})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@vpn_bp.route("/api/l2tp/settings", methods=["POST"])
@api_permission_required("api.vpn.edit")
def l2tp_settings_save():
    try:
        data = request.get_json(silent=True) or {}
        enabled = 1 if bool(data.get("enabled", True)) else 0
        db = get_db()
        cur = db.cursor()
        cur.execute(
            """
            UPDATE l2tp_settings
            SET enabled=?, updated_at=CURRENT_TIMESTAMP
            WHERE id=1
            """,
            (enabled,),
        )
        db.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ----------------------------
# OPENVPN API ENDPOINTS
# ----------------------------
