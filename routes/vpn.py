import sqlite3

from flask import Blueprint, render_template, request, jsonify

from app.database import get_db

vpn_bp = Blueprint("vpn", __name__, url_prefix="/vpn")

# ----------------------------
# VPN MAIN PAGE
# ----------------------------

@vpn_bp.route("/")
def vpn_home():
    return render_template("vpn.html")


# ----------------------------
# OPENVPN PAGE
# ----------------------------

@vpn_bp.route("/openvpn")
def openvpn():
    # OpenVPN Servers (default tab)
    return render_template("openvpn.html", active_tab="servers")


@vpn_bp.route("/openvpn/servers")
def openvpn_servers():
    return render_template("openvpn.html", active_tab="servers")


@vpn_bp.route("/openvpn/clients")
def openvpn_clients():
    return render_template("openvpn_clients.html", active_tab="clients")


@vpn_bp.route("/openvpn/cso")
def openvpn_cso():
    return render_template("openvpn_cso.html", active_tab="cso")


@vpn_bp.route("/openvpn/wizards")
def openvpn_wizards():
    return render_template("openvpn_wizards1.html", active_tab="wizards")


@vpn_bp.route("/openvpn/wizards/step2")
def openvpn_wizards_step2():
    return render_template("openvpn_wizards2.html", active_tab="wizards")


@vpn_bp.route("/openvpn/wizards/step3")
def openvpn_wizards_step3():
    return render_template("openvpn_wizards3.html", active_tab="wizards")


# ----------------------------
# IPsec PAGE
# ----------------------------

@vpn_bp.route("/ipsec")
def ipsec():
    return render_template("ipsec.html")


# ----------------------------
# IPsec API (Phase 1)
# ----------------------------

@vpn_bp.route("/api/ipsec/p1", methods=["GET"])
def ipsec_p1_list():
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute(
            """
            SELECT id, disabled, ike_version, remote_gateway, auth_method,
                   internet_protocol, interface, description
            FROM ipsec_phase1
            ORDER BY id
            """
        )
        rows = cur.fetchall()
        tunnels = []
        for r in rows:
            # algorithms summary
            cur.execute(
                """SELECT encryption, key_length, hash, dh_group
                   FROM ipsec_phase1_algorithms WHERE phase1_id=? ORDER BY id""",
                (r["id"],),
            )
            algos = [dict(a) for a in cur.fetchall()]
            tunnels.append({**dict(r), "algorithms": algos})
        return jsonify({"success": True, "tunnels": tunnels})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@vpn_bp.route("/api/ipsec/p1", methods=["POST"])
def ipsec_p1_create():
    try:
        data = request.get_json() or {}
        remote_gateway = (data.get("remote_gateway") or "").strip()
        if not remote_gateway:
            return jsonify({"success": False, "error": "remote_gateway is required"}), 400

        db = get_db()
        cur = db.cursor()

        cur.execute(
            """
            INSERT INTO ipsec_phase1 (
                disabled, ike_version, internet_protocol, interface, remote_gateway,
                auth_method, my_identifier, peer_identifier, pre_shared_key,
                p1_life_time, p1_rekey_time, p1_reauth_time, p1_rand_time,
                child_sa_start_action, child_sa_close_action,
                nat_traversal, mobike,
                gateway_duplicates, split_connections, prf_selection,
                remote_ike_port, remote_nat_t_port,
                dpd_enable, dpd_delay, dpd_max_failures,
                description
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                1 if data.get("disabled") else 0,
                data.get("ike_version", data.get("keyExchange", "ikev2")),
                data.get("internet_protocol", data.get("protocol", "ipv4")),
                data.get("interface", "wan"),
                remote_gateway,
                data.get("auth_method", data.get("authMethod", "mutual-psk")),
                data.get("my_identifier", data.get("myIdentifier", "my-ip")),
                data.get("peer_identifier", data.get("peerIdentifier", "peer-ip")),
                data.get("pre_shared_key", data.get("pre_shared_key", "")),
                int(data.get("p1_life_time", data.get("life_time", 28800)) or 28800),
                int(data.get("p1_rekey_time", data.get("rekey_time", 25920)) or 25920),
                int(data.get("p1_reauth_time", data.get("reauth_time", 0)) or 0),
                int(data.get("p1_rand_time", data.get("rand_time", 2880)) or 2880),
                data.get("child_sa_start_action", "default"),
                data.get("child_sa_close_action", "default"),
                data.get("nat_traversal", "auto"),
                data.get("mobike", "disable"),
                1 if data.get("gateway_duplicates") else 0,
                1 if data.get("split_connections") else 0,
                1 if data.get("prf_selection") else 0,
                (data.get("remote_ike_port") or ""),
                (data.get("remote_nat_t_port") or ""),
                1 if data.get("dpd_enable", True) else 0,
                int(data.get("dpd_delay", 10) or 10),
                int(data.get("dpd_max_failures", 5) or 5),
                (data.get("description") or ""),
            ),
        )
        p1_id = cur.lastrowid

        algos = data.get("algorithms") or []
        if isinstance(algos, list) and len(algos) > 0:
            for a in algos:
                enc = (a.get("encryption") or "").strip()
                if not enc:
                    continue
                cur.execute(
                    """
                    INSERT INTO ipsec_phase1_algorithms (phase1_id, encryption, key_length, hash, dh_group)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        p1_id,
                        enc,
                        a.get("key_length"),
                        a.get("hash"),
                        a.get("dh_group"),
                    ),
                )
        else:
            # store the first default selection if none provided
            cur.execute(
                """
                INSERT INTO ipsec_phase1_algorithms (phase1_id, encryption, key_length, hash, dh_group)
                VALUES (?, ?, ?, ?, ?)
                """,
                (p1_id, "aes", 128, "sha256", "14"),
            )

        db.commit()
        return jsonify({"success": True, "id": p1_id})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@vpn_bp.route("/api/ipsec/p1/<int:p1_id>", methods=["DELETE"])
def ipsec_p1_delete(p1_id):
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute("DELETE FROM ipsec_phase1 WHERE id=?", (p1_id,))
        db.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@vpn_bp.route("/ipsec/mobile-clients")
def ipsec_mobile_clients():
    return render_template("IPsec_mob_clients.html", active_tab="mobile_clients")


@vpn_bp.route("/ipsec/pre-shared-keys")
def ipsec_pre_shared_keys():
    return render_template("IPsec_pre_shared_keys.html", active_tab="psk")


@vpn_bp.route("/ipsec/advanced-settings")
def ipsec_advanced_settings():
    return render_template("IPsec_advanced_settings.html", active_tab="advanced")


# ----------------------------
# IPsec Mobile Clients API
# ----------------------------

@vpn_bp.route("/api/ipsec/mobile-clients", methods=["GET"])
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
def ipsec_mobile_clients_save():
    try:
        data = request.get_json() or {}
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
def ipsec_psk_create():
    try:
        data = request.get_json() or {}
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
                (identifier, secret_type, pre_shared_key),
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
def ipsec_advanced_settings_save():
    try:
        data = request.get_json() or {}
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

@vpn_bp.route("/l2tp")
def l2tp():
    return render_template("l2tp.html")


@vpn_bp.route("/l2tp/users")
def l2tp_users():
    return render_template("l2tp_users.html")


# ----------------------------
# L2TP API (Configuration)
# ----------------------------

@vpn_bp.route("/api/l2tp/settings", methods=["GET"])
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
def l2tp_settings_save():
    try:
        data = request.get_json() or {}
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
