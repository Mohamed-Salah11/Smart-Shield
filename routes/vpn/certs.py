from routes.vpn import vpn_bp
from routes.vpn._common import *  # noqa: F401,F403
from routes.vpn._common import _payload_and_status  # noqa: F401


@vpn_bp.route("/api/ipsec/validate", methods=["GET"])
@login_required
def ipsec_validate():
    """Validate all enabled IPsec Phase 1 + Phase 2 configs."""
    try:
        from app.services.ipsec_writer import validate_ipsec_config
        conn   = get_db()
        errors = validate_ipsec_config(conn)
        return jsonify({"ok": not errors, "errors": errors})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@vpn_bp.route("/api/l2tp/validate", methods=["GET"])
@login_required
def l2tp_validate():
    """Validate L2TP configuration and user list."""
    try:
        from app.services.l2tp_writer import validate_l2tp_config
        conn   = get_db()
        errors = validate_l2tp_config(conn)
        return jsonify({"ok": not errors, "errors": errors})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


# ── Certificate management ─────────────────────────────────────────────────

@vpn_bp.route("/api/certs", methods=["GET"])
@login_required
def list_certificates():
    """List all certificates safe for the UI."""
    try:
        from app.services.cert_manager import list_certs, mask_cert_fields
        cert_type = request.args.get("type")
        conn  = get_db()
        certs = list_certs(conn, cert_type=cert_type or None)
        return jsonify({"ok": True, "certs": [mask_cert_fields(c) for c in certs]})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@vpn_bp.route("/api/certs/create-ca", methods=["POST"])
@api_permission_required("api.vpn.edit")
def create_ca():
    """Create a new internal Certificate Authority."""
    try:
        from app.services.cert_manager import create_ca as _create_ca
        from app.audit_log import log_event
        data = request.get_json(silent=True) or {}
        conn = get_db()
        result = _create_ca(
            conn,
            name=data.get("name", ""),
            common_name=data.get("common_name", ""),
            key_bits=int(data.get("key_bits", 2048) or 2048),
            lifetime_days=int(data.get("lifetime_days", 3650) or 3650),
            country=data.get("country", ""),
            org=data.get("org", ""),
            ou=data.get("ou", ""),
            state=data.get("state", ""),
            city=data.get("city", ""),
        )
        log_event(category="system", action="cert_ca_create",
                  username=session.get("username"), remote_addr=request.remote_addr,
                  details={"name": data.get("name"), "ok": result["ok"]})
        return jsonify(result)
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@vpn_bp.route("/api/certs/create-server", methods=["POST"])
@api_permission_required("api.vpn.edit")
def create_server_cert():
    """Create a server certificate signed by a CA."""
    try:
        from app.services.cert_manager import create_server_cert as _create_sc
        from app.audit_log import log_event
        data = request.get_json(silent=True) or {}
        conn = get_db()
        result = _create_sc(
            conn,
            ca_id=int(data.get("ca_id", 0) or 0),
            name=data.get("name", ""),
            common_name=data.get("common_name", ""),
            key_bits=int(data.get("key_bits", 2048) or 2048),
            lifetime_days=int(data.get("lifetime_days", 397) or 397),
            san_dns=data.get("san_dns", []),
            san_ip=data.get("san_ip", []),
        )
        log_event(category="system", action="cert_server_create",
                  username=session.get("username"), remote_addr=request.remote_addr,
                  details={"name": data.get("name"), "ok": result["ok"]})
        return jsonify(result)
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@vpn_bp.route("/api/certs/create-client", methods=["POST"])
@api_permission_required("api.vpn.edit")
def create_client_cert():
    """Create a client certificate signed by a CA."""
    try:
        from app.services.cert_manager import create_client_cert as _create_cc
        from app.audit_log import log_event
        data = request.get_json(silent=True) or {}
        conn = get_db()
        result = _create_cc(
            conn,
            ca_id=int(data.get("ca_id", 0) or 0),
            name=data.get("name", ""),
            common_name=data.get("common_name", ""),
            key_bits=int(data.get("key_bits", 2048) or 2048),
            lifetime_days=int(data.get("lifetime_days", 397) or 397),
        )
        log_event(category="system", action="cert_client_create",
                  username=session.get("username"), remote_addr=request.remote_addr,
                  details={"name": data.get("name"), "ok": result["ok"]})
        return jsonify(result)
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@vpn_bp.route("/api/certs/<int:cert_id>/revoke", methods=["POST"])
@api_permission_required("api.vpn.edit")
def revoke_certificate(cert_id):
    """Revoke a certificate."""
    try:
        from app.services.cert_manager import revoke_cert
        from app.audit_log import log_event
        conn   = get_db()
        result = revoke_cert(conn, cert_id)
        log_event(category="system", action="cert_revoke",
                  username=session.get("username"), remote_addr=request.remote_addr,
                  details={"cert_id": cert_id, "ok": result["ok"]})
        return jsonify(result)
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@vpn_bp.route("/api/certs/<int:cert_id>/export-pem", methods=["GET"])
@login_required
def export_cert_pem(cert_id):
    """Download the PEM-encoded certificate (no private key)."""
    try:
        from app.services.cert_manager import get_cert_pem
        from flask import Response
        conn    = get_db()
        pem     = get_cert_pem(conn, cert_id)
        if not pem:
            return jsonify({"ok": False, "error": "Certificate not found"}), 404
        return Response(pem, mimetype="application/x-pem-file",
                        headers={"Content-Disposition": f"attachment; filename=cert-{cert_id}.pem"})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@vpn_bp.route("/api/certs/<int:cert_id>/export-p12", methods=["POST"])
@login_required
def export_cert_p12(cert_id):
    """Download a PKCS#12 bundle (cert + key + CA chain)."""
    try:
        from app.services.cert_manager import export_pkcs12
        from flask import Response
        data     = request.get_json(silent=True) or {}
        password = data.get("password", "")
        conn     = get_db()
        p12_bytes = export_pkcs12(conn, cert_id, password=password)
        return Response(p12_bytes, mimetype="application/x-pkcs12",
                        headers={"Content-Disposition": f"attachment; filename=cert-{cert_id}.p12"})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@vpn_bp.route("/api/openvpn/export-pki/<int:server_id>", methods=["POST"])
@api_permission_required("api.vpn.edit")
def openvpn_export_pki(server_id):
    """
    Write CA, server cert, and server key from the cert_manager DB to disk
    so that apply_openvpn() can reference them from the filesystem.

    Request JSON (all optional — if omitted, the server's own IDs are used):
      { "ca_id": int, "server_cert_id": int }
    """
    try:
        from app.services.openvpn_writer import export_pki_to_disk
        conn = get_db()
        data = request.get_json(silent=True) or {}

        # Resolve defaults from openvpn_servers row
        row = conn.execute(
            "SELECT ca_id, server_cert_id FROM openvpn_servers WHERE id=?", (server_id,)
        ).fetchone()
        if not row:
            return jsonify({"ok": False, "message": f"OpenVPN server {server_id} not found."}), 404

        ca_id          = data.get("ca_id")          or (row["ca_id"]          if row else None)
        server_cert_id = data.get("server_cert_id") or (row["server_cert_id"] if row else None)

        result = export_pki_to_disk(conn, server_id, ca_id, server_cert_id)
        log_event(category="vpn", action="openvpn_export_pki",
                  username=session.get("username"), remote_addr=request.remote_addr,
                  details={"server_id": server_id, "ok": result["ok"]})
        return jsonify(result)
    except Exception as exc:
        return jsonify({"ok": False, "message": str(exc)}), 500


# ── Certificate Revocation List (CRL) ──────────────────────────────────────

@vpn_bp.route("/api/certs/<int:ca_id>/crl", methods=["GET"])
@login_required
def get_crl_json(ca_id):
    """
    Generate (or regenerate) a CRL for the given CA and return it as JSON.

    Response::

        {
          "ok": true,
          "revoked_count": <int>,
          "pem": "<PEM string>"
        }
    """
    try:
        from app.services.cert_manager import generate_crl
        conn   = get_db()
        result = generate_crl(conn, ca_id)
        if not result["ok"]:
            return jsonify(result), 404 if "not found" in result.get("message", "") else 500

        # Count revoked certs in the PEM (each entry starts with BEGIN X509 CRL; count lines)
        revoked_rows = conn.execute(
            "SELECT COUNT(*) FROM certificates WHERE ca_id=? AND revoked=1",
            (ca_id,),
        ).fetchone()
        revoked_count = revoked_rows[0] if revoked_rows else 0

        return jsonify({"ok": True, "revoked_count": revoked_count, "pem": result["pem"]})
    except Exception as exc:
        return jsonify({"ok": False, "message": str(exc)}), 500


@vpn_bp.route("/api/certs/<int:ca_id>/crl.pem", methods=["GET"])
@login_required
def download_crl_pem(ca_id):
    """
    Generate a CRL for the given CA and return it as a PEM file download.
    Content-Type: application/x-pem-file
    """
    try:
        from app.services.cert_manager import generate_crl
        conn   = get_db()
        result = generate_crl(conn, ca_id)
        if not result["ok"]:
            status = 404 if "not found" in result.get("message", "") else 500
            return jsonify(result), status
        return Response(
            result["pem"],
            mimetype="application/x-pem-file",
            headers={"Content-Disposition": f"attachment; filename=ca-{ca_id}.crl.pem"},
        )
    except Exception as exc:
        return jsonify({"ok": False, "message": str(exc)}), 500


# ── OpenVPN client config (.ovpn) export ──────────────────────────────────────

@vpn_bp.route("/api/openvpn/client-export/<int:server_id>/<int:client_cert_id>", methods=["GET"])
@login_required
def openvpn_client_export(server_id, client_cert_id):
    """
    Generate and download a self-contained .ovpn client config file.

    The file embeds inline <ca>, <cert>, and <key> blocks so no separate
    PKI files need to be distributed to the end-user.

    URL: GET /vpn/api/openvpn/client-export/<server_id>/<client_cert_id>
    Response: application/x-openvpn-profile download
    """
    try:
        from app.services.openvpn_writer import generate_client_ovpn
        conn    = get_db()
        ovpn    = generate_client_ovpn(conn, server_id, client_cert_id)
        log_event(
            category="vpn",
            action="openvpn_client_export",
            username=session.get("username"),
            remote_addr=request.remote_addr,
            details={"server_id": server_id, "client_cert_id": client_cert_id},
        )
        return Response(
            ovpn,
            mimetype="application/x-openvpn-profile",
            headers={
                "Content-Disposition": f"attachment; filename=client-{client_cert_id}.ovpn"
            },
        )
    except ValueError as exc:
        return jsonify({"ok": False, "message": str(exc)}), 404
    except Exception as exc:
        return jsonify({"ok": False, "message": str(exc)}), 500
