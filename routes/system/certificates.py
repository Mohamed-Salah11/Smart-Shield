from routes.system import system_bp
from routes.system._common import *  # noqa: F401,F403
from routes.system._common import _general_config_path, _config_bool, _load_general_config, _safe_count, _build_dashboard_payload  # noqa: F401


@system_bp.route("/certificates")
@login_required
def certificates():
    from app.services.cert_manager import list_certs, mask_cert_fields
    active_section = request.args.get("section", "certificates")
    if active_section not in ("authorities", "certificates", "revocation"):
        active_section = "certificates"
    conn = get_db()
    cur  = conn.cursor()

    # CAs from the new certificates table
    try:
        cas_raw = list_certs(conn, cert_type="ca")
        cas = [mask_cert_fields(r) for r in cas_raw]
    except Exception:
        cas = []

    # Server + client certs
    try:
        certs_raw = list_certs(conn)
        certs = [mask_cert_fields(r) for r in certs_raw if r.get("cert_type") != "ca"]
    except Exception:
        certs = []

    # Revoked certs (CRL entries)
    try:
        revoked_rows = [dict(r) for r in cur.execute(
            "SELECT id, name, common_name, revoked_at, ca_id "
            "FROM certificates WHERE revoked=1 ORDER BY revoked_at DESC"
        )]
        crls = revoked_rows
    except Exception:
        crls = []

    return render_template(
        "certificates.html",
        active_section=active_section,
        cas=cas,
        certs=certs,
        crls=crls,
    )

@system_bp.route("/add_ca", methods=["GET", "POST"])
@login_required
def add_ca():
    from app.services.cert_manager import create_ca
    if request.method == "POST":
        conn   = get_db()
        result = create_ca(
            conn,
            name=request.form.get("name", "").strip(),
            common_name=request.form.get("common_name", "").strip(),
            key_bits=int(request.form.get("key_bits", 2048) or 2048),
            lifetime_days=int(request.form.get("lifetime_days", 3650) or 3650),
            country=request.form.get("country", "").strip(),
            org=request.form.get("org", "").strip(),
            ou=request.form.get("ou", "").strip(),
            state=request.form.get("state", "").strip(),
            city=request.form.get("city", "").strip(),
        )
        if result["ok"]:
            log_event(category="system", action="ca_created",
                      username=session.get("username"), remote_addr=request.remote_addr,
                      details={"ca_id": result["id"]})
            return redirect(url_for("system.certificates", section="authorities"))
        return render_template("add_ca.html", error=result["message"])
    return render_template("add_ca.html")


@system_bp.route("/add_certificate", methods=["GET", "POST"])
@login_required
def add_certificate():
    from app.services.cert_manager import create_server_cert, create_client_cert, list_certs
    conn = get_db()
    if request.method == "POST":
        cert_type = request.form.get("cert_type", "server").strip().lower()
        ca_id     = request.form.get("ca_id", "")
        try:
            ca_id = int(ca_id)
        except (TypeError, ValueError):
            return render_template("add_certificate.html",
                                   cas=list_certs(conn, cert_type="ca"),
                                   error="A CA must be selected.")
        kwargs = dict(
            conn=conn,
            ca_id=ca_id,
            name=request.form.get("name", "").strip(),
            common_name=request.form.get("common_name", "").strip(),
            key_bits=int(request.form.get("key_bits", 2048) or 2048),
            lifetime_days=int(request.form.get("lifetime_days", 397) or 397),
            country=request.form.get("country", "").strip(),
            org=request.form.get("org", "").strip(),
            ou=request.form.get("ou", "").strip(),
        )
        if cert_type == "client":
            result = create_client_cert(**kwargs)
        else:
            san_raw = request.form.get("san_dns", "")
            san_dns = [s.strip() for s in san_raw.split(",") if s.strip()]
            san_raw_ip = request.form.get("san_ip", "")
            san_ip  = [s.strip() for s in san_raw_ip.split(",") if s.strip()]
            result  = create_server_cert(**kwargs, san_dns=san_dns, san_ip=san_ip)
        if result["ok"]:
            log_event(category="system", action="cert_created",
                      username=session.get("username"), remote_addr=request.remote_addr,
                      details={"cert_id": result["id"], "cert_type": cert_type})
            return redirect(url_for("system.certificates"))
        return render_template("add_certificate.html",
                               cas=list_certs(conn, cert_type="ca"),
                               error=result["message"])
    return render_template("add_certificate.html", cas=list_certs(conn, cert_type="ca"))


@system_bp.route("/api/certificates/<int:cert_id>/revoke", methods=["POST"])
@login_required
@superuser_required
@reauth_required(reason="revoke certificate")
def api_revoke_cert(cert_id):
    from app.services.cert_manager import revoke_cert
    conn   = get_db()
    result = revoke_cert(conn, cert_id)
    log_event(category="system", action="cert_revoked",
              username=session.get("username"), remote_addr=request.remote_addr,
              details={"cert_id": cert_id, "ok": result["ok"]})
    return jsonify(result)


@system_bp.route("/api/certificates/ca/<int:ca_id>/crl", methods=["POST"])
@login_required
@superuser_required
def api_generate_crl(ca_id):
    from app.services.cert_manager import generate_crl
    conn   = get_db()
    result = generate_crl(conn, ca_id)
    if result["ok"]:
        from flask import Response
        return Response(result["pem"], mimetype="application/x-pem-file",
                        headers={"Content-Disposition": f"attachment; filename=ca{ca_id}.crl.pem"})
    return jsonify({"ok": False, "message": result["message"]}), 500


@system_bp.route("/api/certificates/<int:cert_id>/ocsp", methods=["GET"])
@login_required
def api_fetch_ocsp(cert_id):
    from app.services.cert_manager import get_cert_pem, fetch_ocsp_response, _rows as _cm_rows
    conn     = get_db()
    cert_pem = get_cert_pem(conn, cert_id)
    if not cert_pem:
        return jsonify({"ok": False, "message": "Certificate not found."}), 404
    # Load issuer cert
    rows     = _cm_rows(conn, "SELECT ca_id FROM certificates WHERE id=?", (cert_id,))
    ca_id    = rows[0]["ca_id"] if rows else None
    issuer_pem = get_cert_pem(conn, ca_id) if ca_id else ""
    if not issuer_pem:
        return jsonify({"ok": False, "message": "CA certificate not found."}), 404
    result = fetch_ocsp_response(cert_pem, issuer_pem)
    if result["ok"]:
        import base64
        return jsonify({"ok": True, "der_b64": base64.b64encode(result["der"]).decode()})
    return jsonify({"ok": False, "message": result["message"]}), 500


@system_bp.route("/api/certificates/acme/request", methods=["POST"])
@login_required
@superuser_required
def api_acme_request():
    from app.services.cert_manager import request_acme_cert
    data   = request.get_json(force=True) or {}
    conn   = get_db()
    result = request_acme_cert(
        conn,
        domain=data.get("domain", ""),
        email=data.get("email", ""),
        staging=bool(data.get("staging", False)),
    )
    log_event(category="system", action="acme_cert_request",
              username=session.get("username"), remote_addr=request.remote_addr,
              details={"domain": data.get("domain"), "ok": result.get("ok")})
    return jsonify(result)


@system_bp.route("/api/certificates/<int:cert_id>", methods=["GET"])
@login_required
def api_get_cert(cert_id):
    from app.services.cert_manager import get_cert_pem, list_certs
    conn = get_db()
    rows = list_certs(conn)
    row  = next((r for r in rows if r.get("id") == cert_id), None)
    if not row:
        return jsonify({"ok": False, "message": "Not found"}), 404
    pem = get_cert_pem(conn, cert_id)
    return jsonify({"ok": True, "cert": {**row, "pem": pem}})


@system_bp.route("/api/certificates/<int:cert_id>", methods=["DELETE"])
@login_required
@superuser_required
def api_delete_cert(cert_id):
    from app.services.cert_manager import delete_cert
    conn   = get_db()
    result = delete_cert(conn, cert_id)
    log_event(category="system", action="cert_deleted",
              username=session.get("username"), remote_addr=request.remote_addr,
              details={"cert_id": cert_id, "ok": result["ok"]})
    return jsonify(result)


@system_bp.route("/api/certificates/ca/<int:ca_id>", methods=["DELETE"])
@login_required
@superuser_required
def api_delete_ca(ca_id):
    from app.services.cert_manager import delete_ca
    conn   = get_db()
    result = delete_ca(conn, ca_id)
    log_event(category="system", action="ca_deleted",
              username=session.get("username"), remote_addr=request.remote_addr,
              details={"ca_id": ca_id, "ok": result["ok"]})
    return jsonify(result)


# ----------------------------
# HIGH AVAILABILITY
# ----------------------------
