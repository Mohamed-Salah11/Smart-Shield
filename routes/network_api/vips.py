from routes.network_api import network_api_bp
from routes.network_api._common import *  # noqa: F401,F403
from routes.network_api._common import _network_apply_enabled, _as_bool, _normalize_interface_name, _parse_ipv4_network, _safe_ip_address, _split_selector_values, _source_selector_matches, _load_interface_context, _classify_host_interface, _fetch_active_firewall_rules, _evaluate_host_policy, _merge_host_record, _refresh_tracked_hosts, _list_tracked_hosts, _capture_interfaces, _aggregate_web_activity  # noqa: F401


@network_api_bp.route("/connections", methods=["GET"])
@login_required
def get_connections():
    if not sys.platform.startswith("freebsd"):
        return jsonify(
            {
                "status": "success",
                "data": [],
                "message": "Live connection listing is available only on FreeBSD.",
            }
        )

    try:
        lines = list_live_connections()
        return jsonify({"status": "success", "data": lines})
    except FreeBSDNetworkError as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@network_api_bp.route("/vips/apply", methods=["POST"])
@api_permission_required("api.network.edit")
def apply_vips_endpoint():
    """Apply all virtual IPs (IP aliases) from the DB to the live system."""
    conn = get_db()
    from app.services.network_service import apply_vips
    result = apply_vips(conn)
    log_event(category="network", action="vips_apply", username=session.get("username"),
              remote_addr=request.remote_addr, details={"ok": result["ok"]})
    return jsonify(result)


@network_api_bp.route("/vips", methods=["GET"])
@login_required
def list_vips():
    """List configured virtual IPs from the database."""
    conn = get_db()
    rows = [dict(r) for r in conn.execute(
        "SELECT * FROM virtual_ips_configs ORDER BY interface, address"
    )]
    return jsonify({"ok": True, "vips": rows})
