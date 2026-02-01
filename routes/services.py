import json

from flask import Blueprint, render_template, request, redirect, url_for, session, jsonify

from app.database import get_db

services_bp = Blueprint("services", __name__, url_prefix="/services")

# ----------------------------
# SERVICES MAIN PAGE
# ----------------------------

@services_bp.route("/")
def services_home():
    return render_template("services.html")


# ----------------------------
# AUTO CONFIG BACKUP
# ----------------------------

@services_bp.route("/auto-config-backup")
def auto_config_backup():
    return render_template("auto_config_backup.html")


# ----------------------------
# CAPTIVE PORTAL
# ----------------------------

@services_bp.route("/captive-portal")
def captive_portal():
    return render_template("captive_portal.html")


# ----------------------------
# DHCP RELAY
# ----------------------------

@services_bp.route("/dhcp-relay")
def dhcp_relay():
    return render_template("dhcp_relay.html")


@services_bp.route("/api/dhcp-relay", methods=["GET"])
def get_dhcp_relay_settings():
    """Return DHCP Relay settings + list of upstream servers."""
    try:
        db = get_db()
        cur = db.cursor()

        cur.execute("SELECT enabled, downstream_interfaces, carp_status_vip, append_circuit_id FROM dhcp_relay_settings WHERE id = 1")
        row = cur.fetchone()
        if row is None:
            # default empty settings
            settings = {
                "enabled": False,
                "downstream_interfaces": "",
                "carp_status_vip": "none",
                "append_circuit_id": False,
            }
        else:
            settings = {
                "enabled": bool(row[0]),
                "downstream_interfaces": row[1] or "",
                "carp_status_vip": row[2] or "none",
                "append_circuit_id": bool(row[3]),
            }

        cur.execute("SELECT server_address FROM dhcp_relay_upstream_servers ORDER BY id")
        servers = [r[0] for r in cur.fetchall()]

        return jsonify({"success": True, "settings": settings, "upstream_servers": servers})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@services_bp.route("/api/dhcp-relay", methods=["POST"])
def save_dhcp_relay_settings():
    """Save DHCP Relay settings + upstream servers.

    Expects JSON:
      {
        enabled: bool,
        downstream_interfaces: string,
        carp_status_vip: string,
        append_circuit_id: bool,
        upstream_servers: string[]
      }
    """
    try:
        data = request.get_json() or {}
        enabled = 1 if data.get("enabled") else 0
        downstream_interfaces = (data.get("downstream_interfaces") or "").strip()
        carp_status_vip = (data.get("carp_status_vip") or "none").strip() or "none"
        append_circuit_id = 1 if data.get("append_circuit_id") else 0
        upstream_servers = data.get("upstream_servers") or []
        if not isinstance(upstream_servers, list):
            return jsonify({"success": False, "error": "upstream_servers must be a list"}), 400

        # normalize/unique, keep order
        cleaned = []
        seen = set()
        for s in upstream_servers:
            addr = str(s).strip()
            if not addr:
                continue
            if addr in seen:
                continue
            cleaned.append(addr)
            seen.add(addr)

        db = get_db()
        cur = db.cursor()

        cur.execute(
            """
            INSERT INTO dhcp_relay_settings (id, enabled, downstream_interfaces, carp_status_vip, append_circuit_id, updated_at)
            VALUES (1, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(id) DO UPDATE SET
              enabled=excluded.enabled,
              downstream_interfaces=excluded.downstream_interfaces,
              carp_status_vip=excluded.carp_status_vip,
              append_circuit_id=excluded.append_circuit_id,
              updated_at=CURRENT_TIMESTAMP
            """,
            (enabled, downstream_interfaces, carp_status_vip, append_circuit_id),
        )

        # replace servers list
        cur.execute("DELETE FROM dhcp_relay_upstream_servers")
        for addr in cleaned:
            cur.execute("INSERT OR IGNORE INTO dhcp_relay_upstream_servers (server_address) VALUES (?)", (addr,))

        db.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ----------------------------
# DHCP SERVER (General)
# ----------------------------

@services_bp.route("/dhcp-server")
def dhcp_server():
    return render_template("dhcp_server.html")


# LAN DHCP SERVER
@services_bp.route("/dhcp-server-lan")
def dhcp_server_lan():
    return render_template("dhcp_server_lan.html")


@services_bp.route("/api/dhcp-server/<string:iface>", methods=["GET"])
def api_get_dhcp_server_settings(iface):
    """Load DHCP server settings for an interface (wan/lan)."""
    try:
        iface = (iface or '').lower()
        if iface not in ('wan', 'lan'):
            return jsonify({"success": False, "error": "Invalid interface"}), 400

        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT settings_json FROM dhcp_server_settings WHERE interface=?", (iface,))
        row = cur.fetchone()
        settings = {}
        if row and row[0]:
            try:
                settings = json.loads(row[0])
            except Exception:
                settings = {}
        return jsonify({"success": True, "interface": iface, "settings": settings})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@services_bp.route("/api/dhcp-server/<string:iface>", methods=["POST"])
def api_save_dhcp_server_settings(iface):
    """Save DHCP server settings for an interface (wan/lan). Expects JSON: { settings: {...} }"""
    try:
        iface = (iface or '').lower()
        if iface not in ('wan', 'lan'):
            return jsonify({"success": False, "error": "Invalid interface"}), 400

        data = request.get_json() or {}
        settings = data.get('settings') or {}
        if not isinstance(settings, dict):
            return jsonify({"success": False, "error": "settings must be an object"}), 400

        db = get_db()
        cur = db.cursor()
        cur.execute(
            """
            INSERT INTO dhcp_server_settings (interface, settings_json, updated_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(interface) DO UPDATE SET
              settings_json=excluded.settings_json,
              updated_at=CURRENT_TIMESTAMP
            """,
            (iface, json.dumps(settings)),
        )
        db.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# DHCP Static Mapping (global)
@services_bp.route("/dhcp-server/static-mapping")
def dhcp_static_mapping():
    return render_template("dhcp_static_mapping.html")


# DHCP Static Mapping (LAN)
@services_bp.route("/dhcp-server-lan/static-mapping")
def dhcp_static_mapping_lan():
    return render_template("dhcp_static_mapping_lan.html")


# ----------------------------
# DHCPv6 SERVICES
# ----------------------------

@services_bp.route("/dhcpv6-relay")
def dhcpv6_relay():
    return render_template("dhcpv6_relay.html")


@services_bp.route("/dhcpv6-server")
def dhcpv6_server():
    return render_template("dhcpv6_server.html")


# ----------------------------
# DNS FORWARDER
# ----------------------------

@services_bp.route("/dns-forwarder")
def dns_forwarder():
    return render_template("dns_forwarder.html")


@services_bp.route("/dns-forwarder/edit-host-override", methods=["GET", "POST"])
def dns_forwarder_edit_host():
    if request.method == "POST":
        return redirect(url_for("services.dns_forwarder"))
    return render_template("dns_forwarder_edit_host.html")


@services_bp.route("/dns-forwarder/edit-domain-override", methods=["GET", "POST"])
def dns_forwarder_edit_domain():
    if request.method == "POST":
        return redirect(url_for("services.dns_forwarder"))
    return render_template("dns_forwarder_edit_domain.html")


# ----------------------------
# DNS RESOLVER
# ----------------------------

@services_bp.route("/dns-resolver")
def dns_resolver():
    hosts = session.get("resolver_host_overrides", [])
    domains = session.get("resolver_domain_overrides", [])
    lists = session.get("resolver_access_lists", [])
    return render_template("dns_resolver.html", hosts=hosts, domains=domains, lists=lists)


@services_bp.route("/dns-resolver/edit-host", methods=["GET", "POST"])
def dns_resolver_edit_host():
    if request.method == "POST":
        hosts = session.get("resolver_host_overrides", [])
        host = request.form.get("host")
        domain = request.form.get("domain")
        ip = request.form.get("ip")
        description = request.form.get("description", "")
        if host or domain:
            hosts.append({"host": host, "domain": domain, "ip": ip, "description": description})
            session["resolver_host_overrides"] = hosts
        return redirect(url_for("services.dns_resolver"))
    return render_template("dns_resolver_edit_host.html")


@services_bp.route("/dns-resolver/edit-domain", methods=["GET", "POST"])
def dns_resolver_edit_domain():
    if request.method == "POST":
        domains = session.get("resolver_domain_overrides", [])
        domain = request.form.get("domain")
        server = request.form.get("server")
        tls_queries = bool(request.form.get("tls_queries"))
        tls_hostname = request.form.get("tls_hostname")
        description = request.form.get("description", "")
        if domain:
            domains.append({"domain": domain, "server": server, "tls_queries": tls_queries,
                            "tls_hostname": tls_hostname, "description": description})
            session["resolver_domain_overrides"] = domains
        return redirect(url_for("services.dns_resolver"))
    return render_template("dns_resolver_edit_domain.html")


@services_bp.route("/dns-resolver/advanced", methods=["GET", "POST"])
def dns_resolver_advanced():
    if request.method == "POST":
        return redirect(url_for("services.dns_resolver_advanced"))
    return render_template("dns_resolver_advanced.html")


@services_bp.route("/dns-resolver/access-lists")
def dns_resolver_access_lists():
    lists = session.get("resolver_access_lists", [])
    return render_template("dns_resolver_access_lists.html", lists=lists)


@services_bp.route("/dns-resolver/access-lists/edit", methods=["GET", "POST"])
def dns_resolver_access_lists_edit():
    if request.method == "POST":
        lists = session.get("resolver_access_lists", [])
        name = request.form.get("name")
        action = request.form.get("action")
        description = request.form.get("description")
        if name:
            lists.append({"name": name, "action": action, "description": description})
            session["resolver_access_lists"] = lists
        return redirect(url_for("services.dns_resolver_access_lists"))
    return render_template("dns_resolver_access_lists_edit.html")


# ----------------------------
# DYNAMIC DNS
# ----------------------------

@services_bp.route("/dynamic-dns", methods=["GET", "POST"])
def dynamic_dns():
    if request.method == "POST":
        clients = session.get("dynamic_dns_clients", [])
        client = {
            "disabled": bool(request.form.get("disabled")),
            "service_type": request.form.get("service_type"),
            "interface": request.form.get("interface"),
            "check_ip_mode": request.form.get("check_ip_mode"),
            "hostname": request.form.get("hostname"),
            "mx": request.form.get("mx"),
            "wildcards": bool(request.form.get("wildcards")),
            "verbose": bool(request.form.get("verbose")),
            "username": request.form.get("username"),
            "description": request.form.get("description", "")
        }
        clients.append(client)
        session["dynamic_dns_clients"] = clients
        return redirect(url_for("services.dynamic_dns"))
    return render_template("dynamic_dns.html")


@services_bp.route("/dynamic-dns/rfc2136", methods=["GET", "POST"])
def dynamic_dns_rfc2136():
    if request.method == "POST":
        clients = session.get("rfc2136_clients", [])
        client = {
            "enabled": bool(request.form.get("enable")),
            "interface": request.form.get("interface"),
            "hostname": request.form.get("hostname"),
            "zone": request.form.get("zone"),
            "ttl": request.form.get("ttl"),
            "key_name": request.form.get("key_name"),
            "key_algorithm": request.form.get("key_algorithm"),
            "key": request.form.get("key"),
            "server": request.form.get("server"),
            "protocol_tcp": bool(request.form.get("protocol_tcp")),
            "use_public_ip": bool(request.form.get("use_public_ip")),
            "update_source": request.form.get("update_source"),
            "update_source_family": request.form.get("update_source_family"),
            "record_type": request.form.get("record_type"),
            "description": request.form.get("description", "")
        }
        clients.append(client)
        session["rfc2136_clients"] = clients
        return redirect(url_for("services.dynamic_dns_rfc2136"))
    return render_template("dynamic_dns_rfc2136.html")


@services_bp.route("/dynamic-dns/checkip", methods=["GET", "POST"])
def dynamic_dns_checkip():
    if "checkip_services" not in session:
        session["checkip_services"] = [
            {"name": "Default", "url": "http://checkip.dyndns.org", "verify_ssl": False,
             "description": "Default Check IP Service"}
        ]
    if request.method == "POST":
        services = session.get("checkip_services", [])
        svc = {
            "enabled": bool(request.form.get("enable")),
            "name": request.form.get("name"),
            "url": request.form.get("url"),
            "username": request.form.get("username"),
            "password": request.form.get("password"),
            "verify_ssl": bool(request.form.get("verify_ssl")),
            "description": request.form.get("description", "")
        }
        services.append(svc)
        session["checkip_services"] = services
        return redirect(url_for("services.dynamic_dns_checkip"))
    return render_template("dynamic_dns_checkip.html")


# ----------------------------
# IGMP PROXY
# ----------------------------

@services_bp.route("/igmp-proxy")
def igmp_proxy():
    return render_template("igmp_proxy.html")


# ----------------------------
# NTP SERVICE
# ----------------------------

@services_bp.route("/ntp")
def ntp():
    return render_template("ntp.html")


# ----------------------------
# OPENVPN SERVER
# ----------------------------

@services_bp.route("/openvpn-server")
def openvpn_server():
    return render_template("openvpn_server.html")


# ----------------------------
# ROUTER ADVERTISEMENT
# ----------------------------

@services_bp.route("/router-advertisement")
def router_advertisement():
    return render_template("router_advertisement.html")


# ----------------------------
# SNMP SERVICE
# ----------------------------

@services_bp.route("/snmp")
def snmp():
    return render_template("snmp.html")


# ----------------------------
# UPnP / IGD / PCP
# ----------------------------

@services_bp.route("/upnp-igd-pcp")
def upnp_igd_pcp():
    return render_template("upnp_igd_pcp.html")


# ----------------------------
# WAKE ON LAN
# ----------------------------

@services_bp.route("/wake-on-lan")
def wake_on_lan():
    interfaces = ["WAN", "LAN"]
    devices = []
    return render_template("wake_on_lan.html", interfaces=interfaces, devices=devices)


# ----------------------------
# ADDITIONAL HELPER ROUTES
# ----------------------------

@services_bp.route("/services")
def services():
    return redirect(url_for("services.services_home"))

@services_bp.route("/dns-host-edit", methods=["GET", "POST"])
def dns_host_edit():
    return redirect(url_for("services.dns_forwarder_edit_host"))

@services_bp.route("/dns-domain-edit", methods=["GET", "POST"])
def dns_domain_edit():
    return redirect(url_for("services.dns_forwarder_edit_domain"))
