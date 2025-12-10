from flask import Blueprint, render_template, request, redirect, url_for, session

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

@services_bp.route("/dynamic-dns")
def dynamic_dns():
    return render_template("dynamic_dns.html")


@services_bp.route("/dynamic-dns/rfc2136")
def dynamic_dns_rfc2136():
    return render_template("dynamic_dns_rfc2136.html")


@services_bp.route("/dynamic-dns/rfc2136/edit", methods=["GET", "POST"])
def dynamic_dns_rfc2136_edit():
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
    return render_template("dynamic_dns_rfc2136_edit.html")


@services_bp.route("/dynamic-dns/checkip")
def dynamic_dns_checkip():
    if "checkip_services" not in session:
        session["checkip_services"] = [
            {"name": "Default", "url": "http://checkip.dyndns.org", "verify_ssl": False,
             "description": "Default Check IP Service"}
        ]
    return render_template("dynamic_dns_checkip.html")


@services_bp.route("/dynamic-dns/checkip/edit", methods=["GET", "POST"])
def dynamic_dns_checkip_edit():
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
    return render_template("dynamic_dns_checkip_edit.html")


@services_bp.route("/dynamic-dns/edit", methods=["GET", "POST"])
def dynamic_dns_edit():
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
    return render_template("dynamic_dns_edit.html")


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
