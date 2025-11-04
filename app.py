from flask import Flask, render_template, request, redirect, url_for, session
import json, os

CONFIG_FILE = "config.json"

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    return {
        "hostname": "pfSense",
        "domain": "home.arpa",
        "dns_servers": [],
        "dns_override": True,
        "dns_behavior": "Use local DNS (127.0.0.1), fall back to remote DNS Servers (Default)",
        "timezone": "Etc/UTC",
        "timeservers": "2.pfsense.pool.ntp.org",
        "language": "English",
        "theme": "pfSense",
        "login_color": "Dark Blue",
        "show_hostname": True,
        "login_message": ""
    }

def save_config(data):
    with open(CONFIG_FILE, "w") as f:
        json.dump(data, f, indent=4)


app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Required for session

# login credentials
USER = {"username": "admin", "password": "1234"}

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == USER['username'] and password == USER['password']:
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid username or password'
    return render_template('login.html', error=error)

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/system')
def system():
    return render_template('system.html')

# System submenu pages
@app.route('/system/advanced')
def advanced():
    return redirect(url_for('admin_access'))

@app.route('/system/advanced/admin-access')
def admin_access():
    return render_template('admin_access.html')

@app.route('/system/advanced/firewall-nat')
def advanced_firewall_nat():
    return render_template('advanced_firewall_nat.html')

@app.route('/system/advanced/network')
def advanced_network():
    return render_template('advanced_network.html')

@app.route('/system/advanced/miscellaneous')
def advanced_miscellaneous():
    return render_template('advanced_miscellaneous.html')

@app.route('/system/advanced/system-tunables')
def advanced_system_tunables():
    tunables = session.get('tunables', [
        {'name': 'net.inet.ip.portrange.first', 'value': '1024', 'description': ''}
    ])
    return render_template('advanced_system_tunables.html', tunables=tunables)

@app.route('/system/advanced/system-tunables/edit', methods=['GET', 'POST'])
@app.route('/system/advanced/system-tunables/edit/<int:index>', methods=['GET', 'POST'])
def advanced_system_tunables_edit(index=None):
    tunables = session.get('tunables', [
        {'name': 'net.inet.ip.portrange.first', 'value': '1024', 'description': ''}
    ])
    
    tunable = tunables[index] if index is not None and index < len(tunables) else None
    return render_template('advanced_system_tunables_edit.html', tunable=tunable, index=index)

@app.route('/system/advanced/system-tunables/save', methods=['POST'])
def advanced_system_tunables_save():
    tunables = session.get('tunables', [
        {'name': 'net.inet.ip.portrange.first', 'value': '1024', 'description': ''}
    ])
    
    tunable_name = request.form.get('tunable_name')
    tunable_value = request.form.get('tunable_value')
    tunable_description = request.form.get('tunable_description', '')
    index = request.form.get('index')
    
    new_tunable = {
        'name': tunable_name,
        'value': tunable_value,
        'description': tunable_description
    }
    
    if index is not None and index.isdigit():
        tunables[int(index)] = new_tunable
    else:
        tunables.append(new_tunable)
    
    session['tunables'] = tunables
    return redirect(url_for('advanced_system_tunables'))

@app.route('/system/advanced/system-tunables/delete/<int:index>', methods=['POST'])
def advanced_system_tunables_delete(index):
    tunables = session.get('tunables', [
        {'name': 'net.inet.ip.portrange.first', 'value': '1024', 'description': ''}
    ])
    
    if index < len(tunables):
        tunables.pop(index)
        session['tunables'] = tunables
    
    return redirect(url_for('advanced_system_tunables'))

@app.route('/system/advanced/notifications')
def notifications():
    return render_template('notifications.html')

@app.route('/system/certificates')
def certificates():
    return render_template('certificates.html')

@app.route('/system/general-setup', methods=['GET', 'POST'])
def general_setup():
    config = load_config()

    if request.method == "POST":
        config["hostname"] = request.form.get("hostname")
        config["domain"] = request.form.get("domain")
        config["dns_servers"] = request.form.getlist("dns_server")
        config["dns_override"] = bool(request.form.get("dns_override"))
        config["dns_behavior"] = request.form.get("dns_behavior")
        config["timezone"] = request.form.get("timezone")
        config["timeservers"] = request.form.get("timeservers")
        config["language"] = request.form.get("language")
        config["theme"] = request.form.get("theme")
        config["login_color"] = request.form.get("login_color")
        config["show_hostname"] = bool(request.form.get("show_hostname"))
        config["login_message"] = request.form.get("login_message")
        save_config(config)
        return redirect(url_for("general_setup"))

    return render_template("general_setup.html", config=config)

    
    return render_template('general_setup.html')

@app.route('/system/high-availability')
def high_availability():
    
    return render_template('high_availability.html')

@app.route('/system/logout')
def logout():
    return redirect(url_for('login'))

@app.route('/system/package-manager')
def package_manager():
    
    return render_template('package_manager.html')

@app.route('/system/setup-wizard')
def setup_wizard():
    return render_template('setup_wizard.html')


@app.route('/system/setup-wizard/step/<int:step>')
def setup_wizard_step(step):
    # Simple step router: render the template for the requested step if it exists.
    # For now we only implement step 2 as the next page shown in the attachment.
    if step == 2:
        return render_template('setup_wizard_step2.html')
    if step == 3:
        return render_template('setup_wizard_step3.html')
    if step == 4:
        return render_template('setup_wizard_step4.html')
    if step == 5:
        return render_template('setup_wizard_step5.html')
    if step == 6:
        return render_template('setup_wizard_step6.html')
    if step == 7:
        return render_template('setup_wizard_step7.html')
    if step == 8:
        return render_template('setup_wizard_step8.html')
    if step == 9:
        return render_template('setup_wizard_step9.html')
    if step == 10:
        return render_template('setup_wizard_step10.html')
    

@app.route('/system/copyright', methods=['GET', 'POST'])
def copyright_page():
    # Simple accept flow: on POST (Accept) redirect to dashboard
    if request.method == 'POST':
        return redirect(url_for('dashboard'))
    return render_template('copyright.html')



@app.route('/system/update', methods=['GET', 'POST'])
def update_page():
    if request.method == 'POST':
        if 'check_updates' in request.form:
            return render_template('update.html', message="Checking for updates...", active_tab="system")
        elif 'update_system' in request.form:
            return render_template('update.html', message="System update initiated...", active_tab="system")
        elif 'save_settings' in request.form:
            return render_template('update.html', message="Settings saved successfully", active_tab="settings")
    
    return render_template('update.html', active_tab="system")

@app.route('/system/user-manager', methods=['GET', 'POST'])
def user_manager():
    if request.method == 'POST':
        if 'add_user' in request.form:
            return render_template('user_manager.html', message="User added successfully")
        elif 'delete_user' in request.form:
            return render_template('user_manager.html', message="User deleted successfully")
        elif 'change_password' in request.form:
            return render_template('user_manager.html', message="Password changed successfully")
    
    users = [
        {
            'username': 'admin',
            'full_name': 'System Administrator',
            'status': 'active',
            'groups': 'admins'
        }
    ]
    
    return render_template('user_manager.html', users=users)

@app.route('/system/user-password-manager')
def user_password_manager():
    return render_template('user_password_manager.html')

@app.route('/system/register')
def register():
    return render_template('register.html')

@app.route('/system/routing')
def routing():
    # Provide gateways and current default selections to the template
    gateways = session.get('gateways', [
        {'name': 'WAN_DHCP', 'interface': 'WAN', 'gateway': '8.8.8.8', 'monitor': '8.8.8.8', 'description': 'Interface WAN_DHCP Gateway', 'disabled': False, 'address_family': 'IPv4'},
        {'name': 'WAN_DHCP6', 'interface': 'WAN', 'gateway': 'dynamic', 'monitor': 'dynamic', 'description': 'Interface WAN_DHCP6 Gateway', 'disabled': False, 'address_family': 'IPv6'},
        {'name': 'WANGW', 'interface': 'WAN', 'gateway': '8.8.8.8', 'monitor': '8.8.8.8', 'description': 'Interface wan Gateway', 'disabled': False, 'address_family': 'IPv4'},
    ])
    # Default selection fallbacks: prefer WANGW for IPv4 (matches UI image),
    # and Automatic (empty string) for IPv6.
    default_ipv4 = session.get('default_gateway_ipv4', 'WANGW')
    default_ipv6 = session.get('default_gateway_ipv6', '')
    return render_template('routing.html', gateways=gateways, default_ipv4=default_ipv4, default_ipv6=default_ipv6)


@app.route('/system/routing/gateway/edit', methods=['GET', 'POST'])
@app.route('/system/routing/gateway/edit/<int:index>', methods=['GET', 'POST'])
def routing_edit_gateway(index=None):
    # Load gateways from session or use sample data
    gateways = session.get('gateways', [
        {'name': 'WAN_DHCP', 'interface': 'WAN', 'gateway': '8.8.8.8', 'monitor': '8.8.8.8', 'description': 'Interface WAN_DHCP Gateway', 'disabled': False, 'address_family': 'IPv4'},
        {'name': 'WAN_DHCP6', 'interface': 'WAN', 'gateway': 'dynamic', 'monitor': 'dynamic', 'description': 'Interface WAN_DHCP6 Gateway', 'disabled': False, 'address_family': 'IPv4'},
        {'name': 'WANGW', 'interface': 'WAN', 'gateway': '8.8.8.8', 'monitor': '8.8.8.8', 'description': 'Interface wan Gateway', 'disabled': False, 'address_family': 'IPv4'},
    ])

    gateway = gateways[index] if index is not None and 0 <= index < len(gateways) else None

    if request.method == 'POST':
        # collect form values
        disabled = bool(request.form.get('disabled'))
        interface = request.form.get('interface')
        address_family = request.form.get('address_family')
        name = request.form.get('name')
        gw = request.form.get('gateway')
        monitor = request.form.get('monitor')
        description = request.form.get('description')
        # additional fields: force state and state killing behavior
        force_state = bool(request.form.get('force_state'))
        state_killing = request.form.get('state_killing')
        disable_monitoring = bool(request.form.get('disable_monitoring'))
        disable_monitoring_action = bool(request.form.get('disable_monitoring_action'))

        new_gateway = {
            'disabled': disabled,
            'interface': interface,
            'address_family': address_family,
            'name': name,
            'gateway': gw,
            'monitor': monitor,
            'description': description,
            'force_state': force_state,
            'state_killing': state_killing,
            'disable_monitoring': disable_monitoring,
            'disable_monitoring_action': disable_monitoring_action,
        }

        if index is not None and 0 <= index < len(gateways):
            gateways[index] = new_gateway
        else:
            gateways.append(new_gateway)

        session['gateways'] = gateways
        return redirect(url_for('routing'))

    return render_template('routing_edit_gateway.html', gateway=gateway, index=index)


@app.route('/system/routing/static')
def routing_static():
    # Render the static routes page (empty list for now)
    static_routes = session.get('static_routes', [])
    return render_template('static_routes.html', static_routes=static_routes)


@app.route('/system/routing/static/edit', methods=['GET', 'POST'])
@app.route('/system/routing/static/edit/<int:index>', methods=['GET', 'POST'])
def routing_static_edit(index=None):
    # Load static routes and available gateways
    static_routes = session.get('static_routes', [])
    gateways = session.get('gateways', [
        {'name': 'WAN_DHCP', 'interface': 'WAN', 'gateway': '8.8.8.8', 'monitor': '8.8.8.8', 'description': 'Interface WAN_DHCP Gateway', 'disabled': False, 'address_family': 'IPv4'},
        {'name': 'WAN_DHCP6', 'interface': 'WAN', 'gateway': 'dynamic', 'monitor': 'dynamic', 'description': 'Interface WAN_DHCP6 Gateway', 'disabled': False, 'address_family': 'IPv6'},
        {'name': 'WANGW', 'interface': 'WAN', 'gateway': '8.8.8.8', 'monitor': '8.8.8.8', 'description': 'Interface wan Gateway', 'disabled': False, 'address_family': 'IPv4'},
    ])

    route = static_routes[index] if index is not None and 0 <= index < len(static_routes) else None

    if request.method == 'POST':
        network = request.form.get('network')
        prefix = request.form.get('prefix')
        gateway = request.form.get('gateway')
        disabled = bool(request.form.get('disabled'))
        description = request.form.get('description', '')

        new_route = {
            'network': network,
            'prefix': prefix,
            'gateway': gateway,
            'disabled': disabled,
            'description': description,
        }

        if index is not None and 0 <= index < len(static_routes):
            static_routes[index] = new_route
        else:
            static_routes.append(new_route)

        session['static_routes'] = static_routes
        return redirect(url_for('routing_static'))

    return render_template('static_route_edit.html', route=route, index=index, gateways=gateways)


@app.route('/system/routing/static/delete/<int:index>', methods=['POST'])
def routing_static_delete(index):
    static_routes = session.get('static_routes', [])
    if 0 <= index < len(static_routes):
        static_routes.pop(index)
        session['static_routes'] = static_routes
    return redirect(url_for('routing_static'))


@app.route('/system/routing/groups')
def routing_groups():
    # Render the gateway groups page
    gateway_groups = session.get('gateway_groups', [])
    return render_template('gateway_groups.html', gateway_groups=gateway_groups)


@app.route('/system/routing/groups/edit', methods=['GET', 'POST'])
@app.route('/system/routing/groups/edit/<int:index>', methods=['GET', 'POST'])
def routing_groups_edit(index=None):
    # Load existing groups and gateways
    gateway_groups = session.get('gateway_groups', [])
    gateways = session.get('gateways', [
        {'name': 'WAN_DHCP', 'interface': 'WAN', 'gateway': '8.8.8.8', 'monitor': '8.8.8.8', 'description': 'Interface WAN_DHCP Gateway', 'disabled': False, 'address_family': 'IPv4'},
        {'name': 'WAN_DHCP6', 'interface': 'WAN', 'gateway': 'dynamic', 'monitor': 'dynamic', 'description': 'Interface WAN_DHCP6 Gateway', 'disabled': False, 'address_family': 'IPv6'},
        {'name': 'WANGW', 'interface': 'WAN', 'gateway': '8.8.8.8', 'monitor': '8.8.8.8', 'description': 'Interface wan Gateway', 'disabled': False, 'address_family': 'IPv4'},
    ])

    group = gateway_groups[index] if index is not None and 0 <= index < len(gateway_groups) else None

    if request.method == 'POST':
        name = request.form.get('group_name')
        description = request.form.get('description', '')
        keep_failover = request.form.get('keep_failover', '')
        trigger_level = request.form.get('trigger_level', '')

        # collect per-gateway settings from form; expect fields like tier_<name>, vip_<name>, desc_<name>
        members = []
        for g in gateways:
            key = g.get('name')
            tier = request.form.get(f'tier_{key}', 'Never')
            vip = request.form.get(f'vip_{key}', '')
            member_desc = request.form.get(f'desc_{key}', '')
            members.append({'gateway': key, 'tier': tier, 'vip': vip, 'description': member_desc})

        new_group = {
            'name': name,
            'members': members,
            'keep_failover': keep_failover,
            'trigger_level': trigger_level,
            'description': description,
        }

        if index is not None and 0 <= index < len(gateway_groups):
            gateway_groups[index] = new_group
        else:
            gateway_groups.append(new_group)

        session['gateway_groups'] = gateway_groups
        return redirect(url_for('routing_groups'))

    return render_template('gateway_group_edit.html', group=group, index=index, gateways=gateways)


@app.route('/system/routing/groups/delete/<int:index>', methods=['POST'])
def routing_groups_delete(index):
    gateway_groups = session.get('gateway_groups', [])
    if 0 <= index < len(gateway_groups):
        gateway_groups.pop(index)
        session['gateway_groups'] = gateway_groups
    return redirect(url_for('routing_groups'))


@app.route('/system/routing/save', methods=['POST'])
def routing_save():
    # expects form fields: gateways (json), default_ipv4, default_ipv6
    import json
    gateways_json = request.form.get('gateways')
    default_ipv4 = request.form.get('default_ipv4')
    default_ipv6 = request.form.get('default_ipv6')
    try:
        gateways = json.loads(gateways_json) if gateways_json else []
    except Exception:
        gateways = session.get('gateways', [])

    session['gateways'] = gateways
    session['default_gateway_ipv4'] = default_ipv4
    session['default_gateway_ipv6'] = default_ipv6
    return redirect(url_for('routing'))

@app.route('/interfaces')
def interfaces():
    return render_template('interfaces.html')

@app.route('/interfaces/assignments')
def interfaces_assignments():
    return render_template('interfaces_assignments.html')

@app.route('/interfaces/wan')
def interfaces_wan():
    return render_template('interfaces_wan.html')

@app.route('/interfaces/lan')
def interfaces_lan():
    return render_template('interfaces_lan.html')

@app.route('/firewall')
def firewall():
    return render_template('firewall.html')

@app.route('/firewall/rules')
def rules():
    return render_template('rules.html')

@app.route('/firewall/nat')
def nat():
    return render_template('nat.html')

@app.route('/firewall/aliases')
def aliases():
    return render_template('aliases.html', tab='ip')


@app.route('/firewall/aliases/<tab>')
def aliases_tab(tab):
    valid_tabs = ['ip', 'ports', 'urls', 'all']
    if tab not in valid_tabs:
        tab = 'ip'
    return render_template('aliases.html', tab=tab)

@app.route('/firewall/schedules')
def schedules():
    return render_template('schedules.html')

@app.route('/firewall/traffic-shaper')
def traffic_shaper():
    return render_template('traffic_shaper.html')

@app.route('/firewall/virtual-ips')
def virtual_ips():
    return render_template('virtual_ips.html')

@app.route('/services')
def services():
    return render_template('services.html')

@app.route('/services/auto-config-backup')
def auto_config_backup():
    return render_template('auto_config_backup.html')

@app.route('/services/captive-portal')
def captive_portal():
    return render_template('captive_portal.html')

@app.route('/services/dhcp-relay')
def dhcp_relay():
    return render_template('dhcp_relay.html')

@app.route('/services/dhcp-server')
def dhcp_server():
    return render_template('dhcp_server.html')

@app.route('/services/dhcp-server-lan')
def dhcp_server_lan():
    return render_template('dhcp_server_lan.html')

@app.route('/services/dhcp-server/static-mapping')
def dhcp_static_mapping():
    return render_template('dhcp_static_mapping.html')

@app.route('/services/dhcp-server-lan/static-mapping')
def dhcp_static_mapping_lan():
    return render_template('dhcp_static_mapping_lan.html')

@app.route('/services/dhcpv6-relay')
def dhcpv6_relay():
    return render_template('dhcpv6_relay.html')

@app.route('/services/dhcpv6-server')
def dhcpv6_server():
    return render_template('dhcpv6_server.html')

@app.route('/services/dns-forwarder')
def dns_forwarder():
    return render_template('dns_forwarder.html')


@app.route('/services/dns-forwarder/edit-host-override', methods=['GET', 'POST'])
def dns_host_edit():
    # A simple edit page for host override. On POST we just redirect back to the DNS Forwarder page
    # (saving is not yet implemented).
    if request.method == 'POST':
        # In future: validate and save host override into session or config
        return redirect(url_for('dns_forwarder'))
    return render_template('dns_forwarder_edit_host.html')


@app.route('/services/dns-forwarder/edit-domain-override', methods=['GET', 'POST'])
def dns_domain_edit():
    # Simple edit page for domain override. On POST we just redirect back to the DNS Forwarder page
    if request.method == 'POST':
        # In future: validate and save domain override into session or config
        return redirect(url_for('dns_forwarder'))
    return render_template('dns_forwarder_edit_domain.html')

@app.route('/services/dns-resolver')
def dns_resolver():
    return render_template('dns_resolver.html')


@app.route('/services/dns-resolver/edit-host', methods=['GET', 'POST'])
def dns_resolver_edit_host():
    # Edit/Add a Host Override for DNS Resolver
    if request.method == 'POST':
        hosts = session.get('resolver_host_overrides', [])
        host = request.form.get('host', '').strip()
        domain = request.form.get('domain', '').strip()
        ip = request.form.get('ip', '').strip()
        description = request.form.get('description', '').strip()
        # Simple validation: require host or domain and ip
        if host or domain:
            hosts.append({'host': host, 'domain': domain, 'ip': ip, 'description': description})
            session['resolver_host_overrides'] = hosts
        return redirect(url_for('dns_resolver'))

    return render_template('dns_resolver_edit_host.html')


@app.route('/services/dns-resolver/edit-domain', methods=['GET', 'POST'])
def dns_resolver_edit_domain():
    # Edit/Add a Domain Override for DNS Resolver
    if request.method == 'POST':
        doms = session.get('resolver_domain_overrides', [])
        domain = request.form.get('domain', '').strip()
        server = request.form.get('server', '').strip()
        tls_queries = bool(request.form.get('tls_queries'))
        tls_hostname = request.form.get('tls_hostname', '').strip()
        description = request.form.get('description', '').strip()
        if domain:
            doms.append({'domain': domain, 'server': server, 'tls_queries': tls_queries, 'tls_hostname': tls_hostname, 'description': description})
            session['resolver_domain_overrides'] = doms
        return redirect(url_for('dns_resolver'))

    return render_template('dns_resolver_edit_domain.html')


@app.route('/services/dns-resolver/advanced', methods=['GET', 'POST'])
def dns_resolver_advanced():
    # Advanced settings view for DNS Resolver
    if request.method == 'POST':
        # For demo: we do not persist advanced settings. In a full implementation we'd save them.
        return redirect(url_for('dns_resolver_advanced'))
    return render_template('dns_resolver_advanced.html')


@app.route('/services/dns-resolver/access-lists')
def dns_resolver_access_lists():
    # Show Access Lists for DNS Resolver (session-backed demo storage)
    lists = session.get('resolver_access_lists', [])
    return render_template('dns_resolver_access_lists.html', lists=lists)


@app.route('/services/dns-resolver/access-lists/edit', methods=['GET', 'POST'])
def dns_resolver_access_lists_edit():
    # Simple Add/Edit form for Access Lists (POST appends to session list)
    if request.method == 'POST':
        lists = session.get('resolver_access_lists', [])
        name = request.form.get('name', '').strip()
        action = request.form.get('action', 'Allow')
        description = request.form.get('description', '').strip()
        if name:
            lists.append({'name': name, 'action': action, 'description': description})
            session['resolver_access_lists'] = lists
        return redirect(url_for('dns_resolver_access_lists'))
    return render_template('dns_resolver_access_lists_edit.html')

@app.route('/services/dynamic-dns')
def dynamic_dns():
    return render_template('dynamic_dns.html')


@app.route('/services/dynamic-dns/rfc2136')
def dynamic_dns_rfc2136():
    # RFC2136 clients listing page
    return render_template('dynamic_dns_rfc2136.html')


@app.route('/services/dynamic-dns/rfc2136/edit', methods=['GET', 'POST'])
def dynamic_dns_rfc2136_edit():
    # RFC2136 edit form: save minimal representation to session for demo
    if request.method == 'POST':
        clients = session.get('rfc2136_clients', [])
        client = {
            'enabled': bool(request.form.get('enable')),
            'interface': request.form.get('interface'),
            'hostname': request.form.get('hostname'),
            'zone': request.form.get('zone'),
            'ttl': request.form.get('ttl'),
            'key_name': request.form.get('key_name'),
            'key_algorithm': request.form.get('key_algorithm'),
            'key': request.form.get('key'),
            'server': request.form.get('server'),
            'protocol_tcp': bool(request.form.get('protocol_tcp')),
            'use_public_ip': bool(request.form.get('use_public_ip')),
            'update_source': request.form.get('update_source'),
            'update_source_family': request.form.get('update_source_family'),
            'record_type': request.form.get('record_type'),
            'description': request.form.get('description', ''),
        }
        clients.append(client)
        session['rfc2136_clients'] = clients
        return redirect(url_for('dynamic_dns_rfc2136'))

    return render_template('dynamic_dns_rfc2136_edit.html')


@app.route('/services/dynamic-dns/checkip')
def dynamic_dns_checkip():
    # Check IP Services listing page
    # Initialize default service in session if not present for demo (keeps UI populated)
    if 'checkip_services' not in session:
        session['checkip_services'] = [
            {'name': 'Default', 'url': 'http://checkip.dyndns.org', 'verify_ssl': False, 'description': 'Default Check IP Service'}
        ]
    return render_template('dynamic_dns_checkip.html')


@app.route('/services/dynamic-dns/checkip/edit', methods=['GET', 'POST'])
def dynamic_dns_checkip_edit():
    if request.method == 'POST':
        services = session.get('checkip_services', [])
        svc = {
            'enabled': bool(request.form.get('enable')),
            'name': request.form.get('name'),
            'url': request.form.get('url'),
            'username': request.form.get('username'),
            # do NOT store raw passwords in real code; demo only
            'password': request.form.get('password'),
            'verify_ssl': bool(request.form.get('verify_ssl')),
            'description': request.form.get('description', '')
        }
        services.append(svc)
        session['checkip_services'] = services
        return redirect(url_for('dynamic_dns_checkip'))

    return render_template('dynamic_dns_checkip_edit.html')


@app.route('/services/dynamic-dns/edit', methods=['GET', 'POST'])
def dynamic_dns_edit():
    # simple edit page for Dynamic DNS client; save minimal fields to session for demo
    if request.method == 'POST':
        clients = session.get('dynamic_dns_clients', [])
        client = {
            'disabled': bool(request.form.get('disabled')),
            'service_type': request.form.get('service_type'),
            'interface': request.form.get('interface'),
            'check_ip_mode': request.form.get('check_ip_mode'),
            'hostname': request.form.get('hostname'),
            'mx': request.form.get('mx'),
            'wildcards': bool(request.form.get('wildcards')),
            'verbose': bool(request.form.get('verbose')),
            'username': request.form.get('username'),
            'description': request.form.get('description', ''),
        }
        clients.append(client)
        session['dynamic_dns_clients'] = clients
        return redirect(url_for('dynamic_dns'))

    return render_template('dynamic_dns_edit.html')

@app.route('/services/igmp-proxy')
def igmp_proxy():
    return render_template('igmp_proxy.html')

@app.route('/services/ntp')
def ntp():
    return render_template('ntp.html')

@app.route('/services/openvpn-server')
def openvpn_server():
    return render_template('openvpn_server.html')

@app.route('/services/router-advertisement')
def router_advertisement():
    return render_template('router_advertisement.html')

@app.route('/services/snmp')
def snmp():
    return render_template('snmp.html')

@app.route('/services/upnp-igd-pcp')
def upnp_igd_pcp():
    return render_template('upnp_igd_pcp.html')

@app.route('/services/wake-on-lan')
def wake_on_lan():
    return render_template('wake_on_lan.html')

@app.route('/vpn')
def vpn():
    return render_template('vpn.html')

@app.route('/vpn/openvpn')
def openvpn():
    return render_template('openvpn.html')

@app.route('/vpn/ipsec')
def ipsec():
    return render_template('ipsec.html')

@app.route('/vpn/l2tp')
def l2tp():
    return render_template('l2tp.html')

@app.route('/status')
def status():
    return render_template('status.html')

@app.route('/status/carp-failover')
def carp_failover():
    return render_template('carp_failover.html')

@app.route('/status/dhcp-leases')
def dhcp_leases():
    return render_template('dhcp_leases.html')

@app.route('/status/dhcpv6-leases')
def dhcpv6_leases():
    return render_template('dhcpv6_leases.html')

@app.route('/status/filter-reload')
def filter_reload():
    return render_template('filter_reload.html')

@app.route('/status/gateways')
def gateways():
    return render_template('gateways.html')

@app.route('/status/monitoring')
def monitoring():
    return render_template('monitoring.html')

@app.route('/status/queues')
def queues():
    return render_template('queues.html')

@app.route('/status/system-logs')
def system_logs():
    return render_template('system_logs.html')

@app.route('/status/traffic-graph')
def traffic_graph():
    return render_template('traffic_graph.html')

@app.route('/diagnostics')
def diagnostics():
    return render_template('diagnostics.html')

@app.route('/diagnostics/arp-table')
def arp_table():
    return render_template('arp_table.html')

@app.route('/diagnostics/authentication')
def authentication():
    return render_template('authentication.html')

@app.route('/diagnostics/backup-restore')
def backup_restore():
    return render_template('backup_restore.html')

@app.route('/diagnostics/command-prompt')
def command_prompt():
    return render_template('command_prompt.html')

@app.route('/diagnostics/dns-lookup')
def dns_lookup():
    return render_template('dns_lookup.html')

@app.route('/diagnostics/edit-file')
def edit_file():
    return render_template('edit_file.html')

@app.route('/diagnostics/factory-defaults')
def factory_defaults():
    return render_template('factory_defaults.html')

@app.route('/diagnostics/halt-system')
def halt_system():
    return render_template('halt_system.html')

@app.route('/diagnostics/limiter-info')
def limiter_info():
    return render_template('limiter_info.html')

@app.route('/diagnostics/ndp-table')
def ndp_table():
    return render_template('ndp_table.html')

@app.route('/diagnostics/packet-capture')
def packet_capture():
    return render_template('packet_capture.html')

@app.route('/diagnostics/pfinfo')
def pfinfo():
    return render_template('pfinfo.html')

@app.route('/diagnostics/pftop')
def pftop():
    return render_template('pftop.html')

@app.route('/diagnostics/ping')
def ping_diag():
    return render_template('ping_diag.html')

@app.route('/diagnostics/reboot')
def reboot():
    return render_template('reboot.html')

@app.route('/diagnostics/routes')
def routes_diag():
    return render_template('routes_diag.html')

@app.route('/diagnostics/smart-status')
def smart_status():
    return render_template('smart_status.html')

@app.route('/diagnostics/sockets')
def sockets():
    return render_template('sockets.html')

@app.route('/diagnostics/states')
def states():
    return render_template('states.html')

@app.route('/diagnostics/status-summary')
def status_summary():
    return render_template('status_summary.html')

@app.route('/diagnostics/system-activity')
def system_activity():
    return render_template('system_activity.html')

@app.route('/diagnostics/tables')
def tables():
    return render_template('tables.html')

@app.route('/diagnostics/test-port')
def test_port():
    return render_template('test_port.html')

@app.route('/diagnostics/tunnels')
def tunnels():
    return render_template('tunnels.html')

@app.route('/help')
def help_page():
    return render_template('help.html')

@app.route('/help/docs')
def docs():
    return render_template('docs.html')

@app.route('/help/about')
def about():
    return render_template('about.html')

@app.route('/help/bug')
def bug():
    return render_template('bug.html')

@app.route('/help/forum')
def forum():
    return render_template('forum.html')

@app.route('/help/freebsd')
def freebsd():
    return render_template('freebsd.html')

@app.route('/help/pfsense-book')
def pfsense_book():
    return render_template('pfsense_book.html')

@app.route('/help/paid-support')
def paid_support():
    return render_template('paid_support.html')

@app.route('/help/survey')
def survey():
    return render_template('survey.html')

@app.route('/help/upgrade')
def upgrade():
    return render_template('upgrade.html')

@app.route('/add_certificate')
def add_certificate():
    return render_template('add_certificate.html')

@app.route('/add_ca')
def add_ca():
    return render_template('add_ca.html')

if __name__ == '__main__':
    app.run(debug=True)