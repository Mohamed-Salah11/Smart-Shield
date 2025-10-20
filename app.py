from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

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
    return render_template('advanced.html')


@app.route('/system/certificates')
def certificates():
    return render_template('certificates.html')


@app.route('/system/general-setup')
def general_setup():
    return render_template('general_setup.html')


@app.route('/system/high-availability')
def high_availability():
    return render_template('high_availability.html')


@app.route('/system/logout')
def logout():
    # For now, perform a redirect back to the login page.
    # In future replace with session clearing (e.g., session.clear()).
    return redirect(url_for('login'))


@app.route('/system/package-manager')
def package_manager():
    return render_template('package_manager.html')


@app.route('/system/setup-wizard')
def setup_wizard():
    return render_template('setup_wizard.html')


@app.route('/system/update', methods=['GET', 'POST'])
def update_page():
    if request.method == 'POST':
        # Handle form submissions for both tabs
        if 'check_updates' in request.form:
            # Handle check for updates
            return render_template('update.html', message="Checking for updates...", active_tab="system")
        elif 'update_system' in request.form:
            # Handle system update
            return render_template('update.html', message="System update initiated...", active_tab="system")
        elif 'save_settings' in request.form:
            # Handle update settings save
            return render_template('update.html', message="Settings saved successfully", active_tab="settings")
    
    return render_template('update.html', active_tab="system")


@app.route('/system/user-manager', methods=['GET', 'POST'])
def user_manager():
    if request.method == 'POST':
        # Handle form submissions
        if 'add_user' in request.form:
            # Handle add user
            return render_template('user_manager.html', message="User added successfully")
        elif 'delete_user' in request.form:
            # Handle delete user
            return render_template('user_manager.html', message="User deleted successfully")
        elif 'change_password' in request.form:
            # Handle password change
            return render_template('user_manager.html', message="Password changed successfully")
    
    # Sample user data (in a real app, this would come from a database)
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


@app.route('/interfaces')
def interfaces():
    return render_template('interfaces.html')


@app.route('/interfaces/assignments')
def interfaces_assignments():
    return render_template('interfaces_assignments.html')


# New: simple WAN and LAN pages for Interfaces dropdown
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
    return render_template('aliases.html')


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


# Services submenu pages
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


@app.route('/services/dhcpv6-relay')
def dhcpv6_relay():
    return render_template('dhcpv6_relay.html')


@app.route('/services/dhcpv6-server')
def dhcpv6_server():
    return render_template('dhcpv6_server.html')


@app.route('/services/dns-forwarder')
def dns_forwarder():
    return render_template('dns_forwarder.html')


@app.route('/services/dns-resolver')
def dns_resolver():
    return render_template('dns_resolver.html')


@app.route('/services/dynamic-dns')
def dynamic_dns():
    return render_template('dynamic_dns.html')


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


# Status submenu pages
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


# Diagnostics detailed pages
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


# Help pages
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


if __name__ == '__main__':
    # Run locally in debug mode for development
    app.run(debug=True)