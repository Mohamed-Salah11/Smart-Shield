"""Blueprint registration.

Extracted from the app factory. Keeping every blueprint import + register call
in one place makes the route surface easy to audit at a glance.
"""


def register_blueprints(app):
    from routes.setup import setup_bp
    from routes.auth import auth_bp
    from routes.users import users_bp
    from routes.system import system_bp
    from routes.interfaces import interfaces_bp
    from routes.routing import routing_bp
    from routes.services import services_bp
    from routes.firewall import firewall_bp
    from routes.vpn import vpn_bp
    from routes.status import status_bp
    from routes.diagnostics import diagnostics_bp
    from routes.network_api import network_api_bp
    from routes.ids import ids_bp
    from routes.filters import filters_bp
    from routes.portal import portal_bp
    from routes.chatbot import chatbot_bp
    from routes.soc import soc_bp
    from routes.soc_portal import soc_portal_bp
    from routes.vpn_portal import vpn_portal_bp
    from routes.terminal import terminal_bp
    from routes.hec import hec_bp
    from routes.firewall_logs import firewall_logs_bp
    from routes.dns_logs import dns_logs_bp

    app.register_blueprint(setup_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(system_bp)
    app.register_blueprint(interfaces_bp)
    app.register_blueprint(routing_bp)
    app.register_blueprint(services_bp)
    app.register_blueprint(firewall_bp)
    app.register_blueprint(vpn_bp)
    app.register_blueprint(status_bp)
    app.register_blueprint(diagnostics_bp)
    app.register_blueprint(network_api_bp)
    app.register_blueprint(ids_bp)
    app.register_blueprint(filters_bp)
    app.register_blueprint(portal_bp)
    app.register_blueprint(chatbot_bp)
    app.register_blueprint(soc_bp)
    app.register_blueprint(soc_portal_bp)
    app.register_blueprint(vpn_portal_bp)
    app.register_blueprint(terminal_bp)
    app.register_blueprint(hec_bp)
    app.register_blueprint(firewall_logs_bp)
    app.register_blueprint(dns_logs_bp)
