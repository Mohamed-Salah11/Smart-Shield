from flask import Flask
from .database import init_db
from .vpndb import init_vpn_db
from .vpn_servers_db import init_vpn_servers_db
from .cscdb import init_csc_db
from .wizardsdb import init_wizards_db
from .tunnelsdb import init_tunnels_table
from .mobclientsdb import init_mobile_clients_table
from .pskdb import init_psk_table
from .advs import init_advanced_settings_table
from .l2configdb import init_l2tp_config_table
from .l2users import init_l2tp_users_table
import os

def create_app():
    # Get the parent directory of the app folder (the project root)
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    app = Flask(__name__, 
                template_folder=os.path.join(base_dir, 'templates'),
                static_folder=os.path.join(base_dir, 'static'))
    app.secret_key = "your-secret-key"

    # Initialize SQLite database and ensure default admin user is created
    init_db()
    init_vpn_servers_db()
    init_vpn_db()
    init_csc_db()
    init_wizards_db()
    init_tunnels_table()
    init_mobile_clients_table()
    init_psk_table()
    init_advanced_settings_table()
    init_l2tp_config_table()
    init_l2tp_users_table()

    # Import blueprints
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

    # Register blueprints
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

    return app
