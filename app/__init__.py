from flask import Flask
from .database import init_db
import os
from dotenv import load_dotenv
from .security import get_csrf_token, validate_csrf_or_abort


def create_app():
    load_dotenv()
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    app = Flask(
        __name__,
        template_folder=os.path.join(base_dir, "templates"),
        static_folder=os.path.join(base_dir, "static"),
    )

    app.secret_key = os.getenv("SECRET_KEY")
    if not app.secret_key:
        raise RuntimeError(
            "SECRET_KEY is not set. Create a .env file (for example: copy .env.example .env) and set SECRET_KEY."
        )

    @app.before_request
    def _csrf_guard():
        validate_csrf_or_abort()

    @app.context_processor
    def _csrf_context():
        return {"csrf_token": get_csrf_token}

    init_db()

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

    return app
