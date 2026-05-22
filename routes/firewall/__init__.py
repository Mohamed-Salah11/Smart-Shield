"""routes/firewall — firewall blueprint package.

Split from the former monolithic routes/firewall.py for maintainability.
The blueprint name ("firewall") and url_prefix ("/firewall") are unchanged,
so the URL map and every url_for() reference are identical.
"""
from flask import Blueprint

firewall_bp = Blueprint("firewall", __name__, url_prefix="/firewall")

# Import submodules so their @firewall_bp.route decorators register.
from routes.firewall import (  # noqa: E402,F401
    rules, nat, aliases, schedules, shaper, apply,
)
