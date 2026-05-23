"""routes/services — services blueprint package (split from routes/services.py).
Blueprint name and url_prefix preserved; URL map identical."""
from flask import Blueprint

# Re-export the original Blueprint definition verbatim so any keyword
# args (subdomain, static_folder, ...) survive the split.
services_bp = Blueprint("services", __name__, url_prefix="/services")

from routes.services import (  # noqa: E402,F401
    dns_dhcp, network, captive,
)
