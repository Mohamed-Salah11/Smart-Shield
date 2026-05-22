"""routes/network_api — network_api blueprint package (split from routes/network_api.py).
Blueprint name and url_prefix preserved; URL map identical."""
from flask import Blueprint

# Re-export the original Blueprint definition verbatim so any keyword
# args (subdomain, static_folder, ...) survive the split.
network_api_bp = Blueprint("network_api", __name__, url_prefix="/api/network")

from routes.network_api import (  # noqa: E402,F401
    interfaces, vips,
)
