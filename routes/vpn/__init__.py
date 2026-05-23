"""routes/vpn — vpn blueprint package (split from routes/vpn.py).
Blueprint name and url_prefix preserved; URL map identical."""
from flask import Blueprint

# Re-export the original Blueprint definition verbatim so any keyword
# args (subdomain, static_folder, ...) survive the split.
vpn_bp = Blueprint("vpn", __name__, url_prefix="/vpn")

from routes.vpn import (  # noqa: E402,F401
    views, api, certs,
)
