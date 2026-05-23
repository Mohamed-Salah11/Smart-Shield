"""routes/system — system blueprint package (split from routes/system.py).
Blueprint name and url_prefix preserved; URL map identical."""
from flask import Blueprint

# Re-export the original Blueprint definition verbatim so any keyword
# args (subdomain, static_folder, ...) survive the split.
system_bp = Blueprint("system", __name__, url_prefix="/system")

from routes.system import (  # noqa: E402,F401
    pages, advanced, certificates, tools, soc_mail,
)
