"""routes/diagnostics — diagnostics blueprint package (split from routes/diagnostics.py).
Blueprint name and url_prefix preserved; URL map identical."""
from flask import Blueprint

# Re-export the original Blueprint definition verbatim so any keyword
# args (subdomain, static_folder, ...) survive the split.
diagnostics_bp = Blueprint("diagnostics", __name__, url_prefix="/diagnostics")

from routes.diagnostics import (  # noqa: E402,F401
    backup, tools,
)
