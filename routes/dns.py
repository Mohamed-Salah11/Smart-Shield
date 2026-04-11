from flask import Blueprint, render_template
from app.auth_utils import login_required

dns_bp = Blueprint("dns", __name__, url_prefix="/services")

@dns_bp.route("/dns-resolver")
@login_required
def resolver():
    return render_template("dns_resolver.html")
