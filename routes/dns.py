from flask import Blueprint, render_template

dns_bp = Blueprint("dns", __name__, url_prefix="/services")

@dns_bp.route("/dns-resolver")
def resolver():
    return render_template("dns_resolver.html")
