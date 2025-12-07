from flask import Blueprint, render_template

routing_bp = Blueprint("routing", __name__, url_prefix="/system/routing")

@routing_bp.route("/")
def routing_index():
    return render_template("routing.html")
