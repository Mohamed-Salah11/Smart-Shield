from flask import Blueprint, render_template
from app.auth_utils import login_required
routing_bp = Blueprint("routing", __name__, url_prefix="/system/routing")

@routing_bp.route("/")
@login_required
def routing_index():
    return render_template("routing.html")

@routing_bp.route("/static")
@login_required
def static_routes():
    return render_template("static_routes.html")

@routing_bp.route("/groups")
@login_required
def gateway_groups():
    return render_template("gateway_groups.html")

@routing_bp.route("/gateway/edit")
@routing_bp.route("/gateway/edit/<int:index>")
@login_required
def gateway_edit(index=None):
    return render_template("routing_edit_gateway.html", index=index)

@routing_bp.route("/static/edit")
@routing_bp.route("/static/edit/<int:index>")
@login_required
def static_route_edit(index=None):
    return render_template("static_route_edit.html", index=index)

@routing_bp.route("/group/edit")
@routing_bp.route("/group/edit/<int:index>")
@login_required
def gateway_group_edit(index=None):
    return render_template("gateway_group_edit.html", index=index)

@routing_bp.route("/save", methods=["POST"])
@login_required
def routing_save():
    # Handle save for gateways
    from flask import request, redirect, url_for
    return redirect(url_for("routing.routing_index"))

@routing_bp.route("/static/delete/<int:index>", methods=["POST"])
@login_required
def static_route_delete(index):
    from flask import redirect, url_for
    # Handle deletion of static route at index
    return redirect(url_for("routing.static_routes"))

@routing_bp.route("/group/delete/<int:index>", methods=["POST"])
@login_required
def gateway_group_delete(index):
    from flask import redirect, url_for
    # Handle deletion of gateway group at index
    return redirect(url_for("routing.gateway_groups"))
