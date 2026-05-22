import json
import sys
from flask import Blueprint, render_template, request, redirect, url_for, jsonify, flash
from app.auth_utils import login_required
from app.database import get_db
from app.audit_log import log_event

routing_bp = Blueprint("routing", __name__, url_prefix="/system/routing")


def _rows(conn, sql, params=()):
    cur = conn.cursor()
    cur.execute(sql, params)
    return [dict(r) for r in cur.fetchall()]


def _get_gateways(conn):
    return _rows(conn, "SELECT * FROM gateways ORDER BY name")


# ── Gateways (main tab) ───────────────────────────────────────────────────────

@routing_bp.route("/")
@login_required
def routing_index():
    conn = get_db()
    gateways   = _get_gateways(conn)
    default_v4 = next((g["name"] for g in gateways if g["is_default_v4"]), "")
    default_v6 = next((g["name"] for g in gateways if g["is_default_v6"]), "")
    return render_template("routing.html",
                           gateways=gateways,
                           default_ipv4=default_v4,
                           default_ipv6=default_v6)


@routing_bp.route("/gateway/edit", methods=["GET", "POST"])
@routing_bp.route("/gateway/edit/<int:gw_id>", methods=["GET", "POST"])
@login_required
def gateway_edit(gw_id=None):
    conn = get_db()

    if request.method == "POST":
        d = request.form
        disabled    = 1 if d.get("disabled") else 0
        name        = (d.get("name") or "").strip()
        interface   = d.get("interface", "WAN")
        af          = d.get("address_family", "IPv4")
        gateway     = (d.get("gateway") or "").strip()
        monitor     = (d.get("monitor") or "").strip()
        dis_mon     = 1 if d.get("disable_monitoring") else 0
        dis_mon_act = 1 if d.get("disable_monitoring_action") else 0
        force_state = 1 if d.get("force_state") else 0
        state_kill  = d.get("state_killing", "global")
        description = (d.get("description") or "").strip()

        if not name or not gateway:
            flash("Name and Gateway IP are required.", "danger")
            return redirect(request.url)

        if gw_id:
            conn.execute("""
                UPDATE gateways SET disabled=?, name=?, interface=?, address_family=?,
                    gateway=?, monitor=?, disable_monitoring=?, disable_monitoring_action=?,
                    force_state=?, state_killing=?, description=?
                WHERE id=?
            """, (disabled, name, interface, af, gateway, monitor,
                  dis_mon, dis_mon_act, force_state, state_kill, description, gw_id))
        else:
            conn.execute("""
                INSERT INTO gateways
                    (disabled, name, interface, address_family, gateway, monitor,
                     disable_monitoring, disable_monitoring_action, force_state,
                     state_killing, description)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """, (disabled, name, interface, af, gateway, monitor,
                  dis_mon, dis_mon_act, force_state, state_kill, description))

        conn.commit()
        log_event(category="system", action="gateway_save",
                  remote_addr=request.remote_addr,
                  details={"name": name, "gateway": gateway, "id": gw_id})
        return redirect(url_for("routing.routing_index"))

    gateway_row = None
    if gw_id:
        cur = conn.cursor()
        cur.execute("SELECT * FROM gateways WHERE id=?", (gw_id,))
        row = cur.fetchone()
        gateway_row = dict(row) if row else None

    return render_template("routing_edit_gateway.html", gateway=gateway_row, gw_id=gw_id)


@routing_bp.route("/gateway/delete/<int:gw_id>", methods=["POST"])
@login_required
def gateway_delete(gw_id):
    conn = get_db()
    conn.execute("DELETE FROM gateways WHERE id=?", (gw_id,))
    conn.commit()
    log_event(category="system", action="gateway_delete",
              remote_addr=request.remote_addr,
              details={"id": gw_id})
    return redirect(url_for("routing.routing_index"))


@routing_bp.route("/gateway/set-default", methods=["POST"])
@login_required
def gateway_set_default():
    conn = get_db()
    default_v4 = request.form.get("default_ipv4", "")
    default_v6 = request.form.get("default_ipv6", "")
    # Clear all defaults then set
    conn.execute("UPDATE gateways SET is_default_v4=0")
    conn.execute("UPDATE gateways SET is_default_v6=0")
    if default_v4:
        conn.execute("UPDATE gateways SET is_default_v4=1 WHERE name=?", (default_v4,))
    if default_v6:
        conn.execute("UPDATE gateways SET is_default_v6=1 WHERE name=?", (default_v6,))
    conn.commit()
    log_event(category="system", action="gateway_set_default",
              remote_addr=request.remote_addr,
              details={"ipv4": default_v4, "ipv6": default_v6})
    return redirect(url_for("routing.routing_index"))


# ── Apply gateway to OS ───────────────────────────────────────────────────────

@routing_bp.route("/gateway/apply/<int:gw_id>", methods=["POST"])
@login_required
def gateway_apply(gw_id):
    """Apply the default gateway to the live OS routing table (FreeBSD only)."""
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT * FROM gateways WHERE id=?", (gw_id,))
    row = cur.fetchone()
    if not row:
        return jsonify({"ok": False, "message": "Gateway not found"}), 404
    gw = dict(row)

    if not sys.platform.startswith("freebsd"):
        return jsonify({"ok": True, "message": "Non-FreeBSD — OS apply skipped.",
                        "gateway": gw["gateway"]})
    try:
        from app.services.network_service import run_command
        run_command(["route", "-n", "delete", "default"], check=False)
        r = run_command(["route", "-n", "add", "default", gw["gateway"]], check=False)
        ok = r.returncode == 0
        log_event(category="system", action="gateway_apply_os",
                  remote_addr=request.remote_addr,
                  details={"gateway": gw["gateway"], "ok": ok})
        return jsonify({"ok": ok, "message": f"route add default {gw['gateway']}: " +
                        (r.stdout or r.stderr or "done").strip()})
    except Exception as exc:
        return jsonify({"ok": False, "message": str(exc)}), 500


# ── Static Routes ─────────────────────────────────────────────────────────────

@routing_bp.route("/static")
@login_required
def static_routes_page():
    conn = get_db()
    routes = _rows(conn, """
        SELECT sr.*, g.name AS gateway_name, g.gateway AS gateway_ip, g.interface
        FROM static_routes sr
        LEFT JOIN gateways g ON sr.gateway_id = g.id
        ORDER BY sr.id
    """)
    return render_template("static_routes.html", static_routes=routes)


@routing_bp.route("/static/edit", methods=["GET", "POST"])
@routing_bp.route("/static/edit/<int:route_id>", methods=["GET", "POST"])
@login_required
def static_route_edit(route_id=None):
    conn = get_db()
    gateways = _get_gateways(conn)

    if request.method == "POST":
        d           = request.form
        destination = (d.get("destination") or "").strip()
        gateway_id  = d.get("gateway_id") or None
        description = (d.get("description") or "").strip()
        disabled    = 1 if d.get("disabled") else 0

        if not destination:
            flash("Destination network is required.", "danger")
            return redirect(request.url)

        # On edit: capture the previous destination/gateway so we can delete the
        # old kernel route before installing the new one. Skipping this would
        # leave stale routes in the kernel table when an admin edits a route.
        old_destination = None
        old_gateway     = None
        if route_id:
            old = conn.execute("""
                SELECT sr.destination, g.gateway
                FROM static_routes sr LEFT JOIN gateways g ON sr.gateway_id=g.id
                WHERE sr.id=?
            """, (route_id,)).fetchone()
            if old:
                old_destination = old["destination"]
                old_gateway     = old["gateway"]
            conn.execute("""
                UPDATE static_routes SET disabled=?, destination=?, gateway_id=?, description=?
                WHERE id=?
            """, (disabled, destination, gateway_id, description, route_id))
        else:
            conn.execute("""
                INSERT INTO static_routes (disabled, destination, gateway_id, description)
                VALUES (?,?,?,?)
            """, (disabled, destination, gateway_id, description))

        conn.commit()

        # Apply on FreeBSD: delete the stale route if changed, then add the
        # new one. Errors are surfaced to the UI via flash() instead of
        # silently swallowed, so admins see when the OS rejected the change.
        route_errors = []
        if sys.platform.startswith("freebsd"):
            from app.services.network_service import run_command
            if route_id and old_destination and old_gateway and (
                old_destination != destination or
                # gateway changed if the new resolved gw differs; check below
                True
            ):
                try:
                    run_command(["route", "-n", "delete", "-net",
                                 old_destination, old_gateway], check=False)
                except Exception as exc:
                    route_errors.append(f"delete old route failed: {exc}")
            if not disabled and gateway_id:
                try:
                    gw_row = conn.execute(
                        "SELECT gateway FROM gateways WHERE id=?", (gateway_id,)
                    ).fetchone()
                    if gw_row:
                        r = run_command(["route", "-n", "add", "-net",
                                         destination, gw_row["gateway"]], check=False)
                        if r.returncode != 0:
                            route_errors.append(
                                f"add route failed: "
                                f"{(r.stderr or r.stdout or '').strip()}"
                            )
                except Exception as exc:
                    route_errors.append(f"add route raised: {exc}")
        for msg in route_errors:
            flash(msg, "warning")

        log_event(category="system", action="static_route_save",
                  remote_addr=request.remote_addr,
                  details={"destination": destination, "id": route_id})
        return redirect(url_for("routing.static_routes_page"))

    route_row = None
    if route_id:
        cur = conn.cursor()
        cur.execute("SELECT * FROM static_routes WHERE id=?", (route_id,))
        row = cur.fetchone()
        route_row = dict(row) if row else None

    return render_template("static_route_edit.html",
                           route=route_row, route_id=route_id, gateways=gateways)


@routing_bp.route("/static/delete/<int:route_id>", methods=["POST"])
@login_required
def static_route_delete(route_id):
    conn = get_db()
    # Capture destination/gateway BEFORE deleting the DB row so we can also
    # remove it from the kernel routing table. Errors are surfaced to the UI
    # rather than silently swallowed — admins need to know if the OS still
    # has the route after the DB delete.
    row = conn.execute("""
        SELECT sr.destination, g.gateway
        FROM static_routes sr LEFT JOIN gateways g ON sr.gateway_id=g.id
        WHERE sr.id=?
    """, (route_id,)).fetchone()

    if sys.platform.startswith("freebsd") and row and row["gateway"]:
        try:
            from app.services.network_service import run_command
            r = run_command(["route", "-n", "delete", "-net",
                             row["destination"], row["gateway"]], check=False)
            if r.returncode != 0:
                flash(
                    f"Route {row['destination']} via {row['gateway']} could not "
                    f"be removed from the kernel: "
                    f"{(r.stderr or r.stdout or '').strip()}",
                    "warning",
                )
        except Exception as exc:
            flash(f"OS route delete failed: {exc}", "warning")

    conn.execute("DELETE FROM static_routes WHERE id=?", (route_id,))
    conn.commit()
    log_event(category="system", action="static_route_delete",
              remote_addr=request.remote_addr, details={"id": route_id})
    return redirect(url_for("routing.static_routes_page"))


# ── Gateway Groups ────────────────────────────────────────────────────────────

@routing_bp.route("/groups")
@login_required
def gateway_groups_page():
    conn  = get_db()
    groups = _rows(conn, "SELECT * FROM gateway_groups ORDER BY name")
    for g in groups:
        try:
            g["members"] = json.loads(g.get("members_json") or "[]")
        except Exception:
            g["members"] = []
    return render_template("gateway_groups.html", gateway_groups=groups)


@routing_bp.route("/group/edit", methods=["GET", "POST"])
@routing_bp.route("/group/edit/<int:group_id>", methods=["GET", "POST"])
@login_required
def gateway_group_edit(group_id=None):
    conn = get_db()
    gateways = _get_gateways(conn)

    if request.method == "POST":
        d           = request.form
        name        = (d.get("name") or "").strip()
        description = (d.get("description") or "").strip()
        trigger     = d.get("trigger", "down")

        # Collect tier assignments for each gateway
        members = []
        for gw in gateways:
            tier = d.get(f"tier_{gw['name']}", "never")
            if tier != "never":
                vip = d.get(f"vip_{gw['name']}", "")
                members.append({
                    "gateway": gw["name"],
                    "tier": int(tier),
                    "vip": vip,
                })
        members_json = json.dumps(members)

        if not name:
            flash("Group name is required.", "danger")
            return redirect(request.url)

        if group_id:
            conn.execute("""
                UPDATE gateway_groups
                SET name=?, trigger_level=?, description=?, members_json=?
                WHERE id=?
            """, (name, trigger, description, members_json, group_id))
        else:
            conn.execute("""
                INSERT INTO gateway_groups (name, trigger_level, description, members_json)
                VALUES (?,?,?,?)
            """, (name, trigger, description, members_json))

        conn.commit()
        log_event(category="system", action="gateway_group_save",
                  remote_addr=request.remote_addr,
                  details={"name": name, "id": group_id})
        return redirect(url_for("routing.gateway_groups_page"))

    group_row = None
    group_members = {}
    if group_id:
        cur = conn.cursor()
        cur.execute("SELECT * FROM gateway_groups WHERE id=?", (group_id,))
        row = cur.fetchone()
        if row:
            group_row = dict(row)
            try:
                for m in json.loads(group_row.get("members_json") or "[]"):
                    group_members[m["gateway"]] = m
            except Exception:
                pass

    return render_template("gateway_group_edit.html",
                           group=group_row, group_id=group_id,
                           gateways=gateways, group_members=group_members)


@routing_bp.route("/group/delete/<int:group_id>", methods=["POST"])
@login_required
def gateway_group_delete(group_id):
    conn = get_db()
    conn.execute("DELETE FROM gateway_groups WHERE id=?", (group_id,))
    conn.commit()
    log_event(category="system", action="gateway_group_delete",
              remote_addr=request.remote_addr, details={"id": group_id})
    return redirect(url_for("routing.gateway_groups_page"))


# ── API: live route table ─────────────────────────────────────────────────────

@routing_bp.route("/api/live-routes")
@login_required
def api_live_routes():
    """Return the live OS routing table (FreeBSD netstat -rn)."""
    if not sys.platform.startswith("freebsd"):
        return jsonify({"ok": True, "routes": [], "on_freebsd": False})
    try:
        from app.services.network_service import run_command
        r = run_command(["netstat", "-rn", "-f", "inet"], check=False)
        routes = []
        for line in (r.stdout or "").splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0] not in ("Destination", "Internet:"):
                routes.append({
                    "destination": parts[0], "gateway": parts[1],
                    "flags": parts[2],       "iface": parts[-1],
                })
        return jsonify({"ok": True, "routes": routes, "on_freebsd": True})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@routing_bp.route("/api/apply-all", methods=["POST"])
@login_required
def api_apply_all_static_routes():
    """
    Apply all enabled static routes to the live OS and persist them in
    rc.conf via apply_static_routes() from rc_conf_writer.
    """
    conn = get_db()
    try:
        from app.services.rc_conf_writer import apply_static_routes
        result = apply_static_routes(conn)
    except Exception as exc:
        return jsonify({"ok": False, "message": str(exc)}), 500

    log_event(
        category="network", action="static_routes_apply_all",
        username=None, remote_addr=request.remote_addr,
        details={"ok": result.get("ok"), "message": result.get("message", "")},
    )
    status = 200 if result.get("ok") else 500
    return jsonify(result), status


@routing_bp.route("/api/gateway-health")
@login_required
def api_gateway_health():
    """
    Return current gateway reachability from the background monitor.

    Response::

        {"ok": true, "gateways": [{"id": 1, "name": "WAN GW", "reachable": true, "ip": "..."}, ...]}
    """
    conn = get_db()
    try:
        from app.services.gateway_monitor import get_gateway_health
        health = get_gateway_health()
    except Exception:
        health = {}

    rows = _rows(conn, "SELECT id, name, gateway AS ip FROM gateways ORDER BY name")
    gateways = []
    for gw in rows:
        gw_id = gw["id"]
        reachable = health.get(gw_id)
        gateways.append({
            "id":        gw_id,
            "name":      gw["name"],
            "ip":        gw.get("ip", ""),
            "reachable": reachable,  # None = not yet probed
        })
    return jsonify({"ok": True, "gateways": gateways})


@routing_bp.route("/api/gateway-failover/apply", methods=["POST"])
@login_required
def api_gateway_failover_apply():
    """
    Probe all gateway-group members and switch the default route to the
    highest-priority reachable gateway.  No-op on non-FreeBSD.
    """
    conn = get_db()
    try:
        from app.services.network_service import apply_gateway_failover
        result = apply_gateway_failover(conn)
    except Exception as exc:
        return jsonify({"ok": False, "message": str(exc)}), 500

    log_event(
        category="network", action="gateway_failover_apply",
        username=None, remote_addr=request.remote_addr,
        details={"ok": result.get("ok"), "message": result.get("message", "")},
    )
    return jsonify(result)
