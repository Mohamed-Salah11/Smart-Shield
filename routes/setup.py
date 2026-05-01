"""
routes/setup.py
---------------
First-boot setup wizard.

The wizard runs when Smart Shield has never been configured (no interface
assignments in the DB).  It guides the operator through four steps:

  Step 1 — Interface assignment  (WAN / LAN port selection)
  Step 2 — LAN IP configuration  (IP address + subnet)
  Step 3 — Admin password change (mandatory on first run)
  Step 4 — Apply & reboot        (writes configs, starts services)

After step 4 the wizard marks itself complete by writing a 'setup_complete'
row to service_state and redirects to the dashboard.

The wizard is accessible without authentication so a fresh install can be
configured from the browser before any users exist.  Once complete, all
/setup/* routes redirect to the dashboard.
"""

import json
import os

from flask import (
    Blueprint,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from app.database import get_db

setup_bp = Blueprint("setup", __name__, url_prefix="/setup")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_setup_complete() -> bool:
    """Return True when the wizard has already been finished."""
    try:
        conn = get_db()
        row  = conn.execute(
            "SELECT value_json FROM service_state WHERE key_name='setup_complete'"
        ).fetchone()
        if row:
            return json.loads(row["value_json"] or "false") is True
    except Exception:
        pass
    return False


def _mark_setup_complete(conn):
    conn.execute(
        """
        INSERT INTO service_state (key_name, value_json, updated_at)
        VALUES ('setup_complete', 'true', CURRENT_TIMESTAMP)
        ON CONFLICT(key_name) DO UPDATE SET
            value_json  = 'true',
            updated_at  = CURRENT_TIMESTAMP
        """
    )
    conn.commit()


def _wizard_guard():
    """Redirect away from wizard if it's already done."""
    if _is_setup_complete():
        return redirect(url_for("system.dashboard"))
    return None


# ---------------------------------------------------------------------------
# Step 0 — Wizard entry point
# ---------------------------------------------------------------------------

@setup_bp.route("/")
def wizard_index():
    guard = _wizard_guard()
    if guard:
        return guard
    return redirect(url_for("setup.step1"))


# ---------------------------------------------------------------------------
# Step 1 — Interface assignment
# ---------------------------------------------------------------------------

@setup_bp.route("/step1", methods=["GET"])
def step1():
    guard = _wizard_guard()
    if guard:
        return guard
    return render_template("setup/step1_interfaces.html")


@setup_bp.route("/api/step1/available-ports", methods=["GET"])
def api_step1_ports():
    """Return a list of detected network interfaces."""
    guard = _wizard_guard()
    if guard:
        return jsonify({"ok": False, "message": "Setup already complete."}), 403
    ports = []
    try:
        import sys
        if sys.platform.startswith("freebsd"):
            from app.services.network_service import run_command
            r = run_command(["ifconfig", "-l"], check=False)
            ports = (r.stdout or "").split()
        else:
            # Dev: return placeholder names
            ports = ["em0", "em1", "em2", "vtnet0", "vtnet1"]
    except Exception:
        ports = ["em0", "em1"]
    return jsonify({"ok": True, "ports": ports})


@setup_bp.route("/api/step1/save", methods=["POST"])
def api_step1_save():
    guard = _wizard_guard()
    if guard:
        return jsonify({"ok": False, "message": "Setup already complete."}), 403

    data    = request.get_json(force=True) or {}
    wan_port = (data.get("wan_port") or "").strip()
    lan_port = (data.get("lan_port") or "").strip()

    if not wan_port or not lan_port:
        return jsonify({"ok": False, "message": "Both WAN and LAN ports are required."}), 400
    if wan_port == lan_port:
        return jsonify({"ok": False, "message": "WAN and LAN must be different ports."}), 400

    conn = get_db()
    for itype, port in [("WAN", wan_port), ("LAN", lan_port)]:
        conn.execute(
            """
            INSERT INTO interface_assignments (interface_type, network_port)
            VALUES (?, ?)
            ON CONFLICT(interface_type) DO UPDATE SET
                network_port = excluded.network_port
            """,
            (itype, port),
        )
    conn.commit()
    session["setup_wan_port"] = wan_port
    session["setup_lan_port"] = lan_port
    return jsonify({"ok": True, "message": "Interface assignment saved."})


# ---------------------------------------------------------------------------
# Step 2 — LAN IP configuration
# ---------------------------------------------------------------------------

@setup_bp.route("/step2", methods=["GET"])
def step2():
    guard = _wizard_guard()
    if guard:
        return guard
    return render_template("setup/step2_lan.html")


@setup_bp.route("/api/step2/save", methods=["POST"])
def api_step2_save():
    guard = _wizard_guard()
    if guard:
        return jsonify({"ok": False, "message": "Setup already complete."}), 403

    data       = request.get_json(force=True) or {}
    lan_cidr   = (data.get("lan_ip") or "").strip()       # e.g. 192.168.1.1/24
    wan_type   = (data.get("wan_type") or "dhcp").lower() # dhcp | static | pppoe
    wan_ip     = (data.get("wan_ip") or "").strip()
    wan_gw     = (data.get("wan_gw") or "").strip()

    if not lan_cidr:
        return jsonify({"ok": False, "message": "LAN IP/CIDR is required."}), 400

    try:
        import ipaddress
        iface = ipaddress.ip_interface(lan_cidr)
    except ValueError:
        return jsonify({"ok": False, "message": f"Invalid LAN CIDR: {lan_cidr!r}"}), 400

    wan_port = session.get("setup_wan_port", "em0")
    lan_port = session.get("setup_lan_port", "em1")

    conn = get_db()
    conn.execute(
        """
        INSERT INTO lan_config (assigned_port, ipv4_address)
        VALUES (?, ?)
        ON CONFLICT(id) DO UPDATE SET
            assigned_port = excluded.assigned_port,
            ipv4_address  = excluded.ipv4_address
        """,
        (lan_port, lan_cidr),
    )
    conn.execute(
        """
        INSERT INTO wan_config (assigned_port, ipv4_config_type, ipv4_address, ipv4_gateway)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            assigned_port    = excluded.assigned_port,
            ipv4_config_type = excluded.ipv4_config_type,
            ipv4_address     = excluded.ipv4_address,
            ipv4_gateway     = excluded.ipv4_gateway
        """,
        (wan_port, wan_type, wan_ip, wan_gw),
    )
    conn.commit()
    return jsonify({"ok": True, "message": "Network configuration saved."})


# ---------------------------------------------------------------------------
# Step 3 — Admin password
# ---------------------------------------------------------------------------

@setup_bp.route("/step3", methods=["GET"])
def step3():
    guard = _wizard_guard()
    if guard:
        return guard
    return render_template("setup/step3_password.html")


@setup_bp.route("/api/step3/save", methods=["POST"])
def api_step3_save():
    guard = _wizard_guard()
    if guard:
        return jsonify({"ok": False, "message": "Setup already complete."}), 403

    data     = request.get_json(force=True) or {}
    username = (data.get("username") or "admin").strip()
    password = (data.get("password") or "").strip()
    confirm  = (data.get("confirm")  or "").strip()

    if len(password) < 8:
        return jsonify({"ok": False, "message": "Password must be at least 8 characters."}), 400
    if password != confirm:
        return jsonify({"ok": False, "message": "Passwords do not match."}), 400

    from werkzeug.security import generate_password_hash
    pw_hash = generate_password_hash(password)

    conn = get_db()
    existing = conn.execute(
        "SELECT id FROM users WHERE username=?", (username,)
    ).fetchone()
    if existing:
        conn.execute(
            "UPDATE users SET password=? WHERE username=?",
            (pw_hash, username),
        )
    else:
        conn.execute(
            "INSERT INTO users (username, password, is_superuser) VALUES (?, ?, 1)",
            (username, pw_hash),
        )
    conn.commit()
    session["setup_admin_username"] = username
    return jsonify({"ok": True, "message": f"Admin account '{username}' updated."})


# ---------------------------------------------------------------------------
# Step 4 — Apply & finish
# ---------------------------------------------------------------------------

@setup_bp.route("/step4", methods=["GET"])
def step4():
    guard = _wizard_guard()
    if guard:
        return guard
    return render_template("setup/step4_apply.html")


@setup_bp.route("/api/step4/apply", methods=["POST"])
def api_step4_apply():
    guard = _wizard_guard()
    if guard:
        return jsonify({"ok": False, "message": "Setup already complete."}), 403

    conn    = get_db()
    results = []

    try:
        from app.services.service_manager import reload_all_services
        svc_result = reload_all_services(conn)
        results.append({"step": "services", "ok": svc_result["ok"],
                         "details": svc_result.get("results", [])})
    except Exception as exc:
        results.append({"step": "services", "ok": False, "details": str(exc)})

    _mark_setup_complete(conn)

    overall_ok = all(r.get("ok", False) for r in results)
    return jsonify({
        "ok": overall_ok,
        "message": "Setup complete! Redirecting to dashboard." if overall_ok
                   else "Setup finished with warnings — check results.",
        "results": results,
        "redirect": url_for("system.dashboard"),
    })


@setup_bp.route("/complete")
def wizard_complete():
    return redirect(url_for("system.dashboard"))
