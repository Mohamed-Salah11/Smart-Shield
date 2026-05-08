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
import ipaddress

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
from app.validators import validate_interface_name


def _port_payload_from_nics(nics):
    ports = []
    for nic in nics:
        name = (nic.get("name") or "").strip()
        if not name:
            continue

        ether = (nic.get("ether") or "").strip()
        status = (nic.get("status") or "").strip()
        media = (nic.get("media") or "").strip()
        details = []
        if ether:
            details.append(ether)
        if status:
            details.append(f"status: {status}")
        if media:
            details.append(media)

        ports.append({
            "name": name,
            "label": name if not details else f"{name} ({', '.join(details)})",
            "ether": ether,
            "status": status,
            "media": media,
        })
    return ports

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


def _get_saved_setup_ports(conn):
    rows = conn.execute(
        "SELECT interface_type, network_port FROM interface_assignments"
    ).fetchall()
    ports = {
        (row["interface_type"] or "").upper(): (row["network_port"] or "").strip()
        for row in rows
    }
    return ports.get("WAN", ""), ports.get("LAN", "")


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

    try:
        from app.services.network_service import list_physical_nics
        ports = _port_payload_from_nics(list_physical_nics())
        if not ports:
            ports = [
                {"name": "em0", "label": "em0", "ether": "", "status": "", "media": ""},
                {"name": "em1", "label": "em1", "ether": "", "status": "", "media": ""},
            ]
    except Exception:
        ports = [
            {"name": "em0", "label": "em0", "ether": "", "status": "", "media": ""},
            {"name": "em1", "label": "em1", "ether": "", "status": "", "media": ""},
        ]

    return jsonify({"ok": True, "status": "success", "ports": ports})


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
    try:
        validate_interface_name(wan_port, allow_empty=False)
        validate_interface_name(lan_port, allow_empty=False)
    except ValueError as exc:
        return jsonify({"ok": False, "message": str(exc)}), 400

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
    conn.execute(
        """
        UPDATE wan_config
        SET assigned_port = ?
        WHERE id = 1
        """,
        (wan_port,),
    )
    conn.execute(
        """
        UPDATE lan_config
        SET assigned_port = ?
        WHERE id = 1
        """,
        (lan_port,),
    )
    conn.commit()
    session["setup_wan_port"] = wan_port
    session["setup_lan_port"] = lan_port
    return jsonify({"ok": True, "message": "Interface assignment saved."})


# ---------------------------------------------------------------------------
# Step 2 — LAN IP configuration
# ---------------------------------------------------------------------------

@setup_bp.route("/api/step2/bsd-detect", methods=["GET"])
def api_step2_bsd_detect():
    """Read current BSD state for both WAN and LAN interfaces assigned in step 1."""
    conn = get_db()
    from app.services.network_service import read_interface_config_from_bsd
    wan_row = conn.execute("SELECT assigned_port FROM wan_config WHERE id=1").fetchone()
    lan_row = conn.execute("SELECT assigned_port FROM lan_config WHERE id=1").fetchone()
    wan_iface = ((wan_row["assigned_port"] or "").strip()) if wan_row else ""
    lan_iface = ((lan_row["assigned_port"] or "").strip()) if lan_row else ""
    return jsonify({
        "ok": True,
        "wan": read_interface_config_from_bsd(wan_iface) if wan_iface else {},
        "lan": read_interface_config_from_bsd(lan_iface) if lan_iface else {},
    })


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
        ipaddress.ip_interface(lan_cidr)
    except ValueError:
        return jsonify({"ok": False, "message": f"Invalid LAN CIDR: {lan_cidr!r}"}), 400

    if wan_type not in {"dhcp", "static", "pppoe"}:
        return jsonify({"ok": False, "message": "Invalid WAN type."}), 400

    if wan_type == "static":
        if not wan_ip:
            return jsonify({"ok": False, "message": "WAN static IP/CIDR is required."}), 400
        try:
            ipaddress.ip_interface(wan_ip)
        except ValueError:
            return jsonify({"ok": False, "message": f"Invalid WAN CIDR: {wan_ip!r}"}), 400
        if wan_gw:
            try:
                ipaddress.ip_address(wan_gw)
            except ValueError:
                return jsonify({"ok": False, "message": f"Invalid WAN gateway: {wan_gw!r}"}), 400
    else:
        wan_ip = ""
        wan_gw = ""

    conn = get_db()
    wan_port, lan_port = _get_saved_setup_ports(conn)
    wan_port = wan_port or session.get("setup_wan_port", "")
    lan_port = lan_port or session.get("setup_lan_port", "")

    if not wan_port or not lan_port:
        return jsonify({
            "ok": False,
            "message": "WAN/LAN ports are not assigned. Go back to Step 1.",
        }), 400

    conn.execute(
        """
         INSERT INTO lan_config
             (id, assigned_port, ipv4_config_type, ipv4_address)
        VALUES (1, ?, 'static', ?)
         ON CONFLICT(id) DO UPDATE SET
             assigned_port     = excluded.assigned_port,
             ipv4_config_type  = excluded.ipv4_config_type,
             ipv4_address      = excluded.ipv4_address
         """,
        (lan_port, lan_cidr),
    )
    conn.execute(
          """
          INSERT INTO wan_config
             (id, assigned_port, ipv4_config_type, ipv4_address, ipv4_upstream_gateway)
           VALUES (1, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                 assigned_port          = excluded.assigned_port,
                  ipv4_config_type       = excluded.ipv4_config_type,
                  ipv4_address           = excluded.ipv4_address,
                 ipv4_upstream_gateway  = excluded.ipv4_upstream_gateway
         """,
        (wan_port, wan_type, wan_ip, wan_gw),
    )
    conn.execute(
        """
        INSERT INTO interface_assignments (interface_type, network_port)
        VALUES ('WAN', ?)
        ON CONFLICT(interface_type) DO UPDATE SET
            network_port = excluded.network_port
        """,
        (wan_port,),
    )
    conn.execute(
        """
        INSERT INTO interface_assignments (interface_type, network_port)
        VALUES ('LAN', ?)
        ON CONFLICT(interface_type) DO UPDATE SET
            network_port = excluded.network_port
        """,
        (lan_port,),
    )
    conn.commit()

    # Auto-configure a DHCP pool from the saved LAN CIDR so devices get IPs on first boot
    try:
        from app.services.dhcp_writer import auto_configure_pool
        auto_configure_pool(conn, "LAN")
    except Exception:
        pass  # Non-fatal — admin can configure DHCP manually via the services page

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
        from app.services.rc_conf_writer import apply_rc_conf
        rc_result = apply_rc_conf(conn)
        results.append({
            "step": "rc_conf",
            "ok": rc_result.get("ok", False),
            "details": rc_result.get("message", ""),
        })
    except Exception as exc:
        results.append({"step": "rc_conf", "ok": False, "details": str(exc)})

    try:
        from app.services.network_service import apply_interface_config
        iface_result = apply_interface_config(conn)
        results.append({
            "step": "interfaces",
            "ok": iface_result.get("ok", False),
            "details": iface_result.get("message", ""),
        })
    except Exception as exc:
        results.append({"step": "interfaces", "ok": False, "details": str(exc)})

    try:
        from app.services.service_manager import reload_all_services
        svc_result = reload_all_services(conn)
        results.append({
            "step": "services",
            "ok": svc_result.get("ok", False),
            "details": svc_result.get("results", []),
        })
    except Exception as exc:
        results.append({"step": "services", "ok": False, "details": str(exc)})

    try:
        from app.services.mrtg_writer import apply_mrtg
        mrtg_result = apply_mrtg(conn)
        results.append({
            "step": "mrtg",
            "ok": mrtg_result.get("ok", False),
            "details": mrtg_result.get("message", ""),
        })
    except Exception as exc:
        results.append({"step": "mrtg", "ok": False, "details": str(exc)})

    # Only require the three network steps; MRTG is optional and must not block completion
    _REQUIRED = {"rc_conf", "interfaces", "services"}
    overall_ok = all(r.get("ok", False) for r in results if r.get("step") in _REQUIRED)
    if overall_ok:
        _mark_setup_complete(conn)

    return jsonify({
        "ok": overall_ok,
        "message": "Setup complete! Redirecting to dashboard." if overall_ok
                   else "Setup finished with warnings — check results.",
        "results": results,
        "redirect": url_for("system.dashboard") if overall_ok else None,
    })


@setup_bp.route("/complete")
def wizard_complete():
    return redirect(url_for("system.dashboard"))
