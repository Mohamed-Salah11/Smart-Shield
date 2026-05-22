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
from hmac import compare_digest

from flask import (
    Blueprint,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from app.database import get_db
from app.validators import validate_interface_name


# Path to the one-time setup claim token written on first boot by the BSD
# rc.d script and printed to the local console. Overridable for dev/testing.
SETUP_CLAIM_TOKEN_PATH = os.getenv(
    "SMARTSHIELD_SETUP_CLAIM_TOKEN_PATH",
    "/var/db/smartshield/setup_claim_token",
)


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
    # The one-time claim token is now spent — remove it so it cannot be
    # replayed to re-enter the wizard.
    _clear_claim_token()


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
    """Redirect non-admin users away from wizard if it's already done."""
    if _is_setup_complete():
        # Admins (superusers) may re-enter the wizard after completion.
        from flask import session as _session
        from app.database import get_db as _get_db
        try:
            user_id = _session.get("user_id")
            if user_id:
                conn = _get_db()
                row  = conn.execute(
                    "SELECT is_superuser FROM users WHERE id=?", (user_id,)
                ).fetchone()
                if row and row["is_superuser"]:
                    return None  # Admins can always re-run setup
        except Exception:
            pass
        flash("Setup has already been completed.", "info")
        return redirect(url_for("system.dashboard"))
    return None


# ---------------------------------------------------------------------------
# First-boot access control
#
# The wizard is unauthenticated by necessity (no users exist on a fresh
# install), so it is gated three ways before the first admin is created:
#   1. An authenticated superuser may always (re-)run setup.
#   2. Once an admin exists, unauthenticated setup is refused (login required).
#   3. On a fresh install the request must come from a LAN/loopback source AND
#      present the one-time claim token printed on the local console.
# A session that successfully claims (or runs on a token-less dev host) is
# trusted for the remainder of the wizard, including after step 3 creates the
# admin account.
# ---------------------------------------------------------------------------

def _read_claim_token() -> str | None:
    try:
        with open(SETUP_CLAIM_TOKEN_PATH, "r", encoding="utf-8") as fh:
            token = fh.read().strip()
            return token or None
    except OSError:
        return None


def _clear_claim_token() -> None:
    try:
        os.remove(SETUP_CLAIM_TOKEN_PATH)
    except OSError:
        pass
    # Drop a sentinel so the boot-time token generator does not re-create the
    # claim token after setup has been completed.
    try:
        sentinel = os.path.join(os.path.dirname(SETUP_CLAIM_TOKEN_PATH), ".setup_claimed")
        with open(sentinel, "w", encoding="utf-8") as fh:
            fh.write("1\n")
    except OSError:
        pass


def _admin_exists() -> bool:
    try:
        conn = get_db()
        row = conn.execute(
            "SELECT COUNT(*) AS c FROM users WHERE COALESCE(is_superuser, 0) = 1"
        ).fetchone()
        return (row["c"] if row else 0) > 0
    except Exception:
        return False


def _is_authenticated_superuser() -> bool:
    user_id = session.get("user_id")
    if not user_id:
        return False
    try:
        conn = get_db()
        row = conn.execute("SELECT is_superuser FROM users WHERE id=?", (user_id,)).fetchone()
        return bool(row and row["is_superuser"])
    except Exception:
        return False


def _request_is_lan() -> bool:
    """True when the request source is loopback or RFC1918/ULA (LAN). Used to
    keep the unauthenticated first-boot wizard off the WAN."""
    remote = request.remote_addr or ""
    try:
        ip = ipaddress.ip_address(remote)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private or ip.is_link_local


@setup_bp.before_request
def _enforce_setup_access():
    # The claim-token entry endpoints must stay reachable so the operator can
    # submit the token; they perform their own validation.
    if request.endpoint in {"setup.claim_form", "setup.claim_submit"}:
        return None

    # Superusers may always re-run setup (e.g. to reassign interfaces).
    if _is_authenticated_superuser():
        return None

    # A session that already claimed the install is trusted through the rest
    # of the wizard (including after step 3 creates the admin).
    if session.get("setup_session_authorized"):
        return None

    # Once an admin exists, unauthenticated setup is not allowed.
    if _admin_exists():
        if request.path.startswith("/setup/api/"):
            return jsonify({"ok": False, "message": "Administrator login required."}), 403
        flash("Setup requires an administrator login.", "warning")
        return redirect(url_for("auth.login"))

    # Fresh install: must be on LAN/loopback.
    if not _request_is_lan():
        if request.path.startswith("/setup/api/"):
            return jsonify({"ok": False, "message": "Setup is only available from the local network."}), 403
        return render_template("setup/not_authorized.html"), 403

    # Fresh install: require the console claim token if one was provisioned.
    token = _read_claim_token()
    if token:
        if request.path.startswith("/setup/api/"):
            return jsonify({"ok": False, "message": "Setup claim token required.", "claim_required": True}), 401
        return redirect(url_for("setup.claim_form"))

    # No token file present (dev/lab host) — allow, and trust this session.
    session["setup_session_authorized"] = True
    return None


@setup_bp.route("/claim", methods=["GET"])
def claim_form():
    if _is_setup_complete() or _admin_exists():
        return redirect(url_for("auth.login"))
    if not _request_is_lan():
        return render_template("setup/not_authorized.html"), 403
    return render_template("setup/claim.html")


@setup_bp.route("/api/claim", methods=["POST"])
def claim_submit():
    if _is_setup_complete() or _admin_exists():
        return jsonify({"ok": False, "message": "Setup is no longer available."}), 403
    if not _request_is_lan():
        return jsonify({"ok": False, "message": "Setup is only available from the local network."}), 403

    expected = _read_claim_token()
    if not expected:
        # No token configured — token-less dev/lab host. Authorize directly.
        session["setup_session_authorized"] = True
        return jsonify({"ok": True})

    data = request.get_json(silent=True) or {}
    provided = (data.get("token") or "").strip()
    if provided and compare_digest(provided, expected):
        session["setup_session_authorized"] = True
        return jsonify({"ok": True})
    return jsonify({"ok": False, "message": "Invalid setup claim token."}), 403


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

    # Phase 5.3: cross-check the submitted port names against actual host
    # interfaces. The form normally only offers detected NICs, but the JSON
    # endpoint can be hit directly — refuse names ifconfig does not know.
    try:
        from app.services.network_service import list_physical_nics
        available = {(n.get("name") or "").strip() for n in list_physical_nics()}
        # Empty set means detection failed (dev host) — skip the cross-check
        # in that case rather than blocking install on unrelated NIC errors.
        if available:
            for label, port in [("WAN", wan_port), ("LAN", lan_port)]:
                if port not in available:
                    return jsonify({
                        "ok": False,
                        "message": (
                            f"{label} interface {port!r} not detected on this host. "
                            f"Available: {sorted(available)}"
                        ),
                    }), 400
    except Exception:
        pass  # detection failure is non-fatal — fall through to save

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

    if password != confirm:
        return jsonify({"ok": False, "message": "Passwords do not match."}), 400

    from app.password_policy import validate_password
    errs = validate_password(password, username=username)
    if errs:
        return jsonify({"ok": False, "message": " ".join(errs)}), 400

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
        audit_action = "setup_admin_password_reset"
    else:
        conn.execute(
            "INSERT INTO users (username, password, is_superuser) VALUES (?, ?, 1)",
            (username, pw_hash),
        )
        audit_action = "setup_admin_created"
    conn.commit()
    session["setup_admin_username"] = username
    try:
        from app.audit_log import log_event
        log_event(
            category="security",
            action=audit_action,
            username=username,
            remote_addr=request.remote_addr or "",
            details={"is_superuser": True},
        )
    except Exception:
        pass
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

    # End-to-end verification: are the things the admin actually needs working
    # (LAN IP applied, default route present, forwarding on, PF enabled, NAT
    # rule loaded, DNS+nginx listening) live on the appliance? Reports
    # actionable warnings without blocking wizard completion — the admin can
    # still finish, then fix issues from the dashboard.
    verification = _wizard_verify(conn)
    results.append({"step": "verify", "ok": verification.get("ok", False),
                    "details": verification})

    # Only require the three network steps; MRTG + verify are advisory and
    # must not block wizard completion.
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


def _wizard_verify(conn) -> dict:
    """End-to-end smoke check after Step 4 apply.

    Returns a dict of named boolean checks plus a top-level ``ok`` and human
    summary. Tolerates non-FreeBSD (everything reports skipped=True there).
    """
    import sys as _sys
    out = {
        "lan_ip_ok": False, "default_route_ok": False, "forwarding_ok": False,
        "pf_enabled": False, "nat_present": False,
        "unbound_listening": False, "nginx_listening": False,
        "messages": [],
    }
    if not _sys.platform.startswith("freebsd"):
        out["ok"] = True
        out["skipped"] = True
        out["messages"].append("Non-FreeBSD — verification skipped.")
        return out

    from app.services.network_service import run_command

    lan_rows = conn.execute("SELECT assigned_port, ipv4_address FROM lan_config WHERE id=1").fetchall()
    lan_iface = (lan_rows[0]["assigned_port"] if lan_rows else "") or ""
    lan_cidr  = (lan_rows[0]["ipv4_address"]  if lan_rows else "") or ""
    expected_ip = ""
    if lan_cidr and "/" in lan_cidr:
        try:
            import ipaddress as _ip
            expected_ip = str(_ip.ip_interface(lan_cidr).ip)
        except ValueError:
            pass

    # LAN IP actually configured on the interface?
    if lan_iface and expected_ip:
        try:
            r = run_command(["ifconfig", lan_iface], check=False, timeout_seconds=5)
            out["lan_ip_ok"] = expected_ip in (r.stdout or "")
            if not out["lan_ip_ok"]:
                out["messages"].append(f"LAN IP {expected_ip} not visible on {lan_iface}.")
        except Exception as exc:
            out["messages"].append(f"ifconfig failed: {exc}")

    # Default route present?
    try:
        r = run_command(["netstat", "-rn", "-f", "inet"], check=False, timeout_seconds=5)
        for line in (r.stdout or "").splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "default":
                out["default_route_ok"] = True
                break
        if not out["default_route_ok"]:
            out["messages"].append("No default route present.")
    except Exception as exc:
        out["messages"].append(f"netstat failed: {exc}")

    # ip forwarding sysctl
    try:
        r = run_command(["sysctl", "-n", "net.inet.ip.forwarding"], check=False, timeout_seconds=3)
        out["forwarding_ok"] = (r.stdout or "").strip() == "1"
        if not out["forwarding_ok"]:
            out["messages"].append("net.inet.ip.forwarding != 1 — LAN clients won't route.")
    except Exception:
        pass

    # PF enabled + NAT rule loaded
    try:
        r = run_command(["pfctl", "-s", "info"], check=False, timeout_seconds=5)
        out["pf_enabled"] = "Status: Enabled" in (r.stdout or "")
        if not out["pf_enabled"]:
            out["messages"].append("PF is not enabled.")
    except Exception:
        pass
    try:
        r = run_command(["pfctl", "-sn"], check=False, timeout_seconds=5)
        out["nat_present"] = "nat " in (r.stdout or "") or "nat-anchor" in (r.stdout or "")
        if not out["nat_present"]:
            out["messages"].append("No NAT rule loaded in PF — LAN clients won't reach WAN.")
    except Exception:
        pass

    # Unbound and nginx listeners
    try:
        r = run_command(["sockstat", "-4", "-l"], check=False, timeout_seconds=5)
        stdout = r.stdout or ""
        out["unbound_listening"] = any(":53 " in ln or ":53\t" in ln for ln in stdout.splitlines())
        if not out["unbound_listening"]:
            out["messages"].append("Unbound is not listening on :53.")
        out["nginx_listening"] = any(":80 " in ln or ":443 " in ln or ":80\t" in ln or ":443\t" in ln
                                     for ln in stdout.splitlines())
        if not out["nginx_listening"]:
            out["messages"].append("Nginx is not listening on :80/:443.")
    except Exception:
        pass

    # Overall: anything advisory enough that the wizard should still complete —
    # but report ok=True only when every check passes.
    out["ok"] = all([
        out["lan_ip_ok"], out["default_route_ok"], out["forwarding_ok"],
        out["pf_enabled"], out["nat_present"],
        out["unbound_listening"], out["nginx_listening"],
    ])
    return out


@setup_bp.route("/complete")
def wizard_complete():
    return redirect(url_for("system.dashboard"))
