import sqlite3

from flask import render_template, request, jsonify, session, redirect, url_for
from app.database import get_db
from app.auth_utils import login_required
from app.api_auth import api_permission_required
from app.validators import (
    validate_ip, validate_cidr, validate_protocol,
    validate_description, validate_name, collect_errors,
    validate_port_list,
)

from routes.firewall import firewall_bp
from routes.firewall._common import _validate_rule


# ----------------------------
# FIREWALL MAIN PAGE
# ----------------------------

@firewall_bp.route("/")
@login_required
def firewall_home():
    # The firewall landing page itself is a stub; send operators to the real
    # rules page so production navigation never lands on a placeholder.
    return redirect(url_for("firewall.rules"))


# ----------------------------
# FIREWALL RULES
# ----------------------------

@firewall_bp.route("/rules")
@login_required
def rules():
    return render_template("rules.html")


# Floating Rules CRUD
@firewall_bp.route("/api/rules/floating", methods=["GET"])
@login_required
def get_floating_rules():
    """Get all floating firewall rules"""
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("""
            SELECT id, action, disabled, interface, protocol, source, source_port,
                   destination, dest_port, gateway, queue, schedule, description
            FROM firewall_rules_floating
            ORDER BY rule_order
        """)
        rules = [dict(row) for row in cursor.fetchall()]
        return jsonify({"success": True, "rules": rules})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/rules/floating", methods=["POST"])
@api_permission_required("api.firewall.edit")
def add_floating_rule():
    """Add a new floating rule"""
    try:
        data = request.get_json(silent=True) or {}
        err = _validate_rule(data)
        if err:
            return jsonify({"success": False, "error": err}), 400
        db = get_db()
        cursor = db.cursor()

        position = data.get('position', 'bottom')
        
        if position == 'top':
            # Shift all existing rules down
            cursor.execute("UPDATE firewall_rules_floating SET rule_order = rule_order + 1")
            new_order = 1
        else:
            # Add at bottom
            cursor.execute("SELECT COALESCE(MAX(rule_order), 0) + 1 FROM firewall_rules_floating")
            new_order = cursor.fetchone()[0]
        
        cursor.execute("""
            INSERT INTO firewall_rules_floating
            (action, disabled, interface, protocol, source, source_port, destination,
             dest_port, gateway, queue, schedule, description, rule_order, log_enabled)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data.get('action', 'pass'),
            data.get('disabled', 0),
            data.get('interface', 'WAN'),
            data.get('protocol', 'any'),
            data.get('source', 'any'),
            data.get('source_port', ''),
            data.get('destination', 'any'),
            data.get('dest_port', ''),
            data.get('gateway', ''),
            data.get('queue', ''),
            data.get('schedule', ''),
            data.get('description', ''),
            new_order,
            1 if data.get('log_enabled') else 0,
        ))
        
        db.commit()
        new_id = cursor.lastrowid
        from app.audit_log import log_event
        log_event(
            category="system", action="firewall_rule_added", severity="medium",
            username=session.get("username"), remote_addr=request.remote_addr,
            details={
                "rule_type":   "floating",
                "rule_id":     new_id,
                "action":      data.get("action", "pass"),
                "protocol":    data.get("protocol", "any"),
                "source":      data.get("source", "any"),
                "destination": data.get("destination", "any"),
                "dest_port":   data.get("dest_port", ""),
                "description": data.get("description", ""),
            },
        )
        return jsonify({"success": True, "id": new_id})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/rules/floating/<int:rule_id>/move", methods=["POST"])
@api_permission_required("api.firewall.edit")
def move_floating_rule(rule_id):
    """Move a floating rule up or down"""
    try:
        data = request.get_json(silent=True) or {}
        direction = data.get('direction', 'up')
        db = get_db()
        cursor = db.cursor()
        
        # Get current rule order
        cursor.execute("SELECT rule_order FROM firewall_rules_floating WHERE id=?", (rule_id,))
        row = cursor.fetchone()
        if not row:
            return jsonify({"success": False, "error": "Rule not found"}), 404
        
        current_order = row[0]
        
        if direction == 'up':
            # Find the rule above
            cursor.execute("""
                SELECT id, rule_order FROM firewall_rules_floating 
                WHERE rule_order < ? ORDER BY rule_order DESC LIMIT 1
            """, (current_order,))
            swap_row = cursor.fetchone()
        else:
            # Find the rule below
            cursor.execute("""
                SELECT id, rule_order FROM firewall_rules_floating 
                WHERE rule_order > ? ORDER BY rule_order ASC LIMIT 1
            """, (current_order,))
            swap_row = cursor.fetchone()
        
        if swap_row:
            swap_id, swap_order = swap_row
            # Swap the orders
            cursor.execute("UPDATE firewall_rules_floating SET rule_order=? WHERE id=?", (swap_order, rule_id))
            cursor.execute("UPDATE firewall_rules_floating SET rule_order=? WHERE id=?", (current_order, swap_id))
            db.commit()
        
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/rules/floating/<int:rule_id>", methods=["GET"])
@login_required
def get_floating_rule(rule_id):
    """Get a single floating rule by ID"""
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            "SELECT id, action, disabled, interface, protocol, source, source_port, "
            "destination, dest_port, gateway, queue, schedule, description, log_enabled "
            "FROM firewall_rules_floating WHERE id=?", (rule_id,)
        )
        row = cursor.fetchone()
        if not row:
            return jsonify({"success": False, "error": "Rule not found"}), 404
        return jsonify({"success": True, "rule": dict(row)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/rules/floating/<int:rule_id>", methods=["PUT"])
@api_permission_required("api.firewall.edit")
def update_floating_rule(rule_id):
    """Update a floating rule"""
    try:
        data = request.get_json(silent=True) or {}
        err = _validate_rule(data)
        if err:
            return jsonify({"success": False, "error": err}), 400
        db = get_db()
        cursor = db.cursor()

        cursor.execute("""
            UPDATE firewall_rules_floating
            SET action=?, disabled=?, interface=?, protocol=?, source=?, source_port=?,
                destination=?, dest_port=?, gateway=?, queue=?, schedule=?, description=?,
                log_enabled=?
            WHERE id=?
        """, (
            data.get('action', 'pass'),
            data.get('disabled', 0),
            data.get('interface'),
            data.get('protocol'),
            data.get('source'),
            data.get('source_port'),
            data.get('destination'),
            data.get('dest_port'),
            data.get('gateway'),
            data.get('queue'),
            data.get('schedule'),
            data.get('description'),
            1 if data.get('log_enabled') else 0,
            rule_id
        ))
        
        db.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/rules/floating/<int:rule_id>", methods=["DELETE"])
@api_permission_required("api.firewall.edit")
def delete_floating_rule(rule_id):
    """Delete a floating rule"""
    try:
        db = get_db()
        cursor = db.cursor()
        row = cursor.execute(
            "SELECT action, protocol, source, destination, dest_port, description FROM firewall_rules_floating WHERE id=?",
            (rule_id,)
        ).fetchone()
        cursor.execute("DELETE FROM firewall_rules_floating WHERE id=?", (rule_id,))
        db.commit()
        from app.audit_log import log_event
        log_event(
            category="system", action="firewall_rule_deleted", severity="medium",
            username=session.get("username"), remote_addr=request.remote_addr,
            details={"rule_type": "floating", "rule_id": rule_id,
                     **(dict(row) if row else {})},
        )
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# WAN Rules CRUD
@firewall_bp.route("/api/rules/wan", methods=["GET"])
@login_required
def get_wan_rules():
    """Get all WAN firewall rules"""
    db = None
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("""
            SELECT id, action, disabled, protocol, source, source_port, destination, dest_port, description
            FROM firewall_rules_wan
            ORDER BY rule_order
        """)
        rules = [dict(row) for row in cursor.fetchall()]
        return jsonify({"success": True, "rules": rules})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@firewall_bp.route("/api/rules/wan", methods=["POST"])
@api_permission_required("api.firewall.edit")
def add_wan_rule():
    """Add a new WAN rule"""
    db = None
    try:
        data = request.get_json(silent=True) or {}
        err = _validate_rule(data)
        if err:
            return jsonify({"success": False, "error": err}), 400
        db = get_db()
        cursor = db.cursor()

        position = data.get('position', 'bottom')

        if position == 'top':
            cursor.execute("UPDATE firewall_rules_wan SET rule_order = rule_order + 1")
            new_order = 1
        else:
            cursor.execute("SELECT COALESCE(MAX(rule_order), 0) + 1 FROM firewall_rules_wan")
            new_order = cursor.fetchone()[0]
        
        cursor.execute("""
            INSERT INTO firewall_rules_wan
            (action, disabled, protocol, source, source_port, destination,
             dest_port, description, rule_order, log_enabled)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data.get('action', 'pass'),
            data.get('disabled', 0),
            data.get('protocol', 'any'),
            data.get('source', 'any'),
            data.get('source_port', ''),
            data.get('destination', 'any'),
            data.get('dest_port', ''),
            data.get('description', ''),
            new_order,
            1 if data.get('log_enabled') else 0,
        ))
        
        db.commit()
        return jsonify({"success": True, "id": cursor.lastrowid})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@firewall_bp.route("/api/rules/wan/<int:rule_id>/move", methods=["POST"])
@api_permission_required("api.firewall.edit")
def move_wan_rule(rule_id):
    """Move a WAN rule up or down"""
    try:
        data = request.get_json(silent=True) or {}
        direction = data.get('direction', 'up')
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("SELECT rule_order FROM firewall_rules_wan WHERE id=?", (rule_id,))
        row = cursor.fetchone()
        if not row:
            return jsonify({"success": False, "error": "Rule not found"}), 404
        
        current_order = row[0]
        
        if direction == 'up':
            cursor.execute("""
                SELECT id, rule_order FROM firewall_rules_wan 
                WHERE rule_order < ? ORDER BY rule_order DESC LIMIT 1
            """, (current_order,))
        else:
            cursor.execute("""
                SELECT id, rule_order FROM firewall_rules_wan 
                WHERE rule_order > ? ORDER BY rule_order ASC LIMIT 1
            """, (current_order,))
        
        swap_row = cursor.fetchone()
        if swap_row:
            swap_id, swap_order = swap_row
            cursor.execute("UPDATE firewall_rules_wan SET rule_order=? WHERE id=?", (swap_order, rule_id))
            cursor.execute("UPDATE firewall_rules_wan SET rule_order=? WHERE id=?", (current_order, swap_id))
            db.commit()
        
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/rules/wan/<int:rule_id>", methods=["GET"])
@login_required
def get_wan_rule(rule_id):
    """Get a single WAN rule by ID"""
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            "SELECT id, action, disabled, protocol, source, source_port, "
            "destination, dest_port, description, log_enabled "
            "FROM firewall_rules_wan WHERE id=?", (rule_id,)
        )
        row = cursor.fetchone()
        if not row:
            return jsonify({"success": False, "error": "Rule not found"}), 404
        return jsonify({"success": True, "rule": dict(row)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/rules/wan/<int:rule_id>", methods=["PUT"])
@api_permission_required("api.firewall.edit")
def update_wan_rule(rule_id):
    """Update a WAN rule"""
    try:
        data = request.get_json(silent=True) or {}
        err = _validate_rule(data)
        if err:
            return jsonify({"success": False, "error": err}), 400
        db = get_db()
        cursor = db.cursor()

        cursor.execute("""
            UPDATE firewall_rules_wan
            SET action=?, disabled=?, protocol=?, source=?, source_port=?,
                destination=?, dest_port=?, description=?, log_enabled=?
            WHERE id=?
        """, (
            data.get('action'),
            data.get('disabled'),
            data.get('protocol'),
            data.get('source'),
            data.get('source_port'),
            data.get('destination'),
            data.get('dest_port'),
            data.get('description'),
            1 if data.get('log_enabled') else 0,
            rule_id
        ))
        
        db.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/rules/wan/<int:rule_id>", methods=["DELETE"])
@api_permission_required("api.firewall.edit")
def delete_wan_rule(rule_id):
    """Delete a WAN rule"""
    try:
        db = get_db()
        cursor = db.cursor()
        row = cursor.execute(
            "SELECT action, protocol, source, destination, dest_port, description FROM firewall_rules_wan WHERE id=?",
            (rule_id,)
        ).fetchone()
        cursor.execute("DELETE FROM firewall_rules_wan WHERE id=?", (rule_id,))
        db.commit()
        from app.audit_log import log_event
        log_event(
            category="system", action="firewall_rule_deleted", severity="medium",
            username=session.get("username"), remote_addr=request.remote_addr,
            details={"rule_type": "wan", "rule_id": rule_id,
                     **(dict(row) if row else {})},
        )
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# LAN Rules CRUD
@firewall_bp.route("/api/rules/lan", methods=["GET"])
@login_required
def get_lan_rules():
    """Get all LAN firewall rules"""
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("""
            SELECT id, action, disabled, interface, protocol, source, source_port,
                   destination, dest_port, description
            FROM firewall_rules_lan
            ORDER BY rule_order
        """)
        rules = [dict(row) for row in cursor.fetchall()]
        return jsonify({"success": True, "rules": rules})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/rules/lan", methods=["POST"])
@api_permission_required("api.firewall.edit")
def add_lan_rule():
    """Add a new LAN rule"""
    try:
        data = request.get_json(silent=True) or {}
        err = _validate_rule(data)
        if err:
            return jsonify({"success": False, "error": err}), 400
        db = get_db()
        cursor = db.cursor()

        position = data.get('position', 'bottom')

        if position == 'top':
            cursor.execute("UPDATE firewall_rules_lan SET rule_order = rule_order + 1")
            new_order = 1
        else:
            cursor.execute("SELECT COALESCE(MAX(rule_order), 0) + 1 FROM firewall_rules_lan")
            new_order = cursor.fetchone()[0]
        
        cursor.execute("""
            INSERT INTO firewall_rules_lan
            (action, disabled, interface, protocol, source, source_port,
             destination, dest_port, description, rule_order, log_enabled)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data.get('action', 'pass'),
            data.get('disabled', 0),
            data.get('interface', 'LAN'),
            data.get('protocol', 'any'),
            data.get('source', 'any'),
            data.get('source_port', ''),
            data.get('destination', 'any'),
            data.get('dest_port', ''),
            data.get('description', ''),
            new_order,
            1 if data.get('log_enabled') else 0,
        ))
        
        db.commit()
        return jsonify({"success": True, "id": cursor.lastrowid})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/rules/lan/<int:rule_id>/move", methods=["POST"])
@api_permission_required("api.firewall.edit")
def move_lan_rule(rule_id):
    """Move a LAN rule up or down"""
    try:
        data = request.get_json(silent=True) or {}
        direction = data.get('direction', 'up')
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("SELECT rule_order FROM firewall_rules_lan WHERE id=?", (rule_id,))
        row = cursor.fetchone()
        if not row:
            return jsonify({"success": False, "error": "Rule not found"}), 404
        
        current_order = row[0]
        
        if direction == 'up':
            cursor.execute("""
                SELECT id, rule_order FROM firewall_rules_lan 
                WHERE rule_order < ? ORDER BY rule_order DESC LIMIT 1
            """, (current_order,))
        else:
            cursor.execute("""
                SELECT id, rule_order FROM firewall_rules_lan 
                WHERE rule_order > ? ORDER BY rule_order ASC LIMIT 1
            """, (current_order,))
        
        swap_row = cursor.fetchone()
        if swap_row:
            swap_id, swap_order = swap_row
            cursor.execute("UPDATE firewall_rules_lan SET rule_order=? WHERE id=?", (swap_order, rule_id))
            cursor.execute("UPDATE firewall_rules_lan SET rule_order=? WHERE id=?", (current_order, swap_id))
            db.commit()
        
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/rules/lan/<int:rule_id>", methods=["GET"])
@login_required
def get_lan_rule(rule_id):
    """Get a single LAN rule by ID"""
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            "SELECT id, action, disabled, interface, protocol, source, source_port, "
            "destination, dest_port, description, log_enabled "
            "FROM firewall_rules_lan WHERE id=?", (rule_id,)
        )
        row = cursor.fetchone()
        if not row:
            return jsonify({"success": False, "error": "Rule not found"}), 404
        return jsonify({"success": True, "rule": dict(row)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/rules/lan/<int:rule_id>", methods=["PUT"])
@api_permission_required("api.firewall.edit")
def update_lan_rule(rule_id):
    """Update a LAN rule"""
    try:
        data = request.get_json(silent=True) or {}
        err = _validate_rule(data)
        if err:
            return jsonify({"success": False, "error": err}), 400
        db = get_db()
        cursor = db.cursor()

        cursor.execute("""
            UPDATE firewall_rules_lan
            SET action=?, disabled=?, interface=?, protocol=?, source=?, source_port=?,
                destination=?, dest_port=?, description=?, log_enabled=?
            WHERE id=?
        """, (
            data.get('action', 'pass'),
            data.get('disabled'),
            data.get('interface'),
            data.get('protocol'),
            data.get('source'),
            data.get('source_port'),
            data.get('destination'),
            data.get('dest_port'),
            data.get('description'),
            1 if data.get('log_enabled') else 0,
            rule_id
        ))
        
        db.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/rules/lan/<int:rule_id>", methods=["DELETE"])
@api_permission_required("api.firewall.edit")
def delete_lan_rule(rule_id):
    """Delete a LAN rule"""
    try:
        db = get_db()
        cursor = db.cursor()
        row = cursor.execute(
            "SELECT action, protocol, source, destination, dest_port, description FROM firewall_rules_lan WHERE id=?",
            (rule_id,)
        ).fetchone()
        cursor.execute("DELETE FROM firewall_rules_lan WHERE id=?", (rule_id,))
        db.commit()
        from app.audit_log import log_event
        log_event(
            category="system", action="firewall_rule_deleted", severity="medium",
            username=session.get("username"), remote_addr=request.remote_addr,
            details={"rule_type": "lan", "rule_id": rule_id,
                     **(dict(row) if row else {})},
        )
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ----------------------------
# FIREWALL NAT
# ----------------------------
