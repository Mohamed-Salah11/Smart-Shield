import sqlite3

from flask import Blueprint, render_template, request, jsonify
from app.database import get_db
from app.auth_utils import login_required

firewall_bp = Blueprint("firewall", __name__, url_prefix="/firewall")

# ----------------------------
# FIREWALL MAIN PAGE
# ----------------------------

@firewall_bp.route("/")
@login_required
def firewall_home():
    return render_template("firewall.html")


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
            SELECT id, disabled, interface, protocol, source, source_port, 
                   destination, dest_port, gateway, queue, schedule, description
            FROM firewall_rules_floating
            ORDER BY rule_order
        """)
        rules = [dict(row) for row in cursor.fetchall()]
        return jsonify({"success": True, "rules": rules})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/rules/floating", methods=["POST"])
@login_required
def add_floating_rule():
    """Add a new floating rule"""
    try:
        data = request.get_json()
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
            (disabled, interface, protocol, source, source_port, destination, 
             dest_port, gateway, queue, schedule, description, rule_order)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
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
            new_order
        ))
        
        db.commit()
        return jsonify({"success": True, "id": cursor.lastrowid})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/rules/floating/<int:rule_id>/move", methods=["POST"])
@login_required
def move_floating_rule(rule_id):
    """Move a floating rule up or down"""
    try:
        data = request.get_json()
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


@firewall_bp.route("/api/rules/floating/<int:rule_id>", methods=["PUT"])
@login_required
def update_floating_rule(rule_id):
    """Update a floating rule"""
    try:
        data = request.get_json()
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("""
            UPDATE firewall_rules_floating 
            SET disabled=?, interface=?, protocol=?, source=?, source_port=?, 
                destination=?, dest_port=?, gateway=?, queue=?, schedule=?, description=?
            WHERE id=?
        """, (
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
            rule_id
        ))
        
        db.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/rules/floating/<int:rule_id>", methods=["DELETE"])
@login_required
def delete_floating_rule(rule_id):
    """Delete a floating rule"""
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("DELETE FROM firewall_rules_floating WHERE id=?", (rule_id,))
        db.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# WAN Rules CRUD
@firewall_bp.route("/api/rules/wan", methods=["GET"])
@login_required
def get_wan_rules():
    """Get all WAN firewall rules"""
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("""
            SELECT id, action, disabled, protocol, source, destination, description
            FROM firewall_rules_wan
            ORDER BY rule_order
        """)
        rules = [dict(row) for row in cursor.fetchall()]
        return jsonify({"success": True, "rules": rules})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/rules/wan", methods=["POST"])
@login_required
def add_wan_rule():
    """Add a new WAN rule"""
    try:
        data = request.get_json()
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
            (action, disabled, protocol, source, destination, description, rule_order)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            data.get('action', 'pass'),
            data.get('disabled', 0),
            data.get('protocol', 'any'),
            data.get('source', 'any'),
            data.get('destination', 'any'),
            data.get('description', ''),
            new_order
        ))
        
        db.commit()
        return jsonify({"success": True, "id": cursor.lastrowid})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/rules/wan/<int:rule_id>/move", methods=["POST"])
@login_required
def move_wan_rule(rule_id):
    """Move a WAN rule up or down"""
    try:
        data = request.get_json()
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


@firewall_bp.route("/api/rules/wan/<int:rule_id>", methods=["PUT"])
@login_required
def update_wan_rule(rule_id):
    """Update a WAN rule"""
    try:
        data = request.get_json()
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("""
            UPDATE firewall_rules_wan 
            SET action=?, disabled=?, protocol=?, source=?, destination=?, description=?
            WHERE id=?
        """, (
            data.get('action'),
            data.get('disabled'),
            data.get('protocol'),
            data.get('source'),
            data.get('destination'),
            data.get('description'),
            rule_id
        ))
        
        db.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/rules/wan/<int:rule_id>", methods=["DELETE"])
@login_required
def delete_wan_rule(rule_id):
    """Delete a WAN rule"""
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("DELETE FROM firewall_rules_wan WHERE id=?", (rule_id,))
        db.commit()
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
            SELECT id, disabled, interface, protocol, source, destination, description
            FROM firewall_rules_lan
            ORDER BY rule_order
        """)
        rules = [dict(row) for row in cursor.fetchall()]
        return jsonify({"success": True, "rules": rules})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/rules/lan", methods=["POST"])
@login_required
def add_lan_rule():
    """Add a new LAN rule"""
    try:
        data = request.get_json()
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
            (disabled, interface, protocol, source, destination, description, rule_order)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            data.get('disabled', 0),
            data.get('interface', 'LAN'),
            data.get('protocol', 'any'),
            data.get('source', 'any'),
            data.get('destination', 'any'),
            data.get('description', ''),
            new_order
        ))
        
        db.commit()
        return jsonify({"success": True, "id": cursor.lastrowid})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/rules/lan/<int:rule_id>/move", methods=["POST"])
@login_required
def move_lan_rule(rule_id):
    """Move a LAN rule up or down"""
    try:
        data = request.get_json()
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


@firewall_bp.route("/api/rules/lan/<int:rule_id>", methods=["PUT"])
@login_required
def update_lan_rule(rule_id):
    """Update a LAN rule"""
    try:
        data = request.get_json()
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("""
            UPDATE firewall_rules_lan 
            SET disabled=?, interface=?, protocol=?, source=?, destination=?, description=?
            WHERE id=?
        """, (
            data.get('disabled'),
            data.get('interface'),
            data.get('protocol'),
            data.get('source'),
            data.get('destination'),
            data.get('description'),
            rule_id
        ))
        
        db.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/rules/lan/<int:rule_id>", methods=["DELETE"])
@login_required
def delete_lan_rule(rule_id):
    """Delete a LAN rule"""
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("DELETE FROM firewall_rules_lan WHERE id=?", (rule_id,))
        db.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ----------------------------
# FIREWALL NAT
# ----------------------------

@firewall_bp.route("/nat")
@login_required
def nat():
    return render_template("nat.html")


# Port Forward NAT CRUD
@firewall_bp.route("/api/nat/pf", methods=["GET"])
@login_required
def get_nat_pf():
    """Get all port forward NAT rules"""
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("""
            SELECT id, disabled, interface, protocol, src_type, src_address, 
                   dst_type, dst_address, redirect_ip, description, nat_reflection
            FROM nat_pf
            ORDER BY rule_order
        """)
        rules = [dict(row) for row in cursor.fetchall()]
        return jsonify({"success": True, "rules": rules})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/nat/pf", methods=["POST"])
@login_required
def add_nat_pf():
    """Add a new port forward rule"""
    try:
        data = request.get_json()
        db = get_db()
        cursor = db.cursor()
        
        position = data.get('position', 'bottom')
        
        if position == 'top':
            cursor.execute("UPDATE nat_pf SET rule_order = rule_order + 1")
            new_order = 1
        else:
            cursor.execute("SELECT COALESCE(MAX(rule_order), 0) + 1 FROM nat_pf")
            new_order = cursor.fetchone()[0]
        
        cursor.execute("""
            INSERT INTO nat_pf 
            (disabled, interface, protocol, src_type, src_address, dst_type, 
             dst_address, redirect_ip, description, nat_reflection, rule_order)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data.get('disabled', 0),
            data.get('interface', 'WAN'),
            data.get('protocol', 'tcp'),
            data.get('src_type', 'any'),
            data.get('src_address', ''),
            data.get('dst_type', 'wan_address'),
            data.get('dst_address', ''),
            data.get('redirect_ip', ''),
            data.get('description', ''),
            data.get('nat_reflection', 'default'),
            new_order
        ))
        
        db.commit()
        return jsonify({"success": True, "id": cursor.lastrowid})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/nat/pf/<int:rule_id>/move", methods=["POST"])
@login_required
def move_nat_pf(rule_id):
    """Move a port forward rule up or down"""
    try:
        data = request.get_json()
        direction = data.get('direction', 'up')
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("SELECT rule_order FROM nat_pf WHERE id=?", (rule_id,))
        row = cursor.fetchone()
        if not row:
            return jsonify({"success": False, "error": "Rule not found"}), 404
        
        current_order = row[0]
        
        if direction == 'up':
            cursor.execute("""
                SELECT id, rule_order FROM nat_pf 
                WHERE rule_order < ? ORDER BY rule_order DESC LIMIT 1
            """, (current_order,))
        else:
            cursor.execute("""
                SELECT id, rule_order FROM nat_pf 
                WHERE rule_order > ? ORDER BY rule_order ASC LIMIT 1
            """, (current_order,))
        
        swap_row = cursor.fetchone()
        if swap_row:
            swap_id, swap_order = swap_row
            cursor.execute("UPDATE nat_pf SET rule_order=? WHERE id=?", (swap_order, rule_id))
            cursor.execute("UPDATE nat_pf SET rule_order=? WHERE id=?", (current_order, swap_id))
            db.commit()
        
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/nat/pf/<int:rule_id>", methods=["PUT"])
@login_required
def update_nat_pf(rule_id):
    """Update a port forward rule"""
    try:
        data = request.get_json()
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("""
            UPDATE nat_pf 
            SET disabled=?, interface=?, protocol=?, src_type=?, src_address=?, 
                dst_type=?, dst_address=?, redirect_ip=?, description=?, nat_reflection=?
            WHERE id=?
        """, (
            data.get('disabled'),
            data.get('interface'),
            data.get('protocol'),
            data.get('src_type'),
            data.get('src_address'),
            data.get('dst_type'),
            data.get('dst_address'),
            data.get('redirect_ip'),
            data.get('description'),
            data.get('nat_reflection'),
            rule_id
        ))
        
        db.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/nat/pf/<int:rule_id>", methods=["DELETE"])
@login_required
def delete_nat_pf(rule_id):
    """Delete a port forward rule"""
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("DELETE FROM nat_pf WHERE id=?", (rule_id,))
        db.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# 1:1 NAT CRUD
@firewall_bp.route("/api/nat/1to1", methods=["GET"])
@login_required
def get_nat_1to1():
    """Get all 1:1 NAT mappings"""
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("""
            SELECT id, disabled, interface, external_address, internal_address, 
                   destination_address, description
            FROM nat_1to1
            ORDER BY rule_order
        """)
        rules = [dict(row) for row in cursor.fetchall()]
        return jsonify({"success": True, "rules": rules})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/nat/1to1", methods=["POST"])
@login_required
def add_nat_1to1():
    """Add a new 1:1 NAT mapping"""
    try:
        data = request.get_json()
        db = get_db()
        cursor = db.cursor()
        
        position = data.get('position', 'bottom')
        
        if position == 'top':
            cursor.execute("UPDATE nat_1to1 SET rule_order = rule_order + 1")
            new_order = 1
        else:
            cursor.execute("SELECT COALESCE(MAX(rule_order), 0) + 1 FROM nat_1to1")
            new_order = cursor.fetchone()[0]
        
        cursor.execute("""
            INSERT INTO nat_1to1 
            (disabled, interface, external_address, internal_address, 
             destination_address, description, rule_order)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            data.get('disabled', 0),
            data.get('interface', 'WAN'),
            data.get('external_address', ''),
            data.get('internal_address', ''),
            data.get('destination_address', 'any'),
            data.get('description', ''),
            new_order
        ))
        
        db.commit()
        return jsonify({"success": True, "id": cursor.lastrowid})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/nat/1to1/<int:rule_id>/move", methods=["POST"])
@login_required
def move_nat_1to1(rule_id):
    """Move a 1:1 NAT mapping up or down"""
    try:
        data = request.get_json()
        direction = data.get('direction', 'up')
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("SELECT rule_order FROM nat_1to1 WHERE id=?", (rule_id,))
        row = cursor.fetchone()
        if not row:
            return jsonify({"success": False, "error": "Rule not found"}), 404
        
        current_order = row[0]
        
        if direction == 'up':
            cursor.execute("""
                SELECT id, rule_order FROM nat_1to1 
                WHERE rule_order < ? ORDER BY rule_order DESC LIMIT 1
            """, (current_order,))
        else:
            cursor.execute("""
                SELECT id, rule_order FROM nat_1to1 
                WHERE rule_order > ? ORDER BY rule_order ASC LIMIT 1
            """, (current_order,))
        
        swap_row = cursor.fetchone()
        if swap_row:
            swap_id, swap_order = swap_row
            cursor.execute("UPDATE nat_1to1 SET rule_order=? WHERE id=?", (swap_order, rule_id))
            cursor.execute("UPDATE nat_1to1 SET rule_order=? WHERE id=?", (current_order, swap_id))
            db.commit()
        
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/nat/1to1/<int:rule_id>", methods=["PUT"])
@login_required
def update_nat_1to1(rule_id):
    """Update a 1:1 NAT mapping"""
    try:
        data = request.get_json()
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("""
            UPDATE nat_1to1 
            SET disabled=?, interface=?, external_address=?, internal_address=?, 
                destination_address=?, description=?
            WHERE id=?
        """, (
            data.get('disabled'),
            data.get('interface'),
            data.get('external_address'),
            data.get('internal_address'),
            data.get('destination_address'),
            data.get('description'),
            rule_id
        ))
        
        db.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/nat/1to1/<int:rule_id>", methods=["DELETE"])
@login_required
def delete_nat_1to1(rule_id):
    """Delete a 1:1 NAT mapping"""
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("DELETE FROM nat_1to1 WHERE id=?", (rule_id,))
        db.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# Outbound NAT CRUD
@firewall_bp.route("/api/nat/outbound", methods=["GET"])
def get_nat_outbound():
    """Get all outbound NAT rules"""
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("""
            SELECT id, disabled, interface, src_address, dst_address, 
                   nat_address, static_port, description
            FROM nat_outbound
            ORDER BY rule_order
        """)
        rules = [dict(row) for row in cursor.fetchall()]
        return jsonify({"success": True, "rules": rules})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/nat/outbound", methods=["POST"])
@login_required
def add_nat_outbound():
    """Add a new outbound NAT rule"""
    try:
        data = request.get_json()
        db = get_db()
        cursor = db.cursor()
        
        position = data.get('position', 'bottom')
        
        if position == 'top':
            cursor.execute("UPDATE nat_outbound SET rule_order = rule_order + 1")
            new_order = 1
        else:
            cursor.execute("SELECT COALESCE(MAX(rule_order), 0) + 1 FROM nat_outbound")
            new_order = cursor.fetchone()[0]
        
        cursor.execute("""
            INSERT INTO nat_outbound 
            (disabled, interface, src_address, dst_address, nat_address, 
             static_port, description, rule_order)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data.get('disabled', 0),
            data.get('interface', 'WAN'),
            data.get('src_address', ''),
            data.get('dst_address', 'any'),
            data.get('nat_address', ''),
            data.get('static_port', 0),
            data.get('description', ''),
            new_order
        ))
        
        db.commit()
        return jsonify({"success": True, "id": cursor.lastrowid})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/nat/outbound/<int:rule_id>/move", methods=["POST"])
@login_required
def move_nat_outbound(rule_id):
    """Move an outbound NAT rule up or down"""
    try:
        data = request.get_json()
        direction = data.get('direction', 'up')
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("SELECT rule_order FROM nat_outbound WHERE id=?", (rule_id,))
        row = cursor.fetchone()
        if not row:
            return jsonify({"success": False, "error": "Rule not found"}), 404
        
        current_order = row[0]
        
        if direction == 'up':
            cursor.execute("""
                SELECT id, rule_order FROM nat_outbound 
                WHERE rule_order < ? ORDER BY rule_order DESC LIMIT 1
            """, (current_order,))
        else:
            cursor.execute("""
                SELECT id, rule_order FROM nat_outbound 
                WHERE rule_order > ? ORDER BY rule_order ASC LIMIT 1
            """, (current_order,))
        
        swap_row = cursor.fetchone()
        if swap_row:
            swap_id, swap_order = swap_row
            cursor.execute("UPDATE nat_outbound SET rule_order=? WHERE id=?", (swap_order, rule_id))
            cursor.execute("UPDATE nat_outbound SET rule_order=? WHERE id=?", (current_order, swap_id))
            db.commit()
        
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/nat/outbound/<int:rule_id>", methods=["PUT"])
@login_required
def update_nat_outbound(rule_id):
    """Update an outbound NAT rule"""
    try:
        data = request.get_json()
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("""
            UPDATE nat_outbound 
            SET disabled=?, interface=?, src_address=?, dst_address=?, 
                nat_address=?, static_port=?, description=?
            WHERE id=?
        """, (
            data.get('disabled'),
            data.get('interface'),
            data.get('src_address'),
            data.get('dst_address'),
            data.get('nat_address'),
            data.get('static_port'),
            data.get('description'),
            rule_id
        ))
        
        db.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/nat/outbound/<int:rule_id>", methods=["DELETE"])
@login_required
def delete_nat_outbound(rule_id):
    """Delete an outbound NAT rule"""
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("DELETE FROM nat_outbound WHERE id=?", (rule_id,))
        db.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# NPt (Network Prefix Translation) CRUD
@firewall_bp.route("/api/nat/npt", methods=["GET"])
def get_nat_npt():
    """Get all NPt mappings"""
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("""
            SELECT id, disabled, interface, src_not, src_prefix, src_prefix_length,
                   dst_not, dst_type, dst_prefix, dst_prefix_length, description
            FROM nat_npt
            ORDER BY rule_order
        """)
        rules = [dict(row) for row in cursor.fetchall()]
        return jsonify({"success": True, "rules": rules})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/nat/npt", methods=["POST"])
@login_required
def add_nat_npt():
    """Add a new NPt mapping"""
    try:
        data = request.get_json()
        db = get_db()
        cursor = db.cursor()
        
        position = data.get('position', 'bottom')
        
        if position == 'top':
            cursor.execute("UPDATE nat_npt SET rule_order = rule_order + 1")
            new_order = 1
        else:
            cursor.execute("SELECT COALESCE(MAX(rule_order), 0) + 1 FROM nat_npt")
            new_order = cursor.fetchone()[0]
        
        cursor.execute("""
            INSERT INTO nat_npt 
            (disabled, interface, src_not, src_prefix, src_prefix_length,
             dst_not, dst_type, dst_prefix, dst_prefix_length, description, rule_order)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data.get('disabled', 0),
            data.get('interface', 'WAN'),
            data.get('src_not', 0),
            data.get('src_prefix', ''),
            data.get('src_prefix_length', 128),
            data.get('dst_not', 0),
            data.get('dst_type', 'Prefix'),
            data.get('dst_prefix', ''),
            data.get('dst_prefix_length', 128),
            data.get('description', ''),
            new_order
        ))
        
        db.commit()
        return jsonify({"success": True, "id": cursor.lastrowid})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/nat/npt/<int:rule_id>/move", methods=["POST"])
@login_required
def move_nat_npt(rule_id):
    """Move an NPt mapping up or down"""
    try:
        data = request.get_json()
        direction = data.get('direction', 'up')
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("SELECT rule_order FROM nat_npt WHERE id=?", (rule_id,))
        row = cursor.fetchone()
        if not row:
            return jsonify({"success": False, "error": "Rule not found"}), 404
        
        current_order = row[0]
        
        if direction == 'up':
            cursor.execute("""
                SELECT id, rule_order FROM nat_npt 
                WHERE rule_order < ? ORDER BY rule_order DESC LIMIT 1
            """, (current_order,))
        else:
            cursor.execute("""
                SELECT id, rule_order FROM nat_npt 
                WHERE rule_order > ? ORDER BY rule_order ASC LIMIT 1
            """, (current_order,))
        
        swap_row = cursor.fetchone()
        if swap_row:
            swap_id, swap_order = swap_row
            cursor.execute("UPDATE nat_npt SET rule_order=? WHERE id=?", (swap_order, rule_id))
            cursor.execute("UPDATE nat_npt SET rule_order=? WHERE id=?", (current_order, swap_id))
            db.commit()
        
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/nat/npt/<int:rule_id>", methods=["PUT"])
@login_required
def update_nat_npt(rule_id):
    """Update an NPt mapping"""
    try:
        data = request.get_json()
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("""
            UPDATE nat_npt 
            SET disabled=?, interface=?, src_not=?, src_prefix=?, src_prefix_length=?,
                dst_not=?, dst_type=?, dst_prefix=?, dst_prefix_length=?, description=?
            WHERE id=?
        """, (
            data.get('disabled'),
            data.get('interface'),
            data.get('src_not'),
            data.get('src_prefix'),
            data.get('src_prefix_length'),
            data.get('dst_not'),
            data.get('dst_type'),
            data.get('dst_prefix'),
            data.get('dst_prefix_length'),
            data.get('description'),
            rule_id
        ))
        
        db.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/nat/npt/<int:rule_id>", methods=["DELETE"])
@login_required
def delete_nat_npt(rule_id):
    """Delete an NPt mapping"""
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("DELETE FROM nat_npt WHERE id=?", (rule_id,))
        db.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ----------------------------
# FIREWALL ALIASES
# ----------------------------

@firewall_bp.route("/aliases")
def aliases():
    # Default tab = 'all'
    return render_template("aliases.html", tab="all")


@firewall_bp.route("/aliases/<tab>")
def firewall_aliases_tab(tab):
    valid_tabs = ["ip", "ports", "urls", "all"]
    if tab not in valid_tabs:
        tab = "all"
    return render_template("aliases.html", tab=tab)


@firewall_bp.route("/api/aliases", methods=["GET"])
def get_aliases():
    """Get all aliases with optional type filter"""
    try:
        alias_type = request.args.get('type', 'all').lower()
        db = get_db()
        cursor = db.cursor()
        
        if alias_type == 'all':
            cursor.execute("""
                SELECT id, name, type, alias_values, description
                FROM firewall_aliases
                ORDER BY name
            """)
        else:
            # Map filter types to database type patterns
            if alias_type in ['host', 'ip']:
                # Match Host(s), Network(s), or IP-related types
                cursor.execute("""
                    SELECT id, name, type, alias_values, description
                    FROM firewall_aliases
                    WHERE LOWER(type) LIKE '%host%' OR LOWER(type) LIKE '%network%'
                    ORDER BY name
                """)
            elif alias_type == 'port':
                # Match Port(s) types
                cursor.execute("""
                    SELECT id, name, type, alias_values, description
                    FROM firewall_aliases
                    WHERE LOWER(type) LIKE '%port%'
                    ORDER BY name
                """)
            elif alias_type == 'url':
                # Match URL types
                cursor.execute("""
                    SELECT id, name, type, alias_values, description
                    FROM firewall_aliases
                    WHERE LOWER(type) LIKE '%url%'
                    ORDER BY name
                """)
            else:
                # Fallback to exact match
                cursor.execute("""
                    SELECT id, name, type, alias_values, description
                    FROM firewall_aliases
                    WHERE type=?
                    ORDER BY name
                """, (alias_type,))
        
        aliases = [dict(row) for row in cursor.fetchall()]
        return jsonify({"success": True, "aliases": aliases})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/aliases", methods=["POST"])
@login_required
def add_alias():
    """Add a new alias"""
    try:
        data = request.get_json()
        db = get_db()
        cursor = db.cursor()
        
        # Convert values array to JSON string for storage
        import json
        values_json = json.dumps(data.get('values', []))
        
        cursor.execute("""
            INSERT INTO firewall_aliases (name, type, alias_values, description)
            VALUES (?, ?, ?, ?)
        """, (
            data.get('name', ''),
            data.get('type', 'host'),
            values_json,
            data.get('description', '')
        ))
        
        db.commit()
        return jsonify({"success": True, "id": cursor.lastrowid})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/aliases/<int:alias_id>", methods=["PUT"])
@login_required
def update_alias(alias_id):
    """Update an alias"""
    try:
        data = request.get_json()
        db = get_db()
        cursor = db.cursor()
        
        # Convert values array to JSON string for storage
        import json
        values_json = json.dumps(data.get('values', []))
        
        cursor.execute("""
            UPDATE firewall_aliases 
            SET name=?, type=?, alias_values=?, description=?
            WHERE id=?
        """, (
            data.get('name'),
            data.get('type'),
            values_json,
            data.get('description'),
            alias_id
        ))
        
        db.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/aliases/<int:alias_id>", methods=["DELETE"])
@login_required
def delete_alias(alias_id):
    """Delete an alias"""
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("DELETE FROM firewall_aliases WHERE id=?", (alias_id,))
        db.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ----------------------------
# FIREWALL SCHEDULES
# ----------------------------

@firewall_bp.route("/schedules")
@login_required
def schedules():
    return render_template("schedules.html")


@firewall_bp.route("/api/schedules", methods=["GET"])
def list_schedules():
    """List all firewall schedules with their ranges."""
    try:
        db = get_db()
        cursor = db.cursor()

        cursor.execute(
            "SELECT id, name, description FROM firewall_schedules ORDER BY name COLLATE NOCASE"
        )
        schedules_rows = cursor.fetchall()
        schedules_list = []
        for s in schedules_rows:
            cursor.execute(
                """
                SELECT id, year, month, days_csv, start_time, end_time, range_description
                FROM firewall_schedule_ranges
                WHERE schedule_id = ?
                ORDER BY year, month, start_time, end_time, id
                """,
                (s["id"],),
            )
            ranges = [dict(r) for r in cursor.fetchall()]
            schedules_list.append(
                {
                    "id": s["id"],
                    "name": s["name"],
                    "description": s["description"],
                    "ranges": ranges,
                }
            )

        return jsonify({"success": True, "schedules": schedules_list})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/schedules", methods=["POST"])
@login_required
def create_schedule():
    """Create a schedule (with ranges). Expects JSON: {name, description, ranges:[...]}."""
    try:
        data = request.get_json() or {}
        name = (data.get("name") or "").strip()
        if not name:
            return jsonify({"success": False, "error": "Schedule name is required"}), 400

        ranges = data.get("ranges") or []
        if not isinstance(ranges, list):
            return jsonify({"success": False, "error": "ranges must be a list"}), 400

        db = get_db()
        cursor = db.cursor()

        cursor.execute(
            "INSERT INTO firewall_schedules (name, description) VALUES (?, ?)",
            (name, (data.get("description") or "").strip()),
        )
        schedule_id = cursor.lastrowid

        for r in ranges:
            # strict-ish parsing: keep simple strings & ints to match UI
            year = int(r.get("year"))
            month = int(r.get("month"))
            days_csv = (r.get("days_csv") or "").strip()
            start_time = (r.get("start_time") or "").strip()
            end_time = (r.get("end_time") or "").strip()
            if not (days_csv and start_time and end_time):
                continue
            cursor.execute(
                """
                INSERT INTO firewall_schedule_ranges
                    (schedule_id, year, month, days_csv, start_time, end_time, range_description)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    schedule_id,
                    year,
                    month,
                    days_csv,
                    start_time,
                    end_time,
                    (r.get("range_description") or "").strip(),
                ),
            )

        db.commit()
        return jsonify({"success": True, "id": schedule_id})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/schedules/<int:schedule_id>", methods=["PUT"])
@login_required
def update_schedule(schedule_id):
    """Replace schedule fields and ranges. Expects JSON: {name, description, ranges:[...]}."""
    try:
        data = request.get_json() or {}
        name = (data.get("name") or "").strip()
        if not name:
            return jsonify({"success": False, "error": "Schedule name is required"}), 400

        ranges = data.get("ranges") or []
        if not isinstance(ranges, list):
            return jsonify({"success": False, "error": "ranges must be a list"}), 400

        db = get_db()
        cursor = db.cursor()

        cursor.execute(
            "UPDATE firewall_schedules SET name=?, description=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (name, (data.get("description") or "").strip(), schedule_id),
        )
        if cursor.rowcount == 0:
            return jsonify({"success": False, "error": "Schedule not found"}), 404

        # Replace ranges
        cursor.execute("DELETE FROM firewall_schedule_ranges WHERE schedule_id=?", (schedule_id,))
        for r in ranges:
            year = int(r.get("year"))
            month = int(r.get("month"))
            days_csv = (r.get("days_csv") or "").strip()
            start_time = (r.get("start_time") or "").strip()
            end_time = (r.get("end_time") or "").strip()
            if not (days_csv and start_time and end_time):
                continue
            cursor.execute(
                """
                INSERT INTO firewall_schedule_ranges
                    (schedule_id, year, month, days_csv, start_time, end_time, range_description)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    schedule_id,
                    year,
                    month,
                    days_csv,
                    start_time,
                    end_time,
                    (r.get("range_description") or "").strip(),
                ),
            )

        db.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/schedules/<int:schedule_id>", methods=["DELETE"])
@login_required
def delete_schedule(schedule_id):
    """Delete a schedule and its ranges."""
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("DELETE FROM firewall_schedules WHERE id=?", (schedule_id,))
        db.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ----------------------------
# VIRTUAL IPs
# ----------------------------

@firewall_bp.route("/virtual-ips")
@login_required
def virtual_ips():
    return render_template("virtual_ips.html")


# ----------------------------
# TRAFFIC SHAPER
# ----------------------------

@firewall_bp.route("/traffic-shaper")
def traffic_shaper():
    return render_template("traffic_shaper.html")

@firewall_bp.route("/get-traffic-shaper-configs", methods=['GET'])
@login_required
def get_traffic_shaper_configs():
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT id, interface_type, enable_disable, name, scheduler_type, bandwidth, bandwidth_unit, queue_limit, tbr_size FROM traffic_shaper_configs ORDER BY interface_type, id')
        configs = cursor.fetchall()
        
        configs_list = [
            {
                'id': c[0],
                'interface_type': c[1],
                'enable_disable': bool(c[2]),
                'name': c[3],
                'scheduler_type': c[4],
                'bandwidth': c[5],
                'bandwidth_unit': c[6],
                'queue_limit': c[7],
                'tbr_size': c[8]
            }
            for c in configs
        ]
        return jsonify({'status': 'success', 'data': configs_list})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@firewall_bp.route("/save-traffic-shaper-config", methods=['POST'])
@login_required
def save_traffic_shaper_config():
    try:
        data = request.get_json()
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''INSERT INTO traffic_shaper_configs (interface_type, enable_disable, name, scheduler_type, bandwidth, bandwidth_unit, queue_limit, tbr_size) 
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                       (data['interfaceType'], data['enableDisable'], data['name'], data['schedulerType'], data['bandwidth'], data['bandwidthUnit'], data['queueLimit'], data['tbrSize']))
        db.commit()
        config_id = cursor.lastrowid
        return jsonify({'status': 'success', 'message': 'Config saved', 'id': config_id})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@firewall_bp.route("/get-traffic-shaper-config/<int:config_id>", methods=['GET'])
@login_required
def get_traffic_shaper_config(config_id):
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT id, interface_type, enable_disable, name, scheduler_type, bandwidth, bandwidth_unit, queue_limit, tbr_size FROM traffic_shaper_configs WHERE id = ?', (config_id,))
        config = cursor.fetchone()
        
        if config:
            return jsonify({'status': 'success', 'data': {
                'id': config[0],
                'interface_type': config[1],
                'enable_disable': bool(config[2]),
                'name': config[3],
                'scheduler_type': config[4],
                'bandwidth': config[5],
                'bandwidth_unit': config[6],
                'queue_limit': config[7],
                'tbr_size': config[8]
            }})
        return jsonify({'status': 'error', 'message': 'Config not found'}), 404
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@firewall_bp.route("/update-traffic-shaper-config/<int:config_id>", methods=['PUT'])
@login_required
def update_traffic_shaper_config(config_id):
    try:
        data = request.get_json()
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''UPDATE traffic_shaper_configs SET interface_type = ?, enable_disable = ?, name = ?, scheduler_type = ?, bandwidth = ?, bandwidth_unit = ?, queue_limit = ?, tbr_size = ? WHERE id = ?''',
                       (data['interfaceType'], data['enableDisable'], data['name'], data['schedulerType'], data['bandwidth'], data['bandwidthUnit'], data['queueLimit'], data['tbrSize'], config_id))
        db.commit()
        return jsonify({'status': 'success', 'message': 'Config updated'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@firewall_bp.route("/delete-traffic-shaper-config/<int:config_id>", methods=['DELETE'])
@login_required
def delete_traffic_shaper_config(config_id):
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute('DELETE FROM traffic_shaper_configs WHERE id = ?', (config_id,))
        db.commit()
        return jsonify({'status': 'success', 'message': 'Config deleted'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400


# ----------------------------
# LIMITERS
# ----------------------------

@firewall_bp.route("/get-limiters-configs", methods=['GET'])
@login_required
def get_limiters_configs():
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT id, enable_disable, name, bandwidth, bandwidth_unit, mask_type, ipv4_mask_bits, ipv6_mask_bits, queue_management_algorithm, scheduler, queue_length, delay_ms, packet_loss_rate, bucket_size_slots, description FROM limiters_configs ORDER BY id')
        configs = cursor.fetchall()
        
        configs_list = [
            {
                'id': c[0],
                'enable_disable': bool(c[1]),
                'name': c[2],
                'bandwidth': c[3],
                'bandwidth_unit': c[4],
                'mask_type': c[5],
                'ipv4_mask_bits': c[6],
                'ipv6_mask_bits': c[7],
                'queue_management_algorithm': c[8],
                'scheduler': c[9],
                'queue_length': c[10],
                'delay_ms': c[11],
                'packet_loss_rate': c[12],
                'bucket_size_slots': c[13],
                'description': c[14]
            }
            for c in configs
        ]
        return jsonify({'status': 'success', 'data': configs_list})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@firewall_bp.route("/save-limiters-config", methods=['POST'])
@login_required
def save_limiters_config():
    try:
        data = request.get_json()
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''INSERT INTO limiters_configs (enable_disable, name, bandwidth, bandwidth_unit, mask_type, ipv4_mask_bits, ipv6_mask_bits, queue_management_algorithm, scheduler, queue_length, delay_ms, packet_loss_rate, bucket_size_slots, description) 
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                       (data['enableDisable'], data['name'], data['bandwidth'], data['bandwidthUnit'], data['maskType'], data['ipv4MaskBits'], data['ipv6MaskBits'], data['queueManagementAlgorithm'], data['scheduler'], data['queueLength'], data['delayMs'], data['packetLossRate'], data['bucketSizeSlots'], data['description']))
        db.commit()
        config_id = cursor.lastrowid
        return jsonify({'status': 'success', 'message': 'Limiter saved', 'id': config_id})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@firewall_bp.route("/get-limiters-config/<int:config_id>", methods=['GET'])
@login_required
def get_limiters_config(config_id):
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT id, enable_disable, name, bandwidth, bandwidth_unit, mask_type, ipv4_mask_bits, ipv6_mask_bits, queue_management_algorithm, scheduler, queue_length, delay_ms, packet_loss_rate, bucket_size_slots, description FROM limiters_configs WHERE id = ?', (config_id,))
        config = cursor.fetchone()
        
        if config:
            return jsonify({'status': 'success', 'data': {
                'id': config[0],
                'enable_disable': bool(config[1]),
                'name': config[2],
                'bandwidth': config[3],
                'bandwidth_unit': config[4],
                'mask_type': config[5],
                'ipv4_mask_bits': config[6],
                'ipv6_mask_bits': config[7],
                'queue_management_algorithm': config[8],
                'scheduler': config[9],
                'queue_length': config[10],
                'delay_ms': config[11],
                'packet_loss_rate': config[12],
                'bucket_size_slots': config[13],
                'description': config[14]
            }})
        return jsonify({'status': 'error', 'message': 'Config not found'}), 404
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@firewall_bp.route("/update-limiters-config/<int:config_id>", methods=['PUT'])
@login_required
def update_limiters_config(config_id):
    try:
        data = request.get_json()
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''UPDATE limiters_configs SET enable_disable = ?, name = ?, bandwidth = ?, bandwidth_unit = ?, mask_type = ?, ipv4_mask_bits = ?, ipv6_mask_bits = ?, queue_management_algorithm = ?, scheduler = ?, queue_length = ?, delay_ms = ?, packet_loss_rate = ?, bucket_size_slots = ?, description = ? WHERE id = ?''',
                       (data['enableDisable'], data['name'], data['bandwidth'], data['bandwidthUnit'], data['maskType'], data['ipv4MaskBits'], data['ipv6MaskBits'], data['queueManagementAlgorithm'], data['scheduler'], data['queueLength'], data['delayMs'], data['packetLossRate'], data['bucketSizeSlots'], data['description'], config_id))
        db.commit()
        return jsonify({'status': 'success', 'message': 'Limiter updated'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@firewall_bp.route("/delete-limiters-config/<int:config_id>", methods=['DELETE'])
@login_required
def delete_limiters_config(config_id):
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute('DELETE FROM limiters_configs WHERE id = ?', (config_id,))
        db.commit()
        return jsonify({'status': 'success', 'message': 'Limiter deleted'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400


# ----------------------------
# VIRTUAL IPS
# ----------------------------

@firewall_bp.route("/get-virtual-ips-configs", methods=['GET'])
@login_required
def get_virtual_ips_configs():
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT id, type, interface, address_type, address, prefix, expansion, description FROM virtual_ips_configs ORDER BY id')
        configs = cursor.fetchall()
        
        configs_list = [
            {
                'id': c[0],
                'type': c[1],
                'interface': c[2],
                'address_type': c[3],
                'address': c[4],
                'prefix': c[5],
                'expansion': bool(c[6]),
                'description': c[7]
            }
            for c in configs
        ]
        return jsonify({'status': 'success', 'data': configs_list})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@firewall_bp.route("/save-virtual-ips-config", methods=['POST'])
@login_required
def save_virtual_ips_config():
    try:
        data = request.get_json()
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''INSERT INTO virtual_ips_configs (type, interface, address_type, address, prefix, expansion, description) 
                          VALUES (?, ?, ?, ?, ?, ?, ?)''',
                       (data['type'], data['interface'], data.get('address_type') or data.get('addressType') or 'single', data['address'], data['prefix'], data['expansion'], data.get('description', '')))
        db.commit()
        config_id = cursor.lastrowid
        return jsonify({'status': 'success', 'message': 'Virtual IP saved', 'id': config_id})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@firewall_bp.route("/get-virtual-ips-config/<int:config_id>", methods=['GET'])
@login_required
def get_virtual_ips_config(config_id):
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT id, type, interface, address_type, address, prefix, expansion, description FROM virtual_ips_configs WHERE id = ?', (config_id,))
        config = cursor.fetchone()
        
        if config:
            return jsonify({'status': 'success', 'data': {
                'id': config[0],
                'type': config[1],
                'interface': config[2],
                'address_type': config[3],
                'address': config[4],
                'prefix': config[5],
                'expansion': bool(config[6]),
                'description': config[7]
            }})
        return jsonify({'status': 'error', 'message': 'Config not found'}), 404
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@firewall_bp.route("/update-virtual-ips-config/<int:config_id>", methods=['PUT', 'POST'])
@login_required
def update_virtual_ips_config(config_id):
    try:
        data = request.get_json()
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''UPDATE virtual_ips_configs SET type = ?, interface = ?, address_type = ?, address = ?, prefix = ?, expansion = ?, description = ? WHERE id = ?''',
                       (data['type'], data['interface'], data.get('address_type') or data.get('addressType') or 'single', data['address'], data['prefix'], data['expansion'], data.get('description', ''), config_id))
        db.commit()
        return jsonify({'status': 'success', 'message': 'Virtual IP updated'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@firewall_bp.route("/delete-virtual-ips-config/<int:config_id>", methods=['DELETE'])
@login_required
def delete_virtual_ips_config(config_id):
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute('DELETE FROM virtual_ips_configs WHERE id = ?', (config_id,))
        db.commit()
        return jsonify({'status': 'success', 'message': 'Virtual IP deleted'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400


# ----------------------------
# FIREWALL HOME
# ----------------------------

# @firewall_bp.route("/home")
# def home():
#     return redirect(url_for("firewall.firewall_home"))
