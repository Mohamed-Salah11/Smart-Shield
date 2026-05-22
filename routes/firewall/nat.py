import sqlite3

from flask import render_template, request, jsonify, session
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
                   dst_type, dst_address, dst_port, redirect_ip, redirect_port,
                   description, nat_reflection
            FROM nat_pf
            ORDER BY rule_order
        """)
        rules = [dict(row) for row in cursor.fetchall()]
        return jsonify({"success": True, "rules": rules})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/nat/pf", methods=["POST"])
@api_permission_required("api.firewall.edit")
def add_nat_pf():
    """Add a new port forward rule"""
    try:
        data = request.get_json(silent=True) or {}
        err = _validate_rule(data)
        if err:
            return jsonify({"success": False, "error": err}), 400
        redir_ip = (data.get("redirect_ip") or "").strip()
        if redir_ip:
            try:
                validate_ip(redir_ip)
            except ValueError as exc:
                return jsonify({"success": False, "error": f"Invalid redirect IP: {exc}"}), 400
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
             dst_address, dst_port, redirect_ip, redirect_port, description,
             nat_reflection, rule_order)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data.get('disabled', 0),
            data.get('interface', 'WAN'),
            data.get('protocol', 'tcp'),
            data.get('src_type', 'any'),
            data.get('src_address', ''),
            data.get('dst_type', 'wan_address'),
            data.get('dst_address', ''),
            (data.get('dst_port') or '').strip(),
            data.get('redirect_ip', ''),
            (data.get('redirect_port') or '').strip(),
            data.get('description', ''),
            data.get('nat_reflection', 'default'),
            new_order
        ))
        
        db.commit()
        return jsonify({"success": True, "id": cursor.lastrowid})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/nat/pf/<int:rule_id>/move", methods=["POST"])
@api_permission_required("api.firewall.edit")
def move_nat_pf(rule_id):
    """Move a port forward rule up or down"""
    try:
        data = request.get_json(silent=True) or {}
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


@firewall_bp.route("/api/nat/pf/<int:rule_id>", methods=["GET"])
@login_required
def get_nat_pf_rule(rule_id):
    """Get a single port forward rule by ID"""
    try:
        db = get_db()
        row = db.execute(
            "SELECT id, disabled, interface, protocol, src_type, src_address, "
            "dst_type, dst_address, dst_port, redirect_ip, redirect_port, "
            "description, nat_reflection "
            "FROM nat_pf WHERE id=?", (rule_id,)
        ).fetchone()
        if not row:
            return jsonify({"success": False, "error": "Rule not found"}), 404
        return jsonify({"success": True, "rule": dict(row)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/nat/pf/<int:rule_id>", methods=["PUT"])
@api_permission_required("api.firewall.edit")
def update_nat_pf(rule_id):
    """Update a port forward rule"""
    try:
        data = request.get_json(silent=True) or {}
        err = _validate_rule(data)
        if err:
            return jsonify({"success": False, "error": err}), 400
        redir_ip = (data.get("redirect_ip") or "").strip()
        if redir_ip:
            try:
                validate_ip(redir_ip)
            except ValueError as exc:
                return jsonify({"success": False, "error": f"Invalid redirect IP: {exc}"}), 400
        db = get_db()
        cursor = db.cursor()

        cursor.execute("""
            UPDATE nat_pf
            SET disabled=?, interface=?, protocol=?, src_type=?, src_address=?,
                dst_type=?, dst_address=?, dst_port=?, redirect_ip=?, redirect_port=?,
                description=?, nat_reflection=?
            WHERE id=?
        """, (
            data.get('disabled'),
            data.get('interface'),
            data.get('protocol'),
            data.get('src_type'),
            data.get('src_address'),
            data.get('dst_type'),
            data.get('dst_address'),
            (data.get('dst_port') or '').strip(),
            data.get('redirect_ip'),
            (data.get('redirect_port') or '').strip(),
            data.get('description'),
            data.get('nat_reflection'),
            rule_id
        ))
        
        db.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/nat/pf/<int:rule_id>", methods=["DELETE"])
@api_permission_required("api.firewall.edit")
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
@api_permission_required("api.firewall.edit")
def add_nat_1to1():
    """Add a new 1:1 NAT mapping"""
    try:
        data = request.get_json(silent=True) or {}
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
@api_permission_required("api.firewall.edit")
def move_nat_1to1(rule_id):
    """Move a 1:1 NAT mapping up or down"""
    try:
        data = request.get_json(silent=True) or {}
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


@firewall_bp.route("/api/nat/1to1/<int:rule_id>", methods=["GET"])
@login_required
def get_nat_1to1_rule(rule_id):
    """Get a single 1:1 NAT mapping by ID"""
    try:
        db = get_db()
        row = db.execute(
            "SELECT id, disabled, interface, external_address, internal_address, "
            "destination_address, description FROM nat_1to1 WHERE id=?", (rule_id,)
        ).fetchone()
        if not row:
            return jsonify({"success": False, "error": "Rule not found"}), 404
        return jsonify({"success": True, "rule": dict(row)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/nat/1to1/<int:rule_id>", methods=["PUT"])
@api_permission_required("api.firewall.edit")
def update_nat_1to1(rule_id):
    """Update a 1:1 NAT mapping"""
    try:
        data = request.get_json(silent=True) or {}
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
@api_permission_required("api.firewall.edit")
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
@login_required
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
@api_permission_required("api.firewall.edit")
def add_nat_outbound():
    """Add a new outbound NAT rule"""
    try:
        data = request.get_json(silent=True) or {}
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
@api_permission_required("api.firewall.edit")
def move_nat_outbound(rule_id):
    """Move an outbound NAT rule up or down"""
    try:
        data = request.get_json(silent=True) or {}
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


@firewall_bp.route("/api/nat/outbound/<int:rule_id>", methods=["GET"])
@login_required
def get_nat_outbound_rule(rule_id):
    """Get a single outbound NAT rule by ID"""
    try:
        db = get_db()
        row = db.execute(
            "SELECT * FROM nat_outbound WHERE id=?", (rule_id,)
        ).fetchone()
        if not row:
            return jsonify({"success": False, "error": "Rule not found"}), 404
        return jsonify({"success": True, "rule": dict(row)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/nat/outbound/<int:rule_id>", methods=["PUT"])
@api_permission_required("api.firewall.edit")
def update_nat_outbound(rule_id):
    """Update an outbound NAT rule"""
    try:
        data = request.get_json(silent=True) or {}
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
@api_permission_required("api.firewall.edit")
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
@login_required
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
@api_permission_required("api.firewall.edit")
def add_nat_npt():
    """Add a new NPt mapping"""
    try:
        data = request.get_json(silent=True) or {}
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
@api_permission_required("api.firewall.edit")
def move_nat_npt(rule_id):
    """Move an NPt mapping up or down"""
    try:
        data = request.get_json(silent=True) or {}
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


@firewall_bp.route("/api/nat/npt/<int:rule_id>", methods=["GET"])
@login_required
def get_nat_npt_rule(rule_id):
    """Get a single NPt mapping by ID"""
    try:
        db = get_db()
        row = db.execute(
            "SELECT * FROM nat_npt WHERE id=?", (rule_id,)
        ).fetchone()
        if not row:
            return jsonify({"success": False, "error": "Rule not found"}), 404
        return jsonify({"success": True, "rule": dict(row)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/nat/npt/<int:rule_id>", methods=["PUT"])
@api_permission_required("api.firewall.edit")
def update_nat_npt(rule_id):
    """Update an NPt mapping"""
    try:
        data = request.get_json(silent=True) or {}
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
@api_permission_required("api.firewall.edit")
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
