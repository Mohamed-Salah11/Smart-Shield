from flask import Blueprint, render_template, request, jsonify, redirect, url_for
from app.database import get_db

firewall_bp = Blueprint("firewall", __name__, url_prefix="/firewall")

# ----------------------------
# FIREWALL MAIN PAGE
# ----------------------------

@firewall_bp.route("/")
def firewall_home():
    return render_template("firewall.html")


# ----------------------------
# FIREWALL RULES
# ----------------------------

@firewall_bp.route("/rules")
def rules():
    return render_template("rules.html")


# Floating Rules CRUD
@firewall_bp.route("/api/rules/floating", methods=["GET"])
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
def add_floating_rule():
    """Add a new floating rule"""
    try:
        data = request.get_json()
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("""
            INSERT INTO firewall_rules_floating 
            (disabled, interface, protocol, source, source_port, destination, 
             dest_port, gateway, queue, schedule, description, rule_order)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 
                   (SELECT COALESCE(MAX(rule_order), 0) + 1 FROM firewall_rules_floating))
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
            data.get('description', '')
        ))
        
        db.commit()
        return jsonify({"success": True, "id": cursor.lastrowid})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/rules/floating/<int:rule_id>", methods=["PUT"])
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
def add_wan_rule():
    """Add a new WAN rule"""
    try:
        data = request.get_json()
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("""
            INSERT INTO firewall_rules_wan 
            (action, disabled, protocol, source, destination, description, rule_order)
            VALUES (?, ?, ?, ?, ?, ?, 
                   (SELECT COALESCE(MAX(rule_order), 0) + 1 FROM firewall_rules_wan))
        """, (
            data.get('action', 'pass'),
            data.get('disabled', 0),
            data.get('protocol', 'any'),
            data.get('source', 'any'),
            data.get('destination', 'any'),
            data.get('description', '')
        ))
        
        db.commit()
        return jsonify({"success": True, "id": cursor.lastrowid})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/rules/wan/<int:rule_id>", methods=["PUT"])
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
def add_lan_rule():
    """Add a new LAN rule"""
    try:
        data = request.get_json()
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("""
            INSERT INTO firewall_rules_lan 
            (disabled, interface, protocol, source, destination, description, rule_order)
            VALUES (?, ?, ?, ?, ?, ?, 
                   (SELECT COALESCE(MAX(rule_order), 0) + 1 FROM firewall_rules_lan))
        """, (
            data.get('disabled', 0),
            data.get('interface', 'LAN'),
            data.get('protocol', 'any'),
            data.get('source', 'any'),
            data.get('destination', 'any'),
            data.get('description', '')
        ))
        
        db.commit()
        return jsonify({"success": True, "id": cursor.lastrowid})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/rules/lan/<int:rule_id>", methods=["PUT"])
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
def nat():
    return render_template("nat.html")


# Port Forward NAT CRUD
@firewall_bp.route("/api/nat/pf", methods=["GET"])
def get_nat_pf():
    """Get all port forward NAT rules"""
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("""
            SELECT id, disabled, interface, protocol, src_type, src_address, 
                   dst_type, dst_address, redirect_ip, description, nat_reflection
            FROM nat_pf
            ORDER BY id
        """)
        rules = [dict(row) for row in cursor.fetchall()]
        return jsonify({"success": True, "rules": rules})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/nat/pf", methods=["POST"])
def add_nat_pf():
    """Add a new port forward rule"""
    try:
        data = request.get_json()
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("""
            INSERT INTO nat_pf 
            (disabled, interface, protocol, src_type, src_address, dst_type, 
             dst_address, redirect_ip, description, nat_reflection)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            data.get('nat_reflection', 'default')
        ))
        
        db.commit()
        return jsonify({"success": True, "id": cursor.lastrowid})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/nat/pf/<int:rule_id>", methods=["PUT"])
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
def get_nat_1to1():
    """Get all 1:1 NAT mappings"""
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("""
            SELECT id, disabled, interface, external_address, internal_address, 
                   destination_address, description
            FROM nat_1to1
            ORDER BY id
        """)
        rules = [dict(row) for row in cursor.fetchall()]
        return jsonify({"success": True, "rules": rules})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/nat/1to1", methods=["POST"])
def add_nat_1to1():
    """Add a new 1:1 NAT mapping"""
    try:
        data = request.get_json()
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("""
            INSERT INTO nat_1to1 
            (disabled, interface, external_address, internal_address, 
             destination_address, description)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            data.get('disabled', 0),
            data.get('interface', 'WAN'),
            data.get('external_address', ''),
            data.get('internal_address', ''),
            data.get('destination_address', 'any'),
            data.get('description', '')
        ))
        
        db.commit()
        return jsonify({"success": True, "id": cursor.lastrowid})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/nat/1to1/<int:rule_id>", methods=["PUT"])
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
            ORDER BY id
        """)
        rules = [dict(row) for row in cursor.fetchall()]
        return jsonify({"success": True, "rules": rules})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/nat/outbound", methods=["POST"])
def add_nat_outbound():
    """Add a new outbound NAT rule"""
    try:
        data = request.get_json()
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("""
            INSERT INTO nat_outbound 
            (disabled, interface, src_address, dst_address, nat_address, 
             static_port, description)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            data.get('disabled', 0),
            data.get('interface', 'WAN'),
            data.get('src_address', ''),
            data.get('dst_address', 'any'),
            data.get('nat_address', ''),
            data.get('static_port', 0),
            data.get('description', '')
        ))
        
        db.commit()
        return jsonify({"success": True, "id": cursor.lastrowid})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/nat/outbound/<int:rule_id>", methods=["PUT"])
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
            ORDER BY id
        """)
        rules = [dict(row) for row in cursor.fetchall()]
        return jsonify({"success": True, "rules": rules})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/nat/npt", methods=["POST"])
def add_nat_npt():
    """Add a new NPt mapping"""
    try:
        data = request.get_json()
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("""
            INSERT INTO nat_npt 
            (disabled, interface, src_not, src_prefix, src_prefix_length,
             dst_not, dst_type, dst_prefix, dst_prefix_length, description)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            data.get('description', '')
        ))
        
        db.commit()
        return jsonify({"success": True, "id": cursor.lastrowid})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/nat/npt/<int:rule_id>", methods=["PUT"])
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
    # Default tab = 'ip'
    return render_template("aliases.html", tab="ip")


@firewall_bp.route("/aliases/<tab>")
def firewall_aliases_tab(tab):
    valid_tabs = ["ip", "ports", "urls", "all"]
    if tab not in valid_tabs:
        tab = "ip"
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
def schedules():
    return render_template("schedules.html")


# ----------------------------
# TRAFFIC SHAPER
# ----------------------------

@firewall_bp.route("/traffic-shaper")
def traffic_shaper():
    return render_template("traffic_shaper.html")


# ----------------------------
# VIRTUAL IPs
# ----------------------------

@firewall_bp.route("/virtual-ips")
def virtual_ips():
    return render_template("virtual_ips.html")


# ----------------------------
# FIREWALL HOME
# ----------------------------

@firewall_bp.route("/home")
def home():
    return redirect(url_for("firewall.firewall_home"))
