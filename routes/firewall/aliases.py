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


@firewall_bp.route("/aliases")
@login_required
def aliases():
    # Default tab = 'all'
    return render_template("aliases.html", tab="all")


@firewall_bp.route("/aliases/<tab>")
@login_required
def firewall_aliases_tab(tab):
    valid_tabs = ["ip", "ports", "urls", "all"]
    if tab not in valid_tabs:
        tab = "all"
    return render_template("aliases.html", tab=tab)


@firewall_bp.route("/api/aliases", methods=["GET"])
@login_required
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
@api_permission_required("api.firewall.edit")
def add_alias():
    """Add a new alias"""
    try:
        data = request.get_json(silent=True) or {}
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


@firewall_bp.route("/api/aliases/<int:alias_id>", methods=["GET"])
@login_required
def get_alias(alias_id):
    """Get a single alias by ID"""
    try:
        db = get_db()
        row = db.execute(
            "SELECT id, name, type, alias_values, description FROM firewall_aliases WHERE id=?",
            (alias_id,)
        ).fetchone()
        if not row:
            return jsonify({"success": False, "error": "Alias not found"}), 404
        return jsonify({"success": True, "alias": dict(row)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@firewall_bp.route("/api/aliases/<int:alias_id>", methods=["PUT"])
@api_permission_required("api.firewall.edit")
def update_alias(alias_id):
    """Update an alias"""
    try:
        data = request.get_json(silent=True) or {}
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
@api_permission_required("api.firewall.edit")
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
