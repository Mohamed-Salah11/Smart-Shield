from flask import Blueprint, render_template, request, jsonify, current_app, redirect, url_for
import sqlite3
from app.auth_utils import login_required
from app.api_auth import api_permission_required
from app.db_utils import db_cursor
from app.database import get_db
from app.secret_store import encrypt_secret
from app.validators import validate_ip, validate_cidr, validate_interface_name, collect_errors

interfaces_bp = Blueprint("interfaces", __name__, url_prefix="/interfaces")

# ----------------------------
# INTERFACES MAIN PAGE
# ----------------------------

@interfaces_bp.route("/")
@login_required
def interfaces_home():
    # interfaces.html is a placeholder stub; the Assignments page is the
    # real landing screen for the Interfaces section.
    return redirect(url_for("interfaces.interfaces_assignments"))

@interfaces_bp.route("/interfaces")
@login_required
def interfaces():
    return redirect(url_for("interfaces.interfaces_assignments"))


# ----------------------------
# INTERFACE ASSIGNMENTS PAGE
# ----------------------------

@interfaces_bp.route("/assignments")
@login_required
def interfaces_assignments():
    return render_template("interfaces_assignments.html")

@interfaces_bp.route("/available-ports", methods=['GET'])
@login_required
def available_ports():
    """Return physical NICs for assignment dropdowns."""
    import sys
    is_freebsd = sys.platform.startswith("freebsd")
    try:
        from app.services.network_service import list_physical_nics

        ports = []
        for nic in list_physical_nics():
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

            label = name if not details else f"{name} ({', '.join(details)})"
            ports.append({
                "name": name,
                "label": label,
                "ether": ether,
                "status": status,
                "media": media,
            })

        # P2-06: on FreeBSD, an empty result means real detection failed —
        # fail loud rather than mask the issue with em0/em1 fake data.
        # On non-FreeBSD (dev box), surface the em0/em1 stub data but flag
        # it as dev_mode so the UI can render a "DEV / DEMO DATA" badge.
        dev_mode = False
        if not ports:
            if is_freebsd:
                return jsonify({
                    "status": "error",
                    "message": "No network interfaces detected. Check ifconfig -l output.",
                }), 503
            dev_mode = True
            ports = [
                {"name": "em0", "label": "em0", "ether": "", "status": "", "media": ""},
                {"name": "em1", "label": "em1", "ether": "", "status": "", "media": ""},
            ]

        return jsonify({"status": "success", "ports": ports, "dev_mode": dev_mode})
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400

@interfaces_bp.route("/get-interface-groups", methods=['GET'])
@login_required
def get_interface_groups():
    try:
        with db_cursor() as (_, cursor):
            cursor.execute('SELECT id, group_name, description, members FROM interface_groups')
            groups = cursor.fetchall()

        groups_list = [
            {
                'id': g["id"],
                'name': g["group_name"],
                'description': g["description"],
                'members': g["members"].split(',') if g["members"] else []
            }
            for g in groups
        ]
        return jsonify({'status': 'success', 'data': groups_list})
    except Exception as e:
        current_app.logger.exception("interfaces: %s", e)
        return jsonify({'status': 'error', 'message': str(e)}), 400
    
@interfaces_bp.route("/save-interface-group", methods=['POST'])
@api_permission_required("api.network.edit")
def save_interface_group():
    try:
        data = request.get_json(silent=True) or {}
        name = (data.get('groupName') or '').strip()
        errs = [] if name else ["Group name is required"]
        if errs:
            return jsonify({'status': 'error', 'message': '; '.join(errs)}), 400
        with db_cursor(commit=True) as (_, cursor):
            cursor.execute(
                '''INSERT INTO interface_groups (group_name, description, members)
                   VALUES (?, ?, ?)''',
                (
                    data['groupName'],
                    data.get('groupDescription', ''),
                    ','.join(data.get('groupMembers', []))
                )
            )
        return jsonify({'status': 'success', 'message': 'Interface group saved'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/get-interface-group/<int:group_id>", methods=['GET'])
@login_required
def get_interface_group(group_id):
    try:
        with db_cursor() as (_, cursor):
            cursor.execute(
                'SELECT id, group_name, description, members FROM interface_groups WHERE id = ?',
                (group_id,)
            )
            group = cursor.fetchone()

        if group:
            return jsonify({'status': 'success', 'data': {
                'id': group["id"],
                'name': group["group_name"],
                'description': group["description"],
                'members': group["members"].split(',') if group["members"] else []
            }})
        return jsonify({'status': 'error', 'message': 'Group not found'}), 404
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/update-interface-group/<int:group_id>", methods=['PUT'])
@api_permission_required("api.network.edit")
def update_interface_group(group_id):
    try:
        data = request.get_json(silent=True) or {}
        name = (data.get('groupName') or '').strip()
        errs = [] if name else ["Group name is required"]
        if errs:
            return jsonify({'status': 'error', 'message': '; '.join(errs)}), 400
        with db_cursor(commit=True) as (_, cursor):
            cursor.execute(
                '''UPDATE interface_groups
                   SET group_name = ?, description = ?, members = ?
                   WHERE id = ?''',
                (
                    data['groupName'],
                    data.get('groupDescription', ''),
                    ','.join(data.get('groupMembers', [])),
                    group_id
                )
            )
        return jsonify({'status': 'success', 'message': 'Group updated'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/delete-interface-group/<int:group_id>", methods=['DELETE'])
@api_permission_required("api.network.edit")
def delete_interface_group(group_id):
    try:
        with db_cursor(commit=True) as (_, cursor):
            cursor.execute('DELETE FROM interface_groups WHERE id = ?', (group_id,))
        return jsonify({'status': 'success', 'message': 'Group deleted'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

# ----------------------------
# INTERFACE ASSIGNMENTS (WAN/LAN)
# ----------------------------

@interfaces_bp.route("/get-interface-assignments", methods=['GET'])
@login_required
def get_interface_assignments():
    try:
        with db_cursor() as (_, cursor):
            cursor.execute('SELECT id, interface_type, network_port FROM interface_assignments')
            assignments = cursor.fetchall()

        assignments_list = [
            {
                'id': a["id"],
                'interface_type': a["interface_type"],
                'network_port': a["network_port"]
            }
            for a in assignments
        ]
        return jsonify({'status': 'success', 'data': assignments_list})
    except Exception as e:
        current_app.logger.exception("interfaces: %s", e)
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/save-interface-assignment", methods=['POST'])
@api_permission_required("api.network.edit")
def save_interface_assignment():
    try:
        data = request.get_json(silent=True) or {}
        iface_type = (data.get('interfaceType') or '').strip().upper()
        net_port   = (data.get('networkPort') or '').strip()

        if iface_type not in {"WAN", "LAN"}:
            return jsonify({'status': 'error', 'message': 'interfaceType must be WAN or LAN'}), 400
        if not net_port:
            return jsonify({'status': 'error', 'message': 'networkPort is required'}), 400

        try:
            validate_interface_name(net_port, allow_empty=False)
        except ValueError as exc:
            return jsonify({'status': 'error', 'message': str(exc)}), 400

        opposite = "LAN" if iface_type == "WAN" else "WAN"

        with db_cursor(commit=True) as (_, cursor):
            cursor.execute(
                'SELECT network_port FROM interface_assignments WHERE interface_type = ?',
                (opposite,)
            )
            other = cursor.fetchone()
            if other and (other["network_port"] or "").strip() == net_port:
                return jsonify({
                    'status': 'error',
                    'message': f'{net_port} is already assigned to {opposite}',
                }), 400

            cursor.execute(
                '''
                INSERT INTO interface_assignments (interface_type, network_port)
                VALUES (?, ?)
                ON CONFLICT(interface_type) DO UPDATE SET
                    network_port = excluded.network_port
                ''',
                (iface_type, net_port)
            )

            if iface_type == "WAN":
                cursor.execute(
                    'UPDATE wan_config SET assigned_port = ? WHERE id = 1',
                    (net_port,)
                )
            else:
                cursor.execute(
                    'UPDATE lan_config SET assigned_port = ? WHERE id = 1',
                    (net_port,)
                )

        return jsonify({'status': 'success', 'message': f'{iface_type} assigned to {net_port}'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/delete-interface-assignment/<interface_type>", methods=['DELETE'])
@api_permission_required("api.network.edit")
def delete_interface_assignment(interface_type):
    try:
        iface_type = (interface_type or '').strip().upper()
        if iface_type not in {"WAN", "LAN"}:
            return jsonify({'status': 'error', 'message': 'interface_type must be WAN or LAN'}), 400

        with db_cursor(commit=True) as (_, cursor):
            cursor.execute(
                'DELETE FROM interface_assignments WHERE interface_type = ?',
                (iface_type,)
            )

            if iface_type == "WAN":
                cursor.execute("UPDATE wan_config SET assigned_port = '' WHERE id = 1")
            else:
                cursor.execute("UPDATE lan_config SET assigned_port = '' WHERE id = 1")

        return jsonify({'status': 'success', 'message': f'{iface_type} assignment deleted'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

# ----------------------------
# WIRELESS INTERFACE CONFIGURATION
# ----------------------------

@interfaces_bp.route("/get-wireless-configs", methods=['GET'])
@login_required
def get_wireless_configs():
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''SELECT id, parent_interface, mode, description FROM wireless_configs''')
        configs = cursor.fetchall()
        
        configs_list = [
            {
                'id': c[0],
                'parent_interface': c[1],
                'mode': c[2],
                'description': c[3]
            }
            for c in configs
        ]
        return jsonify({'status': 'success', 'data': configs_list})
    except Exception as e:
        current_app.logger.exception("interfaces: %s", e)
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/save-wireless-config", methods=['POST'])
@api_permission_required("api.network.edit")
def save_wireless_config():
    try:
        data = request.get_json(silent=True) or {}
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO wireless_configs (parent_interface, mode, description) 
                          VALUES (?, ?, ?)''', 
                       (data['parentInterface'], data['mode'], data['description']))
        conn.commit()
        return jsonify({'status': 'success', 'message': 'Wireless config saved'})
    except Exception as e:
        current_app.logger.exception("interfaces: %s", e)
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/get-wireless-config/<int:config_id>", methods=['GET'])
@login_required
def get_wireless_config(config_id):
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT id, parent_interface, mode, description FROM wireless_configs WHERE id = ?', (config_id,))
        config = cursor.fetchone()
        
        if config:
            return jsonify({'status': 'success', 'data': {
                'id': config[0],
                'parent_interface': config[1],
                'mode': config[2],
                'description': config[3]
            }})
        return jsonify({'status': 'error', 'message': 'Config not found'}), 404
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/update-wireless-config/<int:config_id>", methods=['PUT'])
@api_permission_required("api.network.edit")
def update_wireless_config(config_id):
    try:
        data = request.get_json(silent=True) or {}
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''UPDATE wireless_configs SET parent_interface = ?, mode = ?, description = ? WHERE id = ?''',
                       (data['parentInterface'], data['mode'], data['description'], config_id))
        conn.commit()
        return jsonify({'status': 'success', 'message': 'Config updated'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/delete-wireless-config/<int:config_id>", methods=['DELETE'])
@api_permission_required("api.network.edit")
def delete_wireless_config(config_id):
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM wireless_configs WHERE id = ?', (config_id,))
        conn.commit()
        return jsonify({'status': 'success', 'message': 'Config deleted'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

# ----------------------------
# VLAN CONFIGURATION
# ----------------------------

@interfaces_bp.route("/get-vlan-configs", methods=['GET'])
@login_required
def get_vlan_configs():
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''SELECT id, parent_interface, vlan_tag, vlan_priority, description FROM vlan_configs''')
        configs = cursor.fetchall()
        
        configs_list = [
            {
                'id': c[0],
                'parent_interface': c[1],
                'vlan_tag': c[2],
                'vlan_priority': c[3],
                'description': c[4]
            }
            for c in configs
        ]
        return jsonify({'status': 'success', 'data': configs_list})
    except Exception as e:
        current_app.logger.exception("interfaces: %s", e)
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/save-vlan-config", methods=['POST'])
@api_permission_required("api.network.edit")
def save_vlan_config():
    try:
        data = request.get_json(silent=True) or {}
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO vlan_configs (parent_interface, vlan_tag, vlan_priority, description) 
                          VALUES (?, ?, ?, ?)''', 
                       (data['parentInterface'], data['vlanTag'], data['vlanPriority'], data['description']))
        conn.commit()
        return jsonify({'status': 'success', 'message': 'VLAN config saved'})
    except Exception as e:
        current_app.logger.exception("interfaces: %s", e)
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/get-vlan-config/<int:config_id>", methods=['GET'])
@login_required
def get_vlan_config(config_id):
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT id, parent_interface, vlan_tag, vlan_priority, description FROM vlan_configs WHERE id = ?', (config_id,))
        config = cursor.fetchone()
        
        if config:
            return jsonify({'status': 'success', 'data': {
                'id': config[0],
                'parent_interface': config[1],
                'vlan_tag': config[2],
                'vlan_priority': config[3],
                'description': config[4]
            }})
        return jsonify({'status': 'error', 'message': 'Config not found'}), 404
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/update-vlan-config/<int:config_id>", methods=['PUT'])
@api_permission_required("api.network.edit")
def update_vlan_config(config_id):
    try:
        data = request.get_json(silent=True) or {}
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''UPDATE vlan_configs SET parent_interface = ?, vlan_tag = ?, vlan_priority = ?, description = ? WHERE id = ?''',
                       (data['parentInterface'], data['vlanTag'], data['vlanPriority'], data['description'], config_id))
        conn.commit()
        return jsonify({'status': 'success', 'message': 'Config updated'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/delete-vlan-config/<int:config_id>", methods=['DELETE'])
@api_permission_required("api.network.edit")
def delete_vlan_config(config_id):
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM vlan_configs WHERE id = ?', (config_id,))
        conn.commit()
        return jsonify({'status': 'success', 'message': 'Config deleted'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

# ----------------------------
# QINQ CONFIGURATION
# ----------------------------

@interfaces_bp.route("/get-qinq-configs", methods=['GET'])
@login_required
def get_qinq_configs():
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''SELECT id, parent_interface, first_level_tag, add_to_groups, description, member_tags FROM qinq_configs''')
        configs = cursor.fetchall()
        
        configs_list = [
            {
                'id': c[0],
                'parent_interface': c[1],
                'first_level_tag': c[2],
                'add_to_groups': bool(c[3]),
                'description': c[4],
                'member_tags': c[5].split(',') if c[5] else []
            }
            for c in configs
        ]
        return jsonify({'status': 'success', 'data': configs_list})
    except Exception as e:
        current_app.logger.exception("interfaces: %s", e)
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/save-qinq-config", methods=['POST'])
@api_permission_required("api.network.edit")
def save_qinq_config():
    try:
        data = request.get_json(silent=True) or {}
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO qinq_configs (parent_interface, first_level_tag, add_to_groups, description, member_tags) 
                          VALUES (?, ?, ?, ?, ?)''', 
                       (data['parentInterface'], data['firstLevelTag'], data['addToGroups'], data['description'], ','.join(data['memberTags'])))
        conn.commit()
        return jsonify({'status': 'success', 'message': 'QinQ config saved'})
    except Exception as e:
        current_app.logger.exception("interfaces: %s", e)
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/get-qinq-config/<int:config_id>", methods=['GET'])
@login_required
def get_qinq_config(config_id):
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT id, parent_interface, first_level_tag, add_to_groups, description, member_tags FROM qinq_configs WHERE id = ?', (config_id,))
        config = cursor.fetchone()
        
        if config:
            return jsonify({'status': 'success', 'data': {
                'id': config[0],
                'parent_interface': config[1],
                'first_level_tag': config[2],
                'add_to_groups': bool(config[3]),
                'description': config[4],
                'member_tags': config[5].split(',') if config[5] else []
            }})
        return jsonify({'status': 'error', 'message': 'Config not found'}), 404
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/update-qinq-config/<int:config_id>", methods=['PUT'])
@api_permission_required("api.network.edit")
def update_qinq_config(config_id):
    try:
        data = request.get_json(silent=True) or {}
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''UPDATE qinq_configs SET parent_interface = ?, first_level_tag = ?, add_to_groups = ?, description = ?, member_tags = ? WHERE id = ?''',
                       (data['parentInterface'], data['firstLevelTag'], data['addToGroups'], data['description'], ','.join(data['memberTags']), config_id))
        conn.commit()
        return jsonify({'status': 'success', 'message': 'Config updated'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/delete-qinq-config/<int:config_id>", methods=['DELETE'])
@api_permission_required("api.network.edit")
def delete_qinq_config(config_id):
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM qinq_configs WHERE id = ?', (config_id,))
        conn.commit()
        return jsonify({'status': 'success', 'message': 'Config deleted'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

# ----------------------------
# PPP CONFIGURATION
# ----------------------------

@interfaces_bp.route("/get-ppp-configs", methods=['GET'])
@login_required
def get_ppp_configs():
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT id, link_type, link_interfaces, description, username, dial_on_demand FROM ppp_configs')
        configs = cursor.fetchall()
        
        configs_list = [
            {
                'id': c[0],
                'link_type': c[1],
                'link_interfaces': c[2].split(',') if c[2] else [],
                'description': c[3],
                'username': c[4],
                'dial_on_demand': bool(c[5])
            }
            for c in configs
        ]
        return jsonify({'status': 'success', 'data': configs_list})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/save-ppp-config", methods=['POST'])
@api_permission_required("api.network.edit")
def save_ppp_config():
    try:
        data = request.get_json(silent=True) or {}
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO ppp_configs (link_type, link_interfaces, description, username, password, dial_on_demand)
                          VALUES (?, ?, ?, ?, ?, ?)''',
                       (data['linkType'], ','.join(data['linkInterfaces']), data['description'], data['username'], data['password'], data['dialOnDemand']))
        conn.commit()
        return jsonify({'status': 'success', 'message': 'Config saved'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/get-ppp-config/<int:config_id>", methods=['GET'])
@login_required
def get_ppp_config(config_id):
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT id, link_type, link_interfaces, description, username, password, dial_on_demand FROM ppp_configs WHERE id = ?', (config_id,))
        config = cursor.fetchone()
        
        if config:
            return jsonify({'status': 'success', 'data': {
                'id': config[0],
                'link_type': config[1],
                'link_interfaces': config[2].split(',') if config[2] else [],
                'description': config[3],
                'username': config[4],
                'password': config[5],
                'dial_on_demand': bool(config[6])
            }})
        return jsonify({'status': 'error', 'message': 'Config not found'}), 404
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/update-ppp-config/<int:config_id>", methods=['PUT'])
@api_permission_required("api.network.edit")
def update_ppp_config(config_id):
    try:
        data = request.get_json(silent=True) or {}
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''UPDATE ppp_configs SET link_type = ?, link_interfaces = ?, description = ?, username = ?, password = ?, dial_on_demand = ? WHERE id = ?''',
                       (data['linkType'], ','.join(data['linkInterfaces']), data['description'], data['username'], data['password'], data['dialOnDemand'], config_id))
        conn.commit()
        return jsonify({'status': 'success', 'message': 'Config updated'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/delete-ppp-config/<int:config_id>", methods=['DELETE'])
@api_permission_required("api.network.edit")
def delete_ppp_config(config_id):
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM ppp_configs WHERE id = ?', (config_id,))
        conn.commit()
        return jsonify({'status': 'success', 'message': 'Config deleted'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

# ----------------------------
# GRE CONFIGURATION
# ----------------------------

@interfaces_bp.route("/get-gre-configs", methods=['GET'])
@login_required
def get_gre_configs():
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT id, parent_interface, gre_remote_address, gre_local_address, ipv4_tunnel_remote_address, ipv4_tunnel_remote_prefix, ipv4_tunnel_local_address, ipv4_tunnel_local_prefix, ipv6_tunnel_remote_address, ipv6_tunnel_remote_prefix, ipv6_tunnel_local_address, ipv6_tunnel_local_prefix, description FROM gre_configs')
        configs = cursor.fetchall()
        
        configs_list = [
            {
                'id': c[0],
                'parent_interface': c[1],
                'gre_remote_address': c[2],
                'gre_local_address': c[3],
                'ipv4_tunnel_remote_address': c[4],
                'ipv4_tunnel_remote_prefix': c[5],
                'ipv4_tunnel_local_address': c[6],
                'ipv4_tunnel_local_prefix': c[7],
                'ipv6_tunnel_remote_address': c[8],
                'ipv6_tunnel_remote_prefix': c[9],
                'ipv6_tunnel_local_address': c[10],
                'ipv6_tunnel_local_prefix': c[11],
                'description': c[12]
            }
            for c in configs
        ]
        return jsonify({'status': 'success', 'data': configs_list})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/save-gre-config", methods=['POST'])
@api_permission_required("api.network.edit")
def save_gre_config():
    try:
        data = request.get_json(silent=True) or {}
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO gre_configs (parent_interface, gre_remote_address, gre_local_address, ipv4_tunnel_remote_address, ipv4_tunnel_remote_prefix, ipv4_tunnel_local_address, ipv4_tunnel_local_prefix, ipv6_tunnel_remote_address, ipv6_tunnel_remote_prefix, ipv6_tunnel_local_address, ipv6_tunnel_local_prefix, description)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                       (data['parentInterface'], data['greRemoteAddress'], data['greLocalAddress'], data['ipv4TunnelRemoteAddress'], data['ipv4TunnelRemotePrefix'], data['ipv4TunnelLocalAddress'], data['ipv4TunnelLocalPrefix'], data['ipv6TunnelRemoteAddress'], data['ipv6TunnelRemotePrefix'], data['ipv6TunnelLocalAddress'], data['ipv6TunnelLocalPrefix'], data['description']))
        conn.commit()
        return jsonify({'status': 'success', 'message': 'Config saved'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/get-gre-config/<int:config_id>", methods=['GET'])
@login_required
def get_gre_config(config_id):
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT id, parent_interface, gre_remote_address, gre_local_address, ipv4_tunnel_remote_address, ipv4_tunnel_remote_prefix, ipv4_tunnel_local_address, ipv4_tunnel_local_prefix, ipv6_tunnel_remote_address, ipv6_tunnel_remote_prefix, ipv6_tunnel_local_address, ipv6_tunnel_local_prefix, description FROM gre_configs WHERE id = ?', (config_id,))
        config = cursor.fetchone()
        
        if config:
            return jsonify({'status': 'success', 'data': {
                'id': config[0],
                'parent_interface': config[1],
                'gre_remote_address': config[2],
                'gre_local_address': config[3],
                'ipv4_tunnel_remote_address': config[4],
                'ipv4_tunnel_remote_prefix': config[5],
                'ipv4_tunnel_local_address': config[6],
                'ipv4_tunnel_local_prefix': config[7],
                'ipv6_tunnel_remote_address': config[8],
                'ipv6_tunnel_remote_prefix': config[9],
                'ipv6_tunnel_local_address': config[10],
                'ipv6_tunnel_local_prefix': config[11],
                'description': config[12]
            }})
        return jsonify({'status': 'error', 'message': 'Config not found'}), 404
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/update-gre-config/<int:config_id>", methods=['PUT'])
@api_permission_required("api.network.edit")
def update_gre_config(config_id):
    try:
        data = request.get_json(silent=True) or {}
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''UPDATE gre_configs SET parent_interface = ?, gre_remote_address = ?, gre_local_address = ?, ipv4_tunnel_remote_address = ?, ipv4_tunnel_remote_prefix = ?, ipv4_tunnel_local_address = ?, ipv4_tunnel_local_prefix = ?, ipv6_tunnel_remote_address = ?, ipv6_tunnel_remote_prefix = ?, ipv6_tunnel_local_address = ?, ipv6_tunnel_local_prefix = ?, description = ? WHERE id = ?''',
                       (data['parentInterface'], data['greRemoteAddress'], data['greLocalAddress'], data['ipv4TunnelRemoteAddress'], data['ipv4TunnelRemotePrefix'], data['ipv4TunnelLocalAddress'], data['ipv4TunnelLocalPrefix'], data['ipv6TunnelRemoteAddress'], data['ipv6TunnelRemotePrefix'], data['ipv6TunnelLocalAddress'], data['ipv6TunnelLocalPrefix'], data['description'], config_id))
        conn.commit()
        return jsonify({'status': 'success', 'message': 'Config updated'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/delete-gre-config/<int:config_id>", methods=['DELETE'])
@api_permission_required("api.network.edit")
def delete_gre_config(config_id):
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM gre_configs WHERE id = ?', (config_id,))
        conn.commit()
        return jsonify({'status': 'success', 'message': 'Config deleted'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

# ----------------------------
# GIF CONFIGURATION
# ----------------------------

@interfaces_bp.route("/get-gif-configs", methods=['GET'])
@login_required
def get_gif_configs():
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT id, parent_interface, gif_remote_address, gif_tunnel_local_address, gif_tunnel_remote_address, gif_tunnel_subnet, ecn_friendly_behavior, outer_source_filtering, description FROM gif_configs')
        configs = cursor.fetchall()
        
        configs_list = [
            {
                'id': c[0],
                'parent_interface': c[1],
                'gif_remote_address': c[2],
                'gif_tunnel_local_address': c[3],
                'gif_tunnel_remote_address': c[4],
                'gif_tunnel_subnet': c[5],
                'ecn_friendly_behavior': bool(c[6]),
                'outer_source_filtering': bool(c[7]),
                'description': c[8]
            }
            for c in configs
        ]
        return jsonify({'status': 'success', 'data': configs_list})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/save-gif-config", methods=['POST'])
@api_permission_required("api.network.edit")
def save_gif_config():
    try:
        data = request.get_json(silent=True) or {}
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO gif_configs (parent_interface, gif_remote_address, gif_tunnel_local_address, gif_tunnel_remote_address, gif_tunnel_subnet, ecn_friendly_behavior, outer_source_filtering, description)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                       (data['parentInterface'], data['gifRemoteAddress'], data['gifTunnelLocalAddress'], data['gifTunnelRemoteAddress'], data['gifTunnelSubnet'], data['ecnFriendlyBehavior'], data['outerSourceFiltering'], data['description']))
        conn.commit()
        return jsonify({'status': 'success', 'message': 'Config saved'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/get-gif-config/<int:config_id>", methods=['GET'])
@login_required
def get_gif_config(config_id):
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT id, parent_interface, gif_remote_address, gif_tunnel_local_address, gif_tunnel_remote_address, gif_tunnel_subnet, ecn_friendly_behavior, outer_source_filtering, description FROM gif_configs WHERE id = ?', (config_id,))
        config = cursor.fetchone()
        
        if config:
            return jsonify({'status': 'success', 'data': {
                'id': config[0],
                'parent_interface': config[1],
                'gif_remote_address': config[2],
                'gif_tunnel_local_address': config[3],
                'gif_tunnel_remote_address': config[4],
                'gif_tunnel_subnet': config[5],
                'ecn_friendly_behavior': bool(config[6]),
                'outer_source_filtering': bool(config[7]),
                'description': config[8]
            }})
        return jsonify({'status': 'error', 'message': 'Config not found'}), 404
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/update-gif-config/<int:config_id>", methods=['PUT'])
@api_permission_required("api.network.edit")
def update_gif_config(config_id):
    try:
        data = request.get_json(silent=True) or {}
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''UPDATE gif_configs SET parent_interface = ?, gif_remote_address = ?, gif_tunnel_local_address = ?, gif_tunnel_remote_address = ?, gif_tunnel_subnet = ?, ecn_friendly_behavior = ?, outer_source_filtering = ?, description = ? WHERE id = ?''',
                       (data['parentInterface'], data['gifRemoteAddress'], data['gifTunnelLocalAddress'], data['gifTunnelRemoteAddress'], data['gifTunnelSubnet'], data['ecnFriendlyBehavior'], data['outerSourceFiltering'], data['description'], config_id))
        conn.commit()
        return jsonify({'status': 'success', 'message': 'Config updated'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/delete-gif-config/<int:config_id>", methods=['DELETE'])
@api_permission_required("api.network.edit")
def delete_gif_config(config_id):
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM gif_configs WHERE id = ?', (config_id,))
        conn.commit()
        return jsonify({'status': 'success', 'message': 'Config deleted'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

# ----------------------------
# BRIDGE CONFIGURATION
# ----------------------------

@interfaces_bp.route("/get-bridge-configs", methods=['GET'])
@login_required
def get_bridge_configs():
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT id, member_interfaces, description, cache_size, cache_max_age, span_interfaces, edge_interfaces, auto_edge_interfaces, ptp_interfaces, sticky_ports FROM bridge_configs')
        configs = cursor.fetchall()
        
        configs_list = [
            {
                'id': c[0],
                'member_interfaces': c[1].split(',') if c[1] else [],
                'description': c[2],
                'cache_size': c[3],
                'cache_max_age': c[4],
                'span_interfaces': c[5].split(',') if c[5] else [],
                'edge_interfaces': c[6].split(',') if c[6] else [],
                'auto_edge_interfaces': c[7].split(',') if c[7] else [],
                'ptp_interfaces': c[8].split(',') if c[8] else [],
                'sticky_ports': bool(c[9])
            }
            for c in configs
        ]
        return jsonify({'status': 'success', 'data': configs_list})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/save-bridge-config", methods=['POST'])
@api_permission_required("api.network.edit")
def save_bridge_config():
    try:
        data = request.get_json(silent=True) or {}
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO bridge_configs (member_interfaces, description, cache_size, cache_max_age, span_interfaces, edge_interfaces, auto_edge_interfaces, ptp_interfaces, sticky_ports)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                       (','.join(data['memberInterfaces']), data['description'], data['cacheSize'], data['cacheMaxAge'], ','.join(data['spanInterfaces']), ','.join(data['edgeInterfaces']), ','.join(data['autoEdgeInterfaces']), ','.join(data['ptpInterfaces']), data['stickyPorts']))
        conn.commit()
        return jsonify({'status': 'success', 'message': 'Config saved'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/get-bridge-config/<int:config_id>", methods=['GET'])
@login_required
def get_bridge_config(config_id):
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT id, member_interfaces, description, cache_size, cache_max_age, span_interfaces, edge_interfaces, auto_edge_interfaces, ptp_interfaces, sticky_ports FROM bridge_configs WHERE id = ?', (config_id,))
        config = cursor.fetchone()
        
        if config:
            return jsonify({'status': 'success', 'data': {
                'id': config[0],
                'member_interfaces': config[1].split(',') if config[1] else [],
                'description': config[2],
                'cache_size': config[3],
                'cache_max_age': config[4],
                'span_interfaces': config[5].split(',') if config[5] else [],
                'edge_interfaces': config[6].split(',') if config[6] else [],
                'auto_edge_interfaces': config[7].split(',') if config[7] else [],
                'ptp_interfaces': config[8].split(',') if config[8] else [],
                'sticky_ports': bool(config[9])
            }})
        return jsonify({'status': 'error', 'message': 'Config not found'}), 404
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/update-bridge-config/<int:config_id>", methods=['PUT'])
@api_permission_required("api.network.edit")
def update_bridge_config(config_id):
    try:
        data = request.get_json(silent=True) or {}
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''UPDATE bridge_configs SET member_interfaces = ?, description = ?, cache_size = ?, cache_max_age = ?, span_interfaces = ?, edge_interfaces = ?, auto_edge_interfaces = ?, ptp_interfaces = ?, sticky_ports = ? WHERE id = ?''',
                       (','.join(data['memberInterfaces']), data['description'], data['cacheSize'], data['cacheMaxAge'], ','.join(data['spanInterfaces']), ','.join(data['edgeInterfaces']), ','.join(data['autoEdgeInterfaces']), ','.join(data['ptpInterfaces']), data['stickyPorts'], config_id))
        conn.commit()
        return jsonify({'status': 'success', 'message': 'Config updated'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/delete-bridge-config/<int:config_id>", methods=['DELETE'])
@api_permission_required("api.network.edit")
def delete_bridge_config(config_id):
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM bridge_configs WHERE id = ?', (config_id,))
        conn.commit()
        return jsonify({'status': 'success', 'message': 'Config deleted'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

# ----------------------------
# LAGG CONFIGURATION
# ----------------------------

@interfaces_bp.route("/get-lagg-configs", methods=['GET'])
@login_required
def get_lagg_configs():
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT id, parent_interfaces, aggregation_protocol, description FROM lagg_configs')
        configs = cursor.fetchall()
        
        configs_list = [
            {
                'id': c[0],
                'parent_interfaces': c[1],
                'aggregation_protocol': c[2],
                'description': c[3]
            }
            for c in configs
        ]
        return jsonify({'status': 'success', 'data': configs_list})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/save-lagg-config", methods=['POST'])
@api_permission_required("api.network.edit")
def save_lagg_config():
    try:
        data = request.get_json(silent=True) or {}
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO lagg_configs (parent_interfaces, aggregation_protocol, description) 
                          VALUES (?, ?, ?)''',
                       (','.join(data['parentInterfaces']), data['aggregationProtocol'], data['description']))
        conn.commit()
        config_id = cursor.lastrowid
        return jsonify({'status': 'success', 'message': 'Config saved', 'id': config_id})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/get-lagg-config/<int:config_id>", methods=['GET'])
@login_required
def get_lagg_config(config_id):
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT id, parent_interfaces, aggregation_protocol, description FROM lagg_configs WHERE id = ?', (config_id,))
        config = cursor.fetchone()
        
        if config:
            return jsonify({'status': 'success', 'data': {
                'id': config[0],
                'parent_interfaces': config[1].split(',') if config[1] else [],
                'aggregation_protocol': config[2],
                'description': config[3]
            }})
        return jsonify({'status': 'error', 'message': 'Config not found'}), 404
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/update-lagg-config/<int:config_id>", methods=['PUT'])
@api_permission_required("api.network.edit")
def update_lagg_config(config_id):
    try:
        data = request.get_json(silent=True) or {}
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''UPDATE lagg_configs SET parent_interfaces = ?, aggregation_protocol = ?, description = ? WHERE id = ?''',
                       (','.join(data['parentInterfaces']), data['aggregationProtocol'], data['description'], config_id))
        conn.commit()
        return jsonify({'status': 'success', 'message': 'Config updated'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/delete-lagg-config/<int:config_id>", methods=['DELETE'])
@api_permission_required("api.network.edit")
def delete_lagg_config(config_id):
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM lagg_configs WHERE id = ?', (config_id,))
        conn.commit()
        return jsonify({'status': 'success', 'message': 'Config deleted'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

# ----------------------------
# WAN INTERFACE CONFIGURATION
# ----------------------------

@interfaces_bp.route("/wan")
@login_required
def interfaces_wan():
    return render_template("interfaces_wan.html")

@interfaces_bp.route("/get-wan-config", methods=['GET'])
@login_required
def get_wan_config():
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT assigned_port, enable_interface, description, ipv4_config_type, ipv6_config_type, mac_address, mtu, mss, speed_and_duplex, ipv4_address, ipv4_upstream_gateway, username, password, dial_on_demand, idle_timeout, block_private_networks, block_bogon_networks FROM wan_config WHERE id = 1')
        config = cursor.fetchone()
        
        if config:
            return jsonify({'status': 'success', 'data': {
                'assigned_port': config[0],
                'enable_interface': bool(config[1]),
                'description': config[2],
                'ipv4_config_type': config[3],
                'ipv6_config_type': config[4],
                'mac_address': config[5],
                'mtu': config[6],
                'mss': config[7],
                'speed_and_duplex': config[8],
                'ipv4_address': config[9],
                'ipv4_upstream_gateway': config[10],
                'username': config[11],
                'has_password': bool(config[12]),
                'dial_on_demand': bool(config[13]),
                'idle_timeout': config[14],
                'block_private_networks': bool(config[15]),
                'block_bogon_networks': bool(config[16])
            }})
        return jsonify({'status': 'error', 'message': 'Config not found'}), 404
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/save-wan-config", methods=['POST'])
@api_permission_required("api.network.edit")
def save_wan_config():
    try:
        data = request.get_json(silent=True) or {}
        encrypted_password = encrypt_secret(data.get('password')) if data.get('password') else None
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''UPDATE wan_config SET enable_interface = ?, description = ?, ipv4_config_type = ?, ipv6_config_type = ?, mac_address = ?, mtu = ?, mss = ?, speed_and_duplex = ?, ipv4_address = ?, ipv4_upstream_gateway = ?, username = ?, password = COALESCE(NULLIF(?, ''), password), dial_on_demand = ?, idle_timeout = ?, block_private_networks = ?, block_bogon_networks = ? WHERE id = 1''',
                       (data['enableInterface'], data['description'], data['ipv4ConfigType'], data['ipv6ConfigType'], data['macAddress'], data['mtu'], data['mss'], data['speedAndDuplex'], data['ipv4Address'], data['ipv4UpstreamGateway'], data['username'], encrypted_password, data['dialOnDemand'], data['idleTimeout'], data['blockPrivateNetworks'], data['blockBogonNetworks']))
        conn.commit()
        # Auto-apply to BSD so changes take effect immediately
        bsd_applied = False
        bsd_message = ""
        try:
            from app.services.network_service import apply_interface_config
            from app.services.rc_conf_writer import apply_rc_conf
            apply_rc_conf(conn)
            res = apply_interface_config(conn)
            bsd_applied = res.get("ok", False)
            bsd_message = res.get("message", "")
        except Exception as exc:
            bsd_message = str(exc)
        return jsonify({'status': 'success', 'message': 'Config saved',
                        'bsd_applied': bsd_applied, 'bsd_message': bsd_message})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400


@interfaces_bp.route("/bsd-state/<interface_type>", methods=["GET"])
@login_required
def get_interface_bsd_state(interface_type):
    """Read live BSD state for LAN or WAN interface (ifconfig + sysrc)."""
    conn = get_db()
    table = "lan_config" if interface_type.upper() == "LAN" else "wan_config"
    row = conn.execute(f"SELECT assigned_port FROM {table} WHERE id=1").fetchone()
    iface = ((row["assigned_port"] or "").strip()) if row else ""
    if not iface:
        return jsonify({"ok": False, "message": "Interface not assigned yet."})
    from app.services.network_service import read_interface_config_from_bsd
    return jsonify({"ok": True, "bsd_state": read_interface_config_from_bsd(iface)})


# ----------------------------
# LAN INTERFACE CONFIGURATION
# ----------------------------

@interfaces_bp.route("/lan")
@login_required
def interfaces_lan():
    return render_template("interfaces_lan.html")

@interfaces_bp.route("/get-lan-config", methods=['GET'])
@login_required
def get_lan_config():
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT assigned_port, enable_interface, description, ipv4_config_type, ipv6_config_type, mac_address, mtu, mss, speed_and_duplex, ipv4_address, ipv4_upstream_gateway, block_private_networks, block_bogon_networks FROM lan_config WHERE id = 1')
        config = cursor.fetchone()

        if config:
            return jsonify({'status': 'success', 'data': {
                'assigned_port': config[0],
                'enable_interface': bool(config[1]),
                'description': config[2],
                'ipv4_config_type': config[3],
                'ipv6_config_type': config[4],
                'mac_address': config[5],
                'mtu': config[6],
                'mss': config[7],
                'speed_and_duplex': config[8],
                'ipv4_address': config[9],
                'ipv4_upstream_gateway': config[10],
                'block_private_networks': bool(config[11]),
                'block_bogon_networks': bool(config[12])
            }})
        return jsonify({'status': 'error', 'message': 'Config not found'}), 404
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/save-lan-config", methods=['POST'])
@api_permission_required("api.network.edit")
def save_lan_config():
    try:
        data = request.get_json(silent=True) or {}
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''UPDATE lan_config SET enable_interface = ?, description = ?, ipv4_config_type = ?, ipv6_config_type = ?, mac_address = ?, mtu = ?, mss = ?, speed_and_duplex = ?, ipv4_address = ?, ipv4_upstream_gateway = ?, block_private_networks = ?, block_bogon_networks = ? WHERE id = 1''',
                       (data['enableInterface'], data['description'], data['ipv4ConfigType'], data['ipv6ConfigType'], data['macAddress'], data['mtu'], data['mss'], data['speedAndDuplex'], data['ipv4Address'], data['ipv4UpstreamGateway'], data['blockPrivateNetworks'], data['blockBogonNetworks']))
        conn.commit()
        # Auto-apply to BSD so changes take effect immediately
        bsd_applied = False
        bsd_message = ""
        try:
            from app.services.network_service import apply_interface_config
            from app.services.rc_conf_writer import apply_rc_conf
            apply_rc_conf(conn)
            res = apply_interface_config(conn)
            bsd_applied = res.get("ok", False)
            bsd_message = res.get("message", "")
            # Regenerate nginx only AFTER the interface holds the new LAN IP,
            # so `service nginx reload` does not fail with EADDRNOTAVAIL.
            if bsd_applied:
                from app.services.nginx_writer import apply_nginx
                nginx_res = apply_nginx(conn)
                bsd_message = f"{bsd_message} | nginx: {nginx_res.get('message', '')}"
        except Exception as exc:
            bsd_message = str(exc)
        return jsonify({'status': 'success', 'message': 'Config saved',
                        'bsd_applied': bsd_applied, 'bsd_message': bsd_message})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400


# ---------------------------------------------------------------------------
# Network apply — write rc.conf block + push config live
# ---------------------------------------------------------------------------

@interfaces_bp.route("/api/apply-network", methods=["POST"])
@api_permission_required("api.network.edit")
def api_apply_network():
    """
    Persist the current interface configuration to /etc/rc.conf.local so it
    survives a reboot, then apply IP/gateway changes live via ifconfig/route.
    """
    from flask import session
    from app.audit_log import log_event
    from app.services.rc_conf_writer import apply_rc_conf
    from app.services.network_service import apply_interface_config

    conn    = get_db()
    results = []

    # 1. Write rc.conf.local block
    rc_result = apply_rc_conf(conn)
    results.append({"step": "rc.conf", "ok": rc_result["ok"], "message": rc_result["message"]})

    # 2. Apply interface config live
    try:
        live_result = apply_interface_config(conn)
        results.append({"step": "live_apply", "ok": live_result.get("ok", True),
                         "message": live_result.get("message", "Applied")})
    except Exception as exc:
        results.append({"step": "live_apply", "ok": False, "message": str(exc)})

    overall_ok = all(r["ok"] for r in results)
    log_event(
        category="system", action="network_apply",
        username=session.get("username", "system"),
        remote_addr=request.remote_addr,
        details={"ok": overall_ok, "results": results},
    )
    return jsonify({"ok": overall_ok, "results": results})


@interfaces_bp.route("/api/rc-conf-preview", methods=["GET"])
@login_required
def api_rc_conf_preview():
    """Return the rc.conf block that would be written, without applying it."""
    from app.services.rc_conf_writer import generate_rc_conf_block
    conn  = get_db()
    block = generate_rc_conf_block(conn)
    return jsonify({"ok": True, "block": block})
