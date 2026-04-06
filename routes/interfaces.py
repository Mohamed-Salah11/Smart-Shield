from flask import Blueprint, render_template, request, jsonify
import sqlite3
from app.auth_utils import login_required

interfaces_bp = Blueprint("interfaces", __name__, url_prefix="/interfaces")

# ----------------------------
# INTERFACES MAIN PAGE
# ----------------------------

@interfaces_bp.route("/")
@login_required
def interfaces_home():
    return render_template("interfaces.html")

@interfaces_bp.route("/interfaces")
@login_required
def interfaces():
    return render_template("interfaces.html")


# ----------------------------
# INTERFACE ASSIGNMENTS PAGE
# ----------------------------

@interfaces_bp.route("/assignments")
@login_required
def interfaces_assignments():
    return render_template("interfaces_assignments.html")

@interfaces_bp.route("/get-interface-groups", methods=['GET'])
@login_required
def get_interface_groups():
    try:
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id, group_name, description, members FROM interface_groups')
        groups = cursor.fetchall()
        conn.close()
        
        groups_list = [
            {
                'id': g[0],
                'name': g[1],
                'description': g[2],
                'members': g[3].split(',') if g[3] else []
            }
            for g in groups
        ]
        return jsonify({'status': 'success', 'data': groups_list})
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 400
    
@interfaces_bp.route("/save-interface-group", methods=['POST'])
@login_required
def save_interface_group():
    try:
        data = request.get_json()
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO interface_groups (group_name, description, members) 
                          VALUES (?, ?, ?)''', 
                       (data['groupName'], data['groupDescription'], ','.join(data['groupMembers'])))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success', 'message': 'Interface group saved'})
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/get-interface-group/<int:group_id>", methods=['GET'])
@login_required
def get_interface_group(group_id):
    try:
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id, group_name, description, members FROM interface_groups WHERE id = ?', (group_id,))
        group = cursor.fetchone()
        conn.close()
        
        if group:
            return jsonify({'status': 'success', 'data': {
                'id': group[0],
                'name': group[1],
                'description': group[2],
                'members': group[3].split(',') if group[3] else []
            }})
        return jsonify({'status': 'error', 'message': 'Group not found'}), 404
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/update-interface-group/<int:group_id>", methods=['PUT'])
@login_required
def update_interface_group(group_id):
    try:
        data = request.get_json()
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('''UPDATE interface_groups SET group_name = ?, description = ?, members = ? WHERE id = ?''',
                       (data['groupName'], data['groupDescription'], ','.join(data['groupMembers']), group_id))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success', 'message': 'Group updated'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/delete-interface-group/<int:group_id>", methods=['DELETE'])
@login_required
def delete_interface_group(group_id):
    try:
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('DELETE FROM interface_groups WHERE id = ?', (group_id,))
        conn.commit()
        conn.close()
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
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('''SELECT id, interface_type, network_port FROM interface_assignments''')
        assignments = cursor.fetchall()
        conn.close()
        
        assignments_list = [
            {
                'id': a[0],
                'interface_type': a[1],
                'network_port': a[2]
            }
            for a in assignments
        ]
        return jsonify({'status': 'success', 'data': assignments_list})
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/save-interface-assignment", methods=['POST'])
@login_required
def save_interface_assignment():
    try:
        data = request.get_json()
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        
        # Check if assignment already exists for this interface type
        cursor.execute('SELECT id FROM interface_assignments WHERE interface_type = ?', (data['interfaceType'],))
        existing = cursor.fetchone()
        
        if existing:
            # Update existing assignment
            cursor.execute('''UPDATE interface_assignments SET network_port = ? WHERE interface_type = ?''',
                           (data['networkPort'], data['interfaceType']))
        else:
            # Insert new assignment
            cursor.execute('''INSERT INTO interface_assignments (interface_type, network_port) 
                              VALUES (?, ?)''', 
                           (data['interfaceType'], data['networkPort']))
        
        conn.commit()
        conn.close()
        return jsonify({'status': 'success', 'message': 'Interface assignment saved'})
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/delete-interface-assignment/<interface_type>", methods=['DELETE'])
@login_required
def delete_interface_assignment(interface_type):
    try:
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('DELETE FROM interface_assignments WHERE interface_type = ?', (interface_type,))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success', 'message': 'Interface assignment deleted'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

# ----------------------------
# WIRELESS INTERFACE CONFIGURATION
# ----------------------------

@interfaces_bp.route("/get-wireless-configs", methods=['GET'])
@login_required
def get_wireless_configs():
    try:
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('''SELECT id, parent_interface, mode, description FROM wireless_configs''')
        configs = cursor.fetchall()
        conn.close()
        
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
        print(f"Error: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/save-wireless-config", methods=['POST'])
@login_required
def save_wireless_config():
    try:
        data = request.get_json()
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO wireless_configs (parent_interface, mode, description) 
                          VALUES (?, ?, ?)''', 
                       (data['parentInterface'], data['mode'], data['description']))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success', 'message': 'Wireless config saved'})
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/get-wireless-config/<int:config_id>", methods=['GET'])
@login_required
def get_wireless_config(config_id):
    try:
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id, parent_interface, mode, description FROM wireless_configs WHERE id = ?', (config_id,))
        config = cursor.fetchone()
        conn.close()
        
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
@login_required
def update_wireless_config(config_id):
    try:
        data = request.get_json()
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('''UPDATE wireless_configs SET parent_interface = ?, mode = ?, description = ? WHERE id = ?''',
                       (data['parentInterface'], data['mode'], data['description'], config_id))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success', 'message': 'Config updated'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/delete-wireless-config/<int:config_id>", methods=['DELETE'])
@login_required
def delete_wireless_config(config_id):
    try:
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('DELETE FROM wireless_configs WHERE id = ?', (config_id,))
        conn.commit()
        conn.close()
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
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('''SELECT id, parent_interface, vlan_tag, vlan_priority, description FROM vlan_configs''')
        configs = cursor.fetchall()
        conn.close()
        
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
        print(f"Error: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/save-vlan-config", methods=['POST'])
@login_required
def save_vlan_config():
    try:
        data = request.get_json()
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO vlan_configs (parent_interface, vlan_tag, vlan_priority, description) 
                          VALUES (?, ?, ?, ?)''', 
                       (data['parentInterface'], data['vlanTag'], data['vlanPriority'], data['description']))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success', 'message': 'VLAN config saved'})
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/get-vlan-config/<int:config_id>", methods=['GET'])
@login_required
def get_vlan_config(config_id):
    try:
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id, parent_interface, vlan_tag, vlan_priority, description FROM vlan_configs WHERE id = ?', (config_id,))
        config = cursor.fetchone()
        conn.close()
        
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
@login_required
def update_vlan_config(config_id):
    try:
        data = request.get_json()
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('''UPDATE vlan_configs SET parent_interface = ?, vlan_tag = ?, vlan_priority = ?, description = ? WHERE id = ?''',
                       (data['parentInterface'], data['vlanTag'], data['vlanPriority'], data['description'], config_id))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success', 'message': 'Config updated'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/delete-vlan-config/<int:config_id>", methods=['DELETE'])
@login_required
def delete_vlan_config(config_id):
    try:
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('DELETE FROM vlan_configs WHERE id = ?', (config_id,))
        conn.commit()
        conn.close()
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
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('''SELECT id, parent_interface, first_level_tag, add_to_groups, description, member_tags FROM qinq_configs''')
        configs = cursor.fetchall()
        conn.close()
        
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
        print(f"Error: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/save-qinq-config", methods=['POST'])
@login_required
def save_qinq_config():
    try:
        data = request.get_json()
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO qinq_configs (parent_interface, first_level_tag, add_to_groups, description, member_tags) 
                          VALUES (?, ?, ?, ?, ?)''', 
                       (data['parentInterface'], data['firstLevelTag'], data['addToGroups'], data['description'], ','.join(data['memberTags'])))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success', 'message': 'QinQ config saved'})
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/get-qinq-config/<int:config_id>", methods=['GET'])
@login_required
def get_qinq_config(config_id):
    try:
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id, parent_interface, first_level_tag, add_to_groups, description, member_tags FROM qinq_configs WHERE id = ?', (config_id,))
        config = cursor.fetchone()
        conn.close()
        
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
@login_required
def update_qinq_config(config_id):
    try:
        data = request.get_json()
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('''UPDATE qinq_configs SET parent_interface = ?, first_level_tag = ?, add_to_groups = ?, description = ?, member_tags = ? WHERE id = ?''',
                       (data['parentInterface'], data['firstLevelTag'], data['addToGroups'], data['description'], ','.join(data['memberTags']), config_id))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success', 'message': 'Config updated'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/delete-qinq-config/<int:config_id>", methods=['DELETE'])
@login_required
def delete_qinq_config(config_id):
    try:
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('DELETE FROM qinq_configs WHERE id = ?', (config_id,))
        conn.commit()
        conn.close()
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
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id, link_type, link_interfaces, description, username, dial_on_demand FROM ppp_configs')
        configs = cursor.fetchall()
        conn.close()
        
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
@login_required
def save_ppp_config():
    try:
        data = request.get_json()
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO ppp_configs (link_type, link_interfaces, description, username, password, dial_on_demand)
                          VALUES (?, ?, ?, ?, ?, ?)''',
                       (data['linkType'], ','.join(data['linkInterfaces']), data['description'], data['username'], data['password'], data['dialOnDemand']))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success', 'message': 'Config saved'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/get-ppp-config/<int:config_id>", methods=['GET'])
@login_required
def get_ppp_config(config_id):
    try:
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id, link_type, link_interfaces, description, username, password, dial_on_demand FROM ppp_configs WHERE id = ?', (config_id,))
        config = cursor.fetchone()
        conn.close()
        
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
@login_required
def update_ppp_config(config_id):
    try:
        data = request.get_json()
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('''UPDATE ppp_configs SET link_type = ?, link_interfaces = ?, description = ?, username = ?, password = ?, dial_on_demand = ? WHERE id = ?''',
                       (data['linkType'], ','.join(data['linkInterfaces']), data['description'], data['username'], data['password'], data['dialOnDemand'], config_id))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success', 'message': 'Config updated'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/delete-ppp-config/<int:config_id>", methods=['DELETE'])
@login_required
def delete_ppp_config(config_id):
    try:
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('DELETE FROM ppp_configs WHERE id = ?', (config_id,))
        conn.commit()
        conn.close()
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
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id, parent_interface, gre_remote_address, gre_local_address, ipv4_tunnel_remote_address, ipv4_tunnel_remote_prefix, ipv4_tunnel_local_address, ipv4_tunnel_local_prefix, ipv6_tunnel_remote_address, ipv6_tunnel_remote_prefix, ipv6_tunnel_local_address, ipv6_tunnel_local_prefix, description FROM gre_configs')
        configs = cursor.fetchall()
        conn.close()
        
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
@login_required
def save_gre_config():
    try:
        data = request.get_json()
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO gre_configs (parent_interface, gre_remote_address, gre_local_address, ipv4_tunnel_remote_address, ipv4_tunnel_remote_prefix, ipv4_tunnel_local_address, ipv4_tunnel_local_prefix, ipv6_tunnel_remote_address, ipv6_tunnel_remote_prefix, ipv6_tunnel_local_address, ipv6_tunnel_local_prefix, description)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                       (data['parentInterface'], data['greRemoteAddress'], data['greLocalAddress'], data['ipv4TunnelRemoteAddress'], data['ipv4TunnelRemotePrefix'], data['ipv4TunnelLocalAddress'], data['ipv4TunnelLocalPrefix'], data['ipv6TunnelRemoteAddress'], data['ipv6TunnelRemotePrefix'], data['ipv6TunnelLocalAddress'], data['ipv6TunnelLocalPrefix'], data['description']))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success', 'message': 'Config saved'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/get-gre-config/<int:config_id>", methods=['GET'])
@login_required
def get_gre_config(config_id):
    try:
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id, parent_interface, gre_remote_address, gre_local_address, ipv4_tunnel_remote_address, ipv4_tunnel_remote_prefix, ipv4_tunnel_local_address, ipv4_tunnel_local_prefix, ipv6_tunnel_remote_address, ipv6_tunnel_remote_prefix, ipv6_tunnel_local_address, ipv6_tunnel_local_prefix, description FROM gre_configs WHERE id = ?', (config_id,))
        config = cursor.fetchone()
        conn.close()
        
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
@login_required
def update_gre_config(config_id):
    try:
        data = request.get_json()
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('''UPDATE gre_configs SET parent_interface = ?, gre_remote_address = ?, gre_local_address = ?, ipv4_tunnel_remote_address = ?, ipv4_tunnel_remote_prefix = ?, ipv4_tunnel_local_address = ?, ipv4_tunnel_local_prefix = ?, ipv6_tunnel_remote_address = ?, ipv6_tunnel_remote_prefix = ?, ipv6_tunnel_local_address = ?, ipv6_tunnel_local_prefix = ?, description = ? WHERE id = ?''',
                       (data['parentInterface'], data['greRemoteAddress'], data['greLocalAddress'], data['ipv4TunnelRemoteAddress'], data['ipv4TunnelRemotePrefix'], data['ipv4TunnelLocalAddress'], data['ipv4TunnelLocalPrefix'], data['ipv6TunnelRemoteAddress'], data['ipv6TunnelRemotePrefix'], data['ipv6TunnelLocalAddress'], data['ipv6TunnelLocalPrefix'], data['description'], config_id))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success', 'message': 'Config updated'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/delete-gre-config/<int:config_id>", methods=['DELETE'])
@login_required
def delete_gre_config(config_id):
    try:
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('DELETE FROM gre_configs WHERE id = ?', (config_id,))
        conn.commit()
        conn.close()
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
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id, parent_interface, gif_remote_address, gif_tunnel_local_address, gif_tunnel_remote_address, gif_tunnel_subnet, ecn_friendly_behavior, outer_source_filtering, description FROM gif_configs')
        configs = cursor.fetchall()
        conn.close()
        
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
@login_required
def save_gif_config():
    try:
        data = request.get_json()
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO gif_configs (parent_interface, gif_remote_address, gif_tunnel_local_address, gif_tunnel_remote_address, gif_tunnel_subnet, ecn_friendly_behavior, outer_source_filtering, description)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                       (data['parentInterface'], data['gifRemoteAddress'], data['gifTunnelLocalAddress'], data['gifTunnelRemoteAddress'], data['gifTunnelSubnet'], data['ecnFriendlyBehavior'], data['outerSourceFiltering'], data['description']))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success', 'message': 'Config saved'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/get-gif-config/<int:config_id>", methods=['GET'])
@login_required
def get_gif_config(config_id):
    try:
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id, parent_interface, gif_remote_address, gif_tunnel_local_address, gif_tunnel_remote_address, gif_tunnel_subnet, ecn_friendly_behavior, outer_source_filtering, description FROM gif_configs WHERE id = ?', (config_id,))
        config = cursor.fetchone()
        conn.close()
        
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
@login_required
def update_gif_config(config_id):
    try:
        data = request.get_json()
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('''UPDATE gif_configs SET parent_interface = ?, gif_remote_address = ?, gif_tunnel_local_address = ?, gif_tunnel_remote_address = ?, gif_tunnel_subnet = ?, ecn_friendly_behavior = ?, outer_source_filtering = ?, description = ? WHERE id = ?''',
                       (data['parentInterface'], data['gifRemoteAddress'], data['gifTunnelLocalAddress'], data['gifTunnelRemoteAddress'], data['gifTunnelSubnet'], data['ecnFriendlyBehavior'], data['outerSourceFiltering'], data['description'], config_id))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success', 'message': 'Config updated'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/delete-gif-config/<int:config_id>", methods=['DELETE'])
@login_required
def delete_gif_config(config_id):
    try:
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('DELETE FROM gif_configs WHERE id = ?', (config_id,))
        conn.commit()
        conn.close()
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
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id, member_interfaces, description, cache_size, cache_max_age, span_interfaces, edge_interfaces, auto_edge_interfaces, ptp_interfaces, sticky_ports FROM bridge_configs')
        configs = cursor.fetchall()
        conn.close()
        
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
@login_required
def save_bridge_config():
    try:
        data = request.get_json()
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO bridge_configs (member_interfaces, description, cache_size, cache_max_age, span_interfaces, edge_interfaces, auto_edge_interfaces, ptp_interfaces, sticky_ports)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                       (','.join(data['memberInterfaces']), data['description'], data['cacheSize'], data['cacheMaxAge'], ','.join(data['spanInterfaces']), ','.join(data['edgeInterfaces']), ','.join(data['autoEdgeInterfaces']), ','.join(data['ptpInterfaces']), data['stickyPorts']))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success', 'message': 'Config saved'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/get-bridge-config/<int:config_id>", methods=['GET'])
@login_required
def get_bridge_config(config_id):
    try:
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id, member_interfaces, description, cache_size, cache_max_age, span_interfaces, edge_interfaces, auto_edge_interfaces, ptp_interfaces, sticky_ports FROM bridge_configs WHERE id = ?', (config_id,))
        config = cursor.fetchone()
        conn.close()
        
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
@login_required
def update_bridge_config(config_id):
    try:
        data = request.get_json()
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('''UPDATE bridge_configs SET member_interfaces = ?, description = ?, cache_size = ?, cache_max_age = ?, span_interfaces = ?, edge_interfaces = ?, auto_edge_interfaces = ?, ptp_interfaces = ?, sticky_ports = ? WHERE id = ?''',
                       (','.join(data['memberInterfaces']), data['description'], data['cacheSize'], data['cacheMaxAge'], ','.join(data['spanInterfaces']), ','.join(data['edgeInterfaces']), ','.join(data['autoEdgeInterfaces']), ','.join(data['ptpInterfaces']), data['stickyPorts'], config_id))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success', 'message': 'Config updated'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/delete-bridge-config/<int:config_id>", methods=['DELETE'])
@login_required
def delete_bridge_config(config_id):
    try:
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('DELETE FROM bridge_configs WHERE id = ?', (config_id,))
        conn.commit()
        conn.close()
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
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id, parent_interfaces, aggregation_protocol, description FROM lagg_configs')
        configs = cursor.fetchall()
        conn.close()
        
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
@login_required
def save_lagg_config():
    try:
        data = request.get_json()
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO lagg_configs (parent_interfaces, aggregation_protocol, description) 
                          VALUES (?, ?, ?)''',
                       (','.join(data['parentInterfaces']), data['aggregationProtocol'], data['description']))
        conn.commit()
        config_id = cursor.lastrowid
        conn.close()
        return jsonify({'status': 'success', 'message': 'Config saved', 'id': config_id})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/get-lagg-config/<int:config_id>", methods=['GET'])
@login_required
def get_lagg_config(config_id):
    try:
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id, parent_interfaces, aggregation_protocol, description FROM lagg_configs WHERE id = ?', (config_id,))
        config = cursor.fetchone()
        conn.close()
        
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
@login_required
def update_lagg_config(config_id):
    try:
        data = request.get_json()
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('''UPDATE lagg_configs SET parent_interfaces = ?, aggregation_protocol = ?, description = ? WHERE id = ?''',
                       (','.join(data['parentInterfaces']), data['aggregationProtocol'], data['description'], config_id))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success', 'message': 'Config updated'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/delete-lagg-config/<int:config_id>", methods=['DELETE'])
@login_required
def delete_lagg_config(config_id):
    try:
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('DELETE FROM lagg_configs WHERE id = ?', (config_id,))
        conn.commit()
        conn.close()
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
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('SELECT enable_interface, description, ipv4_config_type, ipv6_config_type, mac_address, mtu, mss, speed_and_duplex, ipv4_address, ipv4_upstream_gateway, username, password, dial_on_demand, idle_timeout, block_private_networks, block_bogon_networks FROM wan_config WHERE id = 1')
        config = cursor.fetchone()
        conn.close()
        
        if config:
            return jsonify({'status': 'success', 'data': {
                'enable_interface': bool(config[0]),
                'description': config[1],
                'ipv4_config_type': config[2],
                'ipv6_config_type': config[3],
                'mac_address': config[4],
                'mtu': config[5],
                'mss': config[6],
                'speed_and_duplex': config[7],
                'ipv4_address': config[8],
                'ipv4_upstream_gateway': config[9],
                'username': config[10],
                'password': config[11],
                'dial_on_demand': bool(config[12]),
                'idle_timeout': config[13],
                'block_private_networks': bool(config[14]),
                'block_bogon_networks': bool(config[15])
            }})
        return jsonify({'status': 'error', 'message': 'Config not found'}), 404
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/save-wan-config", methods=['POST'])
@login_required
def save_wan_config():
    try:
        data = request.get_json()
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('''UPDATE wan_config SET enable_interface = ?, description = ?, ipv4_config_type = ?, ipv6_config_type = ?, mac_address = ?, mtu = ?, mss = ?, speed_and_duplex = ?, ipv4_address = ?, ipv4_upstream_gateway = ?, username = ?, password = ?, dial_on_demand = ?, idle_timeout = ?, block_private_networks = ?, block_bogon_networks = ? WHERE id = 1''',
                       (data['enableInterface'], data['description'], data['ipv4ConfigType'], data['ipv6ConfigType'], data['macAddress'], data['mtu'], data['mss'], data['speedAndDuplex'], data['ipv4Address'], data['ipv4UpstreamGateway'], data['username'], data['password'], data['dialOnDemand'], data['idleTimeout'], data['blockPrivateNetworks'], data['blockBogonNetworks']))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success', 'message': 'Config saved'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400


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
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('SELECT enable_interface, description, ipv4_config_type, ipv6_config_type, mac_address, mtu, mss, speed_and_duplex, ipv4_address, ipv4_upstream_gateway, block_private_networks, block_bogon_networks FROM lan_config WHERE id = 1')
        config = cursor.fetchone()
        conn.close()
        
        if config:
            return jsonify({'status': 'success', 'data': {
                'enable_interface': bool(config[0]),
                'description': config[1],
                'ipv4_config_type': config[2],
                'ipv6_config_type': config[3],
                'mac_address': config[4],
                'mtu': config[5],
                'mss': config[6],
                'speed_and_duplex': config[7],
                'ipv4_address': config[8],
                'ipv4_upstream_gateway': config[9],
                'block_private_networks': bool(config[10]),
                'block_bogon_networks': bool(config[11])
            }})
        return jsonify({'status': 'error', 'message': 'Config not found'}), 404
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@interfaces_bp.route("/save-lan-config", methods=['POST'])
@login_required
def save_lan_config():
    try:
        data = request.get_json()
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('''UPDATE lan_config SET enable_interface = ?, description = ?, ipv4_config_type = ?, ipv6_config_type = ?, mac_address = ?, mtu = ?, mss = ?, speed_and_duplex = ?, ipv4_address = ?, ipv4_upstream_gateway = ?, block_private_networks = ?, block_bogon_networks = ? WHERE id = 1''',
                       (data['enableInterface'], data['description'], data['ipv4ConfigType'], data['ipv6ConfigType'], data['macAddress'], data['mtu'], data['mss'], data['speedAndDuplex'], data['ipv4Address'], data['ipv4UpstreamGateway'], data['blockPrivateNetworks'], data['blockBogonNetworks']))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success', 'message': 'Config saved'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400
