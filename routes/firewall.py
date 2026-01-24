from flask import Blueprint, render_template, request, jsonify
import sqlite3

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


# ----------------------------
# FIREWALL NAT
# ----------------------------

@firewall_bp.route("/nat")
def nat():
    return render_template("nat.html")


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


# ----------------------------
# FIREWALL SCHEDULES
# ----------------------------

@firewall_bp.route("/schedules")
def schedules():
    return render_template("schedules.html")


# ----------------------------
# VIRTUAL IPs
# ----------------------------

@firewall_bp.route("/virtual-ips")
def virtual_ips():
    return render_template("virtual_ips.html")


# ----------------------------
# TRAFFIC SHAPER
# ----------------------------

@firewall_bp.route("/traffic-shaper")
def traffic_shaper():
    return render_template("traffic_shaper.html")

@firewall_bp.route("/get-traffic-shaper-configs", methods=['GET'])
def get_traffic_shaper_configs():
    try:
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id, interface_type, enable_disable, name, scheduler_type, bandwidth, bandwidth_unit, queue_limit, tbr_size FROM traffic_shaper_configs ORDER BY interface_type, id')
        configs = cursor.fetchall()
        conn.close()
        
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
def save_traffic_shaper_config():
    try:
        data = request.get_json()
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO traffic_shaper_configs (interface_type, enable_disable, name, scheduler_type, bandwidth, bandwidth_unit, queue_limit, tbr_size) 
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                       (data['interfaceType'], data['enableDisable'], data['name'], data['schedulerType'], data['bandwidth'], data['bandwidthUnit'], data['queueLimit'], data['tbrSize']))
        conn.commit()
        config_id = cursor.lastrowid
        conn.close()
        return jsonify({'status': 'success', 'message': 'Config saved', 'id': config_id})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@firewall_bp.route("/get-traffic-shaper-config/<int:config_id>", methods=['GET'])
def get_traffic_shaper_config(config_id):
    try:
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id, interface_type, enable_disable, name, scheduler_type, bandwidth, bandwidth_unit, queue_limit, tbr_size FROM traffic_shaper_configs WHERE id = ?', (config_id,))
        config = cursor.fetchone()
        conn.close()
        
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
def update_traffic_shaper_config(config_id):
    try:
        data = request.get_json()
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('''UPDATE traffic_shaper_configs SET interface_type = ?, enable_disable = ?, name = ?, scheduler_type = ?, bandwidth = ?, bandwidth_unit = ?, queue_limit = ?, tbr_size = ? WHERE id = ?''',
                       (data['interfaceType'], data['enableDisable'], data['name'], data['schedulerType'], data['bandwidth'], data['bandwidthUnit'], data['queueLimit'], data['tbrSize'], config_id))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success', 'message': 'Config updated'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@firewall_bp.route("/delete-traffic-shaper-config/<int:config_id>", methods=['DELETE'])
def delete_traffic_shaper_config(config_id):
    try:
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('DELETE FROM traffic_shaper_configs WHERE id = ?', (config_id,))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success', 'message': 'Config deleted'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400


# ----------------------------
# LIMITERS
# ----------------------------

@firewall_bp.route("/get-limiters-configs", methods=['GET'])
def get_limiters_configs():
    try:
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id, enable_disable, name, bandwidth, bandwidth_unit, mask_type, ipv4_mask_bits, ipv6_mask_bits, queue_management_algorithm, scheduler, queue_length, delay_ms, packet_loss_rate, bucket_size_slots, description FROM limiters_configs ORDER BY id')
        configs = cursor.fetchall()
        conn.close()
        
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
def save_limiters_config():
    try:
        data = request.get_json()
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO limiters_configs (enable_disable, name, bandwidth, bandwidth_unit, mask_type, ipv4_mask_bits, ipv6_mask_bits, queue_management_algorithm, scheduler, queue_length, delay_ms, packet_loss_rate, bucket_size_slots, description) 
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                       (data['enableDisable'], data['name'], data['bandwidth'], data['bandwidthUnit'], data['maskType'], data['ipv4MaskBits'], data['ipv6MaskBits'], data['queueManagementAlgorithm'], data['scheduler'], data['queueLength'], data['delayMs'], data['packetLossRate'], data['bucketSizeSlots'], data['description']))
        conn.commit()
        config_id = cursor.lastrowid
        conn.close()
        return jsonify({'status': 'success', 'message': 'Limiter saved', 'id': config_id})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@firewall_bp.route("/get-limiters-config/<int:config_id>", methods=['GET'])
def get_limiters_config(config_id):
    try:
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id, enable_disable, name, bandwidth, bandwidth_unit, mask_type, ipv4_mask_bits, ipv6_mask_bits, queue_management_algorithm, scheduler, queue_length, delay_ms, packet_loss_rate, bucket_size_slots, description FROM limiters_configs WHERE id = ?', (config_id,))
        config = cursor.fetchone()
        conn.close()
        
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
def update_limiters_config(config_id):
    try:
        data = request.get_json()
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('''UPDATE limiters_configs SET enable_disable = ?, name = ?, bandwidth = ?, bandwidth_unit = ?, mask_type = ?, ipv4_mask_bits = ?, ipv6_mask_bits = ?, queue_management_algorithm = ?, scheduler = ?, queue_length = ?, delay_ms = ?, packet_loss_rate = ?, bucket_size_slots = ?, description = ? WHERE id = ?''',
                       (data['enableDisable'], data['name'], data['bandwidth'], data['bandwidthUnit'], data['maskType'], data['ipv4MaskBits'], data['ipv6MaskBits'], data['queueManagementAlgorithm'], data['scheduler'], data['queueLength'], data['delayMs'], data['packetLossRate'], data['bucketSizeSlots'], data['description'], config_id))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success', 'message': 'Limiter updated'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@firewall_bp.route("/delete-limiters-config/<int:config_id>", methods=['DELETE'])
def delete_limiters_config(config_id):
    try:
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('DELETE FROM limiters_configs WHERE id = ?', (config_id,))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success', 'message': 'Limiter deleted'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400


# ----------------------------
# VIRTUAL IPS
# ----------------------------

@firewall_bp.route("/get-virtual-ips-configs", methods=['GET'])
def get_virtual_ips_configs():
    try:
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id, type, interface, address_type, address, prefix, expansion, description FROM virtual_ips_configs ORDER BY id')
        configs = cursor.fetchall()
        conn.close()
        
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
def save_virtual_ips_config():
    try:
        data = request.get_json()
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO virtual_ips_configs (type, interface, address_type, address, prefix, expansion, description) 
                          VALUES (?, ?, ?, ?, ?, ?, ?)''',
                       (data['type'], data['interface'], data['addressType'], data['address'], data['prefix'], data['expansion'], data['description']))
        conn.commit()
        config_id = cursor.lastrowid
        conn.close()
        return jsonify({'status': 'success', 'message': 'Virtual IP saved', 'id': config_id})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@firewall_bp.route("/get-virtual-ips-config/<int:config_id>", methods=['GET'])
def get_virtual_ips_config(config_id):
    try:
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id, type, interface, address_type, address, prefix, expansion, description FROM virtual_ips_configs WHERE id = ?', (config_id,))
        config = cursor.fetchone()
        conn.close()
        
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

@firewall_bp.route("/update-virtual-ips-config/<int:config_id>", methods=['POST'])
def update_virtual_ips_config(config_id):
    try:
        data = request.get_json()
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('''UPDATE virtual_ips_configs SET type = ?, interface = ?, address_type = ?, address = ?, prefix = ?, expansion = ?, description = ? WHERE id = ?''',
                       (data['type'], data['interface'], data['addressType'], data['address'], data['prefix'], data['expansion'], data['description'], config_id))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success', 'message': 'Virtual IP updated'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@firewall_bp.route("/delete-virtual-ips-config/<int:config_id>", methods=['DELETE'])
def delete_virtual_ips_config(config_id):
    try:
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('DELETE FROM virtual_ips_configs WHERE id = ?', (config_id,))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success', 'message': 'Virtual IP deleted'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400


# ----------------------------
# FIREWALL HOME
# ----------------------------

# @firewall_bp.route("/home")
# def home():
#     return redirect(url_for("firewall.firewall_home"))
