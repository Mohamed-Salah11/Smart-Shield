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


@firewall_bp.route("/virtual-ips")
@login_required
def virtual_ips():
    return render_template("virtual_ips.html")


# ----------------------------
# TRAFFIC SHAPER
# ----------------------------

@firewall_bp.route("/traffic-shaper")
@login_required
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
@api_permission_required("api.firewall.edit")
def save_traffic_shaper_config():
    try:
        data = request.get_json(silent=True) or {}
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
@api_permission_required("api.firewall.edit")
def update_traffic_shaper_config(config_id):
    try:
        data = request.get_json(silent=True) or {}
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''UPDATE traffic_shaper_configs SET interface_type = ?, enable_disable = ?, name = ?, scheduler_type = ?, bandwidth = ?, bandwidth_unit = ?, queue_limit = ?, tbr_size = ? WHERE id = ?''',
                       (data['interfaceType'], data['enableDisable'], data['name'], data['schedulerType'], data['bandwidth'], data['bandwidthUnit'], data['queueLimit'], data['tbrSize'], config_id))
        db.commit()
        return jsonify({'status': 'success', 'message': 'Config updated'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@firewall_bp.route("/delete-traffic-shaper-config/<int:config_id>", methods=['DELETE'])
@api_permission_required("api.firewall.edit")
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
@api_permission_required("api.firewall.edit")
def save_limiters_config():
    try:
        data = request.get_json(silent=True) or {}
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
@api_permission_required("api.firewall.edit")
def update_limiters_config(config_id):
    try:
        data = request.get_json(silent=True) or {}
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''UPDATE limiters_configs SET enable_disable = ?, name = ?, bandwidth = ?, bandwidth_unit = ?, mask_type = ?, ipv4_mask_bits = ?, ipv6_mask_bits = ?, queue_management_algorithm = ?, scheduler = ?, queue_length = ?, delay_ms = ?, packet_loss_rate = ?, bucket_size_slots = ?, description = ? WHERE id = ?''',
                       (data['enableDisable'], data['name'], data['bandwidth'], data['bandwidthUnit'], data['maskType'], data['ipv4MaskBits'], data['ipv6MaskBits'], data['queueManagementAlgorithm'], data['scheduler'], data['queueLength'], data['delayMs'], data['packetLossRate'], data['bucketSizeSlots'], data['description'], config_id))
        db.commit()
        return jsonify({'status': 'success', 'message': 'Limiter updated'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@firewall_bp.route("/delete-limiters-config/<int:config_id>", methods=['DELETE'])
@api_permission_required("api.firewall.edit")
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
@api_permission_required("api.firewall.edit")
def save_virtual_ips_config():
    try:
        data = request.get_json(silent=True) or {}
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''INSERT INTO virtual_ips_configs (type, interface, address_type, address, prefix, expansion, description) 
                          VALUES (?, ?, ?, ?, ?, ?, ?)''',
                       (data['type'], data['interface'], data.get('address_type') or data.get('addressType') or 'single', data['address'], data['prefix'], data['expansion'], data.get('description', '')))
        db.commit()
        config_id = cursor.lastrowid
        from app.services.network_service import apply_vips
        apply_result = apply_vips(db)
        return jsonify({'status': 'success', 'message': 'Virtual IP saved',
                        'id': config_id, 'apply_result': apply_result})
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
@api_permission_required("api.firewall.edit")
def update_virtual_ips_config(config_id):
    try:
        data = request.get_json(silent=True) or {}
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''UPDATE virtual_ips_configs SET type = ?, interface = ?, address_type = ?, address = ?, prefix = ?, expansion = ?, description = ? WHERE id = ?''',
                       (data['type'], data['interface'], data.get('address_type') or data.get('addressType') or 'single', data['address'], data['prefix'], data['expansion'], data.get('description', ''), config_id))
        db.commit()
        from app.services.network_service import apply_vips
        apply_result = apply_vips(db)
        return jsonify({'status': 'success', 'message': 'Virtual IP updated',
                        'apply_result': apply_result})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@firewall_bp.route("/delete-virtual-ips-config/<int:config_id>", methods=['DELETE'])
@api_permission_required("api.firewall.edit")
def delete_virtual_ips_config(config_id):
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute('DELETE FROM virtual_ips_configs WHERE id = ?', (config_id,))
        db.commit()
        from app.services.network_service import apply_vips
        apply_result = apply_vips(db)
        return jsonify({'status': 'success', 'message': 'Virtual IP deleted',
                        'apply_result': apply_result})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400


# ---------------------------------------------------------------------------
# APPLY — compile DB rules into pf.conf and reload PF
# ---------------------------------------------------------------------------
