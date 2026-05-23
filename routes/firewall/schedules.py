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


@firewall_bp.route("/schedules")
@login_required
def schedules():
    return render_template("schedules.html")


@firewall_bp.route("/api/schedules", methods=["GET"])
@login_required
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
@api_permission_required("api.firewall.edit")
def create_schedule():
    """Create a schedule (with ranges). Expects JSON: {name, description, ranges:[...]}."""
    try:
        data = request.get_json(silent=True) or {}
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
@api_permission_required("api.firewall.edit")
def update_schedule(schedule_id):
    """Replace schedule fields and ranges. Expects JSON: {name, description, ranges:[...]}."""
    try:
        data = request.get_json(silent=True) or {}
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
@api_permission_required("api.firewall.edit")
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
