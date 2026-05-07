"""Route-level tests for interfaces blueprint."""
import pytest


class TestInterfaceRoutes:
    def test_interfaces_home_requires_login(self, client):
        r = client.get("/interfaces/")
        assert r.status_code in (302, 401)

    def test_interfaces_home_accessible(self, superuser):
        client, _ = superuser
        r = client.get("/interfaces/")
        assert r.status_code == 200

    def test_get_interface_groups_empty(self, superuser):
        client, _ = superuser
        r = client.get("/interfaces/get-interface-groups")
        assert r.status_code == 200
        data = r.get_json()
        assert data["status"] == "success"
        assert isinstance(data["data"], list)

    def test_save_group_requires_permission(self, plain_user):
        client, _ = plain_user
        r = client.post("/interfaces/save-interface-group", json={
            "groupName": "test", "groupDescription": "", "groupMembers": []
        })
        assert r.status_code in (401, 403)

    def test_save_group_empty_name_rejected(self, superuser):
        client, _ = superuser
        r = client.post("/interfaces/save-interface-group", json={
            "groupName": "", "groupDescription": "", "groupMembers": []
        })
        assert r.status_code == 400

    def test_save_and_delete_group(self, superuser):
        client, _ = superuser
        r = client.post("/interfaces/save-interface-group", json={
            "groupName": "testgrp", "groupDescription": "desc", "groupMembers": ["em0"]
        })
        assert r.status_code == 200
        assert r.get_json()["status"] == "success"

        # List to find the ID
        r2 = client.get("/interfaces/get-interface-groups")
        groups = r2.get_json()["data"]
        grp_id = next((g["id"] for g in groups if g["name"] == "testgrp"), None)
        assert grp_id is not None

        # Delete
        r3 = client.delete(f"/interfaces/delete-interface-group/{grp_id}")
        assert r3.status_code == 200
        assert r3.get_json()["status"] == "success"

    def test_get_interface_assignments(self, superuser):
        client, _ = superuser
        r = client.get("/interfaces/get-interface-assignments")
        assert r.status_code == 200
        data = r.get_json()
        assert data["status"] == "success"

    def test_save_assignment_requires_permission(self, plain_user):
        client, _ = plain_user
        r = client.post("/interfaces/save-interface-assignment", json={
            "interfaceType": "WAN", "networkPort": "em0"
        })
        assert r.status_code in (401, 403)

    def test_save_assignment_invalid_port_rejected(self, superuser):
        client, _ = superuser
        r = client.post("/interfaces/save-interface-assignment", json={
            "interfaceType": "WAN",
            "networkPort": "bad port name with spaces!!!"
        })
        assert r.status_code == 400

    def test_available_ports_dev_fallback(self, superuser):
        client, _ = superuser
        r = client.get("/interfaces/available-ports")
        assert r.status_code == 200
        data = r.get_json()
        assert data["status"] == "success"
        assert data["ports"][0]["name"] == "em0"
        assert data["ports"][0]["label"] == "em0"

    def test_save_assignment_syncs_config_rows(self, app, superuser):
        client, _ = superuser
        from app.database import get_db

        with app.app_context():
            conn = get_db()
            conn.execute("DELETE FROM interface_assignments")
            conn.execute("UPDATE wan_config SET assigned_port='' WHERE id=1")
            conn.execute("UPDATE lan_config SET assigned_port='' WHERE id=1")
            conn.commit()

        assert client.post("/interfaces/save-interface-assignment", json={
            "interfaceType": "WAN", "networkPort": "em0"
        }).status_code == 200
        assert client.post("/interfaces/save-interface-assignment", json={
            "interfaceType": "LAN", "networkPort": "em1"
        }).status_code == 200

        with app.app_context():
            conn = get_db()
            wan = conn.execute("SELECT network_port FROM interface_assignments WHERE interface_type='WAN'").fetchone()
            lan = conn.execute("SELECT network_port FROM interface_assignments WHERE interface_type='LAN'").fetchone()
            wan_cfg = conn.execute("SELECT assigned_port FROM wan_config WHERE id=1").fetchone()
            lan_cfg = conn.execute("SELECT assigned_port FROM lan_config WHERE id=1").fetchone()
            assert wan["network_port"] == "em0"
            assert lan["network_port"] == "em1"
            assert wan_cfg["assigned_port"] == "em0"
            assert lan_cfg["assigned_port"] == "em1"

    def test_same_port_assignment_rejected(self, app, superuser):
        client, _ = superuser
        from app.database import get_db

        with app.app_context():
            conn = get_db()
            conn.execute("DELETE FROM interface_assignments")
            conn.execute(
                "INSERT INTO interface_assignments (interface_type, network_port) VALUES ('WAN', 'em0')"
            )
            conn.commit()

        r = client.post("/interfaces/save-interface-assignment", json={
            "interfaceType": "LAN", "networkPort": "em0"
        })
        assert r.status_code == 400
        assert "already assigned" in r.get_json()["message"]

    def test_delete_assignment_clears_config_row(self, app, superuser):
        client, _ = superuser
        from app.database import get_db

        with app.app_context():
            conn = get_db()
            conn.execute("DELETE FROM interface_assignments")
            conn.execute(
                "INSERT INTO interface_assignments (interface_type, network_port) VALUES ('LAN', 'em1')"
            )
            conn.execute("UPDATE lan_config SET assigned_port='em1' WHERE id=1")
            conn.commit()

        r = client.delete("/interfaces/delete-interface-assignment/LAN")
        assert r.status_code == 200
        with app.app_context():
            conn = get_db()
            lan_cfg = conn.execute("SELECT assigned_port FROM lan_config WHERE id=1").fetchone()
            assert lan_cfg["assigned_port"] == ""

    def test_wan_password_is_encrypted_and_not_returned(self, app, superuser):
        client, _ = superuser
        from app.database import get_db
        from app.secret_store import decrypt_secret

        payload = {
            "enableInterface": True,
            "description": "WAN",
            "ipv4ConfigType": "pppoe",
            "ipv6ConfigType": "none",
            "macAddress": "",
            "mtu": "",
            "mss": "",
            "speedAndDuplex": "default",
            "ipv4Address": "",
            "ipv4UpstreamGateway": "",
            "username": "isp-user",
            "password": "isp-secret",
            "dialOnDemand": False,
            "idleTimeout": 0,
            "blockPrivateNetworks": True,
            "blockBogonNetworks": True,
        }
        r = client.post("/interfaces/save-wan-config", json=payload)
        assert r.status_code == 200

        with app.app_context():
            conn = get_db()
            row = conn.execute("SELECT password FROM wan_config WHERE id=1").fetchone()
            assert row["password"].startswith("enc:")
            assert decrypt_secret(row["password"]) == "isp-secret"

        r = client.get("/interfaces/get-wan-config")
        data = r.get_json()["data"]
        assert "password" not in data
        assert data["has_password"] is True

        payload["password"] = ""
        payload["username"] = "isp-user-2"
        assert client.post("/interfaces/save-wan-config", json=payload).status_code == 200
        with app.app_context():
            conn = get_db()
            row = conn.execute("SELECT password FROM wan_config WHERE id=1").fetchone()
            assert decrypt_secret(row["password"]) == "isp-secret"
