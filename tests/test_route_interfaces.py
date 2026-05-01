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
