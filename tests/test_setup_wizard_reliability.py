import pytest

from app.database import get_db


@pytest.fixture()
def setup_conn(app):
    with app.app_context():
        conn = get_db()
        conn.execute("DELETE FROM service_state WHERE key_name='setup_complete'")
        conn.execute("DELETE FROM interface_assignments")
        conn.execute("UPDATE wan_config SET assigned_port='', ipv4_config_type='dhcp', ipv4_address='', ipv4_upstream_gateway='' WHERE id=1")
        conn.execute("UPDATE lan_config SET assigned_port='', ipv4_config_type='static', ipv4_address='', ipv4_upstream_gateway='' WHERE id=1")
        conn.commit()
        yield conn
        conn.execute("DELETE FROM service_state WHERE key_name='setup_complete'")
        conn.execute("DELETE FROM interface_assignments")
        conn.execute("UPDATE wan_config SET assigned_port='', ipv4_config_type='dhcp', ipv4_address='', ipv4_upstream_gateway='' WHERE id=1")
        conn.execute("UPDATE lan_config SET assigned_port='', ipv4_config_type='static', ipv4_address='', ipv4_upstream_gateway='' WHERE id=1")
        conn.commit()


def _assign_ports(conn, wan="em0", lan="em1"):
    conn.execute(
        """
        INSERT INTO interface_assignments (interface_type, network_port)
        VALUES ('WAN', ?)
        ON CONFLICT(interface_type) DO UPDATE SET network_port=excluded.network_port
        """,
        (wan,),
    )
    conn.execute(
        """
        INSERT INTO interface_assignments (interface_type, network_port)
        VALUES ('LAN', ?)
        ON CONFLICT(interface_type) DO UPDATE SET network_port=excluded.network_port
        """,
        (lan,),
    )
    conn.commit()


def test_step1_save_syncs_assignment_rows_and_config_rows(client, setup_conn):
    response = client.post(
        "/setup/api/step1/save",
        json={"wan_port": "em0", "lan_port": "em1"},
    )

    assert response.status_code == 200
    assert response.get_json()["ok"] is True

    wan_assignment = setup_conn.execute(
        "SELECT network_port FROM interface_assignments WHERE interface_type='WAN'"
    ).fetchone()
    lan_assignment = setup_conn.execute(
        "SELECT network_port FROM interface_assignments WHERE interface_type='LAN'"
    ).fetchone()
    wan_config = setup_conn.execute(
        "SELECT assigned_port FROM wan_config WHERE id=1"
    ).fetchone()
    lan_config = setup_conn.execute(
        "SELECT assigned_port FROM lan_config WHERE id=1"
    ).fetchone()

    assert wan_assignment["network_port"] == "em0"
    assert lan_assignment["network_port"] == "em1"
    assert wan_config["assigned_port"] == "em0"
    assert lan_config["assigned_port"] == "em1"


def test_step2_fails_when_ports_are_not_assigned(client, setup_conn):
    response = client.post(
        "/setup/api/step2/save",
        json={"lan_ip": "192.168.50.1/24", "wan_type": "dhcp"},
    )

    assert response.status_code == 400
    assert "WAN/LAN ports are not assigned" in response.get_json()["message"]


def test_step2_recovers_ports_from_database_without_session(client, setup_conn):
    _assign_ports(setup_conn, wan="vtnet0", lan="vtnet1")

    response = client.post(
        "/setup/api/step2/save",
        json={"lan_ip": "192.168.50.1/24", "wan_type": "dhcp"},
    )

    assert response.status_code == 200
    assert response.get_json()["ok"] is True
    wan = setup_conn.execute(
        "SELECT assigned_port, ipv4_config_type, ipv4_address, ipv4_upstream_gateway FROM wan_config WHERE id=1"
    ).fetchone()
    lan = setup_conn.execute(
        "SELECT assigned_port, ipv4_address FROM lan_config WHERE id=1"
    ).fetchone()

    assert wan["assigned_port"] == "vtnet0"
    assert wan["ipv4_config_type"] == "dhcp"
    assert wan["ipv4_address"] == ""
    assert wan["ipv4_upstream_gateway"] == ""
    assert lan["assigned_port"] == "vtnet1"
    assert lan["ipv4_address"] == "192.168.50.1/24"


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ({"lan_ip": "192.168.50.1/24", "wan_type": "bad"}, "Invalid WAN type."),
        (
            {"lan_ip": "192.168.50.1/24", "wan_type": "static", "wan_ip": "bad"},
            "Invalid WAN CIDR",
        ),
        (
            {
                "lan_ip": "192.168.50.1/24",
                "wan_type": "static",
                "wan_ip": "203.0.113.10/24",
                "wan_gw": "bad-gateway",
            },
            "Invalid WAN gateway",
        ),
    ],
)
def test_step2_rejects_invalid_wan_data(client, setup_conn, payload, message):
    _assign_ports(setup_conn)

    response = client.post("/setup/api/step2/save", json=payload)

    assert response.status_code == 400
    assert message in response.get_json()["message"]


def test_step2_saves_static_wan_gateway_to_upstream_gateway(client, setup_conn):
    _assign_ports(setup_conn)

    response = client.post(
        "/setup/api/step2/save",
        json={
            "lan_ip": "192.168.50.1/24",
            "wan_type": "static",
            "wan_ip": "203.0.113.10/24",
            "wan_gw": "203.0.113.1",
        },
    )

    assert response.status_code == 200
    wan = setup_conn.execute(
        "SELECT ipv4_config_type, ipv4_address, ipv4_upstream_gateway FROM wan_config WHERE id=1"
    ).fetchone()
    assert wan["ipv4_config_type"] == "static"
    assert wan["ipv4_address"] == "203.0.113.10/24"
    assert wan["ipv4_upstream_gateway"] == "203.0.113.1"


def test_step4_failed_apply_does_not_mark_setup_complete(client, setup_conn, monkeypatch):
    monkeypatch.setattr(
        "app.services.rc_conf_writer.apply_rc_conf",
        lambda conn: {"ok": True, "message": "rc ok"},
    )
    monkeypatch.setattr(
        "app.services.network_service.apply_interface_config",
        lambda conn: {"ok": False, "message": "interface failed"},
    )
    monkeypatch.setattr(
        "app.services.service_manager.reload_all_services",
        lambda conn: {"ok": True, "results": []},
    )

    response = client.post("/setup/api/step4/apply", json={})
    data = response.get_json()

    assert response.status_code == 200
    assert data["ok"] is False
    assert data["redirect"] is None
    row = setup_conn.execute(
        "SELECT value_json FROM service_state WHERE key_name='setup_complete'"
    ).fetchone()
    assert row is None


def test_step4_success_marks_setup_complete_and_redirects(client, setup_conn, monkeypatch):
    monkeypatch.setattr(
        "app.services.rc_conf_writer.apply_rc_conf",
        lambda conn: {"ok": True, "message": "rc ok"},
    )
    monkeypatch.setattr(
        "app.services.network_service.apply_interface_config",
        lambda conn: {"ok": True, "message": "interfaces ok"},
    )
    monkeypatch.setattr(
        "app.services.service_manager.reload_all_services",
        lambda conn: {"ok": True, "results": [{"service": "pf", "ok": True}]},
    )

    response = client.post("/setup/api/step4/apply", json={})
    data = response.get_json()

    assert response.status_code == 200
    assert data["ok"] is True
    assert data["redirect"] == "/system/dashboard"
    row = setup_conn.execute(
        "SELECT value_json FROM service_state WHERE key_name='setup_complete'"
    ).fetchone()
    assert row["value_json"] == "true"
