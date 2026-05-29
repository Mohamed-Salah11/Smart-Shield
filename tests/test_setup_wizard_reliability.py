import pytest

from app.database import get_db


@pytest.fixture(autouse=True)
def _authorize_setup_session(client):
    """The tests share a session-scoped app/DB with the rest of the suite, so
    by the time these run an admin user usually lingers from earlier test files.
    The setup guard (routes/setup.py) then blocks unauthenticated wizard access
    (403/302). A real wizard run is authorized once the operator claims the box,
    which sets ``setup_session_authorized`` in the session — replicate that here
    so these tests exercise the step logic, not the access guard. (Run in
    isolation the guard auto-authorizes a token-less dev session, which is why
    they pass alone but failed in the full suite.)"""
    with client.session_transaction() as sess:
        sess["setup_session_authorized"] = True


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
    # step4 refuses to mark setup complete in dry-run mode (routes/setup.py).
    # Other test modules set SMARTSHIELD_NETWORK_DRY_RUN=1 at import time, which
    # is ambient for the whole session — force a live apply so this success-path
    # test is deterministic regardless of collection order.
    monkeypatch.setattr(
        "app.services.network_service.is_network_dry_run",
        lambda: False,
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


# ---------------------------------------------------------------------------
# Phase 2.1: superuser re-running the wizard after setup_complete must reauth
# ---------------------------------------------------------------------------

def _mark_setup_complete(conn):
    conn.execute(
        "INSERT INTO service_state (key_name, value_json, updated_at) "
        "VALUES ('setup_complete', 'true', CURRENT_TIMESTAMP) "
        "ON CONFLICT(key_name) DO UPDATE SET value_json='true', "
        "updated_at=CURRENT_TIMESTAMP"
    )
    conn.commit()


_STEP_ROUTES_BODIES = [
    ("/setup/api/step1/save", {"wan_port": "em0", "lan_port": "em1"}),
    ("/setup/api/step2/save", {"ipv4_config_type": "dhcp"}),
    ("/setup/api/step3/save", {"username": "admin", "password": "x"}),
    ("/setup/api/step4/apply", {}),
]


import pytest as _pytest
from datetime import datetime, timezone


@_pytest.mark.parametrize("path,body", _STEP_ROUTES_BODIES)
def test_completed_wizard_blocks_superuser_without_reauth(app, superuser, setup_conn, path, body):
    # Setup is complete + superuser is logged in but session lacks a fresh
    # reauth → every step endpoint must return 403 reauth_required.
    client, _ = superuser
    with app.app_context():
        _mark_setup_complete(get_db())
    # The shared superuser fixture stamps reauth_time fresh — explicitly clear it.
    with client.session_transaction() as sess:
        sess.pop("reauth_time", None)
    r = client.post(path, json=body)
    assert r.status_code == 403, f"{path}: expected 403 (got {r.status_code})"
    data = r.get_json() or {}
    assert data.get("reauth_required") is True, f"{path}: missing reauth_required:true"


@_pytest.mark.parametrize("path,body", _STEP_ROUTES_BODIES)
def test_completed_wizard_admits_superuser_with_fresh_reauth(app, superuser, setup_conn, path, body):
    # Same setup as above but with a fresh reauth_time — the reauth gate must
    # NOT fire (the route may still 400/500 downstream for its own reasons).
    client, _ = superuser
    with app.app_context():
        _mark_setup_complete(get_db())
    with client.session_transaction() as sess:
        sess["reauth_time"] = datetime.now(timezone.utc).isoformat()
    r = client.post(path, json=body)
    data = r.get_json() or {}
    assert not (r.status_code == 403 and data.get("reauth_required") is True), \
        f"{path}: still blocked by reauth gate after a fresh reauth"


@_pytest.mark.parametrize("path,body", _STEP_ROUTES_BODIES)
def test_first_boot_wizard_is_not_reauth_gated(app, client, setup_conn, path, body):
    # First-boot path: setup_complete is NOT set (setup_conn deletes it). No
    # superuser is in session. The reauth decorator must let the request fall
    # through to the route's own first-boot handling — without flipping to 403.
    # The route may still return 400 for missing fields, but never 403
    # reauth_required.
    r = client.post(path, json=body)
    data = r.get_json() or {}
    assert not (r.status_code == 403 and data.get("reauth_required") is True), \
        f"{path}: first-boot request was wrongly reauth-gated"
