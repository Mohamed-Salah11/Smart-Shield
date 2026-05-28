"""
tests/test_pppoe_writer.py
--------------------------
Tests for the PPPoE WAN live-apply path (Phase 1.9).

Covers:
1. validate_pppoe — required username/password, NIC-membership when a NIC list
   is provided, alphanumeric service name.
2. save_wan_config — that a valid PPPoE save actually invokes apply_pppoe
   (proves the dispatch in apply_interface_config is reachable end-to-end from
   the browser route) and that invalid credentials short-circuit with a 400.
"""


# ---------------------------------------------------------------------------
# validate_pppoe — pure unit
# ---------------------------------------------------------------------------

class TestValidatePppoe:

    def test_valid_payload_is_accepted(self):
        from app.services.pppoe_writer import validate_pppoe
        wan = {"assigned_port": "em0", "username": "isp-user",
               "password": "isp-secret"}
        assert validate_pppoe(wan, physical_nics=[{"name": "em0"}]) == []

    def test_missing_username_rejected(self):
        from app.services.pppoe_writer import validate_pppoe
        errs = validate_pppoe({"assigned_port": "em0", "username": "",
                               "password": "pw"})
        assert any("username" in e.lower() for e in errs)

    def test_missing_password_rejected(self):
        from app.services.pppoe_writer import validate_pppoe
        errs = validate_pppoe({"assigned_port": "em0", "username": "u",
                               "password": ""})
        assert any("password" in e.lower() for e in errs)

    def test_assigned_port_not_in_nic_list_rejected(self):
        from app.services.pppoe_writer import validate_pppoe
        errs = validate_pppoe({"assigned_port": "em9", "username": "u",
                               "password": "p"},
                              physical_nics=[{"name": "em0"}, {"name": "em1"}])
        assert any("not a physical NIC" in e for e in errs)

    def test_assigned_port_check_skipped_when_no_nics_listed(self):
        # Off-FreeBSD list_physical_nics() returns []; the NIC-membership
        # check is then skipped so a save can still go through.
        from app.services.pppoe_writer import validate_pppoe
        wan = {"assigned_port": "em0", "username": "u", "password": "p"}
        assert validate_pppoe(wan, physical_nics=[]) == []
        assert validate_pppoe(wan, physical_nics=None) == []

    def test_service_name_must_be_alnum(self):
        from app.services.pppoe_writer import validate_pppoe
        ok = validate_pppoe({"assigned_port": "em0", "username": "u",
                             "password": "p", "service": "internet_1"})
        bad = validate_pppoe({"assigned_port": "em0", "username": "u",
                              "password": "p", "service": "bad name; rm"})
        assert ok == []
        assert any("service" in e.lower() for e in bad)


# ---------------------------------------------------------------------------
# save_wan_config end-to-end — proves apply_pppoe is reached
# ---------------------------------------------------------------------------

_VALID_PPPOE_PAYLOAD = {
    "enableInterface":       True,
    "description":           "WAN",
    "ipv4ConfigType":        "pppoe",
    "ipv6ConfigType":        "none",
    "macAddress":            "",
    "mtu":                   "",
    "mss":                   "",
    "speedAndDuplex":        "default",
    "ipv4Address":           "",
    "ipv4UpstreamGateway":   "",
    "username":              "isp-user",
    "password":              "isp-secret",
    "dialOnDemand":          False,
    "idleTimeout":           0,
    "blockPrivateNetworks":  True,
    "blockBogonNetworks":    True,
}


class TestSavePppoeInvokesApply:

    def test_save_pppoe_invokes_apply(self, app, superuser, monkeypatch):
        # Make sure an assigned_port is on the wan_config row — off-FreeBSD
        # list_physical_nics() is [], so the NIC-membership check is skipped
        # and any non-blank string passes.
        client, _ = superuser
        with app.app_context():
            from app.database import get_db
            get_db().execute(
                "UPDATE wan_config SET assigned_port='em0' WHERE id=1"
            )
            get_db().commit()

        calls = []
        import app.services.pppoe_writer as pw
        # Capture-and-pass: the apply path inside network_service.apply_interface_config
        # imports apply_pppoe at call time, so patching the module attribute is
        # what the dispatch will actually see.
        def _fake_apply(conn):
            calls.append("apply_pppoe")
            return {"ok": True, "message": "stub"}
        monkeypatch.setattr(pw, "apply_pppoe", _fake_apply)

        r = client.post("/interfaces/save-wan-config", json=_VALID_PPPOE_PAYLOAD)
        assert r.status_code == 200, r.get_data(as_text=True)
        assert calls == ["apply_pppoe"], (
            "save_wan_config must invoke apply_pppoe via apply_interface_config "
            "when ipv4ConfigType='pppoe'"
        )
        body = r.get_json()
        assert body["status"] == "success"


# ---------------------------------------------------------------------------
# Invalid PPPoE credentials are rejected up-front
# ---------------------------------------------------------------------------

class TestInvalidPppoeCredentialsRejected:

    def test_invalid_pppoe_credentials_rejected(self, app, superuser):
        client, _ = superuser
        # The conftest app fixture is session-scoped so the wan_config row
        # carries state from prior tests; explicitly clear the credentials so
        # the validator sees a genuinely empty payload (no DB fallback).
        with app.app_context():
            from app.database import get_db
            get_db().execute(
                "UPDATE wan_config SET assigned_port='em0', "
                "username='', password='' WHERE id=1"
            )
            get_db().commit()

        payload = dict(_VALID_PPPOE_PAYLOAD)
        payload["username"] = ""    # missing username
        payload["password"] = ""    # missing password

        r = client.post("/interfaces/save-wan-config", json=payload)
        assert r.status_code == 400
        body = r.get_json()
        assert body["status"] == "error"
        msg = (body.get("message") or "").lower()
        assert "username" in msg
        assert "password" in msg
