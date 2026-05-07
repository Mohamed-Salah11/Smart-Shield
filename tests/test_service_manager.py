"""Tests for service_manager integration glue."""


def test_reload_all_services_uses_apply_helpers():
    import inspect
    from app.services.service_manager import reload_all_services

    source = inspect.getsource(reload_all_services)
    assert "from app.services.snmp_writer import apply_snmp" in source
    assert "from app.services.upnp_writer import apply_upnp" in source
    assert "from app.services.igmp_writer import apply_igmp" in source
    assert "write_snmpd_config" not in source
    assert "write_upnp_conf" not in source
    assert "write_igmp_conf" not in source
