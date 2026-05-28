"""
tests/test_siem_collector.py
----------------------------
Unit tests for the DHCP path of app/services/siem_collector.py.

Covers two related fixes:

1. The lease parser. The previous regex captured ``hardware`` as the field
   key and silently dropped every lease — ``_collect_dhcp_events`` therefore
   emitted nothing. The rewrite walks each lease block line-by-line and
   recognizes the multi-word ISC dhcpd keys (``hardware ethernet``,
   ``binding state``).

2. The per-MAC watermark persistence. ``state["dhcp_seen"]`` used to be an
   in-memory ``set`` of ``(ip, mac)`` tuples — a restart re-emitted every
   active lease as new. It's now a ``{mac: bind_ts}`` dict checkpointed to
   ``siem_state.dhcp_last_seen`` so a restart with a populated watermark
   does NOT re-emit a lease whose bind time is older-or-equal.
"""
import json
import os

import pytest

os.environ.setdefault("SMARTSHIELD_DB_PATH", "file:siemtest?mode=memory&cache=shared")
os.environ.setdefault("SECRET_KEY", "test-siem-key")
os.environ.setdefault("SMARTSHIELD_MASTER_KEY",
    __import__("base64").b64encode(__import__("secrets").token_bytes(32)).decode())


@pytest.fixture()
def conn():
    import secrets as _s
    os.environ["SMARTSHIELD_DB_PATH"] = (
        f"file:siem_{_s.token_hex(4)}?mode=memory&cache=shared"
    )
    from app.database import init_db, get_db
    init_db()
    db = get_db()
    yield db
    db.close()


_LEASE_FIXTURE = """\
lease 192.168.1.50 {
  starts 5 2024/10/01 12:00:00;
  ends 5 2024/10/01 14:00:00;
  cltt 5 2024/10/01 12:05:00;
  binding state active;
  hardware ethernet aa:bb:cc:dd:ee:01;
  client-hostname "host-a";
}
lease 192.168.1.51 {
  starts 5 2024/10/01 12:10:00;
  ends 5 2024/10/01 14:10:00;
  cltt 5 2024/10/01 12:15:00;
  binding state active;
  hardware ethernet aa:bb:cc:dd:ee:02;
  client-hostname "host-b";
}
lease 192.168.1.52 {
  starts 5 2024/10/01 09:00:00;
  ends 5 2024/10/01 11:00:00;
  binding state free;
  hardware ethernet aa:bb:cc:dd:ee:03;
}
"""


class TestParseLeases:

    def test_parser_extracts_active_leases_with_mac(self):
        from app.services.siem_collector import _parse_leases
        leases = _parse_leases(_LEASE_FIXTURE)
        macs = {l["mac"] for l in leases}
        # The two active leases are parsed; the free one is skipped.
        assert macs == {"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"}

    def test_parser_extracts_hostname_and_bind_ts(self):
        from app.services.siem_collector import _parse_leases
        leases = {l["mac"]: l for l in _parse_leases(_LEASE_FIXTURE)}
        a = leases["aa:bb:cc:dd:ee:01"]
        assert a["hostname"] == "host-a"
        # cltt 2024-10-01 12:05:00 UTC = 1727784300
        assert a["bind_ts"] == pytest.approx(1727784300, abs=1)

    def test_parser_uses_starts_when_no_cltt(self):
        text = (
            "lease 10.0.0.5 {\n"
            "  starts 5 2024/10/01 08:00:00;\n"
            "  ends 5 2024/10/01 10:00:00;\n"
            "  binding state active;\n"
            "  hardware ethernet 11:22:33:44:55:66;\n"
            "}\n"
        )
        from app.services.siem_collector import _parse_leases
        l = _parse_leases(text)[0]
        # starts 2024-10-01 08:00:00 UTC = 1727769600
        assert l["bind_ts"] == pytest.approx(1727769600, abs=1)

    def test_parser_handles_epoch_format(self):
        text = (
            "lease 10.0.0.6 {\n"
            "  cltt epoch 1700000000;\n"
            "  binding state active;\n"
            "  hardware ethernet 77:88:99:aa:bb:cc;\n"
            "}\n"
        )
        from app.services.siem_collector import _parse_leases
        l = _parse_leases(text)[0]
        assert l["bind_ts"] == 1700000000.0


class TestParseDhcpdTimestamp:

    def test_default_format(self):
        from app.services.siem_collector import _parse_dhcpd_ts
        assert _parse_dhcpd_ts("5 2024/10/01 12:00:00") == pytest.approx(1727784000, abs=1)

    def test_epoch_format(self):
        from app.services.siem_collector import _parse_dhcpd_ts
        assert _parse_dhcpd_ts("epoch 1727784000") == 1727784000.0

    def test_blank_returns_none(self):
        from app.services.siem_collector import _parse_dhcpd_ts
        assert _parse_dhcpd_ts("") is None
        assert _parse_dhcpd_ts("   ") is None

    def test_unparseable_returns_none(self):
        from app.services.siem_collector import _parse_dhcpd_ts
        assert _parse_dhcpd_ts("never") is None


class TestCollectDhcpEvents:

    def _setup_collector(self, monkeypatch, tmp_path, lease_text, emitted):
        leases_path = tmp_path / "dhcpd.leases"
        leases_path.write_text(lease_text, encoding="utf-8")
        import app.services.siem_collector as sc
        monkeypatch.setattr(sc, "_DHCPD_LEASES", str(leases_path))
        monkeypatch.setattr(sc, "_log",
            lambda category, action, remote_addr="", details=None:
                emitted.append({"action": action, "ip": remote_addr,
                                "mac": (details or {}).get("mac")}))
        return sc, leases_path

    def test_first_poll_emits_active_leases(self, conn, monkeypatch, tmp_path):
        emitted = []
        sc, _ = self._setup_collector(monkeypatch, tmp_path, _LEASE_FIXTURE, emitted)
        state = {}
        sc._collect_dhcp_events(state)
        assert sorted(e["mac"] for e in emitted) == [
            "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"
        ]
        # ee:01 cltt 2024-10-01 12:05:00 UTC = 1727784300; ee:02 is +10min = +600s.
        assert state["dhcp_seen"] == {
            "aa:bb:cc:dd:ee:01": pytest.approx(1727784300, abs=1),
            "aa:bb:cc:dd:ee:02": pytest.approx(1727784900, abs=1),
        }

    def test_second_poll_with_unchanged_leases_is_noop(self, conn, monkeypatch, tmp_path):
        emitted = []
        sc, _ = self._setup_collector(monkeypatch, tmp_path, _LEASE_FIXTURE, emitted)
        state = {}
        sc._collect_dhcp_events(state)
        emitted.clear()
        sc._collect_dhcp_events(state)
        assert emitted == []

    def test_restart_with_watermark_does_not_reemit(self, conn, monkeypatch, tmp_path):
        # Simulate the restart path: persist a watermark, hydrate fresh state
        # from siem_state, then poll the same lease file. Nothing should fire.
        emitted = []
        sc, _ = self._setup_collector(monkeypatch, tmp_path, _LEASE_FIXTURE, emitted)
        first_state = {}
        sc._collect_dhcp_events(first_state)
        assert emitted, "sanity: first poll must emit something"

        # The collector wrote dhcp_last_seen to siem_state during the first
        # poll. Hydrate a brand-new state dict from disk, the same way
        # start_siem_collectors() does on process restart.
        persisted = sc._load_state("dhcp_last_seen", "{}")
        restart_state = {"dhcp_seen": json.loads(persisted)}
        assert restart_state["dhcp_seen"], "watermark must have been persisted"

        emitted.clear()
        sc._collect_dhcp_events(restart_state)
        assert emitted == [], "restart must NOT re-emit leases already covered by the watermark"

    def test_new_lease_after_watermark_is_emitted(self, conn, monkeypatch, tmp_path):
        emitted = []
        sc, leases_path = self._setup_collector(monkeypatch, tmp_path,
                                                _LEASE_FIXTURE, emitted)
        state = {}
        sc._collect_dhcp_events(state)
        emitted.clear()

        # Append a third active lease bound LATER than the watermark.
        leases_path.write_text(_LEASE_FIXTURE + (
            "lease 192.168.1.99 {\n"
            "  cltt 5 2024/10/02 13:00:00;\n"
            "  binding state active;\n"
            "  hardware ethernet aa:bb:cc:dd:ee:99;\n"
            "}\n"
        ), encoding="utf-8")
        sc._collect_dhcp_events(state)
        assert [e["mac"] for e in emitted] == ["aa:bb:cc:dd:ee:99"]

    def test_renewed_lease_with_newer_bind_ts_is_emitted(self, conn, monkeypatch, tmp_path):
        # Same MAC, a later cltt → emit (it's a new bind / renewal).
        emitted = []
        sc, leases_path = self._setup_collector(monkeypatch, tmp_path,
                                                _LEASE_FIXTURE, emitted)
        state = {}
        sc._collect_dhcp_events(state)
        emitted.clear()
        renewed = _LEASE_FIXTURE.replace(
            "cltt 5 2024/10/01 12:05:00",
            "cltt 5 2024/10/02 12:05:00",
        )
        leases_path.write_text(renewed, encoding="utf-8")
        sc._collect_dhcp_events(state)
        assert any(e["mac"] == "aa:bb:cc:dd:ee:01" for e in emitted)


class TestEvictSeen:

    def test_caps_dict_to_size(self):
        from app.services.siem_collector import _evict_seen
        seen = {f"mac-{i:04d}": float(i) for i in range(20)}
        _evict_seen(seen, cap=5)
        assert len(seen) == 5
        # The 5 newest entries (highest ts) survive.
        assert set(seen) == {f"mac-{i:04d}" for i in range(15, 20)}

    def test_under_cap_is_noop(self):
        from app.services.siem_collector import _evict_seen
        seen = {"a": 1.0, "b": 2.0}
        _evict_seen(seen, cap=10)
        assert seen == {"a": 1.0, "b": 2.0}
