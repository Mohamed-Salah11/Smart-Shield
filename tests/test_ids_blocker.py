"""
tests/test_ids_blocker.py
-------------------------
Unit tests for app/services/ids_blocker.py (block-on-alert → <ss_ids_blocks>).

No FreeBSD required: pfctl mutation is a FreeBSD-only best-effort no-op off
FreeBSD, so the DB bookkeeping (ids_blocked_ips) is what we assert. The audit
``log_event`` is stubbed so blocks/unblocks don't depend on the event store.
"""
import os
import time
import pytest

os.environ.setdefault("SMARTSHIELD_DB_PATH", "file:idsblk?mode=memory&cache=shared")
os.environ.setdefault("SECRET_KEY", "test-idsblk-key")
os.environ.setdefault("SMARTSHIELD_MASTER_KEY",
    __import__("base64").b64encode(__import__("secrets").token_bytes(32)).decode())


@pytest.fixture()
def conn():
    import secrets
    os.environ["SMARTSHIELD_DB_PATH"] = f"file:idsblk_{secrets.token_hex(4)}?mode=memory&cache=shared"
    from app.database import init_db, get_db
    init_db()
    db = get_db()
    yield db
    db.close()


@pytest.fixture(autouse=True)
def _stub_audit(monkeypatch):
    """Keep auto-block/unblock audit writes deterministic and out of the way."""
    import app.audit_log as al
    monkeypatch.setattr(al, "log_event", lambda **kw: "")


def _blocked_ips(conn):
    return {r["ip"] for r in conn.execute("SELECT ip FROM ids_blocked_ips").fetchall()}


class TestMaybeBlock:

    def test_high_severity_alert_blocks_ip(self, conn):
        from app.services.ids_blocker import maybe_block
        res = maybe_block(conn, src_ip="203.0.113.7", severity="high",
                          signature="ET SCAN Nmap", signature_id="2001",
                          source_alert_id="uuid-1")
        assert res and res["ok"] is True
        assert "203.0.113.7" in _blocked_ips(conn)

    def test_low_severity_alert_does_not_block(self, conn):
        from app.services.ids_blocker import maybe_block
        res = maybe_block(conn, src_ip="203.0.113.8", severity="low",
                          signature="ET INFO", signature_id="3001")
        assert res is None
        assert "203.0.113.8" not in _blocked_ips(conn)

    def test_admin_listed_sid_blocks_even_low_severity(self, conn):
        conn.execute("UPDATE ids_config SET auto_block_sids='3002,4004' WHERE id=1")
        conn.commit()
        from app.services.ids_blocker import maybe_block
        res = maybe_block(conn, src_ip="203.0.113.9", severity="low",
                          signature="ET POLICY", signature_id="3002")
        assert res and res["ok"] is True
        assert "203.0.113.9" in _blocked_ips(conn)

    def test_already_blocked_ip_is_noop(self, conn):
        from app.services.ids_blocker import maybe_block
        first  = maybe_block(conn, src_ip="203.0.113.10", severity="critical")
        second = maybe_block(conn, src_ip="203.0.113.10", severity="critical")
        assert first and first["ok"] is True
        assert second is None
        count = conn.execute(
            "SELECT COUNT(*) c FROM ids_blocked_ips WHERE ip='203.0.113.10'"
        ).fetchone()["c"]
        assert count == 1

    def test_invalid_ip_is_ignored(self, conn):
        from app.services.ids_blocker import maybe_block
        assert maybe_block(conn, src_ip="not-an-ip", severity="high") is None
        assert _blocked_ips(conn) == set()

    def test_ttl_comes_from_config(self, conn):
        conn.execute("UPDATE ids_config SET auto_block_ttl_seconds=120 WHERE id=1")
        conn.commit()
        from app.services.ids_blocker import maybe_block
        before = time.time()
        res = maybe_block(conn, src_ip="203.0.113.11", severity="high")
        assert res["ttl_seconds"] == 120
        assert before + 110 <= res["expires_at"] <= before + 130


class TestExpire:

    def test_expire_deletes_past_due_rows(self, conn):
        from app.services.ids_blocker import expire_blocks
        now = time.time()
        conn.execute(
            "INSERT INTO ids_blocked_ips (ip, added_at, expires_at) VALUES (?,?,?)",
            ("198.51.100.5", now - 7200, now - 3600),   # expired an hour ago
        )
        conn.execute(
            "INSERT INTO ids_blocked_ips (ip, added_at, expires_at) VALUES (?,?,?)",
            ("198.51.100.6", now, now + 3600),           # still active
        )
        conn.commit()
        res = expire_blocks(conn)
        assert res["ok"] is True
        assert res["expired"] == 1
        ips = _blocked_ips(conn)
        assert "198.51.100.5" not in ips
        assert "198.51.100.6" in ips


class TestUnblock:

    def test_unblock_removes_row(self, conn):
        from app.services.ids_blocker import maybe_block, unblock, list_blocked
        maybe_block(conn, src_ip="203.0.113.20", severity="high")
        assert any(b["ip"] == "203.0.113.20" for b in list_blocked(conn))
        res = unblock(conn, "203.0.113.20", actor="tester")
        assert res["ok"] is True
        assert not any(b["ip"] == "203.0.113.20" for b in list_blocked(conn))

    def test_unblock_rejects_invalid_ip(self, conn):
        from app.services.ids_blocker import unblock
        assert unblock(conn, "bogus")["ok"] is False
