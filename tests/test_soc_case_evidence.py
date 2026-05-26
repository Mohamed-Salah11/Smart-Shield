"""
tests/test_soc_case_evidence.py
-------------------------------
Unit tests for the SOC "snapshot the source log onto a case" path:

  * app.audit_log.get_event_by_uuid       — fetch a full event by uuid / timestamp
  * routes.soc_portal._snapshot_case_event — capture that event into siem_case_events

No FreeBSD and no SOC HTTP session required — these exercise the helpers
directly against an isolated in-memory DB.
"""

import json
import os
import secrets

import pytest

os.environ.setdefault("SMARTSHIELD_DB_PATH", "file:soccase?mode=memory&cache=shared")
os.environ.setdefault("SECRET_KEY", "test-soc-case-key")
os.environ.setdefault(
    "SMARTSHIELD_MASTER_KEY",
    __import__("base64").b64encode(__import__("secrets").token_bytes(32)).decode(),
)


@pytest.fixture()
def conn():
    os.environ["SMARTSHIELD_DB_PATH"] = (
        f"file:soccase_{secrets.token_hex(4)}?mode=memory&cache=shared"
    )
    from app.database import init_db, get_db
    init_db()
    db = get_db()
    yield db
    db.close()


def _insert_event(db, *, uuid="uuid-1", ts="2026-05-26T12:00:00",
                  category="ids", action="alert", severity="high",
                  details=None):
    db.execute(
        "INSERT INTO events (ts, severity, category, action, username, "
        "remote_addr, details, event_uuid) VALUES (?,?,?,?,?,?,?,?)",
        (ts, severity, category, action, "sys", "1.2.3.4",
         json.dumps(details or {"signature": "ET SCAN evil"}), uuid),
    )
    db.commit()


# ---------------------------------------------------------------------------
# get_event_by_uuid
# ---------------------------------------------------------------------------

class TestGetEventByUuid:
    def test_returns_full_event(self, conn):
        from app.audit_log import get_event_by_uuid
        _insert_event(conn, uuid="uuid-abc")
        ev = get_event_by_uuid("uuid-abc")
        assert ev is not None
        assert ev["action"] == "alert"
        assert ev["category"] == "ids"
        assert ev["details"]["signature"] == "ET SCAN evil"
        assert ev["event_uuid"] == "uuid-abc"

    def test_timestamp_fallback(self, conn):
        from app.audit_log import get_event_by_uuid
        _insert_event(conn, uuid="", ts="2026-05-26T09:09:09")
        ev = get_event_by_uuid(timestamp="2026-05-26T09:09:09")
        assert ev is not None
        assert ev["action"] == "alert"

    def test_unknown_returns_none(self, conn):
        from app.audit_log import get_event_by_uuid
        assert get_event_by_uuid("does-not-exist") is None
        assert get_event_by_uuid("") is None


# ---------------------------------------------------------------------------
# _snapshot_case_event
# ---------------------------------------------------------------------------

class TestSnapshotCaseEvent:
    def _open_case(self, conn):
        cur = conn.execute(
            "INSERT INTO siem_cases (title, created_by) VALUES ('t', 'tester')"
        )
        conn.commit()
        return cur.lastrowid

    def test_snapshots_full_event(self, conn):
        from routes.soc_portal import _snapshot_case_event
        _insert_event(conn, uuid="uuid-xyz")
        case_id = self._open_case(conn)
        _snapshot_case_event(conn, case_id, "uuid-xyz", "")
        conn.commit()
        row = conn.execute(
            "SELECT * FROM siem_case_events WHERE case_id=?", (case_id,)
        ).fetchone()
        assert row is not None
        assert row["event_uuid"] == "uuid-xyz"
        assert row["event_action"] == "alert"
        detail = json.loads(row["event_details"])
        assert detail["details"]["signature"] == "ET SCAN evil"

    def test_stub_row_when_event_unresolved(self, conn):
        from routes.soc_portal import _snapshot_case_event
        case_id = self._open_case(conn)
        # No matching event — but a source timestamp is known, so a stub row is
        # still recorded so the case lists the linked log.
        _snapshot_case_event(conn, case_id, "", "2020-01-01T00:00:00")
        conn.commit()
        row = conn.execute(
            "SELECT * FROM siem_case_events WHERE case_id=?", (case_id,)
        ).fetchone()
        assert row is not None
        assert row["event_timestamp"] == "2020-01-01T00:00:00"
        assert (row["event_details"] or "") == ""

    def test_no_row_when_nothing_to_resolve(self, conn):
        from routes.soc_portal import _snapshot_case_event
        case_id = self._open_case(conn)
        _snapshot_case_event(conn, case_id, "", "")
        conn.commit()
        n = conn.execute(
            "SELECT COUNT(*) AS c FROM siem_case_events WHERE case_id=?", (case_id,)
        ).fetchone()["c"]
        assert n == 0
