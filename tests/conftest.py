"""
tests/conftest.py
-----------------
Shared pytest fixtures.

The test suite uses an in-memory SQLite database so no FreeBSD system calls,
no pfctl, no file-system writes, and no network operations are triggered.
System commands in service modules are mocked where needed.
"""

import os
import base64
import secrets

import pytest

# Point at an in-memory DB before importing anything from the app.
_DB_URI = "file:testdb?mode=memory&cache=shared"
os.environ.setdefault("SMARTSHIELD_DB_PATH", _DB_URI)
os.environ.setdefault("SECRET_KEY", "test-secret-key-not-for-production")

# Use a deterministic master key so tests are reproducible.
_TEST_MASTER_KEY = base64.b64encode(secrets.token_bytes(32)).decode()
os.environ.setdefault("SMARTSHIELD_MASTER_KEY", _TEST_MASTER_KEY)

from app import create_app  # noqa: E402 — must be after env setup
from app.database import get_db  # noqa: E402


@pytest.fixture(autouse=True)
def _isolate_volatile_env():
    """Restore leak-prone env vars after every test.

    Several writer/migration test modules (test_phase5, test_*_writer, …) flip
    ``SMARTSHIELD_NETWORK_DRY_RUN=1`` for isolation but never restore it. Because
    the ``app`` fixture is session-scoped and shared, the leak makes later
    modules order-dependent — the setup wizard's step-4 apply refuses to
    complete once it sees a stray ``DRY_RUN=1`` (routes/setup.py rejects dry-run
    as a real apply). Snapshot/restore these apply-gating keys.

    ``SMARTSHIELD_DB_PATH`` is restored too. Many writer/cert/migration tests
    repoint it at a throwaway in-memory DB inside a function-scoped fixture and
    never restore it (e.g. test_cert_manager, test_pf_generator, test_phase5,
    the per-writer fixtures). ``app.database.get_db()`` reads that variable live
    on every call, so a leaked value makes the shared session ``app`` reconnect
    to the wrong (and usually garbage-collected, schema-less) database — which
    surfaced as ``no such table: users`` in TestL2tpSaveConfig. Because the
    leaks all happen inside fixtures (every module-level assignment is a
    no-op ``setdefault``), snapshotting at test start and restoring at teardown
    reverts each leak, and the session ``app``'s ``file:testdb`` — kept alive by
    the anchor in the ``app`` fixture — is always the value restored to.
    """
    keys = (
        "SMARTSHIELD_NETWORK_DRY_RUN",
        "SMARTSHIELD_ENABLE_NETWORK_APPLY",
        "SMARTSHIELD_DB_PATH",
    )
    saved = {k: os.environ.get(k) for k in keys}
    yield
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


@pytest.fixture(scope="session")
def app():
    """Application instance backed by an in-memory database.

    A session-long *anchor* connection is held open to the configured DB URI so
    the shared-cache in-memory database (and its schema) cannot be destroyed
    mid-session. A shared-cache ``mode=memory`` database lives only while at
    least one connection to it is open. Some migration tests
    (TestEventUuidIndexUpgrade) repoint ``SMARTSHIELD_DB_PATH`` at a throwaway
    memory DB and call ``init_db()``, which tears down the library's keep-alive
    connection to the main test DB. Without an independent anchor the main
    ``file:testdb`` database would be garbage-collected, and the next test to
    touch it would hit a fresh, empty schema ("no such table: users"). The
    anchor keeps it alive for the whole session.
    """
    import sqlite3

    db_uri = os.environ["SMARTSHIELD_DB_PATH"]
    anchor = sqlite3.connect(db_uri, uri=db_uri.startswith("file:"))
    application = create_app()
    application.config["TESTING"] = True
    application.config["WTF_CSRF_ENABLED"] = False
    yield application
    anchor.close()


@pytest.fixture()
def client(app):
    """Test client with a fresh request context."""
    return app.test_client()


# ---------------------------------------------------------------------------
# Helpers for seeding users / groups inside tests
# ---------------------------------------------------------------------------

def _create_user(app, username, password, is_superuser=0):
    from werkzeug.security import generate_password_hash
    with app.app_context():
        conn = get_db()
        conn.execute(
            "INSERT OR IGNORE INTO users (username, password, is_superuser) VALUES (?, ?, ?)",
            (username, generate_password_hash(password), is_superuser),
        )
        conn.commit()
        row = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
        return row["id"]


def _create_group(app, name):
    with app.app_context():
        conn = get_db()
        conn.execute("INSERT OR IGNORE INTO groups (name) VALUES (?)", (name,))
        conn.commit()
        row = conn.execute("SELECT id FROM groups WHERE name=?", (name,)).fetchone()
        return row["id"]


def _add_user_to_group(app, user_id, group_id):
    with app.app_context():
        conn = get_db()
        conn.execute(
            "INSERT OR IGNORE INTO user_groups (user_id, group_id) VALUES (?, ?)",
            (user_id, group_id),
        )
        conn.commit()


def _grant_permission(app, group_id, permission):
    with app.app_context():
        conn = get_db()
        conn.execute(
            "INSERT OR IGNORE INTO group_page_permissions (group_id, endpoint) VALUES (?, ?)",
            (group_id, permission),
        )
        conn.commit()


def _login(client, username, password):
    """POST to /login and return the response (CSRF skipped in TESTING mode)."""
    return client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    )


@pytest.fixture()
def superuser(app, client):
    """A logged-in superuser client with a fresh reauth window.

    The fresh ``reauth_time`` means tests can exercise routes that carry
    ``@reauth_required`` without each one having to stamp the session itself.
    Tests that want to verify the reauth gate explicitly should pop the key
    before posting (see tests/integration/test_security_hardening.py)."""
    from datetime import datetime, timezone
    uid = _create_user(app, "superadmin", "superpass", is_superuser=1)
    _login(client, "superadmin", "superpass")
    with client.session_transaction() as sess:
        sess["reauth_time"] = datetime.now(timezone.utc).isoformat()
    return client, uid


@pytest.fixture()
def plain_user(app, client):
    """A logged-in non-superuser with no extra permissions."""
    uid = _create_user(app, "plainuser", "plainpass", is_superuser=0)
    _login(client, "plainuser", "plainpass")
    return client, uid


@pytest.fixture()
def permitted_user(app, client):
    """A logged-in non-superuser with api.firewall.edit permission."""
    uid  = _create_user(app, "fweditor", "fwpass", is_superuser=0)
    gid  = _create_group(app, "fw_editors")
    _add_user_to_group(app, uid, gid)
    _grant_permission(app, gid, "api.firewall.edit")
    _login(client, "fweditor", "fwpass")
    return client, uid
