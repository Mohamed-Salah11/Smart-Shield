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
    """Restore the apply-gating env vars after every test.

    Several writer/migration test modules (test_phase5, test_*_writer, …) flip
    ``SMARTSHIELD_NETWORK_DRY_RUN=1`` for isolation but never restore it. Because
    the ``app`` fixture is session-scoped and shared, the leak makes later
    modules order-dependent — the setup wizard's step-4 apply refuses to
    complete once it sees a stray ``DRY_RUN=1`` (routes/setup.py rejects dry-run
    as a real apply). Snapshot/restore only these apply-gating keys.

    NOTE: ``SMARTSHIELD_DB_PATH`` is deliberately NOT restored here — the
    reload-based DB fixtures destroy their in-memory DB on teardown, so forcing
    the path back would point the shared session app at a dead database.
    """
    keys = (
        "SMARTSHIELD_NETWORK_DRY_RUN",
        "SMARTSHIELD_ENABLE_NETWORK_APPLY",
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
    """Application instance backed by an in-memory database."""
    application = create_app()
    application.config["TESTING"] = True
    application.config["WTF_CSRF_ENABLED"] = False
    return application


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
