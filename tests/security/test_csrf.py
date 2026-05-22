"""
tests/security/test_csrf.py
---------------------------
Exercises the CSRF guard (``app.security.validate_csrf_or_abort``) directly.

The shared ``app`` fixture in tests/conftest.py runs with TESTING=True, which
intentionally short-circuits CSRF enforcement so the test client can POST
without a token. To prove enforcement actually works we build a tiny app here
with TESTING=False and drive the guard inside request contexts.
"""

import pytest
from werkzeug.exceptions import BadRequest
from flask import Flask, session

from app.security import (
    validate_csrf_or_abort,
    CSRF_SESSION_KEY,
    CSRF_HEADER_NAME,
)


@pytest.fixture
def csrf_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "csrf-test-secret-key"
    app.config["TESTING"] = False  # enforce CSRF (production behavior)
    return app


# ── Safe methods never require a token ──────────────────────────────────────

@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS"])
def test_safe_methods_skip_csrf(csrf_app, method):
    with csrf_app.test_request_context("/", method=method):
        validate_csrf_or_abort()  # must not raise


# ── Unsafe methods without a valid token are rejected ───────────────────────

@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_unsafe_without_token_aborts(csrf_app, method):
    with csrf_app.test_request_context("/", method=method):
        session[CSRF_SESSION_KEY] = "expected-token"
        with pytest.raises(BadRequest):
            validate_csrf_or_abort()


def test_post_with_wrong_token_aborts(csrf_app):
    with csrf_app.test_request_context(
        "/", method="POST", headers={CSRF_HEADER_NAME: "wrong-token"}
    ):
        session[CSRF_SESSION_KEY] = "right-token"
        with pytest.raises(BadRequest):
            validate_csrf_or_abort()


def test_no_session_token_aborts_even_with_header(csrf_app):
    """If the session never issued a token, any provided token is rejected."""
    with csrf_app.test_request_context(
        "/", method="POST", headers={CSRF_HEADER_NAME: "some-token"}
    ):
        with pytest.raises(BadRequest):
            validate_csrf_or_abort()


# ── Unsafe methods with a valid token pass ──────────────────────────────────

def test_post_with_matching_header_token_passes(csrf_app):
    with csrf_app.test_request_context(
        "/", method="POST", headers={CSRF_HEADER_NAME: "tok-123"}
    ):
        session[CSRF_SESSION_KEY] = "tok-123"
        validate_csrf_or_abort()  # must not raise


def test_post_with_matching_form_token_passes(csrf_app):
    with csrf_app.test_request_context(
        "/", method="POST", data={"csrf_token": "tok-form"}
    ):
        session[CSRF_SESSION_KEY] = "tok-form"
        validate_csrf_or_abort()  # must not raise


def test_delete_with_matching_header_token_passes(csrf_app):
    with csrf_app.test_request_context(
        "/", method="DELETE", headers={CSRF_HEADER_NAME: "del-tok"}
    ):
        session[CSRF_SESSION_KEY] = "del-tok"
        validate_csrf_or_abort()  # must not raise


# ── Query-string tokens are explicitly NOT accepted ─────────────────────────

def test_query_string_token_is_rejected(csrf_app):
    with csrf_app.test_request_context(
        "/?csrf_token=qs-tok", method="POST"
    ):
        session[CSRF_SESSION_KEY] = "qs-tok"
        with pytest.raises(BadRequest):
            validate_csrf_or_abort()


# ── TESTING mode bypass is intentional and documented ───────────────────────

def test_testing_mode_bypasses_enforcement():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "x"
    app.config["TESTING"] = True
    with app.test_request_context("/", method="POST"):
        # No token at all, but TESTING short-circuits the guard.
        validate_csrf_or_abort()  # must not raise
