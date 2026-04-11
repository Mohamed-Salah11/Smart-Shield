import secrets
from hmac import compare_digest

from flask import abort, request, session


CSRF_SESSION_KEY = "_csrf_token"
CSRF_HEADER_NAME = "X-CSRF-Token"


def get_csrf_token():
    token = session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[CSRF_SESSION_KEY] = token
    return token


def _request_csrf_token():
    return (
        request.headers.get(CSRF_HEADER_NAME)
        or request.form.get("csrf_token")
        or request.args.get("csrf_token")
    )


def validate_csrf_or_abort():
    if request.method in {"GET", "HEAD", "OPTIONS", "TRACE"}:
        return
    expected = session.get(CSRF_SESSION_KEY)
    provided = _request_csrf_token()
    if not expected or not provided or not compare_digest(expected, provided):
        abort(400, description="CSRF token missing or invalid")
