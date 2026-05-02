"""
tests/test_abusech_client.py
----------------------------
Unit tests for the abuse.ch threat intelligence client.

All tests use the fake key ABUSECH_AUTH_KEY=test_key_123.
The real key is never referenced here.  HTTP calls are mocked so tests run
offline and never touch the live abuse.ch API.
"""

import os
from unittest.mock import MagicMock, patch

import pytest

FAKE_KEY = "test_key_123"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _inject_fake_key(monkeypatch):
    """Set a fake key for every test; disable dry-run by default."""
    monkeypatch.setenv("ABUSECH_AUTH_KEY", FAKE_KEY)
    monkeypatch.setenv("ABUSECH_DRY_RUN", "0")


@pytest.fixture()
def dry_run(monkeypatch):
    """Switch a single test into dry-run mode."""
    monkeypatch.setenv("ABUSECH_DRY_RUN", "1")


def _mock_response(data: dict) -> MagicMock:
    resp = MagicMock()
    resp.json.return_value = data
    resp.raise_for_status.return_value = None
    return resp


# ---------------------------------------------------------------------------
# 1. Key is loaded from the environment
# ---------------------------------------------------------------------------

def test_get_auth_key_reads_env():
    from app.services.abusech_client import _get_auth_key
    assert _get_auth_key() == FAKE_KEY


def test_missing_key_raises_with_clear_message(monkeypatch):
    monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)
    from app.services.abusech_client import _get_auth_key
    with pytest.raises(RuntimeError, match="ABUSECH_AUTH_KEY is required for abuse.ch API access"):
        _get_auth_key()


def test_empty_key_raises_with_clear_message(monkeypatch):
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "   ")
    from app.services.abusech_client import _get_auth_key
    with pytest.raises(RuntimeError, match="ABUSECH_AUTH_KEY is required for abuse.ch API access"):
        _get_auth_key()


# ---------------------------------------------------------------------------
# 2. Auth-Key header is sent on every API family
# ---------------------------------------------------------------------------

def test_auth_key_header_urlhaus_host():
    from app.services import abusech_client
    with patch("app.services.abusech_client.requests.post") as mock_post:
        mock_post.return_value = _mock_response({"query_status": "is_host"})
        abusech_client.urlhaus_lookup_host("evil.example.com")
        _, kwargs = mock_post.call_args
        assert kwargs["headers"]["Auth-Key"] == FAKE_KEY


def test_auth_key_header_urlhaus_url():
    from app.services import abusech_client
    with patch("app.services.abusech_client.requests.post") as mock_post:
        mock_post.return_value = _mock_response({"query_status": "no_results"})
        abusech_client.urlhaus_lookup_url("http://evil.example.com/payload")
        _, kwargs = mock_post.call_args
        assert kwargs["headers"]["Auth-Key"] == FAKE_KEY


def test_auth_key_header_urlhaus_recent():
    from app.services import abusech_client
    with patch("app.services.abusech_client.requests.post") as mock_post:
        mock_post.return_value = _mock_response({"query_status": "ok", "urls": []})
        abusech_client.urlhaus_recent(limit=5)
        _, kwargs = mock_post.call_args
        assert kwargs["headers"]["Auth-Key"] == FAKE_KEY


def test_auth_key_header_malwarebazaar_hash():
    from app.services import abusech_client
    with patch("app.services.abusech_client.requests.post") as mock_post:
        mock_post.return_value = _mock_response({"query_status": "hash_not_found"})
        abusech_client.malwarebazaar_lookup_hash("aabbcc112233")
        _, kwargs = mock_post.call_args
        assert kwargs["headers"]["Auth-Key"] == FAKE_KEY


def test_auth_key_header_malwarebazaar_recent():
    from app.services import abusech_client
    with patch("app.services.abusech_client.requests.post") as mock_post:
        mock_post.return_value = _mock_response({"query_status": "ok", "data": []})
        abusech_client.malwarebazaar_recent()
        _, kwargs = mock_post.call_args
        assert kwargs["headers"]["Auth-Key"] == FAKE_KEY


def test_auth_key_header_threatfox_search():
    from app.services import abusech_client
    with patch("app.services.abusech_client.requests.post") as mock_post:
        mock_post.return_value = _mock_response({"query_status": "no_results"})
        abusech_client.threatfox_search_ioc("1.2.3.4")
        _, kwargs = mock_post.call_args
        assert kwargs["headers"]["Auth-Key"] == FAKE_KEY


def test_auth_key_header_threatfox_recent():
    from app.services import abusech_client
    with patch("app.services.abusech_client.requests.post") as mock_post:
        mock_post.return_value = _mock_response({"query_status": "ok", "data": {}})
        abusech_client.threatfox_recent_iocs(days=1)
        _, kwargs = mock_post.call_args
        assert kwargs["headers"]["Auth-Key"] == FAKE_KEY


# ---------------------------------------------------------------------------
# 3. Dry-run mode: no HTTP call, clear marker in response
# ---------------------------------------------------------------------------

def test_dry_run_urlhaus_url_no_http(dry_run):
    from app.services import abusech_client
    with patch("app.services.abusech_client.requests.post") as mock_post:
        result = abusech_client.urlhaus_lookup_url("http://evil.example.com/x")
        mock_post.assert_not_called()
        assert result["query_status"] == "dry_run"


def test_dry_run_urlhaus_host_no_http(dry_run):
    from app.services import abusech_client
    with patch("app.services.abusech_client.requests.post") as mock_post:
        result = abusech_client.urlhaus_lookup_host("evil.example.com")
        mock_post.assert_not_called()
        assert result["query_status"] == "dry_run"


def test_dry_run_urlhaus_recent_no_http(dry_run):
    from app.services import abusech_client
    with patch("app.services.abusech_client.requests.post") as mock_post:
        result = abusech_client.urlhaus_recent()
        mock_post.assert_not_called()
        assert result["query_status"] == "dry_run"


def test_dry_run_malwarebazaar_hash_no_http(dry_run):
    from app.services import abusech_client
    with patch("app.services.abusech_client.requests.post") as mock_post:
        result = abusech_client.malwarebazaar_lookup_hash("deadbeef")
        mock_post.assert_not_called()
        assert result["query_status"] == "dry_run"


def test_dry_run_malwarebazaar_recent_no_http(dry_run):
    from app.services import abusech_client
    with patch("app.services.abusech_client.requests.post") as mock_post:
        result = abusech_client.malwarebazaar_recent()
        mock_post.assert_not_called()
        assert result["query_status"] == "dry_run"


def test_dry_run_threatfox_search_no_http(dry_run):
    from app.services import abusech_client
    with patch("app.services.abusech_client.requests.post") as mock_post:
        result = abusech_client.threatfox_search_ioc("evil.example.com")
        mock_post.assert_not_called()
        assert result["query_status"] == "dry_run"


def test_dry_run_threatfox_recent_no_http(dry_run):
    from app.services import abusech_client
    with patch("app.services.abusech_client.requests.post") as mock_post:
        result = abusech_client.threatfox_recent_iocs()
        mock_post.assert_not_called()
        assert result["query_status"] == "dry_run"


def test_dry_run_does_not_require_key(monkeypatch):
    """Dry-run returns early before _get_auth_key() is called, so no key needed."""
    monkeypatch.setenv("ABUSECH_DRY_RUN", "1")
    monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)
    from app.services import abusech_client
    result = abusech_client.urlhaus_lookup_host("example.com")
    assert result["query_status"] == "dry_run"


# ---------------------------------------------------------------------------
# 4. Real key never appears in logs
# ---------------------------------------------------------------------------

def test_key_not_logged_during_live_request(tmp_path, monkeypatch):
    log_path = str(tmp_path / "app.log")
    monkeypatch.setenv("SMARTSHIELD_APP_LOG_PATH", log_path)

    from app.services import abusech_client
    with patch("app.services.abusech_client.requests.post") as mock_post:
        mock_post.return_value = _mock_response({"query_status": "is_host"})
        abusech_client.urlhaus_lookup_host("example.com")

    if os.path.exists(log_path):
        content = open(log_path, encoding="utf-8").read()
        assert FAKE_KEY not in content, "Auth-Key value must never appear in log output"


def test_key_not_logged_during_error(tmp_path, monkeypatch):
    import requests as _requests
    log_path = str(tmp_path / "app.log")
    monkeypatch.setenv("SMARTSHIELD_APP_LOG_PATH", log_path)

    from app.services import abusech_client
    with patch("app.services.abusech_client.requests.post") as mock_post:
        mock_post.side_effect = _requests.ConnectionError("connection refused")
        with pytest.raises(_requests.ConnectionError):
            abusech_client.urlhaus_lookup_host("example.com")

    if os.path.exists(log_path):
        content = open(log_path, encoding="utf-8").read()
        assert FAKE_KEY not in content, "Auth-Key must not appear in error log output"


def test_key_not_in_dry_run_logs(tmp_path, monkeypatch):
    monkeypatch.setenv("ABUSECH_DRY_RUN", "1")
    log_path = str(tmp_path / "app.log")
    monkeypatch.setenv("SMARTSHIELD_APP_LOG_PATH", log_path)

    from app.services import abusech_client
    abusech_client.urlhaus_lookup_host("example.com")

    if os.path.exists(log_path):
        content = open(log_path, encoding="utf-8").read()
        assert FAKE_KEY not in content, "Auth-Key must not appear in dry-run log output"
