"""
app/services/abusech_client.py
------------------------------
Abuse.ch threat intelligence client for Smart Shield.

Provides authenticated access to URLhaus, MalwareBazaar, and ThreatFox
using the Auth-Key request header.  Defaults to dry-run mode — no live
HTTP calls are made until ABUSECH_DRY_RUN=0 is explicitly set.

Environment variables
---------------------
ABUSECH_AUTH_KEY  Required. Personal Auth-Key from abuse.ch.
ABUSECH_DRY_RUN   Set to "0" to enable live API calls (default: "1").
"""

import os

import requests

from app.app_log import log_error, log_info

_URLHAUS_BASE   = "https://urlhaus-api.abuse.ch/v1"
_MWBAZAAR_BASE  = "https://mb-api.abuse.ch/api/v1"
_THREATFOX_BASE = "https://threatfox-api.abuse.ch/api/v1"

_TIMEOUT = 10  # seconds


def _get_auth_key() -> str:
    """Return the abuse.ch Auth-Key, checking env then the database."""
    key = os.getenv("ABUSECH_AUTH_KEY", "").strip()
    if key:
        return key
    # Fall back to the key stored via the web UI (encrypted in ids_threat_feeds).
    try:
        from app.database import get_db
        from app.secret_store import decrypt_secret
        row = get_db().execute(
            "SELECT abusech_auth_key FROM ids_threat_feeds WHERE id=1"
        ).fetchone()
        if row and row["abusech_auth_key"]:
            key = decrypt_secret(row["abusech_auth_key"]).strip()
            if key:
                return key
    except Exception:
        pass
    raise RuntimeError(
        "ABUSECH_AUTH_KEY is required for abuse.ch API access. "
        "Set it in your .env file or add it via IDS → Threat Feeds in the web UI."
    )


def is_dry_run() -> bool:
    """Return True when ABUSECH_DRY_RUN is unset or any value except '0'."""
    return os.getenv("ABUSECH_DRY_RUN", "1") != "0"


def _auth_headers() -> dict:
    return {"Auth-Key": _get_auth_key()}


def _post_form(url: str, data: dict) -> dict:
    """Authenticated form-encoded POST; returns parsed JSON."""
    log_info("abusech", f"POST {url}", {"has_auth_key": True})
    try:
        resp = requests.post(url, data=data, headers=_auth_headers(), timeout=_TIMEOUT)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as exc:
        log_error("abusech", f"Request failed: {url}", {"error": str(exc)})
        raise


def _post_json_req(url: str, payload: dict) -> dict:
    """Authenticated JSON POST; returns parsed JSON."""
    log_info("abusech", f"POST {url}", {"has_auth_key": True})
    headers = {**_auth_headers(), "Content-Type": "application/json"}
    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=_TIMEOUT)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as exc:
        log_error("abusech", f"Request failed: {url}", {"error": str(exc)})
        raise


# ---------------------------------------------------------------------------
# URLhaus
# ---------------------------------------------------------------------------

def urlhaus_lookup_url(url_to_check: str) -> dict:
    """Look up a URL in URLhaus. Returns the API response dict."""
    if is_dry_run():
        log_info("abusech.urlhaus", "dry-run: skipping URL lookup", {"url": url_to_check})
        return {"query_status": "dry_run"}
    return _post_form(f"{_URLHAUS_BASE}/url/", {"url": url_to_check})


def urlhaus_lookup_host(host: str) -> dict:
    """Look up a hostname or IP address in URLhaus."""
    if is_dry_run():
        log_info("abusech.urlhaus", "dry-run: skipping host lookup", {"host": host})
        return {"query_status": "dry_run"}
    return _post_form(f"{_URLHAUS_BASE}/host/", {"host": host})


def urlhaus_recent(limit: int = 20) -> dict:
    """Fetch recently submitted malicious URLs from URLhaus."""
    if is_dry_run():
        log_info("abusech.urlhaus", "dry-run: skipping recent URL fetch", {"limit": limit})
        return {"query_status": "dry_run", "urls": []}
    return _post_form(f"{_URLHAUS_BASE}/urls/recent/", {"limit": str(limit)})


# ---------------------------------------------------------------------------
# MalwareBazaar
# ---------------------------------------------------------------------------

def malwarebazaar_lookup_hash(file_hash: str) -> dict:
    """Query MalwareBazaar for a file hash (MD5 / SHA-1 / SHA-256)."""
    if is_dry_run():
        log_info("abusech.malwarebazaar", "dry-run: skipping hash lookup", {"hash": file_hash})
        return {"query_status": "dry_run"}
    return _post_json_req(f"{_MWBAZAAR_BASE}/", {"query": "get_info", "hash": file_hash})


def malwarebazaar_recent(selector: str = "time", limit: int = 100) -> dict:
    """Fetch recently submitted samples from MalwareBazaar."""
    if is_dry_run():
        log_info("abusech.malwarebazaar", "dry-run: skipping recent samples fetch", {"limit": limit})
        return {"query_status": "dry_run", "data": []}
    return _post_json_req(
        f"{_MWBAZAAR_BASE}/",
        {"query": "get_recent", "selector": selector, "limit": limit},
    )


# ---------------------------------------------------------------------------
# ThreatFox
# ---------------------------------------------------------------------------

def threatfox_search_ioc(search_term: str) -> dict:
    """Search ThreatFox for an IOC (IP, domain, URL, or file hash)."""
    if is_dry_run():
        log_info("abusech.threatfox", "dry-run: skipping IOC search", {"search_term": search_term})
        return {"query_status": "dry_run"}
    return _post_json_req(f"{_THREATFOX_BASE}/", {"query": "search_ioc", "search_term": search_term})


def threatfox_recent_iocs(days: int = 1) -> dict:
    """Fetch recent IOCs from ThreatFox."""
    if is_dry_run():
        log_info("abusech.threatfox", "dry-run: skipping recent IOC fetch", {"days": days})
        return {"query_status": "dry_run", "data": {}}
    return _post_json_req(f"{_THREATFOX_BASE}/", {"query": "get_iocs", "days": days})
