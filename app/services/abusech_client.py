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
    """Return the abuse.ch Auth-Key if configured.

    Raises RuntimeError when no key is available so callers fail fast
    rather than silently sending unauthenticated requests.
    """
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
    raise RuntimeError("ABUSECH_AUTH_KEY is required for abuse.ch API access")


def is_dry_run(conn=None) -> bool:
    """Return True when live API calls should be suppressed.

    Checks the DB column first (GUI-controlled), falls back to the env var
    (set by install.sh or overridden manually).
    """
    if conn is None:
        try:
            from app.database import get_db
            conn = get_db()
        except Exception:
            pass
    if conn is not None:
        try:
            row = conn.execute(
                "SELECT abusech_dry_run FROM ids_threat_feeds WHERE id=1"
            ).fetchone()
            if row is not None:
                return bool(row["abusech_dry_run"])
        except Exception:
            pass
    return os.getenv("ABUSECH_DRY_RUN", "1") != "0"


def _auth_headers() -> dict:
    key = _get_auth_key()
    return {"Auth-Key": key} if key else {}


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
    # MalwareBazaar API v1 expects form-encoded data, not JSON
    return _post_form(f"{_MWBAZAAR_BASE}/", {"query": "get_info", "hash": file_hash})


def malwarebazaar_recent(selector: str = "time", limit: int = 100) -> dict:
    """Fetch recently submitted samples from MalwareBazaar."""
    if is_dry_run():
        log_info("abusech.malwarebazaar", "dry-run: skipping recent samples fetch", {"limit": limit})
        return {"query_status": "dry_run", "data": []}
    # MalwareBazaar API v1 expects form-encoded data, not JSON
    return _post_form(
        f"{_MWBAZAAR_BASE}/",
        {"query": "get_recent", "selector": selector, "limit": str(limit)},
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


# ---------------------------------------------------------------------------
# Threat intel PF table push
# ---------------------------------------------------------------------------

_TI_IOC_PATH    = "/var/db/smart-shield/threat_intel_ips.txt"
_TI_PF_TABLE    = "ss_threat_intel"
_TI_STATE_KEY   = "threat_intel_last_update"
_TI_UPDATE_SECS = 3600 * 4   # re-fetch every 4 hours by default


def _extract_ips_from_iocs(data: dict) -> list:
    """
    Parse IPs from a ThreatFox ``get_iocs`` response.
    Returns a deduplicated list of IPv4/IPv6 address strings.
    """
    import ipaddress
    ips = set()
    iocs = data.get("data") or {}
    # data is either a list or a dict keyed by IOC id
    if isinstance(iocs, dict):
        iocs = list(iocs.values())
    for ioc in iocs:
        if not isinstance(ioc, dict):
            continue
        ioc_type = (ioc.get("ioc_type") or "").lower()
        value    = (ioc.get("ioc") or "").strip()
        if ioc_type in ("ip:port", "ip"):
            # Strip port component if present (e.g. "1.2.3.4:8080" → "1.2.3.4")
            host = value.split(":")[0] if ":" in value else value
            try:
                ipaddress.ip_address(host)
                ips.add(host)
            except ValueError:
                pass
    return sorted(ips)


def push_threat_intel_to_pf(conn) -> dict:
    """
    Push stored threat-intel IPs to the PF table ``ss_threat_intel``.

    Reads the IP list from the siem_state row written by ``update_threat_feed``,
    writes them to ``/var/db/smart-shield/threat_intel_ips.txt``, then calls
    ``pfctl -t ss_threat_intel -T replace -f <file>`` atomically.

    On non-FreeBSD: no-op, returns ok=True with count.
    """
    import json as _json
    try:
        row = conn.execute(
            "SELECT value FROM siem_state WHERE key=?", (_TI_STATE_KEY + "_ips",)
        ).fetchone()
        ips: list = _json.loads(row["value"]) if row else []
    except Exception:
        ips = []

    count = len(ips)
    if not ips:
        return {"ok": True, "count": 0, "message": "No threat-intel IPs to push."}

    import sys as _sys
    if not _sys.platform.startswith("freebsd"):
        return {"ok": True, "count": count, "message": f"Non-FreeBSD — {count} IPs would be pushed to PF."}

    try:
        import os as _os
        _os.makedirs("/var/db/smart-shield", exist_ok=True)
        with open(_TI_IOC_PATH, "w") as fh:
            fh.write("\n".join(ips) + "\n")

        from app.services.priv_helper import run_privileged
        result = run_privileged(
            "pf.table_replace_file",
            table=_TI_PF_TABLE,
            file_path=_TI_IOC_PATH,
        )
        if result.returncode != 0:
            return {
                "ok": False,
                "count": count,
                "message": f"pfctl table replace failed: {(result.stderr or result.stdout or '').strip()}",
            }
        return {"ok": True, "count": count, "message": f"Pushed {count} threat-intel IPs to PF table {_TI_PF_TABLE}."}
    except Exception as exc:
        return {"ok": False, "count": 0, "message": str(exc)}


def update_threat_feed(conn) -> dict:
    """
    Fetch recent IOCs from ThreatFox, persist the extracted IPs in siem_state,
    and push them to the PF table.

    Returns {"ok": bool, "count": int, "message": str}.
    """
    import json as _json
    import time as _time

    if is_dry_run(conn):
        return {"ok": True, "count": 0, "message": "Threat feed update skipped (dry-run)."}

    try:
        data = threatfox_recent_iocs(days=1)
    except Exception as exc:
        return {"ok": False, "count": 0, "message": f"ThreatFox API error: {exc}"}

    ips   = _extract_ips_from_iocs(data)
    count = len(ips)

    # Persist extracted IPs and update timestamp
    now_str = str(int(_time.time()))
    try:
        for key, val in [
            (_TI_STATE_KEY + "_ips",  _json.dumps(ips)),
            (_TI_STATE_KEY + "_ts",   now_str),
            (_TI_STATE_KEY + "_count", str(count)),
        ]:
            conn.execute(
                "INSERT INTO siem_state (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)"
                " ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=CURRENT_TIMESTAMP",
                (key, val),
            )
        conn.commit()
    except Exception:
        pass

    push_result = push_threat_intel_to_pf(conn)
    return {
        "ok": push_result["ok"],
        "count": count,
        "message": f"Fetched {count} IPs from ThreatFox. " + push_result.get("message", ""),
    }


def get_threat_intel_status(conn) -> dict:
    """Return summary of the last threat feed update."""
    import time as _time
    try:
        row_ts  = conn.execute("SELECT value FROM siem_state WHERE key=?", (_TI_STATE_KEY + "_ts",)).fetchone()
        row_cnt = conn.execute("SELECT value FROM siem_state WHERE key=?", (_TI_STATE_KEY + "_count",)).fetchone()
        last_ts = int(row_ts["value"]) if row_ts else 0
        count   = int(row_cnt["value"]) if row_cnt else 0
    except Exception:
        last_ts, count = 0, 0

    age_s = int(_time.time()) - last_ts if last_ts else None
    return {
        "last_updated_ts": last_ts,
        "age_seconds":     age_s,
        "indicator_count": count,
        "pf_table":        _TI_PF_TABLE,
        "dry_run":         is_dry_run(conn),
    }


# ---------------------------------------------------------------------------
# Background scheduler thread
# ---------------------------------------------------------------------------

_TI_STARTED = __import__("threading").Event()


def start_threat_intel_collector() -> None:
    """
    Start a background daemon thread that refreshes the threat-intel feed
    every ``_TI_UPDATE_SECS`` seconds.  Safe to call multiple times — only
    the first call starts the thread.
    """
    import sys as _sys
    import threading as _threading
    import time as _time

    if _TI_STARTED.is_set():
        return
    _TI_STARTED.set()

    def _worker():
        # Initial delay so app startup isn't slowed down
        _time.sleep(30)
        while True:
            try:
                from app.database import get_db
                _conn = get_db()
                update_threat_feed(_conn)
            except Exception:
                pass
            _time.sleep(_TI_UPDATE_SECS)

    t = _threading.Thread(target=_worker, daemon=True, name="threat-intel-collector")
    t.start()
