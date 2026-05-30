"""Captive-portal / content-policy request interception.

Extracted from the app factory. When content policy or the captive portal is
active, Unbound returns the appliance LAN IP for blocked/unauthenticated
domains; the browser then connects here with ``Host: <blocked-domain>``. This
middleware catches those requests and redirects to the portal / block page.
"""

import ipaddress
import socket
from urllib.parse import urlencode

from flask import redirect, request, session

from app.audit_log import log_event


def _dns_bypass_for_admin(conn) -> bool:
    """True when captive_portal_settings.dns_bypass_for_admin is enabled.

    When set, admin_bypass_clients reach upstream DNS directly (PF emits a
    `no rdr` for them), so their browser resolves blocked domains to the real
    IP and never lands on the middleware. Off by default — see
    app/services/captive_portal.py::generate_pf_anchor.
    """
    try:
        import json as _j
        row = conn.execute(
            "SELECT value_json FROM service_state WHERE key_name='captive_portal_settings'"
        ).fetchone()
        cfg = _j.loads(row["value_json"]) if row and row["value_json"] else {}
        return bool(cfg.get("dns_bypass_for_admin", False))
    except Exception:
        return False


def register_captive_middleware(app):
    @app.before_request
    def _intercept_content_filter_blocked():
        # Logged-in admin sessions pass straight through
        if session.get("user_id"):
            return None

        # Portal, static assets, auth, and setup routes are always reachable
        if request.path.startswith(
            ("/portal", "/static", "/login", "/logout", "/setup")
        ):
            return None

        # Extract bare hostname from the Host header (strip port)
        raw_host = request.headers.get("Host") or ""
        host = raw_host.split(":")[0].strip().lower()
        if not host:
            return None

        # Direct IP access (e.g. http://192.168.1.1/) — not a DNS redirect
        try:
            ipaddress.ip_address(host)
            return None
        except ValueError:
            pass

        # Our own device hostname — not a DNS redirect
        try:
            own = {"localhost", socket.gethostname().lower(), socket.getfqdn().lower()}
            if host in own:
                return None
        except Exception:
            pass

        try:
            from app.database import get_db
            from app.services.content_policy import (
                has_active_captive_session,
                has_active_content_policy,
                is_admin_bypass_session,
                is_blocked_domain,
                is_device_whitelisted,
            )

            conn = get_db()

            # ── Captive portal mode ───────────────────────────────────────────────
            # When captive portal is enabled, every HTTP request that arrives here
            # with a non-local Host header was PF-redirected from an unauthenticated
            # client on port 80.  Send them to the portal login page.  This also
            # covers OS captive-portal probes (Firefox detectportal, Chrome 204,
            # Apple CNA) so browsers show a "Sign in to network" popup automatically.
            import json as _cp_json
            from app.services.captive_portal import _default_portal_ip
            _cp_row = conn.execute(
                "SELECT value_json FROM service_state WHERE key_name='captive_portal_settings'"
            ).fetchone()
            if _cp_row:
                _cp_cfg = _cp_json.loads(_cp_row["value_json"])
                if _cp_cfg.get("enabled", False):
                    if not has_active_captive_session(conn, request.remote_addr or ""):
                        _portal_ip = (_cp_cfg.get("portal_ip") or _default_portal_ip(conn)).strip()
                        _query = urlencode({"url": request.url})
                        return redirect(f"http://{_portal_ip}/portal/?{_query}")
                    # Client is authenticated — fall through to content-policy check

            if not has_active_content_policy(conn):
                return None

            _ip = request.remote_addr or ""

            # P.4: admin-bypass only earns a clean pass-through when DNS bypass
            # is actually in effect for the client (dns_bypass_for_admin). With
            # it, the browser resolves the domain upstream and reaches the real
            # site, so the middleware won't see the request anyway. Without it,
            # DNS still points the client at the LAN IP, so returning None makes
            # Flask answer Host:<blocked-domain> with no matching route -> 404.
            # In that case we fall through to the normal block-page redirect so
            # the admin sees the (P.1) block page instead of a dead 404.
            if is_admin_bypass_session(conn, _ip):
                if _dns_bypass_for_admin(conn):
                    return None
                if not is_blocked_domain(conn, host):
                    return None
                # blocked domain + no DNS bypass → fall through to redirect.
            elif is_device_whitelisted(conn, _ip):
                # Device whitelist == captive-portal bypass only; content policy
                # still applies (see is_device_whitelisted docstring). Same 404
                # trap as admin-bypass, so only pass through non-blocked hosts.
                if not is_blocked_domain(conn, host):
                    return None
            # The bridge.html branch is for authenticated NON-admin clients. An
            # admin-bypass session is also a captive session, but it must not
            # loop through bridge.html (no DNS exemption in this mode) — let it
            # fall through to the block-page redirect instead (P.4).
            if (has_active_captive_session(conn, _ip)
                    and not is_admin_bypass_session(conn, _ip)):
                if is_blocked_domain(conn, host):
                    # Authenticated user hitting a DNS-blocked domain — record
                    # the block so it shows up in the firewall logs and SOC.
                    try:
                        from app.services.content_policy import explain_domain_policy
                        policy = explain_domain_policy(conn, host) or {}
                    except Exception:
                        policy = {}
                    try:
                        log_event(
                            category="security", action="content_policy_block",
                            severity="medium",
                            username=session.get("username", "anonymous"),
                            remote_addr=request.remote_addr,
                            details={
                                "domain":         host,
                                "matched_domain": policy.get("domain", host),
                                "policy_source":  policy.get("source", ""),
                                "policy_action":  policy.get("action", ""),
                                "rule_id":        policy.get("rule_id"),
                                "category":       policy.get("category", ""),
                                "url":            (request.url or "")[:500],
                                "user_agent":     (request.user_agent.string or "")[:200] if request.user_agent else "",
                                "authenticated":  True,
                            },
                        )
                    except Exception:
                        pass
                    # Render a one-shot redirect after 3 s (lets the 5 s Unbound TTL expire).
                    # sessionStorage prevents an auto-retry loop on repeated visits —
                    # if DNS still returns LAN IP the user gets a manual "Open" button.
                    from flask import render_template as _render
                    orig_url = request.url
                    return _render(
                        "portal/bridge.html",
                        host=host,
                        orig_url=orig_url,
                        ss_key=f"ss_bridge_{host}",
                    )
                return None
            if not is_blocked_domain(conn, host):
                return None
        except Exception as _exc:
            import logging as _log
            _log.getLogger(__name__).debug(
                "_intercept_content_filter_blocked error: %s", _exc, exc_info=True
            )
            return None

        # Unauthenticated client hitting a content-policy block — record before
        # redirecting them to the portal so SOC analysts can see the attempt.
        try:
            from app.services.content_policy import explain_domain_policy
            policy = explain_domain_policy(conn, host) or {}
        except Exception:
            policy = {}
        try:
            log_event(
                category="security", action="content_policy_block",
                severity="medium",
                username=session.get("username", "anonymous"),
                remote_addr=request.remote_addr,
                details={
                    "domain":         host,
                    "matched_domain": policy.get("domain", host),
                    "policy_source":  policy.get("source", ""),
                    "policy_action":  policy.get("action", ""),
                    "rule_id":        policy.get("rule_id"),
                    "category":       policy.get("category", ""),
                    "url":            (request.url or "")[:500],
                    "user_agent":     (request.user_agent.string or "")[:200] if request.user_agent else "",
                    "authenticated":  False,
                },
            )
        except Exception:
            pass

        query = urlencode({"policy": "content", "domain": host, "url": request.url})
        # Redirect directly to the captive portal (standard hotel/airport WiFi pattern).
        # This avoids the popup-opener approach and works reliably across browsers.
        try:
            import json as _json
            from app.services.captive_portal import _default_portal_ip
            _cp_row = conn.execute(
                "SELECT value_json FROM service_state WHERE key_name='captive_portal_settings'"
            ).fetchone()
            _cp_cfg = _json.loads(_cp_row["value_json"]) if _cp_row else {}
            _portal_ip = (_cp_cfg.get("portal_ip") or _default_portal_ip(conn) or "").strip()
            portal_url = f"http://{_portal_ip}/portal/block?{query}" if _portal_ip else f"/portal/block?{query}"
        except Exception:
            portal_url = f"/portal/block?{query}"

        return redirect(portal_url)
