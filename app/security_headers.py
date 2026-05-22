"""Security headers, CSP nonce, and template helpers.

Extracted from the app factory (``app/__init__.py``) so the factory stays
small and each concern is independently auditable. ``register_security_headers``
wires up:

  * a per-request CSP nonce (``g.csp_nonce``);
  * the security response headers (CSP, X-Frame-Options, HSTS, …);
  * the ``csp_nonce`` / ``static_v`` template helpers.
"""

import hashlib
import os

from flask import g, request, url_for


def register_security_headers(app):
    # Content-Security-Policy. Strict mode drops `'unsafe-inline'` and instead
    # allows inline `<script nonce="...">` / `<style nonce="...">` blocks via a
    # per-request CSP nonce.
    #
    # Fv11 review §P1-02: strict CSP is the production default. Operators who
    # need the relaxed policy (e.g. while migrating remaining inline blocks)
    # can set SS_STRICT_CSP=0 explicitly. Debug runs default to relaxed so the
    # Flask debugger's inline scripts keep working.
    _csp_env = os.environ.get("SS_STRICT_CSP", "").strip().lower()
    if _csp_env in {"1", "true", "yes", "on"}:
        strict_csp = True
    elif _csp_env in {"0", "false", "no", "off"}:
        strict_csp = False
    else:
        strict_csp = not app.debug

    @app.before_request
    def _gen_csp_nonce():
        import secrets
        g.csp_nonce = secrets.token_urlsafe(16)

    def _build_csp(nonce: str) -> str:
        if strict_csp:
            script_src = f"'self' 'nonce-{nonce}'"
            style_src  = f"'self' 'nonce-{nonce}'"
        else:
            script_src = "'self' 'unsafe-inline'"
            style_src  = "'self' 'unsafe-inline'"
        return (
            "default-src 'self'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            f"style-src {style_src}; "
            f"script-src {script_src}; "
            "connect-src 'self'; "
            "frame-ancestors 'self'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )

    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers.setdefault(
            "Content-Security-Policy",
            _build_csp(getattr(g, "csp_nonce", "")),
        )
        # Only add HSTS on HTTPS responses
        if request.is_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    # Per-file hash cache for cache-busting `?v=` query params on static
    # assets. Built lazily on first request for each path; never re-hashed
    # within a single process.
    _static_v_cache: dict = {}
    _static_root = app.static_folder or ""

    @app.context_processor
    def _inject_template_helpers():
        def csp_nonce() -> str:
            return getattr(g, "csp_nonce", "")

        def static_v(path: str) -> str:
            cached = _static_v_cache.get(path)
            if cached is None:
                full = os.path.join(_static_root, path)
                try:
                    with open(full, "rb") as fh:
                        cached = hashlib.md5(fh.read()).hexdigest()[:8]
                except OSError:
                    cached = ""
                _static_v_cache[path] = cached
            if cached:
                return url_for("static", filename=path, v=cached)
            return url_for("static", filename=path)

        return {"csp_nonce": csp_nonce, "static_v": static_v}
