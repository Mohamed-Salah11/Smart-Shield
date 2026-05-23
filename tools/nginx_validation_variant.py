#!/usr/bin/env python3
"""
nginx_validation_variant.py — rewrite an nginx.conf so `nginx -t` can validate
it without actually binding the LAN IP (which is not yet assigned during
install). Reads stdin, writes the validation-safe variant to stdout.

The real logic lives in app.services.nginx_writer._to_validation_variant —
this CLI exists so bsd/install.sh can share that one regex instead of
maintaining a parallel sed pipeline that misses `default_server` lines.
"""

from __future__ import annotations

import os
import re
import sys


def _fallback_rewrite(text: str) -> str:
    """Inline copy of app.services.nginx_writer._to_validation_variant for
    the case where the import path is not yet ready (installer runs before
    venv site-packages may be importable)."""
    listen_re = re.compile(
        r"^(?P<lead>\s*)listen\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<port>\d+)(?P<rest>.*?);",
        re.MULTILINE,
    )
    seen: dict[int, int] = {}

    def _swap(m: "re.Match[str]") -> str:
        # Keep every substitute on 127.0.0.1 (the only address FreeBSD binds to
        # lo0 by default) and make repeated listens unique by port. Incrementing
        # the last octet instead (127.0.0.2, …) failed with EADDRNOTAVAIL on the
        # second listen during `nginx -t`.
        port = int(m.group("port"))
        base = {80: 8080, 443: 8443}.get(port, port + 8000)
        seen[base] = seen.get(base, -1) + 1
        return f'{m.group("lead")}listen 127.0.0.1:{base + seen[base]}{m.group("rest")};'

    return listen_re.sub(_swap, text)


def _rewrite(text: str) -> str:
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)
    try:
        from app.services.nginx_writer import _to_validation_variant
        return _to_validation_variant(text)
    except Exception:
        return _fallback_rewrite(text)


def main() -> int:
    sys.stdout.write(_rewrite(sys.stdin.read()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
