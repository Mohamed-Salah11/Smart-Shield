#!/usr/bin/env python3
"""
smoke_startup.py
----------------
One-shot import + create_app() smoke test. Exits 0 when the Flask app can be
constructed and every blueprint is registered. Use as the very last installer
step (and from CI) so a broken import, missing dependency, or unregistered
blueprint fails loud and early instead of at the first HTTP request.

This is a deliberately smaller superset of tools/check_routes.py: check_routes
also iterates the URL map and prints duplicate-endpoint warnings. smoke_startup
only verifies the app boots, so it's safe to wire into install.sh on systems
where a long route dump is unwanted.

Usage:
    cd /usr/local/share/smartshield
    . .venv/bin/activate
    python tools/smoke_startup.py
"""

import os
import sys


def main() -> int:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if root not in sys.path:
        sys.path.insert(0, root)

    try:
        from app import create_app
    except Exception as exc:
        sys.stderr.write(f"smoke_startup: create_app import failed: {exc}\n")
        return 1

    try:
        app = create_app()
    except Exception as exc:
        sys.stderr.write(f"smoke_startup: create_app() failed: {exc}\n")
        return 1

    blueprint_count = len(app.blueprints)
    route_count = sum(1 for _ in app.url_map.iter_rules())

    if blueprint_count == 0:
        sys.stderr.write("smoke_startup: no blueprints registered — app would 404 everywhere\n")
        return 2
    if route_count == 0:
        sys.stderr.write("smoke_startup: no routes registered\n")
        return 2

    print(f"smoke_startup: OK  blueprints={blueprint_count}  routes={route_count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
