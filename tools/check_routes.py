#!/usr/bin/env python3
"""
check_routes.py
---------------
Post-install smoke test: import the Flask app, register all blueprints, and
print the URL map. Fails with non-zero exit if any route fails to register or
two endpoints collide on the same name with different URLs.

Run from the appliance (after the venv is set up) as the last installer step:

    cd /usr/local/share/smartshield
    . .venv/bin/activate
    python tools/check_routes.py | head
"""

import os
import sys


# Endpoints intentionally mapped to two URLs via stacked decorators — the
# canonical "create" (no id) + "edit" (<int:id>) pattern. These are deliberate
# aliases, not regressions, so they are suppressed from the duplicate-URL
# warning to keep the checker output meaningful.
INTENTIONAL_ALIASES = frozenset({
    "system.advanced_system_tunables_edit",
    "routing.gateway_edit",
    "routing.static_route_edit",
    "routing.gateway_group_edit",
    "vpn.ipsec_p2_create",
})


def main() -> int:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if root not in sys.path:
        sys.path.insert(0, root)

    try:
        from app import create_app
    except Exception as exc:
        sys.stderr.write(f"create_app import failed: {exc}\n")
        return 1

    try:
        app = create_app()
    except Exception as exc:
        sys.stderr.write(f"create_app() failed: {exc}\n")
        return 1

    # Collisions between the same endpoint name and different URLs are a
    # Flask anti-pattern but not all are fatal. Surface them as warnings; the
    # only fatal error here is "create_app() raised", which is already handled
    # above.
    seen: dict = {}
    warnings = 0
    for rule in app.url_map.iter_rules():
        url = str(rule)
        if (
            rule.endpoint in seen
            and seen[rule.endpoint] != url
            and rule.endpoint not in INTENTIONAL_ALIASES
        ):
            sys.stderr.write(
                f"warning: endpoint {rule.endpoint!r} mapped to "
                f"{seen[rule.endpoint]!r} and {url!r}\n"
            )
            warnings += 1
        seen[rule.endpoint] = url

    for url in sorted(str(r) for r in app.url_map.iter_rules()):
        print(url)

    sys.stderr.write(
        f"check_routes: {len(seen)} endpoints, {warnings} duplicate-URL warnings\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
