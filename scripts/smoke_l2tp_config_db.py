"""Smoke test for L2TP config persistence.

Runs without Flask: initializes the table, saves a sample config, reads it back.
"""

from __future__ import annotations

import os
import sys

# Ensure we're running from project root so relative `data.db` resolves as expected.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(PROJECT_ROOT)

# Ensure imports work when executing as a script.
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app.l2configdb import get_l2tp_config, init_l2tp_config_table, save_l2tp_config  # noqa: E402


def main() -> None:
    init_l2tp_config_table()

    saved = save_l2tp_config(
        {
            "l2tp_enabled": ["on"],
            "interface": ["wan"],
            "local_ip": ["10.0.0.1"],
            "remote_ip_range": ["10.0.0.100-10.0.0.200"],
            "dns_servers": ["1.1.1.1,8.8.8.8"],
            "auth_method": ["pap"],
            "username": ["testuser"],
            "password": ["testpass"],
            "some_future_field": ["kept_in_extras"],
        }
    )
    loaded = get_l2tp_config()

    print("Saved:", saved)
    print("Loaded:", loaded)

    assert loaded.get("interface") == "wan"
    assert loaded.get("enabled") is True
    assert loaded.get("extras", {}).get("some_future_field") == "kept_in_extras"

    print("OK")


if __name__ == "__main__":
    main()
