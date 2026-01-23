"""Smoke test for L2TP users CRUD.

Initializes the table, inserts a user, updates it, lists it, deletes it.
"""

from __future__ import annotations

import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(PROJECT_ROOT)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app.l2users import (  # noqa: E402
    delete_l2tp_user,
    init_l2tp_users_table,
    insert_l2tp_user,
    list_l2tp_users,
    update_l2tp_user,
)


def main() -> None:
    init_l2tp_users_table()

    uid = insert_l2tp_user(
        {
            "username": ["alice"],
            "password": ["secret"],
            "ip_address": ["10.10.10.10"],
        }
    )

    update_l2tp_user(
        uid,
        {
            "username": ["alice2"],
            "password": [""],  # keep existing
            "ip_address": ["10.10.10.11"],
        },
    )

    rows = list_l2tp_users()
    assert any(r["id"] == uid and r["username"] == "alice2" for r in rows)

    delete_l2tp_user(uid)
    rows2 = list_l2tp_users()
    assert not any(r["id"] == uid for r in rows2)

    print("OK")


if __name__ == "__main__":
    main()
