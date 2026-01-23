import sqlite3


def main():
    conn = sqlite3.connect("data.db")
    cur = conn.cursor()

    # Keep this one table (the CA form table)
    keep = {"openvpn_wizard_ca_form"}

    cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'openvpn_wizard_%'"
    )
    tables = [r[0] for r in cur.fetchall()]

    to_drop = [t for t in tables if t not in keep]
    for t in to_drop:
        cur.execute(f"DROP TABLE IF EXISTS {t}")

    conn.commit()
    conn.close()

    print("dropped:", to_drop)


if __name__ == "__main__":
    main()
