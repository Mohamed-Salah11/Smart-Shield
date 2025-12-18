import sqlite3


def main():
    conn = sqlite3.connect("data.db")
    cur = conn.cursor()
    cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'openvpn_wizard_%' ORDER BY name"
    )
    print([r[0] for r in cur.fetchall()])
    conn.close()


if __name__ == "__main__":
    main()
