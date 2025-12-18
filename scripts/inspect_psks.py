import sqlite3

con = sqlite3.connect("data.db")
cur = con.cursor()

has = cur.execute(
    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='ipsec_psks'"
).fetchone() is not None

print("has_table:", has)
if has:
    rows = cur.execute(
        "SELECT id, identifier, secret_type, secret, created_at FROM ipsec_psks ORDER BY id DESC LIMIT 10"
    ).fetchall()
    print("rows:")
    for r in rows:
        print(r)

con.close()
