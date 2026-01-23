import json
import sqlite3

con = sqlite3.connect("data.db")
cur = con.cursor()

has = cur.execute(
    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='ipsec_advanced_settings'"
).fetchone() is not None
print("has_table:", has)

if has:
    row = cur.execute(
        "SELECT id, logging_json, settings_json, updated_at FROM ipsec_advanced_settings WHERE id = 1"
    ).fetchone()
    print("row_exists:", row is not None)
    if row:
        _id, logging_json, settings_json, updated_at = row
        print("updated_at:", updated_at)
        try:
            logging = json.loads(logging_json or "{}")
        except Exception:
            logging = {}
        try:
            settings = json.loads(settings_json or "{}")
        except Exception:
            settings = {}

        print("logging keys:", sorted(logging.keys()))
        print("settings keys:", sorted(settings.keys()))
        # Print a couple sample values
        print("sample logging daemon:", logging.get("daemon"))
        print("sample setting ike_port:", settings.get("ike_port"))

con.close()
