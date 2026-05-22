"""
app/services/soc_blocklist.py
-----------------------------
Persist SOC-portal IP blocks into PF.

L3 analysts block IPs from the SOC portal; the ``soc_blocked_ips`` table is the
source of truth. This module flushes that table into the persistent
``<soc_blocklist>`` PF table (declared by pf_generator), mirroring how
``ids_writer.push_blocked_ips_to_pf`` maintains ``<ss_ids_blocks>``.
"""

import os
import sys

from app.config import _ss_dir as _ss_dir_soc
_SOC_BLOCK_FILE = os.path.join(_ss_dir_soc("/var/db"), "soc_blocked_ips.txt")


def push_soc_blocklist_to_pf(conn) -> dict:
    """
    Write every IP in ``soc_blocked_ips`` to a file and replace the
    ``<soc_blocklist>`` PF table with it.

    Returns ``{"ok": bool, "count": int, "message": str}``. Never raises.
    """
    import ipaddress as _ip

    ips = set()
    try:
        rows = conn.execute("SELECT ip FROM soc_blocked_ips").fetchall()
    except Exception as exc:
        return {"ok": False, "count": 0, "message": f"DB query failed: {exc}"}

    for row in rows:
        ip = ((row["ip"] if hasattr(row, "keys") else row[0]) or "").strip()
        if not ip:
            continue
        try:
            _ip.ip_address(ip)          # validate
        except ValueError:
            continue
        ips.add(ip)

    try:
        os.makedirs(os.path.dirname(_SOC_BLOCK_FILE), exist_ok=True)
        with open(_SOC_BLOCK_FILE, "w") as fh:
            fh.write("\n".join(sorted(ips)) + ("\n" if ips else ""))
    except Exception as exc:
        return {"ok": False, "count": 0, "message": f"Could not write IP file: {exc}"}

    if not sys.platform.startswith("freebsd"):
        return {"ok": True, "count": len(ips),
                "message": f"Non-FreeBSD — {len(ips)} IP(s) written to file "
                           f"(pfctl not called)"}

    try:
        from app.services.priv_helper import run_privileged
        r = run_privileged("pf.table_replace_file", table="soc_blocklist",
                           file_path=_SOC_BLOCK_FILE)
        if r.returncode == 0:
            return {"ok": True, "count": len(ips),
                    "message": f"soc_blocklist table updated with {len(ips)} IP(s)"}
        return {"ok": False, "count": len(ips),
                "message": f"pfctl table replace failed: "
                           f"{(r.stderr or r.stdout or '').strip()}"}
    except Exception as exc:
        return {"ok": False, "count": len(ips), "message": str(exc)}
