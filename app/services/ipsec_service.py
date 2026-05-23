"""IPsec Phase 1 / Phase 2 business logic.

Shared service layer so both the UI routes (``routes/vpn/views.py``) and the
API routes (``routes/vpn/api.py``) call the same code instead of one route
function calling another. Each function takes a DB connection plus a plain
dict of input and returns ``(payload, http_status)`` where ``payload`` is a
JSON-serializable dict using the established ``{"success": bool, ...}`` shape.

Callers are responsible for ``jsonify(payload), status``.
"""

from __future__ import annotations

from app.secret_store import seal


# ── Phase 1 ────────────────────────────────────────────────────────────────

def list_phase1(conn) -> tuple[dict, int]:
    """Return all Phase 1 tunnels with their algorithm summaries."""
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, disabled, ike_version, remote_gateway, auth_method,
                   internet_protocol, interface, description
            FROM ipsec_phase1
            ORDER BY id
            """
        )
        rows = cur.fetchall()
        tunnels = []
        for r in rows:
            cur.execute(
                """SELECT encryption, key_length, hash, dh_group
                   FROM ipsec_phase1_algorithms WHERE phase1_id=? ORDER BY id""",
                (r["id"],),
            )
            algos = [dict(a) for a in cur.fetchall()]
            tunnels.append({**dict(r), "algorithms": algos})
        return {"success": True, "tunnels": tunnels}, 200
    except Exception as e:  # noqa: BLE001 — surfaced to caller as JSON error
        return {"success": False, "error": str(e)}, 500


def create_phase1(conn, data: dict) -> tuple[dict, int]:
    """Insert a Phase 1 tunnel and its algorithm rows."""
    try:
        data = data or {}
        remote_gateway = (data.get("remote_gateway") or "").strip()
        if not remote_gateway:
            return {"success": False, "error": "remote_gateway is required"}, 400

        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO ipsec_phase1 (
                disabled, ike_version, internet_protocol, interface, remote_gateway,
                auth_method, my_identifier, peer_identifier, pre_shared_key,
                p1_life_time, p1_rekey_time, p1_reauth_time, p1_rand_time,
                child_sa_start_action, child_sa_close_action,
                nat_traversal, mobike,
                gateway_duplicates, split_connections, prf_selection,
                remote_ike_port, remote_nat_t_port,
                dpd_enable, dpd_delay, dpd_max_failures,
                description
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                1 if data.get("disabled") else 0,
                data.get("ike_version", data.get("key_exchange", data.get("keyExchange", "ikev2"))),
                data.get("internet_protocol", data.get("protocol", "ipv4")),
                data.get("interface", "wan"),
                remote_gateway,
                data.get("auth_method", data.get("authentication_method", data.get("authMethod", "mutual-psk"))),
                data.get("my_identifier", data.get("myIdentifier", "my-ip")),
                data.get("peer_identifier", data.get("peerIdentifier", "peer-ip")),
                seal(data.get("pre_shared_key", data.get("preshared_key", ""))),
                int(data.get("p1_life_time", data.get("life_time", 28800)) or 28800),
                int(data.get("p1_rekey_time", data.get("rekey_time", 25920)) or 25920),
                int(data.get("p1_reauth_time", data.get("reauth_time", 0)) or 0),
                int(data.get("p1_rand_time", data.get("rand_time", 2880)) or 2880),
                data.get("child_sa_start_action", "default"),
                data.get("child_sa_close_action", "default"),
                data.get("nat_traversal", "auto"),
                data.get("mobike", "disable"),
                1 if data.get("gateway_duplicates") else 0,
                1 if data.get("split_connections") else 0,
                1 if data.get("prf_selection") else 0,
                (data.get("remote_ike_port") or ""),
                (data.get("remote_nat_t_port") or ""),
                1 if data.get("dpd_enable", True) else 0,
                int(data.get("dpd_delay", 10) or 10),
                int(data.get("dpd_max_failures", 5) or 5),
                (data.get("description") or ""),
            ),
        )
        p1_id = cur.lastrowid

        algos = data.get("algorithms") or []
        if isinstance(algos, list) and len(algos) > 0:
            for a in algos:
                enc = (a.get("encryption") or "").strip()
                if not enc:
                    continue
                cur.execute(
                    """
                    INSERT INTO ipsec_phase1_algorithms (phase1_id, encryption, key_length, hash, dh_group)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (p1_id, enc, a.get("key_length"), a.get("hash"), a.get("dh_group")),
                )
        else:
            cur.execute(
                """
                INSERT INTO ipsec_phase1_algorithms (phase1_id, encryption, key_length, hash, dh_group)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    p1_id,
                    data.get("encryption_algorithm", "aes"),
                    int(data.get("key_length", 128) or 128),
                    data.get("hash_algorithm", "sha256"),
                    data.get("dh_key_group", "14"),
                ),
            )

        conn.commit()
        return {"success": True, "id": p1_id}, 200
    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": str(e)}, 500


def delete_phase1(conn, p1_id: int) -> tuple[dict, int]:
    """Delete a Phase 1 tunnel by id."""
    try:
        conn.execute("DELETE FROM ipsec_phase1 WHERE id=?", (p1_id,))
        conn.commit()
        return {"success": True}, 200
    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": str(e)}, 500


# ── Phase 2 ────────────────────────────────────────────────────────────────

def list_phase2(conn, p1_id: int | None = None) -> tuple[dict, int]:
    """List Phase 2 (child SA) entries, optionally scoped to one Phase 1."""
    try:
        cur = conn.cursor()
        if p1_id:
            cur.execute("SELECT * FROM ipsec_phase2 WHERE phase1_id=? ORDER BY id", (p1_id,))
        else:
            cur.execute("SELECT * FROM ipsec_phase2 ORDER BY id")
        rows = [dict(r) for r in cur.fetchall()]
        # Return both keys for back-compat: the JS reads ``phase2s``; older
        # callers may have read ``entries``.
        return {"success": True, "phase2s": rows, "entries": rows}, 200
    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": str(e)}, 500


def upsert_phase2(conn, data: dict, p2_id: int | None = None) -> tuple[dict, int]:
    """Create or update a Phase 2 child SA. ``p2_id`` (from a PUT URL) or
    ``data['id']`` selects update; otherwise insert."""
    try:
        data = data or {}
        p1_id = data.get("phase1_id")
        if not p1_id:
            return {"success": False, "error": "phase1_id required"}, 400
        cur = conn.cursor()
        rid = p2_id or data.get("id")
        fields = {
            "phase1_id":             p1_id,
            "description":           data.get("description", ""),
            "disabled":              1 if data.get("disabled") else 0,
            "mode":                  data.get("mode", "tunnel"),
            "local_network":         data.get("local_network", ""),
            "remote_network":        data.get("remote_network", ""),
            "protocol":              data.get("protocol", "esp"),
            "encryption_algorithms": data.get("encryption_algorithms", "aes256"),
            "hash_algorithms":       data.get("hash_algorithms", "sha256"),
            "pfs_key_group":         data.get("pfs_key_group", "14"),
            "lifetime":              data.get("lifetime", 3600),
        }
        if rid:
            sets = ", ".join(f"{k}=?" for k in fields)
            cur.execute(f"UPDATE ipsec_phase2 SET {sets} WHERE id=?",
                        list(fields.values()) + [rid])
            conn.commit()
            return {"success": True, "id": rid}, 200
        cols = ", ".join(fields.keys())
        vals = ", ".join("?" * len(fields))
        cur.execute(f"INSERT INTO ipsec_phase2 ({cols}) VALUES ({vals})",
                    list(fields.values()))
        conn.commit()
        return {"success": True, "id": cur.lastrowid}, 200
    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": str(e)}, 500


def delete_phase2(conn, p2_id: int) -> tuple[dict, int]:
    """Delete a Phase 2 child SA by id."""
    try:
        conn.execute("DELETE FROM ipsec_phase2 WHERE id=?", (p2_id,))
        conn.commit()
        return {"success": True}, 200
    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": str(e)}, 500
