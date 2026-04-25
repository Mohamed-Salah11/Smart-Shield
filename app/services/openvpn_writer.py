"""
openvpn_writer.py — generates OpenVPN server/client configs + apply/status.
"""
import os
import sys

_OPENVPN_DIR  = "/usr/local/etc/openvpn"
_OPENVPN_KEYS = "/usr/local/etc/openvpn/keys"
_OPENVPN_LOG  = "/var/log/openvpn"
_OPENVPN_RUN  = "/var/run/openvpn"


def _rows(conn, sql, params=()):
    cur = conn.cursor()
    cur.execute(sql, params)
    return [dict(r) for r in cur.fetchall()]


def _on_freebsd():
    return sys.platform.startswith("freebsd")


def _v(row, key, default=""):
    return row.get(key) or default


def _net_parts(cidr):
    try:
        import ipaddress
        net = ipaddress.ip_network(cidr, strict=False)
        return str(net.network_address), str(net.netmask)
    except Exception:
        return cidr.split("/")[0], "255.255.255.0"


# ---------------------------------------------------------------------------
# Server config
# ---------------------------------------------------------------------------

def generate_server_conf(row: dict) -> str:
    sid         = row.get("id", 1)
    proto       = _v(row, "protocol", "udp4").lower()
    proto_clean = proto.replace("4", "").replace("6", "")
    proto6      = "6" in proto
    port        = row.get("local_port") or 1194
    dev_mode    = _v(row, "device_mode", "tun").lower()
    topology    = _v(row, "topology", "subnet")
    tunnel      = _v(row, "tunnel_network", "10.8.0.0/24")
    redirect_gw = bool(row.get("redirect_gateway"))
    local_net   = _v(row, "local_network", "")
    max_clients = row.get("max_clients") or 100
    inter_client = bool(row.get("inter_client_communication"))
    compress    = _v(row, "compression", "")
    dns1        = _v(row, "dns_server1", "")
    dns2        = _v(row, "dns_server2", "")
    ntp1        = _v(row, "ntp_server1", "")
    use_tls     = bool(row.get("tls_key"))
    custom_opts = _v(row, "custom_options", "")
    desc        = _v(row, "description", f"server-{sid}")
    tun_net, tun_mask = _net_parts(tunnel)

    L = [
        f"# Smart Shield — OpenVPN Server {sid}: {desc}",
        "# Auto-generated — DO NOT EDIT MANUALLY",
        "",
        f"port {port}",
        f"proto {proto_clean}{'6' if proto6 else ''}",
        f"dev {dev_mode}{sid}",
        f"dev-type {dev_mode}",
        "",
        "# PKI",
        f"ca   {_OPENVPN_KEYS}/server{sid}-ca.crt",
        f"cert {_OPENVPN_KEYS}/server{sid}.crt",
        f"key  {_OPENVPN_KEYS}/server{sid}.key",
        f"dh   {_OPENVPN_KEYS}/dh2048.pem",
    ]
    if use_tls:
        L.append(f"tls-crypt {_OPENVPN_KEYS}/ta.key")

    L += [
        "",
        "# Network",
        f"topology {topology}",
        f"server {tun_net} {tun_mask}",
        f"ifconfig-pool-persist {_OPENVPN_LOG}/ipp{sid}.txt",
        "",
        "# Cipher (OpenVPN 2.5+)",
        "data-ciphers AES-256-GCM:AES-128-GCM:AES-256-CBC",
        "data-ciphers-fallback AES-256-CBC",
        "auth SHA256",
        "tls-version-min 1.2",
        "",
    ]

    if redirect_gw:
        L.append('push "redirect-gateway def1 bypass-dhcp"')
    if dns1:
        L.append(f'push "dhcp-option DNS {dns1}"')
    if dns2:
        L.append(f'push "dhcp-option DNS {dns2}"')
    if ntp1:
        L.append(f'push "dhcp-option NTP {ntp1}"')
    if local_net:
        a, m = _net_parts(local_net)
        L.append(f'push "route {a} {m}"')
    if inter_client:
        L.append("client-to-client")

    L += [
        "",
        f"max-clients {max_clients}",
        "keepalive 10 120",
        "",
        "# Security",
        "user nobody",
        "group nobody",
        "persist-key",
        "persist-tun",
        "",
    ]

    if compress and compress.lower() not in ("none", ""):
        L += [f"compress {compress}", ""]

    L += [
        "# Logging",
        f"status {_OPENVPN_LOG}/status{sid}.log 30",
        f"log-append {_OPENVPN_LOG}/server{sid}.log",
        "verb 3",
        "mute 10",
        f"writepid {_OPENVPN_RUN}/server{sid}.pid",
    ]

    if custom_opts:
        L += ["", "# Custom options", custom_opts]

    return "\n".join(L) + "\n"


# ---------------------------------------------------------------------------
# Client config
# ---------------------------------------------------------------------------

def generate_client_conf(row: dict) -> str:
    cid         = row.get("id", 1)
    proto       = _v(row, "protocol", "udp4").lower()
    proto_clean = proto.replace("4", "").replace("6", "")
    proto6      = "6" in proto
    server      = _v(row, "server_hostname", "")
    port        = row.get("server_port") or 1194
    enc_alg     = _v(row, "encryption_algorithm", "AES-256-GCM")
    auth_dig    = _v(row, "auth_digest_algorithm", "SHA256")
    inactivity  = row.get("inactivity_timeout") or 300
    ping_int    = row.get("ping_interval") or 10
    ping_tout   = row.get("ping_timeout") or 60
    verbosity   = row.get("verbosity_level") or 3
    use_tls     = bool(row.get("use_tls_key"))
    custom_opts = _v(row, "custom_options", "")
    desc        = _v(row, "description", f"client-{cid}")

    L = [
        f"# Smart Shield — OpenVPN Client {cid}: {desc}",
        "# Auto-generated — DO NOT EDIT MANUALLY",
        "",
        "client",
        "dev tun",
        f"proto {proto_clean}{'6' if proto6 else ''}",
        f"remote {server} {port}",
        "resolv-retry infinite",
        "nobind",
        "",
        "# PKI",
        f"ca   {_OPENVPN_KEYS}/client{cid}-ca.crt",
        f"cert {_OPENVPN_KEYS}/client{cid}.crt",
        f"key  {_OPENVPN_KEYS}/client{cid}.key",
    ]
    if use_tls:
        L.append(f"tls-crypt {_OPENVPN_KEYS}/client{cid}-ta.key")

    L += [
        "",
        "data-ciphers AES-256-GCM:AES-128-GCM:AES-256-CBC",
        f"data-ciphers-fallback {enc_alg}",
        f"auth {auth_dig}",
        "tls-version-min 1.2",
        "",
        "user nobody",
        "group nobody",
        "persist-key",
        "persist-tun",
        "",
        f"inactive {inactivity}",
        f"keepalive {ping_int} {ping_tout}",
        f"verb {verbosity}",
        "mute 10",
        f"log-append {_OPENVPN_LOG}/client{cid}.log",
    ]

    if custom_opts:
        L += ["", "# Custom options", custom_opts]

    return "\n".join(L) + "\n"


# ---------------------------------------------------------------------------
# Write all configs to disk
# ---------------------------------------------------------------------------

def write_openvpn_configs(conn) -> dict:
    servers = _rows(conn, "SELECT * FROM openvpn_servers WHERE disabled=0 ORDER BY id")
    clients = _rows(conn, "SELECT * FROM openvpn_clients WHERE disabled=0 ORDER BY id")
    configs = []
    for row in servers:
        configs.append({"kind": "server", "id": row["id"],
                        "conf": generate_server_conf(row),
                        "filename": f"server-{row['id']}.conf"})
    for row in clients:
        configs.append({"kind": "client", "id": row["id"],
                        "conf": generate_client_conf(row),
                        "filename": f"client-{row['id']}.conf"})

    if not configs:
        return {"ok": True, "message": "No enabled OpenVPN instances.", "configs": []}

    if not _on_freebsd():
        return {"ok": True,
                "message": f"Non-FreeBSD — {len(configs)} config(s) generated but not written.",
                "configs": configs}

    os.makedirs(_OPENVPN_DIR, exist_ok=True)
    os.makedirs(_OPENVPN_KEYS, mode=0o700, exist_ok=True)
    os.makedirs(_OPENVPN_LOG, exist_ok=True)
    os.makedirs(_OPENVPN_RUN, exist_ok=True)

    errors = []
    for item in configs:
        path = os.path.join(_OPENVPN_DIR, item["filename"])
        try:
            with open(path, "w") as fh:
                fh.write(item["conf"])
            os.chmod(path, 0o640)
            item["path"] = path
        except OSError as exc:
            errors.append(f"{item['filename']}: {exc}")

    if errors:
        return {"ok": False, "message": "; ".join(errors), "configs": configs}
    return {"ok": True,
            "message": f"Wrote {len(configs)} config(s) to {_OPENVPN_DIR}",
            "configs": configs}


# ---------------------------------------------------------------------------
# Apply: write + restart service
# ---------------------------------------------------------------------------

def apply_openvpn(conn) -> dict:
    result = write_openvpn_configs(conn)
    if not result["ok"] or not _on_freebsd():
        return result
    try:
        from app.services.service_manager import service_action
        r = service_action("openvpn", "restart")
        return {"ok": r["ok"],
                "message": result["message"] + " | Service: " + r["message"],
                "configs": result["configs"]}
    except Exception as exc:
        return {"ok": False, "message": f"Config written but restart failed: {exc}"}


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

def get_openvpn_status() -> dict:
    if not _on_freebsd():
        return {"running": False, "instances": [], "message": "Not on FreeBSD"}
    try:
        from app.services.network_service import run_command
        r = run_command(["pgrep", "-a", "openvpn"], check=False)
        lines = [l.strip() for l in (r.stdout or "").splitlines() if l.strip()]
        instances = []
        for line in lines:
            parts = line.split(None, 1)
            instances.append({"pid": parts[0], "cmd": parts[1] if len(parts) > 1 else ""})
        return {"running": bool(instances), "instances": instances}
    except Exception as exc:
        return {"running": False, "instances": [], "message": str(exc)}
