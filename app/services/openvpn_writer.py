"""
openvpn_writer.py — generates OpenVPN server/client configs + apply/status.

Public API additions (Phase 3)
-------------------------------
validate_server(row)    -> list[str]   validation errors
validate_client(row)    -> list[str]
apply_openvpn(conn)     -> dict        (already existed, now validates first)
get_connected_clients(server_id) -> list[dict]
get_openvpn_log(server_id, lines) -> str
"""
import os
import re
import sys

_OPENVPN_DIR  = "/usr/local/etc/openvpn"
_OPENVPN_KEYS = "/usr/local/etc/openvpn/keys"
_OPENVPN_LOG  = "/var/log/openvpn"
_OPENVPN_RUN  = "/var/run/openvpn"

_VALID_PROTOCOLS  = {"udp", "tcp", "udp4", "tcp4", "udp6", "tcp6"}
_VALID_DEV_MODES  = {"tun", "tap"}
_VALID_TOPOLOGIES = {"subnet", "p2p", "net30"}


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_server(row: dict) -> list:
    """
    Validate an openvpn_servers row.
    Returns a list of error strings; empty means valid.
    """
    errors = []

    proto = (row.get("protocol") or "").lower()
    if not proto:
        errors.append("Protocol is required.")
    elif proto not in _VALID_PROTOCOLS:
        errors.append(f"Unknown protocol: {proto!r}. Must be one of {sorted(_VALID_PROTOCOLS)}.")

    dev = (row.get("device_mode") or "tun").lower()
    if dev not in _VALID_DEV_MODES:
        errors.append(f"Device mode must be 'tun' or 'tap', got {dev!r}.")

    port = row.get("local_port")
    try:
        p = int(port) if port is not None else 1194
        if not (1 <= p <= 65535):
            errors.append(f"Port must be 1-65535, got {port!r}.")
    except (TypeError, ValueError):
        errors.append(f"Port must be 1-65535, got {port!r}.")

    tunnel = (row.get("tunnel_network") or "").strip()
    if not tunnel:
        errors.append("Tunnel network is required (e.g. 10.8.0.0/24).")
    else:
        try:
            import ipaddress
            ipaddress.ip_network(tunnel, strict=False)
        except ValueError:
            errors.append(f"Tunnel network {tunnel!r} is not a valid CIDR.")

    local_net = (row.get("local_network") or "").strip()
    if local_net:
        try:
            import ipaddress
            ipaddress.ip_network(local_net, strict=False)
        except ValueError:
            errors.append(f"Local network {local_net!r} is not a valid CIDR.")

    topo = (row.get("topology") or "subnet").lower()
    if topo not in _VALID_TOPOLOGIES:
        errors.append(f"Topology must be one of {sorted(_VALID_TOPOLOGIES)}, got {topo!r}.")

    return errors


def validate_client(row: dict) -> list:
    """
    Validate an openvpn_clients row.
    Returns a list of error strings; empty means valid.
    """
    errors = []

    proto = (row.get("protocol") or "").lower()
    if proto and proto not in _VALID_PROTOCOLS:
        errors.append(f"Unknown protocol: {proto!r}.")

    hostname = (row.get("server_hostname") or "").strip()
    if not hostname:
        errors.append("Server hostname or IP is required.")

    port = row.get("server_port")
    try:
        p = int(port) if port is not None else 1194
        if not (1 <= p <= 65535):
            errors.append(f"Server port must be 1-65535, got {port!r}.")
    except (TypeError, ValueError):
        errors.append(f"Server port must be 1-65535, got {port!r}.")

    return errors


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

    from app.services.config_file_utils import atomic_write, backup_config
    errors = []
    for item in configs:
        path = os.path.join(_OPENVPN_DIR, item["filename"])
        try:
            backup_config(path)
            atomic_write(path, item["conf"], mode=0o640)
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
    """Write validated configs and restart OpenVPN."""
    # Validate all servers and clients first
    servers  = _rows(conn, "SELECT * FROM openvpn_servers WHERE disabled=0 ORDER BY id")
    clients  = _rows(conn, "SELECT * FROM openvpn_clients WHERE disabled=0 ORDER BY id")
    all_errs = []
    for row in servers:
        errs = validate_server(row)
        if errs:
            all_errs.append(f"Server {row.get('id')} ({row.get('description','')}): " + "; ".join(errs))
    for row in clients:
        errs = validate_client(row)
        if errs:
            all_errs.append(f"Client {row.get('id')} ({row.get('description','')}): " + "; ".join(errs))
    if all_errs:
        return {"ok": False, "message": "Validation failed: " + " | ".join(all_errs), "configs": []}

    # Auto-export PKI from cert_manager DB to disk for servers that have
    # ca_id + server_cert_id set.  Non-fatal if the cert store is empty.
    pki_warnings = []
    for row in servers:
        ca_id          = row.get("ca_id")
        server_cert_id = row.get("server_cert_id")
        if ca_id and server_cert_id:
            try:
                pki_result = export_pki_to_disk(conn, row["id"], ca_id, server_cert_id)
                if not pki_result.get("ok"):
                    pki_warnings.append(
                        f"Server {row.get('id')}: PKI export failed — {pki_result.get('message', '')}"
                    )
            except Exception as exc:
                pki_warnings.append(f"Server {row.get('id')}: PKI export error — {exc}")

    result = write_openvpn_configs(conn)
    if not result["ok"] or not _on_freebsd():
        return {**result, "rolled_back": False, "pki_warnings": pki_warnings}
    try:
        from app.services.service_manager import service_action, sysrc_set
        from app.services.config_file_utils import rollback_config
        sysrc_set("openvpn_enable", "YES")
        r = service_action("openvpn", "restart")
        if not r["ok"]:
            rolled_back = []
            for item in result.get("configs", []):
                path = item.get("path", "")
                if path:
                    rb = rollback_config(path)
                    if rb["ok"]:
                        rolled_back.append(path)
            return {"ok": False,
                    "rolled_back": bool(rolled_back),
                    "pki_warnings": pki_warnings,
                    "message": result["message"] + " | Service: " + r["message"],
                    "configs": result["configs"]}
        return {"ok": r["ok"],
                "rolled_back": False,
                "pki_warnings": pki_warnings,
                "message": result["message"] + " | Service: " + r["message"],
                "configs": result["configs"]}
    except Exception as exc:
        return {"ok": False, "rolled_back": False, "pki_warnings": pki_warnings,
                "message": f"Config written but restart failed: {exc}"}


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

def get_connected_clients(server_id: int) -> list:
    """
    Parse the OpenVPN status file for server *server_id* and return connected clients.
    Status file format: CSV lines after "CLIENT_LIST" header.
    Returns [] on non-FreeBSD or if the file doesn't exist.
    """
    path = os.path.join(_OPENVPN_LOG, f"status{server_id}.log")
    if not os.path.exists(path):
        return []
    clients = []
    in_clients = False
    try:
        with open(path) as fh:
            for line in fh:
                line = line.rstrip()
                if line.startswith("CLIENT_LIST"):
                    in_clients = True
                    continue
                if line.startswith("ROUTING_TABLE") or line.startswith("GLOBAL_STATS"):
                    in_clients = False
                    continue
                if in_clients:
                    parts = line.split(",")
                    if len(parts) >= 5 and parts[0] != "Common Name":
                        clients.append({
                            "common_name": parts[0],
                            "real_address": parts[1],
                            "virtual_address": parts[2],
                            "bytes_recv": parts[3],
                            "bytes_sent": parts[4],
                            "connected_since": parts[7] if len(parts) > 7 else "",
                        })
    except OSError:
        pass
    return clients


def get_openvpn_log(server_id: int, lines: int = 100) -> str:
    """Return the last *lines* of the OpenVPN server log."""
    path = os.path.join(_OPENVPN_LOG, f"server{server_id}.log")
    if not os.path.exists(path):
        return ""
    try:
        with open(path) as fh:
            all_lines = fh.readlines()
        return "".join(all_lines[-lines:])
    except OSError:
        return ""


# ---------------------------------------------------------------------------
# Phase 18: PKI lifecycle — export certs from cert_manager to disk
# ---------------------------------------------------------------------------

def export_pki_to_disk(conn, server_id: int, ca_id: int, server_cert_id: int) -> dict:
    """
    Write CA cert, server cert, and server key from the cert_manager DB to the
    OpenVPN keys directory so that apply_openvpn() picks them up.

    Parameters
    ----------
    server_id       : openvpn_servers.id (determines filenames)
    ca_id           : certificates.id of the CA certificate
    server_cert_id  : certificates.id of the server certificate

    Returns ``{"ok": bool, "message": str, "files": list}``.
    """
    from app.services.cert_manager import get_cert_pem, get_key_pem, validate_cert_row, list_certs

    # Load CA cert
    ca_pem = get_cert_pem(conn, ca_id)
    if not ca_pem:
        return {"ok": False, "message": f"CA cert id={ca_id} not found.", "files": []}

    # Load server cert + key
    srv_pem = get_cert_pem(conn, server_cert_id)
    srv_key = get_key_pem(conn, server_cert_id)
    if not srv_pem or not srv_key:
        return {"ok": False, "message": f"Server cert id={server_cert_id} not found or key unreadable.", "files": []}

    # Warn on near-expiry
    srv_rows = list_certs(conn)
    srv_row  = next((r for r in srv_rows if r["id"] == server_cert_id), {})
    warnings = validate_cert_row(srv_row)

    if not _on_freebsd():
        return {
            "ok": True,
            "message": f"Non-FreeBSD — PKI export skipped. Warnings: {warnings or 'none'}",
            "files": [],
            "warnings": warnings,
        }

    os.makedirs(_OPENVPN_KEYS, mode=0o700, exist_ok=True)

    written = []
    pairs = [
        (f"server{server_id}-ca.crt",  ca_pem,  0o644),
        (f"server{server_id}.crt",     srv_pem,  0o640),
        (f"server{server_id}.key",     srv_key,  0o600),
    ]
    errors = []
    for fname, content, mode in pairs:
        path = os.path.join(_OPENVPN_KEYS, fname)
        try:
            with open(path, "w") as fh:
                fh.write(content)
            os.chmod(path, mode)
            written.append(path)
        except OSError as exc:
            errors.append(f"{fname}: {exc}")

    if errors:
        return {"ok": False, "message": "; ".join(errors), "files": written, "warnings": warnings}
    return {
        "ok":       True,
        "message":  f"PKI files written for server {server_id}.",
        "files":    written,
        "warnings": warnings,
    }


def generate_client_ovpn(conn, server_id: int, client_cert_id: int) -> str:
    """
    Generate a .ovpn inline-cert client config file content.

    Embeds <ca>, <cert>, <key> blocks inline so the file is self-contained.
    Returns the .ovpn file content as a string.

    Parameters
    ----------
    server_id       : openvpn_servers.id — used to get proto/port/remote_host
    client_cert_id  : certificates.id of the client certificate
    """
    from app.secret_store import decrypt_secret

    # --- Load server row ---
    srv_rows = _rows(conn, "SELECT * FROM openvpn_servers WHERE id=?", (server_id,))
    srv = srv_rows[0] if srv_rows else {}

    proto       = _v(srv, "protocol", "udp4").lower()
    proto_clean = proto.replace("4", "").replace("6", "")
    port        = srv.get("local_port") or 1194
    # Prefer explicit remote_host field; fall back to server_hostname, then placeholder.
    remote_host = (
        srv.get("remote_host")
        or srv.get("server_hostname")
        or "YOUR-SERVER-IP"
    )

    # --- Load client cert ---
    client_rows = _rows(conn, "SELECT * FROM certificates WHERE id=?", (client_cert_id,))
    if not client_rows:
        raise ValueError(f"Client certificate id={client_cert_id} not found.")
    client_row = client_rows[0]

    client_pem     = (client_row.get("cert_pem") or "").strip()
    client_key_enc = client_row.get("private_key_enc") or ""
    client_key     = decrypt_secret(client_key_enc) if client_key_enc else ""
    if not client_pem:
        raise ValueError(f"Client certificate id={client_cert_id} has no PEM cert.")
    if not client_key:
        raise ValueError(f"Client certificate id={client_cert_id} key could not be decrypted.")

    # --- Load CA cert ---
    ca_pem = ""
    ca_id  = client_row.get("ca_id")
    if ca_id:
        ca_rows = _rows(conn, "SELECT cert_pem FROM certificates WHERE id=?", (ca_id,))
        if ca_rows:
            ca_pem = (ca_rows[0].get("cert_pem") or "").strip()
    if not ca_pem:
        # Fallback: look for any CA cert in the table
        ca_rows = _rows(conn, "SELECT cert_pem FROM certificates WHERE cert_type='ca' LIMIT 1")
        if ca_rows:
            ca_pem = (ca_rows[0].get("cert_pem") or "").strip()
    if not ca_pem:
        ca_pem = "# CA certificate not found — insert CA PEM here"

    desc = client_row.get("name") or f"client-{client_cert_id}"

    lines = [
        f"# Smart Shield — OpenVPN client config for {desc}",
        "# Auto-generated — keep this file private",
        "",
        "client",
        "dev tun",
        f"proto {proto_clean}",
        f"remote {remote_host} {port}",
        "resolv-retry infinite",
        "nobind",
        "",
        "data-ciphers AES-256-GCM:AES-128-GCM:AES-256-CBC",
        "data-ciphers-fallback AES-256-CBC",
        "auth SHA256",
        "tls-version-min 1.2",
        "",
        "persist-key",
        "persist-tun",
        "",
        "verb 3",
        "mute 10",
        "",
        "<ca>",
        ca_pem,
        "</ca>",
        "",
        "<cert>",
        client_pem,
        "</cert>",
        "",
        "<key>",
        client_key.strip(),
        "</key>",
    ]

    return "\n".join(lines) + "\n"


def check_openvpn_cert_expiry(conn) -> list:
    """
    Check PKI cert files on disk for near-expiry (warn within 30 days).
    Returns a list of alert dicts: {"file", "days_remaining", "expires"}.
    On non-FreeBSD: returns [].
    """
    if not _on_freebsd():
        return []

    alerts = []
    import datetime as _dt

    try:
        from cryptography import x509 as _x509
        for fname in os.listdir(_OPENVPN_KEYS):
            if not fname.endswith(".crt"):
                continue
            path = os.path.join(_OPENVPN_KEYS, fname)
            try:
                with open(path, "rb") as fh:
                    cert = _x509.load_pem_x509_certificate(fh.read())
                exp   = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=_dt.timezone.utc)
                days  = (exp - _dt.datetime.now(_dt.timezone.utc)).days
                if days < 30:
                    alerts.append({"file": fname, "days_remaining": days, "expires": exp.isoformat()})
            except Exception:
                continue
    except ImportError:
        pass

    return alerts


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
