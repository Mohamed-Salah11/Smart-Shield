"""
cert_manager.py
---------------
X.509 certificate management for Smart Shield VPN services.

Uses Python's `cryptography` library (already in requirements.txt) so no
subprocess openssl calls are needed — no shell injection risk.

Tables used
-----------
certificates  — stores CA, server, and client certs + encrypted private keys

Public API
----------
create_ca(conn, ...)                  -> dict  {"ok", "id", "message"}
create_server_cert(conn, ca_id, ...)  -> dict
create_client_cert(conn, ca_id, ...)  -> dict
revoke_cert(conn, cert_id)            -> dict
get_cert_pem(conn, cert_id)           -> str   PEM cert (no private key)
get_key_pem(conn, cert_id)            -> str   decrypted private key PEM
export_pkcs12(conn, cert_id, password)-> bytes PKCS#12 bundle
validate_cert_row(row)                -> list  [error strings]
list_certs(conn, cert_type=None)      -> list
mask_cert_fields(row)                 -> dict  safe for UI/logs
"""

import datetime
import ipaddress
import os
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

try:
    from cryptography.hazmat.primitives.serialization import pkcs12 as _pkcs12
    _PKCS12_AVAILABLE = True
except ImportError:
    _pkcs12 = None
    _PKCS12_AVAILABLE = False

from app.secret_store import decrypt_secret, encrypt_secret, mask_secret


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rows(conn, sql, params=()):
    cur = conn.cursor()
    cur.execute(sql, params)
    return [dict(r) for r in cur.fetchall()]


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _generate_rsa_key(key_bits: int = 2048):
    return rsa.generate_private_key(public_exponent=65537, key_size=key_bits)


def _key_to_pem(private_key) -> str:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


def _cert_to_pem(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _build_name(cn: str, country: str = "", org: str = "", ou: str = "",
                state: str = "", city: str = "") -> x509.Name:
    attrs = []
    if country:
        attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country[:2].upper()))
    if state:
        attrs.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))
    if city:
        attrs.append(x509.NameAttribute(NameOID.LOCALITY_NAME, city))
    if org:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
    if ou:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou))
    attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
    return x509.Name(attrs)


def _serial() -> int:
    return int.from_bytes(os.urandom(16), "big")


# ---------------------------------------------------------------------------
# Create CA
# ---------------------------------------------------------------------------

def create_ca(
    conn,
    *,
    name: str,
    common_name: str,
    key_bits: int = 2048,
    lifetime_days: int = 3650,
    country: str = "",
    org: str = "",
    ou: str = "",
    state: str = "",
    city: str = "",
) -> dict:
    """
    Generate a self-signed CA certificate and store in the DB.
    Returns ``{"ok": bool, "id": int, "message": str}``.
    Private key is encrypted with the master key before storage.
    """
    if not name or not common_name:
        return {"ok": False, "message": "name and common_name are required"}

    # Check for duplicate name
    existing = _rows(conn, "SELECT id FROM certificates WHERE name=? AND cert_type='ca'", (name,))
    if existing:
        return {"ok": False, "message": f"A CA named {name!r} already exists."}

    try:
        key  = _generate_rsa_key(key_bits)
        subj = _build_name(common_name, country, org, ou, state, city)
        now  = _now()
        not_after = now + datetime.timedelta(days=lifetime_days)

        cert = (
            x509.CertificateBuilder()
            .subject_name(subj)
            .issuer_name(subj)
            .public_key(key.public_key())
            .serial_number(_serial())
            .not_valid_before(now)
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )

        cert_pem = _cert_to_pem(cert)
        key_enc  = encrypt_secret(_key_to_pem(key))

        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO certificates
                (name, cert_type, common_name, ca_id, cert_pem, private_key_enc,
                 serial, not_before, not_after)
            VALUES (?, 'ca', ?, NULL, ?, ?, ?, ?, ?)
            """,
            (
                name, common_name, cert_pem, key_enc,
                str(cert.serial_number),
                now.isoformat(),
                not_after.isoformat(),
            ),
        )
        conn.commit()
        return {"ok": True, "id": cur.lastrowid, "message": f"CA '{name}' created."}

    except Exception as exc:
        return {"ok": False, "message": f"CA creation failed: {exc}"}


# ---------------------------------------------------------------------------
# Create server or client certificate
# ---------------------------------------------------------------------------

def _create_signed_cert(
    conn,
    *,
    ca_id: int,
    name: str,
    common_name: str,
    cert_type: str,          # "server" or "client"
    key_bits: int = 2048,
    lifetime_days: int = 397,
    san_dns: list = None,
    san_ip: list = None,
    country: str = "",
    org: str = "",
    ou: str = "",
) -> dict:
    if not name or not common_name:
        return {"ok": False, "message": "name and common_name are required"}

    # Load CA
    ca_rows = _rows(conn, "SELECT * FROM certificates WHERE id=? AND cert_type='ca'", (ca_id,))
    if not ca_rows:
        return {"ok": False, "message": f"CA id={ca_id} not found."}
    ca_row = ca_rows[0]

    # Check duplicate name within type
    dup = _rows(conn, "SELECT id FROM certificates WHERE name=? AND cert_type=?", (name, cert_type))
    if dup:
        return {"ok": False, "message": f"A {cert_type} certificate named {name!r} already exists."}

    try:
        ca_cert = x509.load_pem_x509_certificate(ca_row["cert_pem"].encode())
        ca_key_pem = decrypt_secret(ca_row["private_key_enc"] or "")
        if not ca_key_pem:
            return {"ok": False, "message": "CA private key could not be decrypted."}
        ca_key = serialization.load_pem_private_key(ca_key_pem.encode(), password=None)

        key  = _generate_rsa_key(key_bits)
        subj = _build_name(common_name, country, org, ou)
        now  = _now()
        not_after = now + datetime.timedelta(days=lifetime_days)

        builder = (
            x509.CertificateBuilder()
            .subject_name(subj)
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(_serial())
            .not_valid_before(now)
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False,
            )
        )

        # Extended Key Usage
        if cert_type == "server":
            eku = x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH])
        else:
            eku = x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.CLIENT_AUTH])
        builder = builder.add_extension(eku, critical=False)

        # Subject Alternative Names
        san_entries = []
        for dns_name in (san_dns or []):
            san_entries.append(x509.DNSName(dns_name.strip()))
        for ip_str in (san_ip or []):
            try:
                san_entries.append(x509.IPAddress(ipaddress.ip_address(ip_str.strip())))
            except ValueError:
                pass
        if san_entries:
            builder = builder.add_extension(x509.SubjectAlternativeName(san_entries), critical=False)

        cert     = builder.sign(ca_key, hashes.SHA256())
        cert_pem = _cert_to_pem(cert)
        key_enc  = encrypt_secret(_key_to_pem(key))

        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO certificates
                (name, cert_type, common_name, ca_id, cert_pem, private_key_enc,
                 serial, not_before, not_after)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                name, cert_type, common_name, ca_id, cert_pem, key_enc,
                str(cert.serial_number),
                now.isoformat(),
                not_after.isoformat(),
            ),
        )
        conn.commit()
        return {"ok": True, "id": cur.lastrowid, "message": f"{cert_type.title()} cert '{name}' created."}

    except Exception as exc:
        return {"ok": False, "message": f"Certificate creation failed: {exc}"}


def create_server_cert(conn, *, ca_id: int, name: str, common_name: str,
                       key_bits: int = 2048, lifetime_days: int = 397,
                       san_dns: list = None, san_ip: list = None,
                       country: str = "", org: str = "", ou: str = "") -> dict:
    return _create_signed_cert(conn, ca_id=ca_id, name=name, common_name=common_name,
                                cert_type="server", key_bits=key_bits,
                                lifetime_days=lifetime_days, san_dns=san_dns, san_ip=san_ip,
                                country=country, org=org, ou=ou)


def create_client_cert(conn, *, ca_id: int, name: str, common_name: str,
                       key_bits: int = 2048, lifetime_days: int = 397,
                       country: str = "", org: str = "", ou: str = "") -> dict:
    return _create_signed_cert(conn, ca_id=ca_id, name=name, common_name=common_name,
                                cert_type="client", key_bits=key_bits,
                                lifetime_days=lifetime_days, country=country, org=org, ou=ou)


# ---------------------------------------------------------------------------
# Revoke
# ---------------------------------------------------------------------------

def revoke_cert(conn, cert_id: int) -> dict:
    rows = _rows(conn, "SELECT id, name, cert_type FROM certificates WHERE id=?", (cert_id,))
    if not rows:
        return {"ok": False, "message": f"Certificate id={cert_id} not found."}
    row = rows[0]
    if row["cert_type"] == "ca":
        return {"ok": False, "message": "Cannot revoke a CA certificate directly."}
    conn.execute(
        "UPDATE certificates SET revoked=1, revoked_at=CURRENT_TIMESTAMP WHERE id=?",
        (cert_id,),
    )
    conn.commit()
    return {"ok": True, "message": f"Certificate '{row['name']}' revoked."}


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def get_cert_pem(conn, cert_id: int) -> str:
    """Return the PEM-encoded certificate (no private key)."""
    rows = _rows(conn, "SELECT cert_pem FROM certificates WHERE id=?", (cert_id,))
    return (rows[0]["cert_pem"] or "") if rows else ""


def get_key_pem(conn, cert_id: int) -> str:
    """Return the decrypted private key PEM.  Never log this value."""
    rows = _rows(conn, "SELECT private_key_enc FROM certificates WHERE id=?", (cert_id,))
    if not rows:
        return ""
    return decrypt_secret(rows[0]["private_key_enc"] or "")


def export_pkcs12(conn, cert_id: int, password: str = "") -> bytes:
    """
    Export a PKCS#12 bundle containing the cert + private key + CA chain.
    Returns raw bytes suitable for download.
    """
    rows = _rows(conn, "SELECT * FROM certificates WHERE id=?", (cert_id,))
    if not rows:
        raise ValueError(f"Certificate id={cert_id} not found.")
    row = rows[0]

    cert = x509.load_pem_x509_certificate(row["cert_pem"].encode())
    key_pem = decrypt_secret(row["private_key_enc"] or "")
    if not key_pem:
        raise ValueError("Private key could not be decrypted.")
    key = serialization.load_pem_private_key(key_pem.encode(), password=None)

    # Load CA cert for chain
    cas = []
    if row.get("ca_id"):
        ca_rows = _rows(conn, "SELECT cert_pem FROM certificates WHERE id=?", (row["ca_id"],))
        if ca_rows:
            cas.append(x509.load_pem_x509_certificate(ca_rows[0]["cert_pem"].encode()))

    enc = (
        serialization.BestAvailableEncryption(password.encode())
        if password
        else serialization.NoEncryption()
    )
    if _PKCS12_AVAILABLE:
        return _pkcs12.serialize_key_and_certificates(
            name=row["name"].encode(),
            key=key,
            cert=cert,
            cas=cas or None,
            encryption_algorithm=enc,
        )
    # Fallback: return DER-encoded cert when PKCS#12 is unavailable
    return cert.public_bytes(serialization.Encoding.DER)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_cert_row(row: dict) -> list:
    """
    Validate a certificate DB row for expiry, common name, etc.
    Returns a list of human-readable error strings; empty = valid.
    """
    errors = []
    cn = (row.get("common_name") or "").strip()
    if not cn:
        errors.append("Common name is empty.")
    if len(cn) > 64:
        errors.append(f"Common name exceeds 64 characters: {cn!r}")

    not_after = row.get("not_after") or ""
    if not_after:
        try:
            exp = datetime.datetime.fromisoformat(not_after.replace("Z", "+00:00"))
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=datetime.timezone.utc)
            if exp < _now():
                errors.append(f"Certificate expired on {not_after}.")
            elif (exp - _now()).days < 30:
                errors.append(f"Certificate expires in < 30 days ({not_after}).")
        except Exception:
            errors.append(f"Cannot parse not_after: {not_after!r}")

    if row.get("revoked"):
        errors.append("Certificate has been revoked.")

    return errors


# ---------------------------------------------------------------------------
# List
# ---------------------------------------------------------------------------

def list_certs(conn, cert_type: Optional[str] = None) -> list:
    """List certificates, safe for UI (private key excluded)."""
    if cert_type:
        rows = _rows(
            conn,
            "SELECT id, name, cert_type, common_name, ca_id, serial, "
            "not_before, not_after, revoked, created_at FROM certificates "
            "WHERE cert_type=? ORDER BY created_at DESC",
            (cert_type,),
        )
    else:
        rows = _rows(
            conn,
            "SELECT id, name, cert_type, common_name, ca_id, serial, "
            "not_before, not_after, revoked, created_at FROM certificates "
            "ORDER BY cert_type, created_at DESC",
        )
    return rows


def mask_cert_fields(row: dict) -> dict:
    """Return a copy of a certificate row safe for API responses and logs."""
    safe = dict(row)
    safe.pop("private_key_enc", None)
    safe.pop("cert_pem", None)
    return safe
