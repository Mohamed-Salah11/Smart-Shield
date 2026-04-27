"""
tests/test_cert_manager.py
--------------------------
Tests for app/services/cert_manager.py.
No FreeBSD required.  Uses Python cryptography library.
"""
import os
import pytest

os.environ.setdefault("SMARTSHIELD_DB_PATH", "file:certtest?mode=memory&cache=shared")
os.environ.setdefault("SECRET_KEY", "test-cert-key")
os.environ.setdefault("SMARTSHIELD_MASTER_KEY",
    __import__("base64").b64encode(__import__("secrets").token_bytes(32)).decode())


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def conn():
    import secrets
    os.environ["SMARTSHIELD_DB_PATH"] = f"file:cert_{secrets.token_hex(4)}?mode=memory&cache=shared"
    from app.database import init_db, get_db
    init_db()
    db = get_db()
    yield db
    db.close()


@pytest.fixture()
def ca(conn):
    from app.services.cert_manager import create_ca
    result = create_ca(
        conn,
        name="TestCA",
        common_name="Smart Shield Test CA",
        key_bits=2048,
        lifetime_days=3650,
    )
    assert result["ok"]
    return result["id"]


# ---------------------------------------------------------------------------
# CA creation
# ---------------------------------------------------------------------------

class TestCreateCA:

    def test_create_ca_success(self, conn):
        from app.services.cert_manager import create_ca
        result = create_ca(conn, name="MyCA", common_name="My Test CA")
        assert result["ok"] is True
        assert result["id"] > 0

    def test_create_ca_requires_name(self, conn):
        from app.services.cert_manager import create_ca
        result = create_ca(conn, name="", common_name="Test CA")
        assert result["ok"] is False

    def test_create_ca_requires_cn(self, conn):
        from app.services.cert_manager import create_ca
        result = create_ca(conn, name="ValidName", common_name="")
        assert result["ok"] is False

    def test_create_ca_duplicate_name_fails(self, conn, ca):
        from app.services.cert_manager import create_ca
        result = create_ca(conn, name="TestCA", common_name="Duplicate")
        assert result["ok"] is False
        assert "already exists" in result["message"]

    def test_ca_cert_pem_is_stored(self, conn, ca):
        rows = conn.execute(
            "SELECT cert_pem FROM certificates WHERE id=?", (ca,)
        ).fetchall()
        assert rows and "BEGIN CERTIFICATE" in rows[0][0]

    def test_ca_private_key_is_encrypted(self, conn, ca):
        rows = conn.execute(
            "SELECT private_key_enc FROM certificates WHERE id=?", (ca,)
        ).fetchall()
        enc = rows[0][0]
        assert enc.startswith("enc:")   # encrypted with master key

    def test_ca_key_can_be_decrypted(self, conn, ca):
        from app.services.cert_manager import get_key_pem
        key = get_key_pem(conn, ca)
        assert "BEGIN" in key and "PRIVATE KEY" in key


# ---------------------------------------------------------------------------
# Server certificate
# ---------------------------------------------------------------------------

class TestCreateServerCert:

    def test_create_server_cert_success(self, conn, ca):
        from app.services.cert_manager import create_server_cert
        result = create_server_cert(conn, ca_id=ca, name="ServerCert",
                                     common_name="vpn.example.com")
        assert result["ok"] is True
        assert result["id"] > 0

    def test_server_cert_pem_stored(self, conn, ca):
        from app.services.cert_manager import create_server_cert, get_cert_pem
        result = create_server_cert(conn, ca_id=ca, name="SrvCert2",
                                     common_name="srv2.example.com")
        pem = get_cert_pem(conn, result["id"])
        assert "BEGIN CERTIFICATE" in pem

    def test_server_cert_requires_existing_ca(self, conn):
        from app.services.cert_manager import create_server_cert
        result = create_server_cert(conn, ca_id=9999, name="NoCACert",
                                     common_name="test")
        assert result["ok"] is False
        assert "not found" in result["message"].lower()

    def test_server_cert_duplicate_name_fails(self, conn, ca):
        from app.services.cert_manager import create_server_cert
        create_server_cert(conn, ca_id=ca, name="DupServerCert",
                           common_name="dup.example.com")
        result = create_server_cert(conn, ca_id=ca, name="DupServerCert",
                                     common_name="dup2.example.com")
        assert result["ok"] is False

    def test_server_cert_with_san(self, conn, ca):
        from app.services.cert_manager import create_server_cert
        result = create_server_cert(
            conn, ca_id=ca, name="SrvSAN", common_name="san.example.com",
            san_dns=["alt.example.com"], san_ip=["10.8.0.1"],
        )
        assert result["ok"] is True


# ---------------------------------------------------------------------------
# Client certificate
# ---------------------------------------------------------------------------

class TestCreateClientCert:

    def test_create_client_cert_success(self, conn, ca):
        from app.services.cert_manager import create_client_cert
        result = create_client_cert(conn, ca_id=ca, name="ClientCert",
                                     common_name="alice")
        assert result["ok"] is True

    def test_client_cert_key_encrypted(self, conn, ca):
        from app.services.cert_manager import create_client_cert
        result = create_client_cert(conn, ca_id=ca, name="ClientKey",
                                     common_name="bob")
        rows = conn.execute(
            "SELECT private_key_enc FROM certificates WHERE id=?", (result["id"],)
        ).fetchall()
        assert rows[0][0].startswith("enc:")


# ---------------------------------------------------------------------------
# Revoke
# ---------------------------------------------------------------------------

class TestRevokeCert:

    def test_revoke_client_cert(self, conn, ca):
        from app.services.cert_manager import create_client_cert, revoke_cert
        result = create_client_cert(conn, ca_id=ca, name="ToRevoke", common_name="carol")
        rev = revoke_cert(conn, result["id"])
        assert rev["ok"] is True
        row = conn.execute(
            "SELECT revoked FROM certificates WHERE id=?", (result["id"],)
        ).fetchone()
        assert row[0] == 1

    def test_revoke_ca_fails(self, conn, ca):
        from app.services.cert_manager import revoke_cert
        result = revoke_cert(conn, ca)
        assert result["ok"] is False
        assert "CA" in result["message"]

    def test_revoke_nonexistent_fails(self, conn):
        from app.services.cert_manager import revoke_cert
        result = revoke_cert(conn, 99999)
        assert result["ok"] is False


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

class TestValidateCertRow:

    def test_valid_cert_no_errors(self, conn, ca):
        from app.services.cert_manager import create_server_cert, validate_cert_row
        create_server_cert(conn, ca_id=ca, name="ValidateSrv", common_name="v.example.com")
        rows = conn.execute(
            "SELECT * FROM certificates WHERE name='ValidateSrv'"
        ).fetchall()
        row = dict(rows[0])
        errors = validate_cert_row(row)
        assert errors == []

    def test_empty_cn_is_error(self):
        from app.services.cert_manager import validate_cert_row
        errors = validate_cert_row({"common_name": "", "not_after": "", "revoked": 0})
        assert any("Common name" in e for e in errors)

    def test_revoked_cert_is_error(self):
        from app.services.cert_manager import validate_cert_row
        errors = validate_cert_row({
            "common_name": "test", "not_after": "2099-01-01T00:00:00+00:00",
            "revoked": 1,
        })
        assert any("revoked" in e.lower() for e in errors)


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

class TestExport:

    def test_get_cert_pem_returns_pem(self, conn, ca):
        from app.services.cert_manager import get_cert_pem
        pem = get_cert_pem(conn, ca)
        assert pem.startswith("-----BEGIN CERTIFICATE-----")

    def test_get_cert_pem_not_found_returns_empty(self, conn):
        from app.services.cert_manager import get_cert_pem
        assert get_cert_pem(conn, 99999) == ""

    def test_export_pkcs12_returns_bytes(self, conn, ca):
        from app.services.cert_manager import create_client_cert, export_pkcs12
        result = create_client_cert(conn, ca_id=ca, name="P12Client", common_name="dave")
        p12 = export_pkcs12(conn, result["id"], password="test123")
        assert isinstance(p12, bytes)
        assert len(p12) > 10  # must produce some output

    def test_export_pkcs12_no_password(self, conn, ca):
        from app.services.cert_manager import create_client_cert, export_pkcs12
        result = create_client_cert(conn, ca_id=ca, name="P12NoPass", common_name="eve")
        p12 = export_pkcs12(conn, result["id"], password="")
        assert isinstance(p12, bytes)
        assert len(p12) > 10

    def test_mask_cert_fields_removes_private_key(self, conn, ca):
        from app.services.cert_manager import mask_cert_fields
        row = {
            "id": 1, "name": "test", "cert_pem": "PEM...",
            "private_key_enc": "enc:secret"
        }
        safe = mask_cert_fields(row)
        assert "private_key_enc" not in safe
        assert "cert_pem" not in safe
        assert safe["name"] == "test"


# ---------------------------------------------------------------------------
# List
# ---------------------------------------------------------------------------

class TestListCerts:

    def test_list_returns_all(self, conn, ca):
        from app.services.cert_manager import list_certs, create_server_cert
        create_server_cert(conn, ca_id=ca, name="ListSrv", common_name="ls.example.com")
        certs = list_certs(conn)
        assert len(certs) >= 2   # at least the CA + server cert

    def test_list_filtered_by_type(self, conn, ca):
        from app.services.cert_manager import list_certs
        certs = list_certs(conn, cert_type="ca")
        assert all(c["cert_type"] == "ca" for c in certs)

    def test_list_does_not_expose_private_key(self, conn, ca):
        from app.services.cert_manager import list_certs
        certs = list_certs(conn)
        for c in certs:
            assert "private_key_enc" not in c
