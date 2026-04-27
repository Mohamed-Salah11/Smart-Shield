"""
tests/test_ipsec_writer.py
--------------------------
Unit tests for app/services/ipsec_writer.py.
No FreeBSD required.
"""
import os
import pytest

os.environ.setdefault("SMARTSHIELD_DB_PATH", "file:ipsectest?mode=memory&cache=shared")
os.environ.setdefault("SECRET_KEY", "test-ipsec-key")
os.environ.setdefault("SMARTSHIELD_MASTER_KEY",
    __import__("base64").b64encode(__import__("secrets").token_bytes(32)).decode())


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def p1_row():
    return {
        "id": 1, "disabled": 0,
        "ike_version": "ikev2",
        "remote_gateway": "203.0.113.1",
        "auth_method": "mutual-psk",
        "my_identifier": "my-ip",
        "peer_identifier": "peer-ip",
        "pre_shared_key": "",           # will be set per test
        "p1_life_time": 28800,
        "dpd_enable": 1, "dpd_delay": 10, "dpd_max_failures": 5,
        "nat_traversal": "auto",
        "description": "Test tunnel",
    }


@pytest.fixture()
def alg_row():
    return {
        "encryption": "aes256",
        "key_length": None,
        "hash": "sha256",
        "dh_group": "modp2048",
    }


@pytest.fixture()
def p2_row():
    return {
        "id": 1, "phase1_id": 1, "disabled": 0,
        "mode": "tunnel",
        "local_network": "192.168.1.0/24",
        "remote_network": "10.10.0.0/24",
        "protocol": "esp",
        "encryption_algorithms": "aes256",
        "hash_algorithms": "sha256",
        "pfs_key_group": "14",
        "lifetime": 3600,
    }


# ---------------------------------------------------------------------------
# Config generation
# ---------------------------------------------------------------------------

class TestGenerateIpsecConf:

    def test_config_setup_section(self):
        import secrets
        os.environ["SMARTSHIELD_DB_PATH"] = f"file:ipsec_{secrets.token_hex(4)}?mode=memory&cache=shared"
        from app.database import init_db, get_db
        from app.services.ipsec_writer import generate_ipsec_conf
        init_db()
        conn = get_db()
        conf = generate_ipsec_conf(conn)
        assert "config setup" in conf

    def test_tunnel_conn_generated(self, p1_row):
        import secrets
        os.environ["SMARTSHIELD_DB_PATH"] = f"file:ipsec_{secrets.token_hex(4)}?mode=memory&cache=shared"
        from app.database import init_db, get_db
        from app.services.ipsec_writer import generate_ipsec_conf
        from app.secret_store import encrypt_secret
        init_db()
        conn = get_db()
        p1_row["pre_shared_key"] = encrypt_secret("mysecret")
        conn.execute(
            "INSERT INTO ipsec_phase1 (disabled, ike_version, remote_gateway, auth_method, "
            "my_identifier, peer_identifier, pre_shared_key, p1_life_time, dpd_enable, "
            "dpd_delay, dpd_max_failures, nat_traversal, description) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (p1_row["disabled"], p1_row["ike_version"], p1_row["remote_gateway"],
             p1_row["auth_method"], p1_row["my_identifier"], p1_row["peer_identifier"],
             p1_row["pre_shared_key"], p1_row["p1_life_time"], p1_row["dpd_enable"],
             p1_row["dpd_delay"], p1_row["dpd_max_failures"], p1_row["nat_traversal"],
             p1_row["description"]),
        )
        conn.commit()
        conf = generate_ipsec_conf(conn)
        assert "conn tunnel_" in conf
        assert "203.0.113.1" in conf
        assert "keyexchange=ikev2" in conf

    def test_secrets_file_contains_psk(self):
        import secrets
        os.environ["SMARTSHIELD_DB_PATH"] = f"file:ipsec_{secrets.token_hex(4)}?mode=memory&cache=shared"
        from app.database import init_db, get_db
        from app.services.ipsec_writer import generate_ipsec_secrets
        from app.secret_store import encrypt_secret
        init_db()
        conn = get_db()
        conn.execute(
            "INSERT INTO ipsec_pre_shared_keys (identifier, secret_type, pre_shared_key) "
            "VALUES ('testpeer', 'psk', ?)",
            (encrypt_secret("correcthorsebattery"),),
        )
        conn.commit()
        secrets_text = generate_ipsec_secrets(conn)
        assert "correcthorsebattery" in secrets_text

    def test_secrets_hashed_psk_produces_empty(self):
        import secrets
        os.environ["SMARTSHIELD_DB_PATH"] = f"file:ipsec_{secrets.token_hex(4)}?mode=memory&cache=shared"
        from app.database import init_db, get_db
        from app.services.ipsec_writer import generate_ipsec_secrets
        init_db()
        conn = get_db()
        # Legacy hash: prefix "hash:" — cannot be decrypted → skipped
        conn.execute(
            "INSERT INTO ipsec_pre_shared_keys (identifier, secret_type, pre_shared_key) "
            "VALUES ('testpeer', 'psk', 'hash:pbkdf2:sha256:...')",
        )
        conn.commit()
        secrets_text = generate_ipsec_secrets(conn)
        # The PSK entry should be skipped (empty key)
        assert "PSK" not in secrets_text or "testpeer" not in secrets_text


# ---------------------------------------------------------------------------
# Phase 1 validation
# ---------------------------------------------------------------------------

class TestValidatePhase1:

    def test_valid_p1_no_errors(self, p1_row, alg_row):
        from app.services.ipsec_writer import validate_phase1
        from app.secret_store import encrypt_secret
        p1_row["pre_shared_key"] = encrypt_secret("strongpassword")
        errors = validate_phase1(p1_row, [alg_row])
        assert errors == []

    def test_missing_remote_gateway(self, p1_row, alg_row):
        from app.services.ipsec_writer import validate_phase1
        from app.secret_store import encrypt_secret
        p1_row["pre_shared_key"] = encrypt_secret("pass")
        p1_row["remote_gateway"] = ""
        errors = validate_phase1(p1_row, [alg_row])
        assert any("Remote gateway" in e for e in errors)

    def test_unknown_ike_version(self, p1_row, alg_row):
        from app.services.ipsec_writer import validate_phase1
        from app.secret_store import encrypt_secret
        p1_row["pre_shared_key"] = encrypt_secret("pass")
        p1_row["ike_version"] = "ikev99"
        errors = validate_phase1(p1_row, [alg_row])
        assert any("IKE version" in e for e in errors)

    def test_no_algorithms_error(self, p1_row):
        from app.services.ipsec_writer import validate_phase1
        from app.secret_store import encrypt_secret
        p1_row["pre_shared_key"] = encrypt_secret("pass")
        errors = validate_phase1(p1_row, [])
        assert any("algorithm" in e.lower() for e in errors)

    def test_psk_missing_error(self, p1_row, alg_row):
        from app.services.ipsec_writer import validate_phase1
        p1_row["pre_shared_key"] = ""
        errors = validate_phase1(p1_row, [alg_row])
        assert any("PSK" in e or "pre-shared" in e.lower() for e in errors)

    def test_very_short_lifetime_warning(self, p1_row, alg_row):
        from app.services.ipsec_writer import validate_phase1
        from app.secret_store import encrypt_secret
        p1_row["pre_shared_key"] = encrypt_secret("pass")
        p1_row["p1_life_time"] = 60  # very short
        errors = validate_phase1(p1_row, [alg_row])
        assert any("lifetime" in e.lower() for e in errors)

    def test_unknown_encryption_alg(self, p1_row, alg_row):
        from app.services.ipsec_writer import validate_phase1
        from app.secret_store import encrypt_secret
        p1_row["pre_shared_key"] = encrypt_secret("pass")
        alg_row["encryption"] = "rc4"
        errors = validate_phase1(p1_row, [alg_row])
        assert any("encryption" in e.lower() for e in errors)


# ---------------------------------------------------------------------------
# Phase 2 validation
# ---------------------------------------------------------------------------

class TestValidatePhase2:

    def test_valid_p2_no_errors(self, p2_row):
        from app.services.ipsec_writer import validate_phase2
        assert validate_phase2(p2_row) == []

    def test_invalid_local_network(self, p2_row):
        from app.services.ipsec_writer import validate_phase2
        p2_row["local_network"] = "not-a-cidr"
        errors = validate_phase2(p2_row)
        assert any("Local" in e for e in errors)

    def test_invalid_remote_network(self, p2_row):
        from app.services.ipsec_writer import validate_phase2
        p2_row["remote_network"] = "bad"
        errors = validate_phase2(p2_row)
        assert any("Remote" in e for e in errors)

    def test_short_lifetime(self, p2_row):
        from app.services.ipsec_writer import validate_phase2
        p2_row["lifetime"] = 30
        errors = validate_phase2(p2_row)
        assert any("lifetime" in e.lower() for e in errors)


# ---------------------------------------------------------------------------
# apply dry-run
# ---------------------------------------------------------------------------

class TestApplyIpsec:

    def test_apply_dry_run_no_tunnels(self):
        import secrets
        os.environ["SMARTSHIELD_DB_PATH"] = f"file:ipsec_{secrets.token_hex(4)}?mode=memory&cache=shared"
        from app.database import init_db, get_db
        from app.services.ipsec_writer import apply_ipsec
        init_db()
        conn = get_db()
        result = apply_ipsec(conn)
        # No Phase 1 tunnels → validation passes, non-FreeBSD → dry-run OK
        assert result["ok"] is True
