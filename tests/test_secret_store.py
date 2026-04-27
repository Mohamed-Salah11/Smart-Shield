"""
tests/test_secret_store.py
--------------------------
Tests for AES-GCM secret encryption / decryption.
"""

import os
import base64
import secrets

import pytest

# Ensure a fresh test master key is set (conftest already sets one,
# but this module can also run standalone).
_KEY = base64.b64encode(secrets.token_bytes(32)).decode()
os.environ.setdefault("SMARTSHIELD_MASTER_KEY", _KEY)

from app.secret_store import (
    encrypt_secret,
    decrypt_secret,
    mask_secret,
    seal,
    unseal,
)


class TestEncryptDecrypt:
    def test_roundtrip_basic(self):
        plaintext = "my-super-secret-password"
        ct = encrypt_secret(plaintext)
        assert decrypt_secret(ct) == plaintext

    def test_roundtrip_special_chars(self):
        plaintext = 'p@$$w0rd!#%&*()<>?/\\"'
        assert decrypt_secret(encrypt_secret(plaintext)) == plaintext

    def test_roundtrip_unicode(self):
        plaintext = "mötörhead-röck"
        assert decrypt_secret(encrypt_secret(plaintext)) == plaintext

    def test_empty_input_returns_empty(self):
        assert encrypt_secret("") == ""
        assert encrypt_secret(None) == ""
        assert decrypt_secret("") == ""
        assert decrypt_secret(None) == ""

    def test_ciphertext_is_prefixed(self):
        ct = encrypt_secret("value")
        assert ct.startswith("enc:")

    def test_ciphertexts_are_unique(self):
        """Same plaintext produces different ciphertexts (random nonce)."""
        ct1 = encrypt_secret("same")
        ct2 = encrypt_secret("same")
        assert ct1 != ct2

    def test_different_plaintexts_different_ct(self):
        assert encrypt_secret("a") != encrypt_secret("b")


class TestDecryptLegacy:
    def test_legacy_hash_prefix_returns_empty(self):
        """Old one-way hashed values (hash:...) cannot be decrypted."""
        legacy = "hash:pbkdf2:sha256:260000$abc$def"
        assert decrypt_secret(legacy) == ""

    def test_plain_text_without_prefix_returned_as_is(self):
        """Values stored before encryption was introduced are returned as-is."""
        assert decrypt_secret("plaintext-value") == "plaintext-value"

    def test_corrupted_ciphertext_returns_empty(self):
        """Corrupted enc: value returns empty rather than raising."""
        assert decrypt_secret("enc:notvalidbase64!!!") == ""

    def test_wrong_key_returns_empty(self, monkeypatch):
        """Decryption with a different key returns empty (auth tag mismatch)."""
        ct = encrypt_secret("secret value")

        # Replace the master key with a different one.
        other_key = base64.b64encode(secrets.token_bytes(32)).decode()
        monkeypatch.setenv("SMARTSHIELD_MASTER_KEY", other_key)

        # Force _load_master_key to re-read env by clearing the module-level cache.
        # (There is no cache in our implementation — it reads env each call.)
        assert decrypt_secret(ct) == ""


class TestMaskSecret:
    def test_non_empty_returns_placeholder(self):
        assert mask_secret("anything") == "••••••••"

    def test_empty_returns_empty(self):
        assert mask_secret("") == ""
        assert mask_secret(None) == ""

    def test_does_not_reveal_value(self):
        value = "super-secret"
        masked = mask_secret(value)
        assert value not in masked


class TestBackwardCompatAliases:
    def test_seal_alias(self):
        ct = seal("value")
        assert ct.startswith("enc:")

    def test_unseal_alias(self):
        ct = seal("roundtrip")
        assert unseal(ct) == "roundtrip"
