"""
app/secret_store.py
-------------------
Reversible secret storage using AES-256-GCM.

Service credentials that must later be rendered into config files
(VPN PSKs, PPPoE passwords, L2TP secrets, RADIUS secrets, etc.) are
encrypted with a per-deployment master key stored outside the database.

Login user passwords must NEVER pass through this module — they are
one-way bcrypt hashes managed directly by werkzeug.security.

Master key resolution order:
  1. SMARTSHIELD_MASTER_KEY environment variable (base64-encoded 32 bytes)
  2. /usr/local/etc/smart-shield/master.key  (FreeBSD production)
  3. %LOCALAPPDATA%/SmartShield/master.key   (Windows dev)
  4. Auto-generated and persisted to the file path above (first run)
"""

import base64
import os
import secrets as _secrets
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_ENC_PREFIX = "enc:"
_HASH_PREFIX = "hash:"   # legacy one-way sealed values — cannot be decrypted

_MASTER_KEY_ENV = "SMARTSHIELD_MASTER_KEY"


def _master_key_path() -> str:
    if sys.platform.startswith("freebsd"):
        return "/usr/local/etc/smart-shield/master.key"
    local = os.getenv("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(local, "SmartShield", "master.key")


def _load_master_key() -> bytes:
    # 1. Environment variable — preferred for containers, CI, and testing.
    env_val = os.getenv(_MASTER_KEY_ENV, "").strip()
    if env_val:
        try:
            raw = base64.b64decode(env_val)
        except Exception:
            raise RuntimeError(f"{_MASTER_KEY_ENV} is not valid base64")
        if len(raw) != 32:
            raise RuntimeError(
                f"{_MASTER_KEY_ENV} must decode to exactly 32 bytes (44 base64 chars)"
            )
        return raw

    # 2. Key file.
    path = _master_key_path()
    if os.path.exists(path):
        with open(path, "rb") as fh:
            raw = base64.b64decode(fh.read().strip())
        if len(raw) != 32:
            raise RuntimeError(
                f"Master key at {path!r} must decode to exactly 32 bytes"
            )
        return raw

    # 3. Generate a new key and persist it (first-run bootstrap).
    raw = _secrets.token_bytes(32)
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(base64.b64encode(raw))
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return raw


def encrypt_secret(plaintext: str) -> str:
    """
    Encrypt *plaintext* with AES-256-GCM and return a portable string
    of the form ``enc:<base64(nonce + ciphertext)>``.

    Returns "" for empty or None input.
    """
    if not plaintext:
        return ""
    key = _load_master_key()
    aesgcm = AESGCM(key)
    nonce = _secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    blob = base64.b64encode(nonce + ct).decode("ascii")
    return f"{_ENC_PREFIX}{blob}"


def decrypt_secret(value: str) -> str:
    """
    Decrypt a value produced by :func:`encrypt_secret`.

    * Returns ``""`` for empty / None input.
    * Returns ``""`` for legacy ``hash:`` one-way sealed values (irrecoverable).
    * Returns the original plaintext for un-prefixed values stored before
      encryption was introduced (migration safety).
    * Returns ``""`` on any decryption error (wrong key, corrupted data, etc.).
    """
    if not value:
        return ""
    value = value.strip()

    if value.startswith(_HASH_PREFIX):
        # Legacy one-way hash — cannot be reversed.
        # The caller should prompt the user to re-enter the secret.
        return ""

    if not value.startswith(_ENC_PREFIX):
        # Plain-text value stored before encryption was introduced.
        return value

    blob = value[len(_ENC_PREFIX):]
    try:
        raw = base64.b64decode(blob)
        if len(raw) < 12:
            return ""
        nonce, ct = raw[:12], raw[12:]
        key = _load_master_key()
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ct, None).decode("utf-8")
    except Exception:
        return ""


def mask_secret(value: str) -> str:
    """Return a safe placeholder for UI / log display. Never reveals the value."""
    if not value:
        return ""
    return "••••••••"


# ---------------------------------------------------------------------------
# Backward-compatibility shims
# ---------------------------------------------------------------------------

def seal(plaintext: str) -> str:
    """Alias for :func:`encrypt_secret`."""
    return encrypt_secret(plaintext)


def unseal(value: str) -> str:
    """Alias for :func:`decrypt_secret`."""
    return decrypt_secret(value)
