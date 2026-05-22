"""
app/totp.py
-----------
RFC 6238 TOTP (Time-based One-Time Password) — stdlib-only implementation.

Used by the SOC portal MFA flow. Secrets are stored AES-GCM-encrypted via
`app.secret_store`; this module only handles secret generation, the
otpauth:// provisioning URI for authenticator apps, and code verification
with a small clock-drift window.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
import time
from urllib.parse import quote


_DIGITS  = 6
_PERIOD  = 30
_ALG     = "SHA1"


def generate_secret(num_bytes: int = 20) -> str:
    """
    Return a fresh base32-encoded TOTP secret. 20 bytes (= 160 bits) matches
    the recommendation in RFC 6238 §5.1 for HMAC-SHA1.
    """
    raw = os.urandom(num_bytes)
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def provisioning_uri(secret: str, account: str, issuer: str = "Smart Shield SOC") -> str:
    """
    Build the otpauth:// URI for QR-code enrollment in any standard
    authenticator app (Google Authenticator, Authy, 1Password, Bitwarden…).
    """
    label = f"{issuer}:{account}"
    params = (
        f"secret={secret}"
        f"&issuer={quote(issuer)}"
        f"&algorithm={_ALG}"
        f"&digits={_DIGITS}"
        f"&period={_PERIOD}"
    )
    return f"otpauth://totp/{quote(label)}?{params}"


def _hotp(secret_b32: str, counter: int) -> str:
    # base32 secrets may be entered by users without padding; restore it.
    padded = secret_b32 + "=" * (-len(secret_b32) % 8)
    try:
        key = base64.b32decode(padded, casefold=True)
    except Exception:
        return ""
    msg    = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code   = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** _DIGITS)
    return str(code).zfill(_DIGITS)


def verify(secret_b32: str, submitted_code: str, window: int = 1) -> bool:
    """
    Return True if *submitted_code* matches the TOTP for *secret_b32* within
    ±*window* steps (default ±30 s either side). Constant-time comparison.
    """
    if not secret_b32 or not submitted_code:
        return False
    code = (submitted_code or "").strip().replace(" ", "")
    if len(code) != _DIGITS or not code.isdigit():
        return False
    counter = int(time.time()) // _PERIOD
    for step in range(-window, window + 1):
        expected = _hotp(secret_b32, counter + step)
        if expected and hmac.compare_digest(expected, code):
            return True
    return False


def current_code(secret_b32: str) -> str:
    """Return the code that should be valid right now — used by tests only."""
    return _hotp(secret_b32, int(time.time()) // _PERIOD)
