"""Shared password policy.

Used by the setup wizard (first admin), user-management routes (admin creates
or resets an account), and any future password-change surfaces. Keeping these
rules in one place ensures the first admin cannot be created with a weaker
password than later admins.
"""

from __future__ import annotations

# A very small in-process blocklist of trivially weak passwords. This is not
# intended to replace a full corpus check (have-i-been-pwned, etc.) — it just
# catches the cases that show up in casual brute-force lists.
_COMMON_PASSWORDS = frozenset({
    "password", "password1", "password123", "passw0rd",
    "12345678", "123456789", "1234567890", "qwerty123",
    "letmein", "welcome", "admin", "administrator",
    "smartshield", "smartshield1", "changeme", "default",
    "iloveyou", "monkey", "dragon", "football",
    "superuser", "root", "freebsd", "pfsense", "opnsense",
})

MIN_LENGTH = 12


def validate_password(password: str, *, username: str | None = None) -> list[str]:
    """Return a list of human-readable rule violations. Empty list = OK.

    Rules:
      - Minimum length :data:`MIN_LENGTH` characters.
      - Must contain at least one letter and one digit (cheap complexity gate).
      - Must not equal or contain the username case-insensitively.
      - Must not be in the common-passwords blocklist.
    """
    pw = password or ""
    errors: list[str] = []

    if len(pw) < MIN_LENGTH:
        errors.append(f"Password must be at least {MIN_LENGTH} characters.")
    has_alpha = any(c.isalpha() for c in pw)
    has_digit = any(c.isdigit() for c in pw)
    if not (has_alpha and has_digit):
        errors.append("Password must contain both letters and digits.")
    if username:
        uname = username.strip().lower()
        if uname and uname in pw.lower():
            errors.append("Password must not contain the username.")
    if pw.lower() in _COMMON_PASSWORDS:
        errors.append("Password is too common; choose a less guessable one.")

    return errors
