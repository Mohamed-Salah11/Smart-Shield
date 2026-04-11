from werkzeug.security import generate_password_hash


HASH_PREFIX = "hash:"


def seal(plaintext: str) -> str:
    """
    One-way sealing used for prototype-stage secret-at-rest hardening.
    For credentials that must be re-rendered later, migrate to a dedicated
    encrypted secret backend.
    """
    if plaintext is None:
        return ""
    value = str(plaintext)
    if value == "":
        return ""
    return f"{HASH_PREFIX}{generate_password_hash(value)}"


def unseal(value: str) -> str:
    # One-way seal cannot be reversed; return empty by design.
    return ""
