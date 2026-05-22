import os
import sys
import tempfile


# Phase 11: internal path rename from `smart-shield` → `smartshield`.
# Resolution order on FreeBSD: pick whichever directory already exists; if
# neither exists yet (fresh install), prefer the new `smartshield` paths.
# This lets existing installs (smart-shield) and new installs (smartshield)
# coexist with no breakage. install.sh / rc.d / nginx examples can migrate
# the install-time directory naming when the rename ships.
def _ss_dir(parent: str, *, subdir_new: str = "smartshield",
            subdir_old: str = "smart-shield") -> str:
    if os.path.isdir(os.path.join(parent, subdir_old)) and \
       not os.path.isdir(os.path.join(parent, subdir_new)):
        return os.path.join(parent, subdir_old)
    return os.path.join(parent, subdir_new)


def _default_db_path() -> str:
    if sys.platform.startswith("freebsd"):
        return os.path.join(_ss_dir("/var/db"), "data.db")
    if sys.platform.startswith("win"):
        local_appdata = os.getenv("LOCALAPPDATA") or tempfile.gettempdir()
        return os.path.join(local_appdata, "SmartShield", "data.db")
    return "data.db"


def _default_config_path() -> str:
    if sys.platform.startswith("freebsd"):
        return os.path.join(_ss_dir("/usr/local/etc"), "config.json")
    return "config.json"


def _default_upload_dir() -> str:
    if sys.platform.startswith("freebsd"):
        return os.path.join(_ss_dir("/var/db"), "uploads", "profile_pictures")
    return os.path.join("static", "uploads", "profile_pictures")


def _default_audit_log() -> str:
    if sys.platform.startswith("freebsd"):
        return os.path.join(_ss_dir("/var/log"), "audit.log")
    return os.path.join("logs", "audit.log")


def _default_app_log() -> str:
    if sys.platform.startswith("freebsd"):
        return os.path.join(_ss_dir("/var/log"), "app.log")
    return os.path.join("logs", "app.log")


class Config:
    # ------------------------------------------------------------------ Flask
    SECRET_KEY: str = os.getenv("SECRET_KEY", "")
    DEBUG: bool = os.getenv("FLASK_DEBUG", "0") == "1"
    TESTING: bool = False

    # Session hardening
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = "Lax"
    SESSION_COOKIE_SECURE: bool = False  # overridden to True in ProductionConfig
    PERMANENT_SESSION_LIFETIME: int = 3600  # seconds

    # ---------------------------------------------------------------- Database
    DB_PATH: str = os.getenv("SMARTSHIELD_DB_PATH", "") or _default_db_path()

    # ------------------------------------------------------------------ Paths
    CONFIG_PATH: str = os.getenv("SMARTSHIELD_CONFIG_PATH", "") or _default_config_path()
    UPLOAD_DIR: str = os.getenv("SMARTSHIELD_UPLOAD_DIR", "") or _default_upload_dir()
    AUDIT_LOG_PATH: str = os.getenv("SMARTSHIELD_AUDIT_LOG_PATH", "") or _default_audit_log()
    APP_LOG_PATH: str = os.getenv("SMARTSHIELD_APP_LOG_PATH", "") or _default_app_log()

    # --------------------------------------------------------- Network control
    # Set SMARTSHIELD_ENABLE_NETWORK_APPLY=1 on a real FreeBSD appliance to
    # allow the app to write config files and restart services.
    ENABLE_NETWORK_APPLY: bool = os.getenv("SMARTSHIELD_ENABLE_NETWORK_APPLY", "0") == "1"

    # Set SMARTSHIELD_NETWORK_DRY_RUN=1 to log commands without executing them.
    NETWORK_DRY_RUN: bool = os.getenv("SMARTSHIELD_NETWORK_DRY_RUN", "0") == "1"

    # Deployment-time kill switch for the in-browser appliance console.
    # Even when a superuser has flipped the DB toggle on, the terminal stays
    # 404 unless this env var is "1". Hardened deployments leave it unset.
    TERMINAL_ENABLED: bool = os.getenv("SMARTSHIELD_TERMINAL_ENABLED", "0") == "1"

    # Reveal unfinished/placeholder pages (about, docs, bug, forum, survey,
    # upgrade, dhcpv6_leases, authentication, edit_file, freebsd). Off by
    # default in production so the UI doesn't expose "Placeholder for …"
    # stubs; flip to 1 in development to render them.
    ENABLE_UNFINISHED_PAGES: bool = os.getenv("SMARTSHIELD_ENABLE_UNFINISHED_PAGES", "0") == "1"

    # -------------------------------------------------------- Bootstrap admin
    # Credentials used to create the first admin account when no users exist.
    BOOTSTRAP_ADMIN_USERNAME: str = os.getenv("BOOTSTRAP_ADMIN_USERNAME", "admin")
    BOOTSTRAP_ADMIN_PASSWORD: str = os.getenv("BOOTSTRAP_ADMIN_PASSWORD", "")

    # ---------------------------------------------------------- Secrets store
    # Base64-encoded 32-byte AES-256-GCM master key for reversible encryption
    # (VPN PSKs, PPPoE passwords, RADIUS secrets, etc.).
    # If blank, a key is auto-generated on first use and persisted to disk.
    MASTER_KEY: str = os.getenv("SMARTSHIELD_MASTER_KEY", "")

    # ------------------------------------------------------ AI Chatbot (Groq)
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")

    # ---------------------------------------------- Threat intelligence (abuse.ch)
    ABUSECH_AUTH_KEY: str = os.getenv("ABUSECH_AUTH_KEY", "")

    # ------------------------------------------------------ Upload constraints
    MAX_CONTENT_LENGTH: int = 2 * 1024 * 1024  # 2 MB max upload size
    ALLOWED_IMAGE_EXTENSIONS: frozenset = frozenset({"png", "jpg", "jpeg", "gif", "webp"})


class DevelopmentConfig(Config):
    DEBUG = True
    TESTING = False


class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True  # requires HTTPS

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)


_INSECURE_SECRET_KEYS = frozenset({
    "changeme",
    "change-me",
    "replace-this-with-a-long-random-secret",
    "replace-with-long-random-secret",
    "dev",
    "secret",
    "secretkey",
    "smartshield",
})


def _require_production_secret_key():
    # Fail fast at import time if running in production without a strong
    # SECRET_KEY. Without this, app/__init__.py's later check would still trip
    # — but the message here points operators at the appliance env file
    # directly and catches the most common copy/paste mistakes.
    if os.getenv("APP_ENV", "development").lower() != "production":
        return
    env_file = os.getenv(
        "SMARTSHIELD_ENV_FILE",
        "/usr/local/etc/smartshield/smartshield.env",
    )
    raw = os.getenv("SECRET_KEY", "").strip()
    if not raw:
        raise RuntimeError(
            "SECRET_KEY is required in production. Set it in "
            f"{env_file} (bsd/install.sh creates this file on a fresh install)."
        )
    if raw.lower() in _INSECURE_SECRET_KEYS:
        raise RuntimeError(
            "SECRET_KEY matches a known weak/default value. Regenerate it "
            f"in {env_file} (e.g. python3 -c \"import secrets; "
            "print(secrets.token_hex(32))\")."
        )
    if len(raw) < 32:
        raise RuntimeError(
            f"SECRET_KEY is too short ({len(raw)} chars); production requires "
            f">= 32 chars. Regenerate it in {env_file}."
        )


_require_production_secret_key()


class TestingConfig(Config):
    TESTING = True
    DEBUG = True
    # In-memory SQLite shared cache — resets between test runs.
    DB_PATH = "file::memory:?cache=shared"
    # Disable CSRF checks in tests (handled separately in conftest).
    ENABLE_NETWORK_APPLY = False
    NETWORK_DRY_RUN = True


# Map the FLASK_ENV / APP_ENV variable to the right config class.
_CONFIG_MAP = {
    "development": DevelopmentConfig,
    "production":  ProductionConfig,
    "testing":     TestingConfig,
}


def get_config() -> type:
    """Return the Config class matching the APP_ENV environment variable."""
    env = os.getenv("APP_ENV", "development").lower()
    return _CONFIG_MAP.get(env, DevelopmentConfig)
