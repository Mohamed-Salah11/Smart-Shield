import os
import sys
import tempfile


def _default_db_path() -> str:
    if sys.platform.startswith("freebsd"):
        return "/var/db/smart-shield/data.db"
    if sys.platform.startswith("win"):
        local_appdata = os.getenv("LOCALAPPDATA") or tempfile.gettempdir()
        return os.path.join(local_appdata, "SmartShield", "data.db")
    return "data.db"


def _default_config_path() -> str:
    if sys.platform.startswith("freebsd"):
        return "/usr/local/etc/smart-shield/config.json"
    return "config.json"


def _default_upload_dir() -> str:
    if sys.platform.startswith("freebsd"):
        return "/var/db/smart-shield/uploads/profile_pictures"
    return os.path.join("static", "uploads", "profile_pictures")


def _default_audit_log() -> str:
    if sys.platform.startswith("freebsd"):
        return "/var/log/smart-shield/audit.log"
    return os.path.join("logs", "audit.log")


def _default_app_log() -> str:
    if sys.platform.startswith("freebsd"):
        return "/var/log/smart-shield/app.log"
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

    # -------------------------------------------------------- Bootstrap admin
    # Credentials used to create the first admin account when no users exist.
    BOOTSTRAP_ADMIN_USERNAME: str = os.getenv("BOOTSTRAP_ADMIN_USERNAME", "admin")
    BOOTSTRAP_ADMIN_PASSWORD: str = os.getenv("BOOTSTRAP_ADMIN_PASSWORD", "")

    # ---------------------------------------------------------- Secrets store
    # Base64-encoded 32-byte AES-256-GCM master key for reversible encryption
    # (VPN PSKs, PPPoE passwords, RADIUS secrets, etc.).
    # If blank, a key is auto-generated on first use and persisted to disk.
    MASTER_KEY: str = os.getenv("SMARTSHIELD_MASTER_KEY", "")

    # ------------------------------------------------------ AI Chatbot (Claude)
    ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")

    # ------------------------------------------------------ Upload constraints
    MAX_CONTENT_LENGTH: int = 2 * 1024 * 1024  # 2 MB max upload size
    ALLOWED_IMAGE_EXTENSIONS: frozenset = frozenset({"png", "jpg", "jpeg", "gif", "webp"})


class DevelopmentConfig(Config):
    DEBUG = True
    TESTING = False


class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True  # requires HTTPS


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
