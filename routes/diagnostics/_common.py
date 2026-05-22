import base64
import binascii
import hashlib
import io
import json
import os
import re
import shutil
import stat
import sys
import tempfile
from datetime import datetime, timezone

from flask import (
    Blueprint,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)

try:
    import yaml
except ImportError:
    yaml = None

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    AESGCM = None

from app import audit_log as audit_log_module
from app import database as database_module
from app.audit_log import log_event
from app.auth_utils import login_required, superuser_required, reauth_required, reauth_required_form
from app.uploads import get_upload_dir



SNAPSHOT_ENVELOPE_FORMAT = "smartshield-snapshot-envelope-v2"
SNAPSHOT_PAYLOAD_FORMAT = "smartshield-system-snapshot-v2"
SNAPSHOT_AAD = b"smartshield-snapshot-aad-v2"
MASKED_SECRET_VALUE = "FortinetPasswordMask"

TEXT_MASK_EXTENSIONS = {
    ".txt",
    ".log",
    ".json",
    ".yaml",
    ".yml",
    ".conf",
    ".cfg",
    ".ini",
    ".env",
}
SECRET_ASSIGNMENT_RE = re.compile(
    r'(?i)("?(?:password|secret|token|api[_-]?key|psk|private[_-]?key|auth|passphrase)"?\s*[:=]\s*)(["\']?)([^,"\r\n]*)(["\']?)'
)


class BackupFormatError(ValueError):
    """Raised when an uploaded backup file is invalid or unsupported."""


class BackupDependencyError(RuntimeError):
    """Raised when optional dependencies for backup features are missing."""


def _env_int(name, default, minimum=1):
    raw = os.getenv(name)
    try:
        value = int(raw) if raw is not None else int(default)
    except (TypeError, ValueError):
        value = int(default)
    return max(value, minimum)


def _env_bool(name, default=False):
    raw = os.getenv(name)
    if raw is None:
        return bool(default)
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def _max_backup_upload_bytes():
    return _env_int("SMARTSHIELD_BACKUP_MAX_BYTES", 256 * 1024 * 1024, minimum=1024 * 1024)


def _pbkdf2_iterations():
    return _env_int("SMARTSHIELD_BACKUP_PBKDF2_ITERATIONS", 390000, minimum=100000)


def _default_backup_dir():
    if sys.platform.startswith("freebsd"):
        from app.config import _ss_dir
        return os.path.join(_ss_dir("/var/db"), "backups")
    return "backups"


def _backup_dir():
    return os.getenv("SMARTSHIELD_BACKUP_DIR", _default_backup_dir())


def _usb_backup_dir():
    return (os.getenv("SMARTSHIELD_USB_BACKUP_DIR") or "").strip()


def _ensure_yaml_support():
    if yaml is None:
        raise BackupDependencyError("PyYAML is not installed. Install requirements and try again.")


def _ensure_crypto_support():
    if AESGCM is None:
        raise BackupDependencyError("cryptography is not installed. Install requirements for encrypted backups.")


def _general_config_path():
    if sys.platform.startswith("freebsd"):
        from app.config import _ss_dir
        default_config_path = os.path.join(_ss_dir("/usr/local/etc"), "config.json")
    else:
        default_config_path = "config.json"
    return os.getenv("SMARTSHIELD_CONFIG_PATH", default_config_path)


def _database_path():
    configured = os.getenv("SMARTSHIELD_DB_PATH")
    if configured:
        return configured

    path_fn = getattr(database_module, "_database_path", None)
    if callable(path_fn):
        try:
            return path_fn()
        except Exception:
            pass

    if sys.platform.startswith("freebsd"):
        from app.config import _ss_dir
        return os.path.join(_ss_dir("/var/db"), "data.db")
    if sys.platform.startswith("win"):
        local_appdata = os.getenv("LOCALAPPDATA") or tempfile.gettempdir()
        return os.path.join(local_appdata, "SmartShield", "data.db")
    return "data.db"


def _audit_log_path():
    configured = os.getenv("SMARTSHIELD_AUDIT_LOG_PATH")
    if configured:
        return configured

    path_fn = getattr(audit_log_module, "_audit_log_path", None)
    if callable(path_fn):
        try:
            return path_fn()
        except Exception:
            pass

    if sys.platform.startswith("freebsd"):
        from app.config import _ss_dir
        return os.path.join(_ss_dir("/var/log"), "audit.log")
    return os.path.join("logs", "audit.log")


def _load_general_config_file():
    config_path = _general_config_path()
    if not os.path.exists(config_path):
        return {}
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            loaded = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _safe_slug(value):
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "").strip()).strip("-")
    return slug or "smartshield"


def _normalize_abs(path):
    return os.path.abspath(os.path.expanduser(str(path)))


def _is_same_or_ancestor(candidate, other):
    candidate_abs = os.path.normcase(_normalize_abs(candidate))
    other_abs = os.path.normcase(_normalize_abs(other))
    return other_abs == candidate_abs or other_abs.startswith(candidate_abs + os.sep)


def _is_overly_broad_directory(path):
    abs_path = _normalize_abs(path)
    if _is_dangerous_target(abs_path):
        return True

    cwd_abs = _normalize_abs(os.getcwd())
    home_abs = _normalize_abs(os.path.expanduser("~"))
    temp_abs = _normalize_abs(tempfile.gettempdir())

    if _is_same_or_ancestor(abs_path, cwd_abs):
        return True
    if _is_same_or_ancestor(abs_path, home_abs):
        return True
    if _is_same_or_ancestor(abs_path, temp_abs):
        return True

    return False


def _b64_encode(raw_bytes):
    return base64.b64encode(raw_bytes).decode("ascii")


def _b64_decode(value, field_name):
    if not isinstance(value, str):
        raise BackupFormatError(f"Invalid backup {field_name}.")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise BackupFormatError(f"Invalid backup {field_name}.") from exc


def _payload_to_bytes(payload_obj):
    return json.dumps(payload_obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _normalize_yaml_value(value):
    if isinstance(value, dict):
        return {str(key): _normalize_yaml_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_normalize_yaml_value(item) for item in value]
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def _is_text_like_path(path):
    ext = os.path.splitext(path)[1].lower()
    if ext in TEXT_MASK_EXTENSIONS:
        return True
    basename = os.path.basename(path).lower()
    return basename in {"config", "settings", "audit", "audit.log"}


def _mask_secrets_in_text(text):
    def _replace(match):
        prefix, quote1, _value, quote2 = match.groups()
        quote = quote1 if quote1 else quote2
        return f"{prefix}{quote}{MASKED_SECRET_VALUE}{quote}"

    return SECRET_ASSIGNMENT_RE.sub(_replace, text)


def _maybe_mask_bytes(path, raw_bytes, mask_passwords):
    if not mask_passwords or not _is_text_like_path(path):
        return raw_bytes, False

    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return raw_bytes, False

    masked_text = _mask_secrets_in_text(text)
    if masked_text == text:
        return raw_bytes, False

    return masked_text.encode("utf-8"), True


def _derive_key(password, salt, iterations):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=32)


def _collect_log_roots():
    candidates = []

    audit_dir = os.path.dirname(_normalize_abs(_audit_log_path()))
    candidates.append(audit_dir)
    candidates.append(_normalize_abs("logs"))

    extra = os.getenv("SMARTSHIELD_EXTRA_LOG_DIRS", "")
    if extra:
        for item in extra.split(os.pathsep):
            item = item.strip()
            if item:
                candidates.append(_normalize_abs(item))

    roots = []
    seen = set()
    for path in candidates:
        norm = os.path.normcase(_normalize_abs(path))
        if norm in seen:
            continue
        seen.add(norm)
        roots.append(_normalize_abs(path))

    return roots


def _collect_config_roots():
    candidates = []
    default_config_root = _normalize_abs(os.path.dirname(_general_config_path()))

    include_default_config_dir = _env_bool(
        "SMARTSHIELD_INCLUDE_CONFIG_DIR",
        default=sys.platform.startswith("freebsd"),
    )
    if include_default_config_dir:
        candidates.append(default_config_root)

    extra = os.getenv("SMARTSHIELD_EXTRA_CONFIG_DIRS", "")
    if extra:
        for item in extra.split(os.pathsep):
            item = item.strip()
            if item:
                candidates.append(_normalize_abs(item))

    roots = []
    seen = set()
    for path in candidates:
        norm = os.path.normcase(_normalize_abs(path))
        if norm in seen:
            continue
        seen.add(norm)
        if _is_overly_broad_directory(path):
            continue
        roots.append(_normalize_abs(path))

    return roots


def _master_key_path():
    try:
        from app.secret_store import _master_key_path as _sk_path
        return _sk_path()
    except Exception:
        pass
    if sys.platform.startswith("freebsd"):
        from app.config import _ss_dir
        return os.path.join(_ss_dir("/usr/local/etc"), "master.key")
    local = os.getenv("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(local, "SmartShield", "master.key")


def _snapshot_component_definitions():
    db_path = _normalize_abs(_database_path())
    config_path = _normalize_abs(_general_config_path())
    upload_path = _normalize_abs(get_upload_dir())
    master_key_path = _normalize_abs(_master_key_path())

    definitions = [
        {"name": "database_main", "kind": "file", "path": db_path, "label": "Database"},
        {"name": "database_wal", "kind": "file", "path": f"{db_path}-wal", "label": "Database WAL"},
        {"name": "database_shm", "kind": "file", "path": f"{db_path}-shm", "label": "Database SHM"},
        {"name": "general_config", "kind": "file", "path": config_path, "label": "General Config"},
        {"name": "secret_master_key", "kind": "file", "path": master_key_path, "label": "Secret Master Key"},
        {"name": "uploads", "kind": "directory", "path": upload_path, "label": "Uploads"},
    ]

    for index, config_root in enumerate(_collect_config_roots(), start=1):
        definitions.append(
            {
                "name": f"config_dir_{index}",
                "kind": "directory",
                "path": _normalize_abs(config_root),
                "label": f"Config Directory {index}",
            }
        )

    for index, log_root in enumerate(_collect_log_roots(), start=1):
        definitions.append(
            {
                "name": f"log_dir_{index}",
                "kind": "directory",
                "path": _normalize_abs(log_root),
                "label": f"Log Directory {index}",
            }
        )

    # Additional critical files always included on FreeBSD
    if sys.platform.startswith("freebsd"):
        _extra_files = [
            ("/usr/local/etc/ipsec.secrets",                 "ipsec_secrets",    "IPsec Secrets"),
            ("/usr/local/etc/suricata/rules/local.rules",    "suricata_local_rules", "Suricata Local Rules"),
        ]
        for path, name, label in _extra_files:
            definitions.append({"name": name, "kind": "file",
                                 "path": _normalize_abs(path), "label": label})

        # OpenVPN key directory (certs exported by export_pki_to_disk)
        definitions.append({"name": "openvpn_keys", "kind": "directory",
                             "path": "/usr/local/etc/openvpn/keys", "label": "OpenVPN Keys"})

    return definitions


def _safe_relative_path(path_value):
    normalized = os.path.normpath(str(path_value or "")).replace("\\", "/")
    if normalized in {"", "."}:
        return ""
    normalized = normalized.lstrip("/")
    if normalized in {"", ".", ".."} or normalized.startswith("../") or "/../" in f"/{normalized}/":
        raise ValueError("Unsafe path value found in backup payload.")
    return normalized


def _is_dangerous_target(path):
    abs_path = _normalize_abs(path)
    if not abs_path:
        return True

    drive, _ = os.path.splitdrive(abs_path)
    root = f"{drive}{os.sep}" if drive else os.path.abspath(os.sep)
    if abs_path == root:
        return True
    if os.path.dirname(abs_path) == abs_path:
        return True
    return False


def _path_within_root(path, root):
    path_abs = _normalize_abs(path)
    root_abs = _normalize_abs(root)
    path_norm = os.path.normcase(path_abs)
    root_norm = os.path.normcase(root_abs)
    return path_norm == root_norm or path_norm.startswith(root_norm + os.sep)


def _snapshot_file_component(component, mask_passwords):
    source_path = component["path"]
    payload = {
        "kind": "file",
        "source_path": source_path,
        "present": False,
    }

    if not os.path.exists(source_path):
        return payload, 0, 0, 0

    if not os.path.isfile(source_path):
        raise ValueError(f"Snapshot path is not a file: {source_path}")

    with open(source_path, "rb") as f:
        raw = f.read()

    processed, masked = _maybe_mask_bytes(source_path, raw, mask_passwords)
    stat_info = os.stat(source_path)

    payload["present"] = True
    payload["masked"] = bool(masked)
    payload["file"] = {
        "data_b64": _b64_encode(processed),
        "sha256": hashlib.sha256(processed).hexdigest(),
        "size": len(processed),
        "mode": int(stat_info.st_mode & 0o777),
        "mtime": float(stat_info.st_mtime),
    }

    return payload, 1, len(processed), 1 if masked else 0


def _snapshot_directory_component(component, mask_passwords):
    root_path = component["path"]
    payload = {
        "kind": "directory",
        "source_path": root_path,
        "present": False,
        "entries": [],
    }

    if not os.path.exists(root_path):
        return payload, 0, 0, 0

    if not os.path.isdir(root_path):
        raise ValueError(f"Snapshot path is not a directory: {root_path}")

    entries = []
    file_count = 0
    byte_count = 0
    masked_count = 0

    for current_root, dir_names, file_names in os.walk(root_path):
        dir_names.sort()
        file_names.sort()

        relative_dir = _safe_relative_path(os.path.relpath(current_root, root_path))
        if relative_dir:
            dir_stat = os.stat(current_root)
            entries.append(
                {
                    "type": "directory",
                    "relative_path": relative_dir,
                    "mode": int(dir_stat.st_mode & 0o777),
                    "mtime": float(dir_stat.st_mtime),
                }
            )

        for file_name in file_names:
            abs_file_path = os.path.join(current_root, file_name)
            relative_file = _safe_relative_path(os.path.relpath(abs_file_path, root_path))
            with open(abs_file_path, "rb") as f:
                raw = f.read()
            processed, masked = _maybe_mask_bytes(abs_file_path, raw, mask_passwords)
            stat_info = os.stat(abs_file_path)
            entries.append(
                {
                    "type": "file",
                    "relative_path": relative_file,
                    "data_b64": _b64_encode(processed),
                    "sha256": hashlib.sha256(processed).hexdigest(),
                    "size": len(processed),
                    "mode": int(stat_info.st_mode & 0o777),
                    "mtime": float(stat_info.st_mtime),
                    "masked": bool(masked),
                }
            )
            file_count += 1
            byte_count += len(processed)
            if masked:
                masked_count += 1

    payload["present"] = True
    payload["entries"] = entries
    return payload, file_count, byte_count, masked_count


def _build_full_snapshot_payload(mask_passwords=False):
    config = _load_general_config_file()
    components = {}

    total_files = 0
    total_bytes = 0
    total_masked_files = 0

    for component in _snapshot_component_definitions():
        if component["kind"] == "file":
            component_payload, file_count, byte_count, masked_count = _snapshot_file_component(component, mask_passwords)
        else:
            component_payload, file_count, byte_count, masked_count = _snapshot_directory_component(component, mask_passwords)

        components[component["name"]] = component_payload
        total_files += file_count
        total_bytes += byte_count
        total_masked_files += masked_count

    try:
        from app.migrations import CURRENT_SCHEMA_VERSION
        schema_ver = CURRENT_SCHEMA_VERSION
    except Exception:
        schema_ver = 0

    return {
        "snapshot_format": SNAPSHOT_PAYLOAD_FORMAT,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "scope": "full_system_snapshot",
        "password_masked": bool(mask_passwords),
        "version_metadata": {
            "app_version": "F27",
            "schema_version": schema_ver,
            "backup_date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        },
        "device": {
            "hostname": config.get("hostname") or "Smart Shield",
            "timezone": config.get("timezone") or "Etc/UTC",
            "platform": sys.platform,
        },
        "components": components,
        "stats": {
            "files": total_files,
            "bytes": total_bytes,
            "masked_files": total_masked_files,
        },
    }


def _serialize_snapshot_envelope(payload_obj, password):
    _ensure_yaml_support()
    payload_bytes = _payload_to_bytes(payload_obj)

    envelope = {
        "envelope_format": SNAPSHOT_ENVELOPE_FORMAT,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "file_format": "yaml",
        "encrypted": bool(password),
        "payload_sha256": hashlib.sha256(payload_bytes).hexdigest(),
    }

    if password:
        _ensure_crypto_support()
        salt = os.urandom(16)
        nonce = os.urandom(12)
        iterations = _pbkdf2_iterations()
        key = _derive_key(password, salt, iterations)
        ciphertext = AESGCM(key).encrypt(nonce, payload_bytes, SNAPSHOT_AAD)
        envelope.update(
            {
                "kdf": {
                    "name": "pbkdf2_sha256",
                    "iterations": iterations,
                    "salt_b64": _b64_encode(salt),
                },
                "cipher": {
                    "name": "aes-256-gcm",
                    "nonce_b64": _b64_encode(nonce),
                },
                "payload_b64": _b64_encode(ciphertext),
            }
        )
    else:
        envelope["payload"] = payload_obj

    yaml_text = yaml.safe_dump(envelope, sort_keys=False, allow_unicode=True)
    return yaml_text.encode("utf-8"), bool(password), len(payload_bytes)


def _decode_snapshot_envelope(raw_backup_bytes, password):
    _ensure_yaml_support()

    if not raw_backup_bytes:
        raise BackupFormatError("Backup file is empty.")

    try:
        parsed = yaml.safe_load(raw_backup_bytes.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise BackupFormatError("Backup file must be valid UTF-8 YAML.") from exc

    parsed = _normalize_yaml_value(parsed)

    if isinstance(parsed, dict) and parsed.get("snapshot_format") == SNAPSHOT_PAYLOAD_FORMAT:
        return parsed, False

    if not isinstance(parsed, dict) or parsed.get("envelope_format") != SNAPSHOT_ENVELOPE_FORMAT:
        raise BackupFormatError("Unsupported backup file format.")

    encrypted = bool(parsed.get("encrypted"))
    payload_obj = None
    payload_bytes = b""

    if encrypted:
        _ensure_crypto_support()
        if not password:
            raise BackupFormatError("This backup is encrypted. Enter the restore password.")

        kdf = parsed.get("kdf")
        cipher = parsed.get("cipher")
        if not isinstance(kdf, dict) or not isinstance(cipher, dict):
            raise BackupFormatError("Backup encryption metadata is missing.")

        if kdf.get("name") != "pbkdf2_sha256":
            raise BackupFormatError("Unsupported backup KDF.")
        if cipher.get("name") != "aes-256-gcm":
            raise BackupFormatError("Unsupported backup cipher.")

        try:
            iterations = int(kdf.get("iterations", 0))
        except (TypeError, ValueError) as exc:
            raise BackupFormatError("Backup KDF iteration count is invalid.") from exc

        min_iterations = _env_int("SMARTSHIELD_BACKUP_MIN_PBKDF2_ITERATIONS", 100000, minimum=1000)
        if iterations < min_iterations:
            raise BackupFormatError("Backup KDF iteration count is too low.")

        salt = _b64_decode(kdf.get("salt_b64"), "salt")
        nonce = _b64_decode(cipher.get("nonce_b64"), "nonce")
        ciphertext = _b64_decode(parsed.get("payload_b64"), "payload")
        key = _derive_key(password, salt, iterations)
        try:
            payload_bytes = AESGCM(key).decrypt(nonce, ciphertext, SNAPSHOT_AAD)
        except Exception as exc:
            raise BackupFormatError("Backup password is incorrect or backup data is corrupted.") from exc

        try:
            payload_obj = json.loads(payload_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BackupFormatError("Backup payload is corrupted.") from exc
    else:
        payload_obj = parsed.get("payload")
        if not isinstance(payload_obj, dict):
            raise BackupFormatError("Backup payload is missing.")
        payload_obj = _normalize_yaml_value(payload_obj)
        payload_bytes = _payload_to_bytes(payload_obj)

    expected_hash = parsed.get("payload_sha256")
    if isinstance(expected_hash, str):
        actual_hash = hashlib.sha256(payload_bytes).hexdigest()
        if actual_hash != expected_hash:
            raise BackupFormatError("Backup checksum validation failed.")

    if not isinstance(payload_obj, dict) or payload_obj.get("snapshot_format") != SNAPSHOT_PAYLOAD_FORMAT:
        raise BackupFormatError("Unsupported backup snapshot format.")
    if not isinstance(payload_obj.get("components"), dict):
        raise BackupFormatError("Backup snapshot components are missing.")

    # Schema-version compatibility check — warn but don't block if backup is older
    version_meta = payload_obj.get("version_metadata") or {}
    backup_schema = version_meta.get("schema_version", 0)
    if backup_schema:
        try:
            from app.migrations import CURRENT_SCHEMA_VERSION
            if isinstance(backup_schema, int) and backup_schema > CURRENT_SCHEMA_VERSION:
                raise BackupFormatError(
                    f"Backup was created with schema v{backup_schema} but this "
                    f"installation is at v{CURRENT_SCHEMA_VERSION}. "
                    f"Upgrade the application before restoring."
                )
        except ImportError:
            pass

    return payload_obj, encrypted


def _build_backup_filename(payload, encrypted):
    device = payload.get("device", {}) if isinstance(payload.get("device"), dict) else {}
    hostname = device.get("hostname") or "smartshield"
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%SZ")
    suffix_parts = []
    if encrypted:
        suffix_parts.append("enc")
    if payload.get("password_masked"):
        suffix_parts.append("masked")
    suffix = f"-{'-'.join(suffix_parts)}" if suffix_parts else ""
    return f"{_safe_slug(hostname)}-snapshot-{timestamp}{suffix}.yaml"


def _save_safety_backup(payload_obj):
    backup_bytes, _, _ = _serialize_snapshot_envelope(payload_obj, "")
    directory = _backup_dir()
    os.makedirs(directory, exist_ok=True)
    filename = f"pre-restore-{_build_backup_filename(payload_obj, encrypted=False)}"
    path = os.path.join(directory, filename)
    with open(path, "wb") as f:
        f.write(backup_bytes)
    return filename, path


def _write_usb_backup(filename, raw_bytes):
    usb_dir = _usb_backup_dir()
    if not usb_dir:
        raise BackupFormatError("USB backup directory is not configured.")
    usb_dir_abs = _normalize_abs(usb_dir)
    os.makedirs(usb_dir_abs, exist_ok=True)
    target_path = os.path.join(usb_dir_abs, filename)
    with open(target_path, "wb") as f:
        f.write(raw_bytes)
    return target_path


def _atomic_write(path, raw_bytes):
    parent = os.path.dirname(_normalize_abs(path))
    os.makedirs(parent, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".tmp-", dir=parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(raw_bytes)
        os.replace(tmp_path, path)
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def _apply_fs_metadata(path, metadata):
    try:
        mode = metadata.get("mode")
        if isinstance(mode, int):
            os.chmod(path, mode)
    except OSError:
        pass

    try:
        mtime = metadata.get("mtime")
        if isinstance(mtime, (int, float)):
            os.utime(path, (float(mtime), float(mtime)))
    except OSError:
        pass


def _decode_file_blob(entry):
    raw = _b64_decode(entry.get("data_b64"), "file data")
    expected_sha = entry.get("sha256")
    if isinstance(expected_sha, str):
        actual_sha = hashlib.sha256(raw).hexdigest()
        if actual_sha != expected_sha:
            raise BackupFormatError("Backup file entry checksum validation failed.")
    expected_size = entry.get("size")
    if isinstance(expected_size, int) and expected_size != len(raw):
        raise BackupFormatError("Backup file entry size validation failed.")
    return raw


def _restore_file_component(component, component_payload):
    target_path = component["path"]
    stats = {"components_applied": 1, "files_restored": 0, "bytes_restored": 0, "dirs_restored": 0}

    is_present = bool(component_payload.get("present"))
    if not is_present:
        if os.path.exists(target_path):
            if os.path.isfile(target_path) or os.path.islink(target_path):
                os.remove(target_path)
            else:
                raise ValueError(f"Snapshot expected file target but found directory: {target_path}")
        return stats

    file_entry = component_payload.get("file")
    if not isinstance(file_entry, dict):
        raise BackupFormatError(f"Snapshot file component '{component['name']}' is invalid.")

    raw = _decode_file_blob(file_entry)
    _atomic_write(target_path, raw)
    _apply_fs_metadata(target_path, file_entry)
    stats["files_restored"] = 1
    stats["bytes_restored"] = len(raw)
    return stats


def _force_rmtree(path):
    def _on_error(func, path, exc_info):
        try:
            os.chmod(path, stat.S_IWRITE)
            func(path)
        except Exception:
            pass
    shutil.rmtree(path, onerror=_on_error)


def _restore_directory_component(component, component_payload):
    target_root = component["path"]
    stats = {"components_applied": 1, "files_restored": 0, "bytes_restored": 0, "dirs_restored": 0}

    if _is_dangerous_target(target_root):
        raise ValueError(f"Refusing restore to dangerous path: {target_root}")

    is_present = bool(component_payload.get("present"))
    if not is_present:
        if os.path.isdir(target_root):
            _force_rmtree(target_root)
        elif os.path.exists(target_root):
            os.remove(target_root)
        return stats

    entries = component_payload.get("entries")
    if not isinstance(entries, list):
        raise BackupFormatError(f"Snapshot directory component '{component['name']}' is invalid.")

    if os.path.isdir(target_root):
        _force_rmtree(target_root)
    elif os.path.exists(target_root):
        os.remove(target_root)
    os.makedirs(target_root, exist_ok=True)

    dir_entries = []
    file_entries = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        entry_type = entry.get("type")
        rel_path = _safe_relative_path(entry.get("relative_path", ""))
        if entry_type == "directory":
            if rel_path:
                dir_entries.append((rel_path, entry))
        elif entry_type == "file":
            if not rel_path:
                raise BackupFormatError("Snapshot file entry has an invalid path.")
            file_entries.append((rel_path, entry))
        else:
            raise BackupFormatError("Snapshot directory contains an unknown entry type.")

    for rel_dir, entry in sorted(dir_entries, key=lambda item: (item[0].count("/"), item[0])):
        abs_dir = _normalize_abs(os.path.join(target_root, rel_dir))
        if not _path_within_root(abs_dir, target_root):
            raise BackupFormatError("Snapshot contains an unsafe directory path.")
        os.makedirs(abs_dir, exist_ok=True)
        _apply_fs_metadata(abs_dir, entry)
        stats["dirs_restored"] += 1

    for rel_file, entry in sorted(file_entries, key=lambda item: item[0]):
        abs_file = _normalize_abs(os.path.join(target_root, rel_file))
        if not _path_within_root(abs_file, target_root):
            raise BackupFormatError("Snapshot contains an unsafe file path.")
        os.makedirs(os.path.dirname(abs_file), exist_ok=True)
        raw = _decode_file_blob(entry)
        _atomic_write(abs_file, raw)
        _apply_fs_metadata(abs_file, entry)
        stats["files_restored"] += 1
        stats["bytes_restored"] += len(raw)

    return stats


def _restore_full_snapshot(payload):
    if not isinstance(payload, dict):
        raise BackupFormatError("Snapshot payload is invalid.")
    if payload.get("password_masked"):
        raise BackupFormatError("Password-masked backups are not restorable snapshots.")

    components_payload = payload.get("components")
    if not isinstance(components_payload, dict):
        raise BackupFormatError("Snapshot components are missing.")

    definitions = {component["name"]: component for component in _snapshot_component_definitions()}
    summary = {"components_applied": 0, "files_restored": 0, "bytes_restored": 0, "dirs_restored": 0}

    for component_name, component in definitions.items():
        component_payload = components_payload.get(component_name)
        if not isinstance(component_payload, dict):
            continue

        if component["kind"] == "file":
            result = _restore_file_component(component, component_payload)
        else:
            result = _restore_directory_component(component, component_payload)

        summary["components_applied"] += result.get("components_applied", 0)
        summary["files_restored"] += result.get("files_restored", 0)
        summary["bytes_restored"] += result.get("bytes_restored", 0)
        summary["dirs_restored"] += result.get("dirs_restored", 0)

    if summary["components_applied"] == 0:
        raise BackupFormatError("Backup does not contain compatible snapshot components for this system.")

    return summary


def _restart_services_after_restore() -> None:
    """
    Restart key services after a config restore so that restored config files
    take effect.  Best-effort — failures are silently ignored so restore
    success is not rolled back due to a service restart hiccup.
    Only runs on FreeBSD; no-op on other platforms.
    """
    import sys as _sys
    if not _sys.platform.startswith("freebsd"):
        return
    _SERVICES_TO_RESTART = [
        "unbound",
        "isc-dhcpd",
        "suricata",
        "openvpn",
        "strongswan",
        "mpd5",
    ]
    try:
        from app.services.service_manager import service_action
        from app.services.priv_helper import run_privileged
        # Reload PF first (most critical — bad pf.conf causes immediate downtime)
        try:
            import os as _os
            from app.database import get_db
            from app.services.pf_generator import generate_pf_conf
            pf_path = "/etc/pf.conf"
            conf = generate_pf_conf(get_db())
            with open(pf_path, "w") as fh:
                fh.write(conf)
            run_privileged("pf.reload", config_path=pf_path)
        except Exception:
            pass
        # Restart each optional service (skip if not installed)
        for svc in _SERVICES_TO_RESTART:
            try:
                service_action(svc, "restart")
            except Exception:
                pass
    except Exception:
        pass


def _backup_page_context():
    config = _load_general_config_file()
    components = _snapshot_component_definitions()
    file_targets = [c for c in components if c["kind"] == "file"]
    directory_targets = [c for c in components if c["kind"] == "directory"]

    return {
        "hostname": config.get("hostname") or "Smart Shield",
        "timezone": config.get("timezone") or "Etc/UTC",
        "max_upload_mb": round(_max_backup_upload_bytes() / (1024 * 1024), 1),
        "backup_dir": _backup_dir(),
        "usb_backup_available": bool(_usb_backup_dir()),
        "usb_backup_dir": _usb_backup_dir() or "",
        "yaml_available": yaml is not None,
        "encryption_available": AESGCM is not None,
        "file_targets": file_targets,
        "directory_targets": directory_targets,
    }

# --------------------------------------------------
# DIAGNOSTICS MAIN PAGE
# --------------------------------------------------
