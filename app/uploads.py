import os
import sys
from typing import Optional

from flask import url_for
from werkzeug.utils import secure_filename


def _default_upload_dir() -> str:
    if sys.platform.startswith("freebsd"):
        return "/var/db/smart-shield/uploads/profile_pictures"
    return "static/uploads/profile_pictures"


def get_upload_dir() -> str:
    return os.getenv("SMARTSHIELD_UPLOAD_DIR", _default_upload_dir())


def ensure_upload_dir() -> str:
    path = get_upload_dir()
    os.makedirs(path, exist_ok=True)
    return path


def _normalize_ref(value: Optional[str]) -> str:
    if not value:
        return ""
    normalized = str(value).replace("\\", "/").lstrip("/")
    if normalized.startswith("static/"):
        normalized = normalized[len("static/") :]
    return normalized


def _safe_relative_path(path: str) -> str:
    normalized = os.path.normpath(path).replace("\\", "/").lstrip("/")
    if normalized in {"", ".", ".."} or normalized.startswith("../"):
        return ""
    return normalized


def profile_picture_url(profile_picture: Optional[str]) -> str:
    normalized = _normalize_ref(profile_picture)
    if not normalized:
        return ""

    if normalized.startswith("uploads/profile_pictures/"):
        filename = secure_filename(normalized.rsplit("/", 1)[-1])
        if not filename:
            return ""
        return url_for("users.profile_picture_file", filename=filename)

    safe_static = _safe_relative_path(normalized)
    if not safe_static:
        return ""
    return url_for("static", filename=safe_static)


def resolve_profile_picture_path(profile_picture: Optional[str]) -> str:
    normalized = _normalize_ref(profile_picture)
    if not normalized:
        return ""

    if normalized.startswith("uploads/profile_pictures/"):
        filename = secure_filename(normalized.rsplit("/", 1)[-1])
        if not filename:
            return ""
        return os.path.join(get_upload_dir(), filename)

    safe_static = _safe_relative_path(normalized)
    if not safe_static:
        return ""
    return os.path.join("static", safe_static.replace("/", os.sep))
