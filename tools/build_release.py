#!/usr/bin/env python3
"""
build_release.py — Smart Shield release builder
================================================
Creates a reproducible release tarball from a whitelist of files.

Usage
-----
    python tools/build_release.py [VERSION] [--output-dir DIR]

    VERSION    : Semantic version string, e.g. 1.0.0
                 Defaults to the content of VERSION file or "dev".
    --output-dir : Where to write the tarball (default: dist/)

Output
------
    dist/smartshield-<VERSION>.tar.gz
    dist/smartshield-<VERSION>.sha256

The archive contains a ``version.json`` file at the root with metadata:

    {
      "version":    "1.0.0",
      "build_date": "2025-01-01T00:00:00Z",
      "git_commit": "abc1234",
      "files":      42
    }

Excluded paths (never included regardless of whitelist)
-------------------------------------------------------
    .env             .env.*           data.db
    audit.log        app.log          *.log
    backups/         uploads/         .git/
    .venv/           __pycache__/     *.pyc
    *.pyo            .pytest_cache/   dist/
    *.sqlite3        *.db             *.bak
    secrets/         *.key            *.pem
    *.p12            *.pfx

Artifact checks
---------------
After building, the script verifies:
    * The archive is non-empty.
    * It contains ``version.json``.
    * It does NOT contain any excluded file patterns.
    * The SHA256 file matches the archive.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Only these top-level paths are candidates for inclusion.
WHITELIST_DIRS = [
    "app",
    "routes",
    "static",
    "templates",
    "bsd",
    "tools",
    "tests",
    "docs",
]
WHITELIST_FILES = [
    "run.py",
    "wsgi.py",
    "requirements.txt",
    "config.example.json",
    ".env.example",
    ".gitignore",
    "README.md",
]

# Patterns that MUST be excluded (applied after whitelist).
EXCLUDE_PATTERNS = [
    re.compile(r"(^|/)\.env($|\.)"),
    re.compile(r"(^|/)data\.db$"),
    re.compile(r"(^|/)audit\.log$"),
    re.compile(r"(^|/)app\.log$"),
    re.compile(r"\.log$"),
    re.compile(r"(^|/)backups/"),
    re.compile(r"(^|/)uploads/"),
    re.compile(r"(^|/)\.git(/|$)"),
    re.compile(r"(^|/)\.venv(/|$)"),
    re.compile(r"__pycache__"),
    re.compile(r"\.pyc$"),
    re.compile(r"\.pyo$"),
    re.compile(r"(^|/)\.pytest_cache(/|$)"),
    re.compile(r"(^|/)dist(/|$)"),
    re.compile(r"\.(sqlite3|db|bak)$"),
    re.compile(r"(^|/)secrets(/|$)"),
    re.compile(r"\.(key|pem|p12|pfx)$"),
    re.compile(r"(^|/)\.claude(/|$)"),
]


def _is_excluded(rel_path: str) -> bool:
    normalized = rel_path.replace("\\", "/")
    return any(pat.search(normalized) for pat in EXCLUDE_PATTERNS)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_git_commit() -> str:
    try:
        r = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=5,
        )
        return r.stdout.strip() if r.returncode == 0 else "unknown"
    except Exception:
        return "unknown"


def _get_version(project_root: Path) -> str:
    vf = project_root / "VERSION"
    if vf.exists():
        return vf.read_text().strip()
    return "dev"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _collect_files(project_root: Path):
    """
    Yield (abs_path, archive_name) for every file that passes the whitelist
    and is not excluded.
    """
    def _yield(p: Path, archive_prefix: str):
        if p.is_file():
            rel = archive_prefix
            if not _is_excluded(rel):
                yield p, rel
        elif p.is_dir():
            for child in sorted(p.iterdir()):
                child_rel = f"{archive_prefix}/{child.name}"
                yield from _yield(child, child_rel)

    for name in WHITELIST_FILES:
        p = project_root / name
        if p.exists() and not _is_excluded(name):
            yield p, name

    for name in WHITELIST_DIRS:
        p = project_root / name
        if p.exists():
            yield from _yield(p, name)


# ---------------------------------------------------------------------------
# Main builder
# ---------------------------------------------------------------------------

def build_release(version: str, project_root: Path, output_dir: Path) -> int:
    output_dir.mkdir(parents=True, exist_ok=True)
    archive_name = f"smartshield-{version}"
    archive_path = output_dir / f"{archive_name}.tar.gz"
    sha256_path  = output_dir / f"{archive_name}.sha256"

    print(f"Building Smart Shield release {version}")
    print(f"  Project root : {project_root}")
    print(f"  Output       : {archive_path}")

    # Collect files
    files = list(_collect_files(project_root))
    print(f"  Files        : {len(files)}")

    # Build version.json content
    version_meta = {
        "version":    version,
        "build_date": datetime.now(timezone.utc).isoformat(),
        "git_commit": _get_git_commit(),
        "files":      len(files) + 1,  # +1 for version.json itself
    }

    # Write archive
    with tarfile.open(archive_path, "w:gz") as tar:
        # Add version.json first
        vj_bytes = json.dumps(version_meta, indent=2).encode()
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            tf.write(vj_bytes)
            tmp_vj = tf.name
        try:
            tar.add(tmp_vj, arcname=f"{archive_name}/version.json")
        finally:
            os.unlink(tmp_vj)

        # Add whitelisted files
        for abs_path, rel_name in files:
            tar.add(abs_path, arcname=f"{archive_name}/{rel_name}")

    # SHA256 checksum
    digest = _sha256_file(archive_path)
    sha256_path.write_text(f"{digest}  {archive_path.name}\n")

    # Artifact checks
    print("\nRunning artifact checks...")
    errors = _check_artifact(archive_path, archive_name, digest, sha256_path)
    if errors:
        print("\n[FAIL] Artifact checks failed:")
        for e in errors:
            print(f"  * {e}")
        return 1

    print(f"\n[OK] Release built successfully:")
    print(f"  Archive : {archive_path}  ({archive_path.stat().st_size / 1024:.1f} KB)")
    print(f"  SHA256  : {sha256_path}")
    print(f"  Digest  : {digest}")
    print(f"\nversion.json metadata:")
    for k, v in version_meta.items():
        print(f"  {k}: {v}")
    return 0


def _check_artifact(
    archive_path: Path,
    archive_name: str,
    expected_digest: str,
    sha256_path: Path,
) -> list:
    errors = []

    # Non-empty
    if archive_path.stat().st_size == 0:
        errors.append("Archive is empty.")
        return errors

    with tarfile.open(archive_path, "r:gz") as tar:
        members = tar.getnames()

        # Must contain version.json
        vj = f"{archive_name}/version.json"
        if vj not in members:
            errors.append(f"version.json not found in archive (expected {vj!r}).")

        # Must not contain excluded patterns
        for name in members:
            # Strip archive prefix for pattern matching
            rel = name.removeprefix(f"{archive_name}/")
            if _is_excluded(rel):
                errors.append(f"Excluded file found in archive: {name!r}")

    # SHA256 verification
    actual = _sha256_file(archive_path)
    if actual != expected_digest:
        errors.append(f"SHA256 mismatch: expected {expected_digest}, got {actual}")

    return errors


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Smart Shield release builder")
    parser.add_argument("version", nargs="?", default=None, help="Version string (e.g. 1.0.0)")
    parser.add_argument("--output-dir", default="dist", help="Output directory (default: dist/)")
    parser.add_argument("--project-root", default=None, help="Project root (default: parent of tools/)")
    args = parser.parse_args()

    script_dir   = Path(__file__).resolve().parent
    project_root = Path(args.project_root) if args.project_root else script_dir.parent
    output_dir   = project_root / args.output_dir

    version = args.version or _get_version(project_root)

    sys.exit(build_release(version, project_root, output_dir))


if __name__ == "__main__":
    main()
