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

# Only these top-level paths are candidates for inclusion. `tests/` is
# intentionally absent: production appliances must not ship test fixtures or
# the test runner — install.sh already excludes `tests/` when deploying to
# APP_ROOT, so the archive contract has to match.
WHITELIST_DIRS = [
    "app",
    "routes",
    "static",
    "templates",
    "bsd",
    "tools",
    "scripts",
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
    "LICENSE",
    "version.json",
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
    # Smart Shield runtime DB sidecars + audit log + working tree caches that
    # were observed leaking into past release archives (Fv11 review §P0-01).
    re.compile(r"(^|/)_v_hn\.db(-shm|-wal)?$"),
    re.compile(r"(^|/)logs(/|$)"),
    re.compile(r"(^|/)tests(/|$)"),
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
    # Prefer version.json (machine-readable; see Item 11), then a plain VERSION
    # file, then fall back to "dev".
    vj = project_root / "version.json"
    if vj.exists():
        try:
            data = json.loads(vj.read_text())
            v = (data.get("version") or "").strip()
            if v:
                return v
        except (ValueError, OSError):
            pass
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

def _count_routes_templates(project_root: Path):
    """Best-effort static counts for RELEASE_MANIFEST.json. We grep instead of
    booting the app so the build script works without Flask installed."""
    routes_root = project_root / "routes"
    templates_root = project_root / "templates"
    route_re = re.compile(r"@\w+\.route\(")
    routes = 0
    if routes_root.is_dir():
        for p in routes_root.rglob("*.py"):
            try:
                routes += len(route_re.findall(p.read_text(encoding="utf-8")))
            except OSError:
                continue
    templates = 0
    if templates_root.is_dir():
        templates = sum(1 for _ in templates_root.rglob("*.html"))
    return routes, templates


def build_release(version: str, project_root: Path, output_dir: Path,
                  release_name: str | None = None) -> int:
    output_dir.mkdir(parents=True, exist_ok=True)
    # `release_name` controls the on-disk directory the archive extracts to AND
    # the archive base filename. Defaulting to "Smart-Shield-<VERSION>" makes
    # the Fv11 review's "extracted root must match archive name" rule
    # (§P0-02) trivially true without forcing every caller to know the
    # marketing version separately.
    if not release_name:
        release_name = f"Smart-Shield-{version}"
    archive_name = release_name
    archive_path = output_dir / f"{archive_name}.tar.gz"
    sha256_path  = output_dir / f"{archive_name}.sha256"

    print(f"Building Smart Shield release {version}  (root dir: {release_name})")
    print(f"  Project root : {project_root}")
    print(f"  Output       : {archive_path}")

    # Collect files
    files = list(_collect_files(project_root))
    print(f"  Files        : {len(files)}")

    # version.json — kept for backwards compatibility with release_check.py
    # (which keys off the file's `version` and `schema_version`).
    version_meta = {
        "version":    version,
        "build_date": datetime.now(timezone.utc).isoformat(),
        "git_commit": _get_git_commit(),
        "files":      len(files) + 2,  # +1 version.json, +1 RELEASE_MANIFEST.json
    }

    # RELEASE_MANIFEST.json — the "what's in this archive" header asked for in
    # Fv11 review §P3-02. Static counts only; runtime checks live in
    # tools/release_check.py and tools/runtime_preflight.py.
    routes_count, templates_count = _count_routes_templates(project_root)
    manifest = {
        "name":           "Smart Shield",
        "version":        version,
        "release_name":   release_name,
        "build_time_utc": version_meta["build_date"],
        "git_commit":     version_meta["git_commit"],
        "python_min":     "3.11",
        "freebsd_min":    "13.2",
        "route_count":    routes_count,
        "template_count": templates_count,
        "file_count":     len(files) + 2,
    }

    # Write archive
    with tarfile.open(archive_path, "w:gz") as tar:
        # Add version.json + RELEASE_MANIFEST.json first
        def _add_json_member(arcname: str, payload: dict) -> None:
            payload_bytes = json.dumps(payload, indent=2).encode()
            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
                tf.write(payload_bytes)
                tmp_path = tf.name
            try:
                tar.add(tmp_path, arcname=f"{archive_name}/{arcname}")
            finally:
                os.unlink(tmp_path)

        _add_json_member("version.json", version_meta)
        _add_json_member("RELEASE_MANIFEST.json", manifest)

        # Add whitelisted files. Skip the source-tree version.json since we've
        # already injected a build-time copy above (avoids a duplicate member).
        for abs_path, rel_name in files:
            if rel_name == "version.json":
                continue
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

        # Must contain version.json + RELEASE_MANIFEST.json
        vj = f"{archive_name}/version.json"
        rm = f"{archive_name}/RELEASE_MANIFEST.json"
        if vj not in members:
            errors.append(f"version.json not found in archive (expected {vj!r}).")
        if rm not in members:
            errors.append(f"RELEASE_MANIFEST.json not found in archive (expected {rm!r}).")

        # Identity consistency: every member must live under the single release
        # root, and the embedded manifest must agree. This makes a
        # Fv7-named-but-Fv11-content style mismatch impossible — name, root
        # dir, and metadata must agree (Fv11 review §P0-02).
        root_prefix = f"{archive_name}/"
        stray = [n for n in members if not n.startswith(root_prefix) and n != archive_name]
        if stray:
            errors.append(
                f"Archive root mismatch: {len(stray)} member(s) not under "
                f"{root_prefix!r} (e.g. {stray[0]!r})."
            )
        if rm in members:
            try:
                rm_meta = json.loads(tar.extractfile(rm).read().decode())
                got_release = str(rm_meta.get("release_name") or "").strip()
                if got_release != archive_name:
                    errors.append(
                        f"RELEASE_MANIFEST.json release_name {got_release!r} "
                        f"!= archive name {archive_name!r}."
                    )
            except (ValueError, OSError, AttributeError) as exc:
                errors.append(f"Could not parse RELEASE_MANIFEST.json: {exc}")

        # Must not contain excluded patterns
        for name in members:
            # Strip archive prefix for pattern matching
            rel = name.removeprefix(root_prefix)
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
    parser.add_argument(
        "--release-name",
        default=None,
        help=(
            "Override the on-disk release root directory and archive base name. "
            "Defaults to 'Smart-Shield-<VERSION>' (e.g. Smart-Shield-Fv11). "
            "The extracted root MUST match the archive name (Fv11 review §P0-02)."
        ),
    )
    args = parser.parse_args()

    script_dir   = Path(__file__).resolve().parent
    project_root = Path(args.project_root) if args.project_root else script_dir.parent
    output_dir   = project_root / args.output_dir

    version = args.version or _get_version(project_root)

    sys.exit(build_release(version, project_root, output_dir, release_name=args.release_name))


if __name__ == "__main__":
    main()
