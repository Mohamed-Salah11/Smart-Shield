#!/bin/sh
# =============================================================================
# release_check.sh — Smart Shield "is this ready to ship?" gate
# =============================================================================
# Fv11 review §P2-03 — single shell entry point that mirrors what CI is
# supposed to run before producing a release archive. Wraps the Python and
# shell linters/checks so the operator doesn't have to remember the
# component list.
#
# Returns non-zero on the first failure. Each section prints its own
# OK/FAIL line so a CI log shows where the gate broke.
#
# Usage (from repo root):
#   sh tools/release_check.sh
#
# CI hook (recommended): make this the only command in the release pipeline's
# pre-build step. tools/build_release.py / scripts/build_release.sh refuse to
# build if this script exits non-zero.
# =============================================================================
set -eu

SRC_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PYBIN="${PYTHON:-python3}"

if ! command -v "${PYBIN}" >/dev/null 2>&1; then
    echo "[release_check] FAIL: ${PYBIN} not on PATH" >&2
    exit 1
fi

echo "[release_check] repo: ${SRC_ROOT}"

# 1. Byte-compile every Python source we ship. Catches syntax errors that
#    didn't make it to import-test or runtime.
echo "[release_check] (1/6) compileall app/routes/tools/scripts"
"${PYBIN}" -m compileall -q "${SRC_ROOT}/app" "${SRC_ROOT}/routes" "${SRC_ROOT}/tools" "${SRC_ROOT}/scripts"

# 2. POSIX-sh syntax-check every shipped shell script. `sh -n` doesn't need
#    the script's dependencies to be available — it just parses.
echo "[release_check] (2/6) sh -n on bsd/* + scripts/*"
for f in \
    "${SRC_ROOT}/bsd/install.sh" \
    "${SRC_ROOT}/bsd/rc.d/smart_shield" \
    "${SRC_ROOT}/bsd/sbin/smartshieldctl" \
    "${SRC_ROOT}/bsd/sbin/smartshield-cli" \
    "${SRC_ROOT}/bsd/firstboot/smart_shield_firstboot" \
    "${SRC_ROOT}/bsd/mrtg-probe.sh" \
    "${SRC_ROOT}/scripts/build_release.sh"
do
    if [ -f "${f}" ]; then
        if ! sh -n "${f}"; then
            echo "[release_check] FAIL: sh -n ${f}" >&2
            exit 1
        fi
    fi
done

# 3. Route ↔ template registration. Catches "endpoint references template
#    that no longer exists" and unregistered blueprints.
echo "[release_check] (3/6) tools/check_routes.py"
( cd "${SRC_ROOT}" && "${PYBIN}" tools/check_routes.py )

# 4. Route security linter. Catches unprotected POST endpoints.
echo "[release_check] (4/6) tools/security_lint_routes.py"
( cd "${SRC_ROOT}" && "${PYBIN}" tools/security_lint_routes.py )

# 5. Full release-readiness battery (deps importable, version consistent,
#    DB schema matches, template references resolve, etc.).
echo "[release_check] (5/6) tools/release_check.py"
( cd "${SRC_ROOT}" && "${PYBIN}" tools/release_check.py )

# 6. Runtime preflight under production env overrides. Confirms create_app()
#    boots when network apply + background workers are off.
echo "[release_check] (6/6) tools/runtime_preflight.py"
( cd "${SRC_ROOT}" && "${PYBIN}" tools/runtime_preflight.py )

# 7. Hygiene gate — refuse to declare the tree releasable if there are
#    forbidden artefacts checked in / lingering in the working dir (Fv11 §P0-01).
echo "[release_check] hygiene scan"
FOUND="$(find "${SRC_ROOT}" \
    \( -path "${SRC_ROOT}/dist" -prune \) -o \
    \( -path "${SRC_ROOT}/.venv" -prune \) -o \
    \( -path "${SRC_ROOT}/.git" -prune \) -o \
    \( -type d -name '__pycache__' -print \) -o \
    \( -type d -name '.pytest_cache' -print \) -o \
    \( -type f -name '*.pyc' -print \) -o \
    \( -type f -name '_v_hn.db*' -print \) 2>/dev/null | head -20 || true)"
if [ -n "${FOUND}" ]; then
    echo "[release_check] WARN: working tree contains build/runtime artefacts:"
    echo "${FOUND}" | sed 's/^/    /'
    echo "  → Build via scripts/build_release.sh, which excludes them from the archive."
fi

echo ""
echo "[release_check] PASS — repo is ready for the release builder."
