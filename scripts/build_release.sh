#!/bin/sh
# =============================================================================
# build_release.sh — Smart Shield release packaging wrapper
# =============================================================================
# Stages the source tree into dist/Smart-Shield-<VERSION>/ via rsync (or tar
# fallback), normalises BSD script executable bits, then hands off to
# tools/build_release.py to produce a tar.gz + sha256 with a matching root
# directory name.
#
# The point of this wrapper (vs. invoking tools/build_release.py directly) is
# to address Fv11 review §P0-01 (release archive contains runtime/build
# artefacts), §P0-02 (extracted root folder name must match archive name),
# and §P2-04 (BSD scripts must be executable in the archive). Running this
# script from a dirty working tree is safe — staging gives the Python builder
# a clean input even when the dev directory has .venv/__pycache__/logs.
#
# Usage:
#   sh scripts/build_release.sh [VERSION] [--release-name NAME]
#
#   VERSION defaults to "Fv11" so the most common case is just:
#       sh scripts/build_release.sh
#   produces dist/Smart-Shield-Fv11.tar.gz with root dir Smart-Shield-Fv11/.
# =============================================================================

set -eu

VERSION="${1:-Fv11}"
shift 2>/dev/null || true

RELEASE_NAME=""
while [ $# -gt 0 ]; do
    case "$1" in
        --release-name)
            RELEASE_NAME="$2"
            shift 2
            ;;
        --release-name=*)
            RELEASE_NAME="${1#--release-name=}"
            shift
            ;;
        *)
            echo "warn: unknown argument: $1" >&2
            shift
            ;;
    esac
done

if [ -z "${RELEASE_NAME}" ]; then
    RELEASE_NAME="Smart-Shield-${VERSION}"
fi

SRC_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${SRC_ROOT}/dist"
STAGE="${OUT_DIR}/${RELEASE_NAME}"

echo "[build_release] source        : ${SRC_ROOT}"
echo "[build_release] release name  : ${RELEASE_NAME}"
echo "[build_release] staging dir   : ${STAGE}"

rm -rf "${STAGE}"
mkdir -p "${OUT_DIR}"

# Stage the tree minus runtime/build state. Excludes mirror tools/build_release.py
# EXCLUDE_PATTERNS so both code paths produce identical contents.
if command -v rsync >/dev/null 2>&1; then
    rsync -a "${SRC_ROOT}/" "${STAGE}/" \
        --exclude '.git' \
        --exclude '.venv' \
        --exclude 'dist' \
        --exclude '__pycache__' \
        --exclude '*.pyc' \
        --exclude '*.pyo' \
        --exclude '.pytest_cache' \
        --exclude 'tests' \
        --exclude '*.db' \
        --exclude '*.db-shm' \
        --exclude '*.db-wal' \
        --exclude 'logs' \
        --exclude 'static/uploads' \
        --exclude '.claude' \
        --exclude '.env' \
        --exclude '.env.*'
else
    mkdir -p "${STAGE}"
    tar -C "${SRC_ROOT}" \
        --exclude='.git' \
        --exclude='.venv' \
        --exclude='dist' \
        --exclude='__pycache__' \
        --exclude='*.pyc' \
        --exclude='*.pyo' \
        --exclude='.pytest_cache' \
        --exclude='tests' \
        --exclude='*.db' \
        --exclude='*.db-shm' \
        --exclude='*.db-wal' \
        --exclude='logs' \
        --exclude='static/uploads' \
        --exclude='.claude' \
        --exclude='.env' \
        --exclude='.env.*' \
        -cf - . | tar -C "${STAGE}" -xf -
fi

# Normalise executable bits on BSD scripts (Fv11 review §P2-04). The unzip
# user typically tries `./bsd/install.sh` first; without these chmods the
# attempt would fail because git/zip don't always preserve mode bits.
find "${STAGE}/bsd" -type f \( -path '*/sbin/*' -o -path '*/rc.d/*' -o -path '*/firstboot/*' -o -path '*/console_menu/*' \) -exec chmod 0755 {} \; 2>/dev/null || true
[ -f "${STAGE}/bsd/install.sh" ]    && chmod 0755 "${STAGE}/bsd/install.sh"
[ -f "${STAGE}/bsd/mrtg-probe.sh" ] && chmod 0755 "${STAGE}/bsd/mrtg-probe.sh"
find "${STAGE}/scripts" -type f -name '*.sh' -exec chmod 0755 {} \; 2>/dev/null || true

# Hand off to the Python builder, pointing it at the staged copy so the
# archive contents exactly match what's on disk in ${STAGE}.
PYBIN="${PYTHON:-python3}"
if ! command -v "${PYBIN}" >/dev/null 2>&1; then
    echo "[build_release] error: ${PYBIN} not found on PATH" >&2
    exit 1
fi

"${PYBIN}" "${SRC_ROOT}/tools/build_release.py" \
    "${VERSION}" \
    --project-root "${STAGE}" \
    --output-dir   "${OUT_DIR}" \
    --release-name "${RELEASE_NAME}"

# Acceptance check (Fv11 review §P0-01 expects this to print "clean"):
echo ""
echo "[build_release] post-build acceptance check (must print 'clean'):"
if tar -tzf "${OUT_DIR}/${RELEASE_NAME}.tar.gz" 2>/dev/null \
    | grep -E '(__pycache__|\.pyc$|\.pytest_cache|\.db$|\.db-shm$|\.db-wal$|/logs/|/tests/)' >/dev/null 2>&1; then
    echo "  FAIL: forbidden artefacts present in archive"
    tar -tzf "${OUT_DIR}/${RELEASE_NAME}.tar.gz" \
        | grep -E '(__pycache__|\.pyc$|\.pytest_cache|\.db$|\.db-shm$|\.db-wal$|/logs/|/tests/)' \
        | head -20
    exit 1
else
    echo "  clean"
fi

# Confirm the extracted root directory matches RELEASE_NAME (§P0-02).
FIRST_ROOT="$(tar -tzf "${OUT_DIR}/${RELEASE_NAME}.tar.gz" | head -1 | awk -F/ '{print $1}')"
if [ "${FIRST_ROOT}" = "${RELEASE_NAME}" ]; then
    echo "  archive root: ${FIRST_ROOT} (matches expected ${RELEASE_NAME})"
else
    echo "  FAIL: archive root '${FIRST_ROOT}' != expected '${RELEASE_NAME}'"
    exit 1
fi

echo "[build_release] Built ${OUT_DIR}/${RELEASE_NAME}.tar.gz"
