#!/bin/sh
# =============================================================================
# Smart Shield — release bundler
# =============================================================================
# Produces dist/smart-shield-<rev>.tar.gz from the current HEAD via
# `git archive`, which respects .gitignore implicitly: no .env, no SQLite
# databases, no virtualenvs, no logs, no PID files. Pairs with §30 of the
# review document.
#
# Usage: sh scripts/release.sh           # tag from HEAD short SHA
#        REL_REV=fv4-rc1 sh scripts/release.sh   # explicit tag
# =============================================================================
set -eu

REV="${REL_REV:-$(git rev-parse --short HEAD)}"
OUT="dist/smart-shield-${REV}.tar.gz"

mkdir -p dist

# Refuse to ship a dirty tree — the release MUST match a commit.
if [ -n "$(git status --porcelain)" ]; then
    printf "ERROR: working tree is dirty. Commit or stash first.\n" >&2
    git status --short >&2
    exit 1
fi

# Confirm none of the §30 forbidden files made it into the index.
forbidden=$(git ls-files | grep -E '\.(env|db|sqlite3?|log|pid|bak)$|__pycache__/|\.venv/|instance/' || true)
if [ -n "$forbidden" ]; then
    printf "ERROR: forbidden files tracked by git:\n%s\n" "$forbidden" >&2
    exit 1
fi

git archive --format=tar.gz --prefix="smart-shield-${REV}/" -o "$OUT" HEAD
printf "Wrote %s (%s bytes)\n" "$OUT" "$(wc -c < "$OUT")"
