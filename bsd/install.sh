#!/bin/sh
# =============================================================================
# Smart Shield — FreeBSD One-Shot Installation Script
# =============================================================================
# Usage:
#   1. Copy the project to /usr/local/share/smartshield
#   2. Run as root: sh /usr/local/share/smartshield/bsd/install.sh
#
# What this script does:
#   1. Installs all required packages via pkg
#   2. Creates all required directory paths with correct permissions
#   3. Copies environment template if not already present
#   4. Copies config.json template if not already present
#   5. Builds Python virtual environment + installs pip dependencies
#   6. Installs rc.d service script + operator CLI tools
#   7. Enables the service in rc.conf
#   8. Runs the Python preflight check to confirm everything is ready
# =============================================================================

set -e

APP_ROOT="/usr/local/share/smartshield"
ETC_DIR="/usr/local/etc/smartshield"
DATA_DIR="/var/db/smartshield"
LOG_DIR="/var/log/smartshield"
RUN_DIR="/var/run/smartshield"
VENV="${APP_ROOT}/.venv"

# Colour helpers (no-op if not a terminal)
RED=''; GREEN=''; YELLOW=''; NC=''; BOLD=''
if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
    NC='\033[0m'; BOLD='\033[1m'
fi

info()    { printf "${GREEN}[+]${NC} %s\n" "$*"; }
warn()    { printf "${YELLOW}[!]${NC} %s\n" "$*"; }
fatal()   { printf "${RED}[✗]${NC} %s\n" "$*"; exit 1; }
section() { printf "\n${BOLD}━━━ %s ━━━${NC}\n" "$*"; }

# ─── LAN defaults (overridable by setting env vars before running this script) ─
LAN_IFACE="${LAN_IFACE:-em1}"
LAN_IP="${LAN_IP:-192.168.1.1}"
LAN_MASK="${LAN_MASK:-255.255.255.0}"

# ─── Root check ──────────────────────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
    fatal "This script must be run as root.  Try: sudo sh $0"
fi

# ─── FreeBSD check ───────────────────────────────────────────────────────────
OS=$(uname -s)
if [ "${OS}" != "FreeBSD" ]; then
    fatal "This script is for FreeBSD only (detected: ${OS})."
fi

# ─── Deployment mode ─────────────────────────────────────────────────────────
# Noninteractive override: lab automation can pre-set SMARTSHIELD_INSTALL_MODE
# (live|dry) and SMARTSHIELD_NONINTERACTIVE=1 to skip prompts entirely.
printf "\n${BOLD}━━━ Deployment Mode ━━━${NC}\n"
printf "  ${GREEN}live${NC}          — Apply real PF rules, interface config, and service control.\n"
printf "  ${YELLOW}prepare${NC}       — Install files, venv, sudoers, nginx config, rc.conf staging, and\n"
printf "                  SSL cert generation, but do NOT mutate live PF rules, change\n"
printf "                  interface state, load kernel modules, start/stop services, or write\n"
printf "                  sysctl. Filesystem state IS modified — re-running install.sh in\n"
printf "                  prepare mode is the documented contract (Fv11 review §P1-03).\n"
printf "  ${YELLOW}validate-only${NC} — Run packaging + preflight checks only. No filesystem writes,\n"
printf "                  no pkg install, no venv build. Use to gate CI.\n"
# Resolve install mode. Back-compat: SMARTSHIELD_INSTALL_MODE=dry → prepare.
_MODE_RAW="${SMARTSHIELD_INSTALL_MODE:-}"
if [ "${SMARTSHIELD_NONINTERACTIVE:-0}" = "1" ]; then
    case "${_MODE_RAW:-prepare}" in
        live)                        INSTALL_MODE=live ;;
        prepare|dry|"")              INSTALL_MODE=prepare ;;
        validate-only|validate|check) INSTALL_MODE=validate-only ;;
        *) fatal "Unknown SMARTSHIELD_INSTALL_MODE='${_MODE_RAW}' (expected live|prepare|validate-only)" ;;
    esac
    info "Install mode: ${INSTALL_MODE} (noninteractive)."
else
    printf "${YELLOW}[?]${NC} Mode? [live/prepare/validate-only, default=prepare]: "
    read -r _MODE_ANS
    case "${_MODE_ANS:-prepare}" in
        live|LIVE)                            INSTALL_MODE=live ;;
        validate-only|validate|check)         INSTALL_MODE=validate-only ;;
        *)                                    INSTALL_MODE=prepare ;;
    esac
    info "Install mode: ${INSTALL_MODE}"
fi

case "${INSTALL_MODE}" in
    live)          DEPLOY_LIVE=1 ;;
    prepare|validate-only) DEPLOY_LIVE=0 ;;
esac
DRY_RUN_VAL=$([ "${DEPLOY_LIVE}" -eq 1 ] && echo 0 || echo 1)

# Phase 5.1 — wrap commands that touch live system state. In dry-run we print
# the planned command instead of running it so the user can review what WOULD
# happen without actually rebooting their network. Use for: pkg install,
# kldload, pfctl reload/enable, service restart, sysctl that mutates state.
# Safe ops (pkg update, command -v, install -d, chown) run unconditionally.
run_live() {
    if [ "${DEPLOY_LIVE:-0}" -eq 1 ]; then
        "$@"
    else
        printf "${YELLOW}[DRY-RUN]${NC} %s\n" "$*"
    fi
}

# stage_write <target> — reads stdin and writes to <target> in live mode, or
# prints a stub line and discards the input in dry-run mode. Use this in place
# of `cat > target` / `printf ... > target` for any path the installer mutates
# directly so dry-run truly leaves the filesystem unchanged.
stage_write() {
    if [ "${DEPLOY_LIVE:-0}" -eq 1 ]; then
        cat > "$1"
    else
        printf "${YELLOW}[DRY-RUN]${NC} would write %s (stdin discarded)\n" "$1"
        cat > /dev/null
    fi
}

# secret_is_weak <value> — returns 0 (true) when the given SECRET_KEY value
# is empty, known-bad, or shorter than 32 chars. Used by §3 to detect a stale
# env file shipping the .env.example placeholder.
secret_is_weak() {
    _s="$1"
    case "${_s}" in
        ""|changeme|change-me|replace-this-with-a-long-random-secret\
          |dev|development|default|secret|smartshield|smart-shield)
            return 0 ;;
    esac
    _len=$(printf '%s' "${_s}" | wc -c | tr -d ' ')
    [ "${_len}" -lt 32 ] && return 0
    return 1
}

# set_env_key <key> <value> <file> — replace or add a KEY=VALUE line in an
# env file without `sed` escape pitfalls. Treats DEPLOY_LIVE=0 as dry-run.
set_env_key() {
    _key="$1"
    _val="$2"
    _file="$3"
    if [ "${DEPLOY_LIVE:-0}" -ne 1 ]; then
        printf "${YELLOW}[DRY-RUN]${NC} would set %s in %s\n" "${_key}" "${_file}"
        return 0
    fi
    _tmp="$(mktemp)"
    if [ -f "${_file}" ]; then
        grep -v "^${_key}=" "${_file}" > "${_tmp}" 2>/dev/null || true
    fi
    printf '%s=%s\n' "${_key}" "${_val}" >> "${_tmp}"
    install -m 0600 "${_tmp}" "${_file}"
    rm -f "${_tmp}"
}

# ─── Source-tree validation ──────────────────────────────────────────────────
# Phase 2 fix: refuse to mutate /etc, /var, or pkg state until we can prove the
# script is being executed from inside a populated Smart Shield repo. Without
# this check, running install.sh from the wrong directory leaves the system
# half-configured (rc.conf entries written, /etc/dhcpd.conf stub created, etc.)
# before pip fails on the missing requirements.txt.
SRC_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
for f in requirements.txt wsgi.py app/__init__.py bsd/rc.d/smart_shield; do
    if [ ! -f "${SRC_ROOT}/${f}" ]; then
        printf "${RED}[FATAL]${NC} Source file missing: %s/%s\n" "${SRC_ROOT}" "${f}" >&2
        printf "        Run install.sh from the repository root (cd into the project first).\n" >&2
        exit 1
    fi
done
info "Source tree validated at ${SRC_ROOT}"

section "0. Live-Mode Preflight (clock & pkg trust)"

# The most common reason a fresh appliance fails the FIRST pkg fetch is one
# of two things, neither of which the rest of install.sh diagnoses:
#
#   * System clock skew (BIOS battery dead, VM snapshot rewound, etc.). A
#     date off by months/years makes every TLS cert look expired and pkg
#     fails with "SSL peer certificate or SSH remote key was not OK" on
#     every URL.
#   * ca_root_nss missing from the base image. It's in CRITICAL_PKGS below,
#     but that's chicken-and-egg: pkg can't fetch it over TLS without it.
#
# Both surface as the same opaque SSL error. This block detects each up
# front, attempts an automatic fix where one is safe, and aborts with a
# specific remediation message otherwise. Prepare/validate-only modes
# skip the network entirely.
if [ "${DEPLOY_LIVE:-0}" -eq 1 ]; then
    # --- Clock sync (always, best-effort) ---------------------------
    # The clock doesn't have to be off by YEARS to break pkg's TLS — the
    # Fastly cert that fronts pkg.FreeBSD.org rotates roughly every 60-90
    # days, so a clock just *weeks* behind real time will see the current
    # cert as "not yet valid" and reject every URL with the same opaque
    # "peer certificate not OK" message. VM snapshots, dead BIOS batteries,
    # and freshly-imaged appliances all hit this. So always try to sync.
    info "Synchronising system clock (best-effort)..."
    _CLOCK_BEFORE=$(date 2>/dev/null || echo unknown)
    _CLOCK_OK=0
    # 1) sntp -Ss is the most portable recipe: no config file required, one
    #    sample, step the system clock, exit. Ships in FreeBSD base.
    if command -v sntp >/dev/null 2>&1; then
        if sntp -Ss pool.ntp.org 2>/dev/null; then
            _CLOCK_OK=1
        fi
    fi
    # 2) ntpd -gq with a one-shot config. -g allows large initial offset,
    #    -q exits after the first sync. We write a temp config so this
    #    works even when /etc/ntp.conf is empty on a custom image.
    if [ "${_CLOCK_OK}" -ne 1 ] && command -v ntpd >/dev/null 2>&1; then
        _NTP_CONF_TMP=$(mktemp -t ss_ntp_conf.XXXXXX 2>/dev/null || echo /tmp/ss_ntp_conf.$$)
        printf 'server pool.ntp.org iburst\nserver time.cloudflare.com iburst\n' > "${_NTP_CONF_TMP}"
        if ntpd -gq -c "${_NTP_CONF_TMP}" -p /var/run/ntpd.pid.preflight 2>/dev/null; then
            _CLOCK_OK=1
        fi
        rm -f "${_NTP_CONF_TMP}"
    fi
    # 3) ntpdate is legacy (removed from FreeBSD 14 base) but still ships
    #    on some custom images.
    if [ "${_CLOCK_OK}" -ne 1 ] && command -v ntpdate >/dev/null 2>&1; then
        if ntpdate -b pool.ntp.org 2>/dev/null; then
            _CLOCK_OK=1
        fi
    fi
    _CLOCK_AFTER=$(date 2>/dev/null || echo unknown)
    if [ "${_CLOCK_OK}" -eq 1 ]; then
        info "  Clock: ${_CLOCK_BEFORE}"
        info "      -> ${_CLOCK_AFTER}"
    else
        warn "  Could not auto-sync clock; continuing with current time."
        warn "  Clock: ${_CLOCK_AFTER}"
    fi

    # Final-floor sanity check — if the year is still obviously wrong
    # after we tried our best, abort with a manual-fix message rather
    # than letting pkg fail later with an opaque TLS error.
    _SYS_YEAR=$(date +%Y 2>/dev/null || echo 1970)
    if [ "${_SYS_YEAR}" -lt 2024 ]; then
        fatal "System clock still reports year ${_SYS_YEAR} after NTP sync.
        Most likely no NTP server is reachable (firewall? wrong DNS?).
        Set the date manually then re-run install.sh:
            date YYYYMMDDhhmm   # e.g. date 202605290900
        Current date: $(date)"
    fi

    # --- pkg repository reachability probe ---------------------------
    # If pkg can't talk to the repo, the CRITICAL_PKGS install at §1
    # below fails with no useful diagnostics beyond pkg's own output.
    # Probe here so the operator sees the failure mode immediately —
    # AND we have a chance to recover ca_root_nss over HTTP.
    info "Probing pkg repository connectivity..."
    _PKG_PROBE_LOG=$(mktemp -t ss_pkg_probe.XXXXXX 2>/dev/null || echo /tmp/ss_pkg_probe.$$)
    if pkg update -q 2>"${_PKG_PROBE_LOG}"; then
        info "  OK — pkg repository reachable, trust store healthy."
    else
        warn "pkg update failed. Error output:"
        cat "${_PKG_PROBE_LOG}" >&2 || true

        if grep -q -i -e 'ssl' -e 'certificate' -e 'remote key' "${_PKG_PROBE_LOG}"; then
            _CA_INSTALLED=$(pkg info ca_root_nss >/dev/null 2>&1 && echo yes || echo no)
            _CA_BUNDLE="/usr/local/share/certs/ca-root-nss.crt"
            warn "TLS verification failed. Diagnosing:"
            warn "  * System clock        : $(date)"
            warn "  * ca_root_nss package : ${_CA_INSTALLED}"
            warn "  * Trust bundle file   : $([ -f "${_CA_BUNDLE}" ] && echo present || echo MISSING)"
            warn "  * /etc/ssl/cert.pem   : $([ -L /etc/ssl/cert.pem ] && readlink /etc/ssl/cert.pem || ([ -f /etc/ssl/cert.pem ] && echo "regular file" || echo MISSING))"

            _PKG_RECOVERED=0

            # ── Recovery path 1: trust bundle exists but the symlink is
            # missing/wrong. This is the ca_root_nss-installed-but-pkg-still-
            # fails case — the package ships the bundle but the post-install
            # symlink at /etc/ssl/cert.pem may not have been created (custom
            # FreeBSD images, manual pkg add, etc.). libfetch reads
            # /etc/ssl/cert.pem; without it, every cert chain looks unsigned.
            if [ -f "${_CA_BUNDLE}" ]; then
                _CURRENT_TARGET=""
                [ -L /etc/ssl/cert.pem ] && _CURRENT_TARGET=$(readlink /etc/ssl/cert.pem 2>/dev/null || echo "")
                if [ "${_CURRENT_TARGET}" != "${_CA_BUNDLE}" ]; then
                    info "  Repairing /etc/ssl/cert.pem -> ${_CA_BUNDLE}"
                    mkdir -p /etc/ssl
                    ln -sf "${_CA_BUNDLE}" /etc/ssl/cert.pem
                    if pkg update -q 2>/dev/null; then
                        info "  Recovery successful — trust-store symlink fixed."
                        _PKG_RECOVERED=1
                    else
                        warn "  Symlink repaired but pkg still failing — falling through."
                    fi
                fi
            fi

            # ── Recovery path 2: ca_root_nss missing entirely. Bootstrap it
            # by downloading the package over HTTP (the only safe way out of
            # the chicken-and-egg). Resolve a real version-pinned filename
            # from the public packagesite index instead of guessing a path.
            if [ "${_PKG_RECOVERED}" -ne 1 ] && [ "${_CA_INSTALLED}" != "yes" ]; then
                _ABI=$(pkg config ABI 2>/dev/null)
                if [ -z "${_ABI}" ]; then
                    _ABI="FreeBSD:$(uname -r | cut -d. -f1 | tr -d -):$(uname -m)"
                fi
                _ALL_URL="http://pkg.FreeBSD.org/${_ABI}/quarterly/All/"
                info "  Bootstrapping ca_root_nss over HTTP from ${_ALL_URL}"
                _CA_FILE=$(fetch -q -o - "${_ALL_URL}" 2>/dev/null \
                    | grep -o 'ca_root_nss-[0-9][^"]*\.\(pkg\|txz\)' \
                    | head -1)
                if [ -n "${_CA_FILE}" ]; then
                    _CA_TMP=$(mktemp -t ss_caroot.XXXXXX 2>/dev/null || echo /tmp/ss_caroot.$$)
                    if fetch -q -o "${_CA_TMP}" "${_ALL_URL}${_CA_FILE}" && pkg add "${_CA_TMP}"; then
                        rm -f "${_CA_TMP}"
                        # Symlink might still need fixing after the manual add.
                        [ -f "${_CA_BUNDLE}" ] && ln -sf "${_CA_BUNDLE}" /etc/ssl/cert.pem
                        if pkg update -q; then
                            info "  Recovery successful — pkg repository reachable now."
                            _PKG_RECOVERED=1
                        fi
                    else
                        rm -f "${_CA_TMP}"
                    fi
                fi
            fi

            if [ "${_PKG_RECOVERED}" -ne 1 ]; then
                fatal "Could not repair pkg TLS. Manual recovery:
            ls -l /etc/ssl/cert.pem
            ln -sf ${_CA_BUNDLE} /etc/ssl/cert.pem   # if symlink broken
            pkg install -f ca_root_nss               # if bundle missing
            pkg update                                # retry
        then re-run install.sh. If pkg still fails, the WAN may be behind
        a TLS-inspecting proxy that's rewriting the cert chain."
            fi
        elif grep -q -i -e 'name resolution' -e 'no address' -e 'host not found' -e 'no such host' "${_PKG_PROBE_LOG}"; then
            fatal "DNS resolution failed for pkg.FreeBSD.org. Fix /etc/resolv.conf or WAN routing, then re-run install.sh."
        elif grep -q -i -e 'connection refused' -e 'no route to host' -e 'timed out' "${_PKG_PROBE_LOG}"; then
            fatal "Network unreachable. Check WAN cable / default gateway / firewall rules upstream, then re-run install.sh."
        else
            fatal "pkg update failed for an unrecognised reason — see error above. Common causes: corporate TLS-inspecting proxy on the WAN, exhausted /var disk, or a stale /var/db/pkg lock."
        fi
    fi
    rm -f "${_PKG_PROBE_LOG}"
fi

section "1. Package Installation"

info "Updating pkg repository..."
# In live mode the §0 preflight already exercised pkg update successfully;
# this re-run is harmless (pkg's catalog is cached) but kept so the dry-run
# trace shows the same step a live install performs.
run_live pkg update -q

# Phase 5.2 — split into three package tiers (Fv11 review §P1-04):
#   * CRITICAL_PKGS  — Smart Shield genuinely will not run without these. A
#                      failure here aborts the install.
#   * OPERATOR_PKGS  — quality-of-life tools (a console editor, git for
#                      pulling updates). Useful but not load-bearing: install
#                      best-effort and warn on miss, never abort.
#   * OPTIONAL_PKGS  — feature dependencies. Same best-effort policy, but
#                      missing packages directly disable a Smart Shield
#                      feature (IDS, VPN, UPnP, etc.).
CRITICAL_PKGS="python3 sqlite3 ca_root_nss unbound isc-dhcp44-server nginx pkgconf curl bind-tools tcpdump rsync"
OPERATOR_PKGS="git nano"
OPTIONAL_PKGS="openvpn strongswan suricata mrtg kea mpd5 miniupnpd igmpproxy ddclient sudo"

info "Installing critical packages: ${CRITICAL_PKGS}"
# shellcheck disable=SC2086
if [ "${DEPLOY_LIVE:-0}" -eq 1 ]; then
    if ! pkg install -y ${CRITICAL_PKGS}; then
        echo "[ERROR] Critical pkg install failed — check network connectivity and package names above."
        exit 1
    fi
else
    printf "${YELLOW}[DRY-RUN]${NC} pkg install -y %s\n" "${CRITICAL_PKGS}"
fi

info "Installing operator tools (best-effort, non-fatal): ${OPERATOR_PKGS}"
MISSING_OPERATOR=""
for _opkg in ${OPERATOR_PKGS}; do
    if [ "${DEPLOY_LIVE:-0}" -eq 1 ]; then
        if pkg install -y "${_opkg}" >/dev/null 2>&1; then
            info "  OK:      ${_opkg}"
        else
            warn "  MISSING: ${_opkg} (operator convenience tool — appliance still works)"
            MISSING_OPERATOR="${MISSING_OPERATOR} ${_opkg}"
        fi
    else
        printf "${YELLOW}[DRY-RUN]${NC} pkg install -y %s\n" "${_opkg}"
    fi
done
if [ -n "${MISSING_OPERATOR}" ]; then
    warn "Operator tools NOT installed:${MISSING_OPERATOR}"
fi

info "Installing optional packages individually (failures are non-fatal): ${OPTIONAL_PKGS}"
MISSING_OPTIONAL=""
for _opkg in ${OPTIONAL_PKGS}; do
    if [ "${DEPLOY_LIVE:-0}" -eq 1 ]; then
        if pkg install -y "${_opkg}" >/dev/null 2>&1; then
            info "  OK:      ${_opkg}"
        else
            warn "  MISSING: ${_opkg} (feature requiring this package will be unavailable)"
            MISSING_OPTIONAL="${MISSING_OPTIONAL} ${_opkg}"
        fi
    else
        printf "${YELLOW}[DRY-RUN]${NC} pkg install -y %s\n" "${_opkg}"
    fi
done
if [ -n "${MISSING_OPTIONAL}" ]; then
    warn "Optional packages NOT installed:${MISSING_OPTIONAL}"
fi

# ─── validate-only short-circuit ──────────────────────────────────────────────
# In validate-only mode we stop here without touching /etc, /var, /usr/local
# directory state. The preflight Python tools run against SRC_ROOT instead
# of APP_ROOT so CI can gate a release on them without a populated install.
if [ "${INSTALL_MODE}" = "validate-only" ]; then
    section "Validate-only preflight"
    if [ -x "${SRC_ROOT}/tools/release_check.py" ] && command -v python3 >/dev/null 2>&1; then
        ( cd "${SRC_ROOT}" && python3 tools/release_check.py ) \
            || fatal "release_check.py failed (validate-only)"
    fi
    if [ -f "${SRC_ROOT}/tools/check_routes.py" ] && command -v python3 >/dev/null 2>&1; then
        ( cd "${SRC_ROOT}" && python3 tools/check_routes.py ) \
            || warn "check_routes.py failed (validate-only)"
    fi
    info "validate-only run complete — no filesystem state was modified."
    exit 0
fi

# Verify the full set of system + service binaries the app calls or exposes as
# features. Keep this list in sync with app/services/freebsd_setup.py:_TOOLS
# (the canonical Python preflight manifest) and the commands referenced in
# app/services/feature_registry.py. Read-only: safe in dry-run.
info "Verifying system + service binary availability..."
# command -v honours $PATH; base tools live under /sbin,/usr/sbin,/bin,/usr/bin
# and may be absent from a minimal root PATH, so fall back to absolute paths.
_have_bin() {
    command -v "$1" >/dev/null 2>&1 && return 0
    for _d in /sbin /usr/sbin /bin /usr/bin /usr/local/sbin /usr/local/bin; do
        [ -x "${_d}/$1" ] && return 0
    done
    return 1
}
# Note: strongSwan is probed via `swanctl` only. Modern strongSwan on FreeBSD
# dropped the legacy `ipsec` starter script, so checking a bare `ipsec` here
# printed a misleading "MISSING: ipsec" even when strongSwan was fully present.
for bin in \
  pfctl ifconfig route netstat arp ndp sockstat sysrc service sysctl \
  kldload kldstat dmesg pgrep pkill dnctl tcpdump \
  unbound unbound-checkconf unbound-control dhcpd \
  openvpn swanctl mpd5 suricata suricata-update \
  mrtg kea-dhcp6 miniupnpd igmpproxy ddclient nsupdate dig nginx \
  ntpd ntpq bsnmpd rtadvd curl openssl; do
    if _have_bin "$bin"; then
        info "  OK: $bin"
    else
        warn "  MISSING: $bin — feature depending on this tool will be unavailable"
    fi
done

# Python sqlite3 extension (required for the app database)
PYTHON_VER=$(python3 -c "import sys; print('%d%d' % sys.version_info[:2])" 2>/dev/null || echo "311")
if [ "${DEPLOY_LIVE:-0}" -eq 1 ]; then
    pkg install -y "py${PYTHON_VER}-sqlite3" 2>/dev/null \
        || pkg install -y py311-sqlite3 \
        || warn "py${PYTHON_VER}-sqlite3 not found — sqlite3 module may already be bundled."
else
    printf "${YELLOW}[DRY-RUN]${NC} pkg install -y py%s-sqlite3\n" "${PYTHON_VER}"
fi

# gevent (gunicorn worker for WebSocket terminal) is pinned in requirements.txt
# and installed into the project venv in section 4 — no system-Python install here.
# suricata-update is also installed into the venv in section 5c after the venv exists,
# so it gets reliable dependency resolution and avoids the system pkg_resources fragility.

# ─── Deploy source tree to APP_ROOT ───────────────────────────────────────────
# Wave I: the installer used to assume the operator had already copied the
# project to ${APP_ROOT}.  That left the install half-broken when an admin
# ran it from /root/Smart-Shield-Fv5/ (unzipped) or any path other than
# /usr/local/share/smartshield.  Now we rsync (or tar-pipe) the source tree
# into APP_ROOT every time, skipping the copy iff SRC_ROOT == APP_ROOT.
#
# Ordering: this runs AFTER §1 (so rsync — a critical pkg — is installed and we
# get a proper --delete prune instead of the tar fallback) and AFTER the
# validate-only short-circuit (so validate-only never writes APP_ROOT, honouring
# its "no filesystem writes" contract). Nothing between §1 and here touches
# APP_ROOT, so the move is behaviour-safe.
#
# Excludes:
#   * .git / .venv / __pycache__ / *.pyc  — never deploy build artefacts
#   * tests/                              — production appliance has no tests
#   * *.md                                — docs live in the source repo
# Runtime state (DB, logs, certs, generated configs) lives outside APP_ROOT
# (/var/db, /usr/local/etc, /var/log, /var/run) so this copy never clobbers
# operator data.
section "1c. Deploy Source Tree"
if [ "${SRC_ROOT}" = "${APP_ROOT}" ]; then
    info "SRC_ROOT == APP_ROOT (${APP_ROOT}) — no source-deploy needed"
else
    info "Deploying source tree: ${SRC_ROOT} → ${APP_ROOT}"
    install -d -m 0755 "${APP_ROOT}"
    if command -v rsync >/dev/null 2>&1; then
        rsync -a --delete \
            --exclude '.git' \
            --exclude '.venv' \
            --exclude '__pycache__' \
            --exclude '*.pyc' \
            --exclude 'tests' \
            --exclude '*.md' \
            --exclude 'data.db' \
            "${SRC_ROOT}/" "${APP_ROOT}/" \
            && info "rsync deploy complete." \
            || fatal "rsync failed during source deploy"
    else
        # Fallback: tar pipe. No --delete equivalent so a stale file removed
        # from the source tree may linger in APP_ROOT — acceptable for the
        # rsync-less edge case (e.g. prepare mode, where pkg install is a no-op).
        warn "rsync not available — falling back to tar (no stale-file pruning)."
        ( cd "${SRC_ROOT}" && tar \
            --exclude '.git' \
            --exclude '.venv' \
            --exclude '__pycache__' \
            --exclude 'tests' \
            --exclude '*.md' \
            --exclude 'data.db' \
            -cf - . ) | ( cd "${APP_ROOT}" && tar -xf - ) \
            && info "tar deploy complete." \
            || fatal "tar deploy failed"
    fi
    chown -R root:wheel "${APP_ROOT}" 2>/dev/null || true
fi

section "2. Directory Creation"

# Smart Shield runtime directories
for DIR in \
    "${DATA_DIR}" \
    "${DATA_DIR}/uploads/profile_pictures" \
    "${LOG_DIR}" \
    "${RUN_DIR}" \
    "${ETC_DIR}" \
    "${APP_ROOT}"
do
    if [ ! -d "${DIR}" ]; then
        install -d -m 0755 "${DIR}"
        info "Created: ${DIR}"
    else
        info "Exists:  ${DIR}"
    fi
done

# Ensure all Smart Shield directories are owned by root:wheel (root runtime).
for DIR in \
    "${APP_ROOT}" \
    "${ETC_DIR}" \
    "${DATA_DIR}" \
    "${DATA_DIR}/uploads/profile_pictures" \
    "${LOG_DIR}" \
    "${RUN_DIR}"
do
    chown -R root:wheel "${DIR}" 2>/dev/null || true
done
info "Ownership set to root:wheel for Smart Shield paths."

# Phase 11 — path canonicalization to `smartshield` (no hyphen).
# Canonical paths are now /usr/local/{share,etc}/smartshield, /var/{db,log,run}/smartshield.
# Drop compatibility symlinks from the legacy `smart-shield` paths so:
#   1. Existing operator shell aliases, third-party scripts, and console_menu
#      installs that hardcode `smart-shield` keep resolving.
#   2. App-side modules that still embed literal `/var/db/smart-shield/...`
#      paths (audit_log.py, captive_portal.py, abusech_client.py, etc.) keep
#      reading and writing to the same on-disk data while the next migration
#      phase routes them through app/config.py:_ss_dir().
# THESE SYMLINKS ARE LOAD-BEARING — do not remove until every module under
# app/ resolves its paths via _ss_dir(); a grep for `smart-shield` under app/
# must come back empty first.
for _pair in \
    "/usr/local/share/smartshield:/usr/local/share/smart-shield" \
    "/usr/local/etc/smartshield:/usr/local/etc/smart-shield" \
    "/var/db/smartshield:/var/db/smart-shield" \
    "/var/log/smartshield:/var/log/smart-shield" \
    "/var/run/smartshield:/var/run/smart-shield"
do
    _src="${_pair%%:*}"
    _dst="${_pair##*:}"
    if [ -d "${_src}" ] && [ ! -e "${_dst}" ]; then
        ln -sfn "${_src}" "${_dst}" 2>/dev/null \
            && info "Compat symlink: ${_dst} → ${_src}" \
            || warn "Could not create ${_dst} symlink — legacy-path tooling may not resolve"
    fi
done

# PF — /etc already exists; no dir needed

# DHCP
DHCPD_DIRS="/var/db/dhcpd"
for DIR in ${DHCPD_DIRS}; do
    install -d -m 0755 "${DIR}" 2>/dev/null && info "Created: ${DIR}" || info "Exists:  ${DIR}"
done

# Unbound
install -d -m 0755 /usr/local/etc/unbound 2>/dev/null && info "Created: /usr/local/etc/unbound" || true

# OpenVPN
install -d -m 0755 /usr/local/etc/openvpn    2>/dev/null && info "Created: /usr/local/etc/openvpn" || true
install -d -m 0700 /usr/local/etc/openvpn/keys 2>/dev/null && info "Created: /usr/local/etc/openvpn/keys (mode 700)" || true
install -d -m 0755 /var/log/openvpn           2>/dev/null && info "Created: /var/log/openvpn" || true
install -d -m 0755 /var/run/openvpn           2>/dev/null && info "Created: /var/run/openvpn" || true

# L2TP (mpd5)
install -d -m 0755 /usr/local/etc/mpd5 2>/dev/null && info "Created: /usr/local/etc/mpd5" || true
install -d -m 0755 /var/run/mpd5       2>/dev/null && info "Created: /var/run/mpd5" || true

# Unbound query log (required by SIEM collector)
install -d -m 0755 /var/log/unbound    2>/dev/null && info "Created: /var/log/unbound" || true

# Suricata
install -d -m 0755 /usr/local/etc/suricata       2>/dev/null && info "Created: /usr/local/etc/suricata" || true
install -d -m 0755 /usr/local/etc/suricata/rules  2>/dev/null && info "Created: /usr/local/etc/suricata/rules" || true
install -d -m 0755 /var/log/suricata              2>/dev/null && info "Created: /var/log/suricata" || true
install -d -m 0755 /var/run/suricata              2>/dev/null && info "Created: /var/run/suricata" || true
# suricata-update writes its merged ruleset here (ids_writer._SURICATA_UPDATE_RULES)
install -d -m 0755 /var/lib/suricata             2>/dev/null && info "Created: /var/lib/suricata" || true
install -d -m 0755 /var/lib/suricata/rules        2>/dev/null && info "Created: /var/lib/suricata/rules" || true
# Placeholder so `suricata -T` passes before the first suricata-update run.
# Real rules from suricata-update overwrite this file in place.
run_live touch /var/lib/suricata/rules/suricata.rules
run_live chmod 0644 /var/lib/suricata/rules/suricata.rules

# Support files referenced by the generated suricata.yaml
# (ids_writer.generate_suricata_yaml writes classification-file / reference-config-file).
# `suricata -T` fails if these are missing, even when the YAML is otherwise valid.
# Prefer the package-shipped copies, then the .sample variants, else a minimal stub.
for _sf in classification.config reference.config; do
    _dst="/usr/local/etc/suricata/${_sf}"
    if [ ! -f "${_dst}" ]; then
        if [ -f "/usr/local/share/suricata/${_sf}" ]; then
            run_live cp "/usr/local/share/suricata/${_sf}" "${_dst}"
            info "Installed Suricata support file: ${_dst} (from share/)"
        elif [ -f "${_dst}.sample" ]; then
            run_live cp "${_dst}.sample" "${_dst}"
            info "Installed Suricata support file: ${_dst} (from .sample)"
        else
            case "${_sf}" in
                classification.config)
                    printf 'config classification: not-suspicious,Not Suspicious Traffic,3\n' \
                        | stage_write "${_dst}"
                    ;;
                reference.config)
                    printf 'config reference: url   http://\n' | stage_write "${_dst}"
                    ;;
            esac
            info "Created minimal Suricata support file: ${_dst} (no package copy found)"
        fi
        run_live chmod 0644 "${_dst}"
    fi
done

# Kea DHCPv6 (used by app/services/dhcpv6_writer.py)
for _KEA_DIR in /usr/local/etc/kea /var/db/kea /var/log/kea; do
    install -d -m 0755 -o root -g wheel "${_KEA_DIR}" 2>/dev/null && info "Created: ${_KEA_DIR}" || true
done

# Nginx
install -d -m 0755 /usr/local/etc/nginx  2>/dev/null && info "Created: /usr/local/etc/nginx" || true
install -d -m 0755 /var/log/nginx        2>/dev/null && info "Created: /var/log/nginx" || true
install -d -m 0755 /var/run/nginx        2>/dev/null && info "Created: /var/run/nginx" || true

# MRTG
install -d -m 0755 /usr/local/etc/mrtg             2>/dev/null && info "Created: /usr/local/etc/mrtg" || true
install -d -m 0755 "${DATA_DIR}/mrtg"       2>/dev/null && info "Created: ${DATA_DIR}/mrtg" || true

# Log rotation (newsyslog)
_NEWSYSLOG_SRC="$(dirname "$0")/etc/newsyslog.d/smartshield.conf"
if [ -f "${_NEWSYSLOG_SRC}" ]; then
    install -d -m 0755 /usr/local/etc/newsyslog.d 2>/dev/null || true
    install -m 0644 "${_NEWSYSLOG_SRC}" /usr/local/etc/newsyslog.d/smartshield.conf
    info "Log rotation config installed → /usr/local/etc/newsyslog.d/smartshield.conf"
fi

# Ensure /etc/newsyslog.conf includes the drop-in directory (minimal installs may omit it)
if [ -f /etc/newsyslog.conf ]; then
    if ! grep -q "/usr/local/etc/newsyslog.d" /etc/newsyslog.conf 2>/dev/null; then
        printf '\n<include> /usr/local/etc/newsyslog.d/*.conf\n' >> /etc/newsyslog.conf
        info "Added newsyslog.d include to /etc/newsyslog.conf"
    else
        info "newsyslog.d already included in /etc/newsyslog.conf"
    fi
fi

# ── Required runtime files ───────────────────────────────────────────────────
# dhcpd refuses to start if dhcpd.leases doesn't exist as a file
if [ ! -f /var/db/dhcpd/dhcpd.leases ]; then
    run_live touch /var/db/dhcpd/dhcpd.leases
    run_live chmod 0644 /var/db/dhcpd/dhcpd.leases
    info "Created: /var/db/dhcpd/dhcpd.leases"
fi

# Minimal PF ruleset — wizard overwrites with generated rules; without this PF can't load.
# Routed through stage_write so dry-run does not leave a "pass all" PF config behind.
if [ ! -f /etc/pf.conf ]; then
    printf '# Smart Shield bootstrap — wizard replaces this\nset skip on lo0\npass all\n' \
        | stage_write /etc/pf.conf
    info "Created: /etc/pf.conf (minimal bootstrap — wizard will replace)"
fi

# Captive-portal PF anchor — empty placeholder so the first toggle-on doesn't
# trip `pfctl -a captive_portal -f /etc/pf.captive_portal.conf` with ENOENT.
# app/services/captive_portal.apply_captive_portal rewrites this with the
# real rdr/anchor rules on first apply.
if [ ! -f /etc/pf.captive_portal.conf ]; then
    printf '# Smart Shield captive portal anchor — apply_captive_portal replaces this\n' \
        | stage_write /etc/pf.captive_portal.conf
    info "Created: /etc/pf.captive_portal.conf (empty placeholder — apply_captive_portal will replace)"
fi

# ─── Legacy-path migration ────────────────────────────────────────────────────
# Phase 11 renamed every runtime dir from `smart-shield` to `smartshield`.
# If the operator is upgrading an old install, move the directory contents
# into the canonical paths so the rest of the installer (and the app) only
# has to think about `smartshield`. Idempotent — exits cleanly when nothing
# is to do.
if [ "${DEPLOY_LIVE:-0}" -eq 1 ] && [ -x "$(command -v python3 2>/dev/null)" ]; then
    if [ -f "${SRC_ROOT}/tools/migrate_legacy_paths.py" ]; then
        python3 "${SRC_ROOT}/tools/migrate_legacy_paths.py" --apply \
            | sed 's/^/    /' || true
    fi
else
    printf "${YELLOW}[DRY-RUN]${NC} python3 tools/migrate_legacy_paths.py --apply\n"
fi

section "3. Environment Configuration"

ENV_FILE="${ETC_DIR}/smartshield.env"
ENV_EXAMPLE="${APP_ROOT}/.env.example"

if [ ! -f "${ENV_FILE}" ]; then
    # Phase 2.5 fix: never fall back to a literal "changeme" secret. token_hex
    # produces only hex characters [0-9a-f], so the value is always safe to
    # write unquoted; rejecting the fallback path means a half-broken Python
    # install fails the installer loudly rather than shipping a weak default.
    SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))" 2>/dev/null || true)
    if [ -z "${SECRET}" ]; then
        fatal "Failed to generate SECRET_KEY (python3 + secrets module required)"
    fi
    if [ -f "${ENV_EXAMPLE}" ]; then
        # Strip any placeholder SECRET_KEY line from the template and append a
        # single canonical line — this avoids sed's & / \ escaping pitfalls if
        # the generator ever produces a non-hex value in the future.
        ENV_TMP="$(mktemp)"
        grep -vE '^(SECRET_KEY|SMARTSHIELD_ENABLE_NETWORK_APPLY|SMARTSHIELD_NETWORK_DRY_RUN)=' \
            "${ENV_EXAMPLE}" > "${ENV_TMP}"
        printf 'SECRET_KEY=%s\n' "${SECRET}"                                    >> "${ENV_TMP}"
        printf 'SMARTSHIELD_ENABLE_NETWORK_APPLY=%s\n' "${DEPLOY_LIVE}"         >> "${ENV_TMP}"
        printf 'SMARTSHIELD_NETWORK_DRY_RUN=%s\n'      "${DRY_RUN_VAL}"         >> "${ENV_TMP}"
        install -m 0600 "${ENV_TMP}" "${ENV_FILE}"
        rm -f "${ENV_TMP}"
        info "Deployment flags set: ENABLE_NETWORK_APPLY=${DEPLOY_LIVE}  DRY_RUN=${DRY_RUN_VAL}"
        info "Created: ${ENV_FILE} (SECRET_KEY set automatically, mode 0600)"
        info "Admin account will be created on first run via the setup wizard."
    else
        warn "No .env.example found — creating minimal env file."
        cat > "${ENV_FILE}" << EOF
SECRET_KEY=${SECRET}
FLASK_DEBUG=0
SMARTSHIELD_DB_PATH=/var/db/smartshield/data.db
SMARTSHIELD_CONFIG_PATH=/usr/local/etc/smartshield/config.json
SMARTSHIELD_UPLOAD_DIR=/var/db/smartshield/uploads/profile_pictures
SMARTSHIELD_AUDIT_LOG_PATH=/var/log/smartshield/audit.log
SMARTSHIELD_ENABLE_NETWORK_APPLY=${DEPLOY_LIVE}
SMARTSHIELD_NETWORK_DRY_RUN=${DRY_RUN_VAL}
# Root-equivalent web terminal — disabled by default (rc.d runs as root, so
# any opened terminal is a root session). Flip to 1 only on trusted LANs.
SMARTSHIELD_TERMINAL_ENABLED=0
# Abuse.ch threat intelligence — set your Auth-Key from https://abuse.ch/
ABUSECH_AUTH_KEY=
ABUSECH_DRY_RUN=1
# SmartShield AI chatbot (Groq) — get a free key at https://console.groq.com/keys
GROQ_API_KEY=
EOF
        chmod 0600 "${ENV_FILE}"
        info "Admin account will be created on first run via the setup wizard."
    fi
else
    info "Env file already exists: ${ENV_FILE}"
    chmod 0600 "${ENV_FILE}"

    # P0-04: an existing env file may carry the .env.example placeholder
    # ("replace-this-with-a-long-random-secret") or another weak SECRET_KEY.
    # Detect and rotate the key in place so production never boots with the
    # template default.
    CURRENT_SECRET="$(awk -F= '$1=="SECRET_KEY"{print substr($0, index($0,"=")+1)}' \
        "${ENV_FILE}" 2>/dev/null | tail -1)"
    if secret_is_weak "${CURRENT_SECRET}"; then
        NEW_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))" 2>/dev/null || true)
        if [ -z "${NEW_SECRET}" ]; then
            fatal "SECRET_KEY in ${ENV_FILE} is weak and python3 token_hex is unavailable to rotate it."
        fi
        if [ "${DEPLOY_LIVE:-0}" -eq 1 ]; then
            set_env_key SECRET_KEY "${NEW_SECRET}" "${ENV_FILE}"
            # Sanity re-read — if the rotation somehow produced another weak
            # value (impossible with token_hex, but cheap insurance), abort
            # rather than silently shipping a half-fixed install.
            VERIFY_SECRET="$(awk -F= '$1=="SECRET_KEY"{print substr($0, index($0,"=")+1)}' \
                "${ENV_FILE}" 2>/dev/null | tail -1)"
            if secret_is_weak "${VERIFY_SECRET}"; then
                fatal "SECRET_KEY is still weak after repair; refusing production install."
            fi
            info "Weak SECRET_KEY detected in ${ENV_FILE} — rotated to a fresh 64-char token."
        else
            warn "Weak SECRET_KEY detected in ${ENV_FILE} — would rotate (skipped in dry-run)."
        fi
    fi
fi

# Prompt for ABUSECH_AUTH_KEY if not already set in the env file
if ! grep -q "^ABUSECH_AUTH_KEY=.\+" "${ENV_FILE}" 2>/dev/null; then
    if [ "${SMARTSHIELD_NONINTERACTIVE:-0}" = "1" ]; then
        ABUSE_KEY="${ABUSECH_AUTH_KEY:-}"
    else
        printf "\n${BOLD}━━━ Abuse.ch Threat Intelligence ━━━${NC}\n"
        printf "Abuse.ch provides URLhaus / MalwareBazaar / ThreatFox threat feeds.\n"
        printf "Get your free API key at: https://abuse.ch/\n"
        printf "${YELLOW}[?]${NC} Enter your ABUSECH_AUTH_KEY (press Enter to skip): "
        read -r ABUSE_KEY
    fi
    if [ -n "${ABUSE_KEY}" ]; then
        set_env_key ABUSECH_AUTH_KEY "${ABUSE_KEY}" "${ENV_FILE}"
        set_env_key ABUSECH_DRY_RUN  "0"            "${ENV_FILE}"
        info "Abuse.ch Auth Key saved and live API calls enabled (dry-run disabled)."
    else
        warn "ABUSECH_AUTH_KEY not set — threat intel features disabled until you add it to ${ENV_FILE}"
    fi
fi

# Prompt for GROQ_API_KEY (SmartShield AI chatbot — Groq)
if ! grep -q "^GROQ_API_KEY=.\+" "${ENV_FILE}" 2>/dev/null; then
    if [ "${SMARTSHIELD_NONINTERACTIVE:-0}" = "1" ]; then
        GROQ_KEY="${GROQ_API_KEY:-}"
    else
        printf "\n${BOLD}━━━ SmartShield AI Chatbot (Groq) ━━━${NC}\n"
        printf "SmartShield includes an AI security assistant powered by Groq (llama-3.3-70b).\n"
        printf "It can analyse logs, explain rules, and answer firewall questions.\n"
        printf "Get a free API key at: https://console.groq.com/keys\n"
        printf "${YELLOW}[?]${NC} Enter your GROQ_API_KEY (press Enter to skip): "
        read -r GROQ_KEY
    fi
    if [ -n "${GROQ_KEY}" ]; then
        set_env_key GROQ_API_KEY "${GROQ_KEY}" "${ENV_FILE}"
        info "Groq API key saved — SmartShield AI chatbot is enabled."
    else
        warn "GROQ_API_KEY not set — AI chatbot disabled until you add it via Admin → Settings → SmartShield AI."
    fi
fi

# Optional: email address to receive the setup claim code.
# Skipped silently in non-interactive installs and in non-live modes (no point
# emailing a code for an appliance that isn't actually being commissioned).
# The actual send happens at the end of install.sh, after the claim token file
# exists and the console banner has already printed the code.
ADMIN_WELCOME_EMAIL=""
if [ "${SMARTSHIELD_NONINTERACTIVE:-0}" != "1" ] && [ "${INSTALL_MODE}" = "live" ]; then
    printf "\n${BOLD}━━━ Optional: Email the setup claim code ━━━${NC}\n"
    printf "If you enter an address, the one-time claim code that unlocks the\n"
    printf "first-run wizard will be emailed there. The same code is also\n"
    printf "printed on screen when install.sh finishes — email is just a\n"
    printf "convenience (handy if you're SSH'd in over a small terminal).\n"
    printf "${YELLOW}[?]${NC} Admin email (press Enter to skip): "
    read -r ADMIN_WELCOME_EMAIL
fi

CONFIG_FILE="${ETC_DIR}/config.json"
CONFIG_EXAMPLE="${APP_ROOT}/config.example.json"
if [ ! -f "${CONFIG_FILE}" ] && [ -f "${CONFIG_EXAMPLE}" ]; then
    cp "${CONFIG_EXAMPLE}" "${CONFIG_FILE}"
    info "Created: ${CONFIG_FILE}"
else
    info "Config already exists or example missing — skipping."
fi

# Pre-generate master encryption key (avoids auto-generate delay on first request)
MASTER_KEY_FILE="${ETC_DIR}/master.key"
if [ ! -f "${MASTER_KEY_FILE}" ]; then
    python3 -c "import os,base64; open('${MASTER_KEY_FILE}','wb').write(base64.b64encode(os.urandom(32))+b'\n')" \
        || warn "Could not pre-generate master.key — will auto-generate on first app start."
    chmod 0600 "${MASTER_KEY_FILE}" 2>/dev/null || true
    info "Generated: ${MASTER_KEY_FILE} (mode 0600)"
fi

section "4. Python Virtual Environment"

# cryptography requires Rust to build from source — install rust before pip
if ! command -v rustc >/dev/null 2>&1; then
    info "Installing rust (required to build cryptography)..."
    run_live pkg install -y rust
else
    info "Rust already installed: $(rustc --version)"
fi

if [ ! -x "${VENV}/bin/python3" ]; then
    info "Creating virtual environment at ${VENV}..."
    python3 -m venv "${VENV}"
else
    info "Virtual environment already exists."
fi

info "Upgrading pip + installing requirements..."
"${VENV}/bin/pip" install --upgrade pip -q
"${VENV}/bin/pip" install -r "${APP_ROOT}/requirements.txt"
info "Python dependencies installed."

# ── suricata-update inside the venv ────────────────────────────────────────────
# Installing into the venv avoids the pkg_resources.ResolutionError that
# affects system-Python installs done with `pip --break-system-packages`,
# because the venv has clean, isolated setuptools/idstools/pyyaml metadata.
info "Installing suricata-update into the project venv..."

# System-path mutations (uninstalling the broken --break-system-packages copy
# and removing a non-symlink at /usr/local/bin) must NOT happen in dry-run.
# Use the explicit system interpreter, never a bare `pip` off $PATH.
if [ "${DEPLOY_LIVE:-0}" -eq 1 ]; then
    python3 -m pip uninstall -y --break-system-packages suricata-update 2>/dev/null || true
    if [ -e /usr/local/bin/suricata-update ] && [ ! -L /usr/local/bin/suricata-update ]; then
        rm -f /usr/local/bin/suricata-update
    fi
else
    printf "${YELLOW}[DRY-RUN]${NC} would remove any system suricata-update + non-symlink /usr/local/bin/suricata-update\n"
fi

# The venv install is project-local (mirrors the unconditional venv setup in §4),
# so it runs in both modes; only the /usr/local/bin symlink + index init are gated.
if "${VENV}/bin/pip" install --upgrade suricata-update idstools pyyaml -q; then
    if [ "${DEPLOY_LIVE:-0}" -eq 1 ]; then
        # Expose the venv wrapper at the conventional path so $PATH lookups work.
        ln -sf "${VENV}/bin/suricata-update" /usr/local/bin/suricata-update
        info "suricata-update installed at ${VENV}/bin/suricata-update (symlinked to /usr/local/bin)"

        # Initialise the source index so 'Update Rules' works on first use.
        "${VENV}/bin/suricata-update" update-sources --no-merge 2>/dev/null \
            && info "suricata-update source index initialised" \
            || warn "suricata-update update-sources failed (offline?) — sources will refresh on first Update Rules click"
    else
        printf "${YELLOW}[DRY-RUN]${NC} would symlink %s -> /usr/local/bin/suricata-update and run update-sources --no-merge\n" "${VENV}/bin/suricata-update"
    fi
else
    warn "suricata-update could not be installed into the venv — IDS rule updates will not work until this is resolved"
fi

# Fv11 review §P1-08 — IDS readiness summary. The previous install path could
# leave the operator with `service suricata` enabled but zero signature
# coverage, so the UI badge said "IDS active" while traffic flew past
# unmonitored. Surface the gap loudly here so the operator knows to click
# "Update Rules" before relying on the IDS page.
info "IDS readiness check (Suricata + rules):"
if command -v suricata >/dev/null 2>&1; then
    info "  suricata binary present: $(command -v suricata)"
    if [ -f /usr/local/etc/suricata/suricata.yaml ]; then
        if suricata -T -c /usr/local/etc/suricata/suricata.yaml >/dev/null 2>&1; then
            info "  suricata -T: config passes"
        else
            warn "  suricata -T: config FAILED — IDS will refuse to start. Re-run after wizard regenerates suricata.yaml."
        fi
    else
        warn "  suricata.yaml not present yet — IDS wizard step has not run."
    fi
    if [ -x "${VENV}/bin/suricata-update" ] || command -v suricata-update >/dev/null 2>&1; then
        info "  suricata-update available"
    else
        warn "  suricata-update missing — IDS will only have the placeholder ruleset until this is fixed."
    fi
    if [ -s /var/lib/suricata/rules/suricata.rules ]; then
        # Count only real rule actions (alert/drop/reject/pass) so include
        # files and comments do not inflate the apparent coverage.
        _rule_lines="$(grep -cE '^(alert|drop|reject|pass) ' /var/lib/suricata/rules/suricata.rules 2>/dev/null || echo 0)"
        if [ "${_rule_lines}" -gt 10 ]; then
            info "  rules file: ${_rule_lines} signatures loaded"
        elif [ "${_rule_lines}" -gt 0 ]; then
            warn "  rules file present but sparse (${_rule_lines} signatures). Click 'Update Rules' in the IDS page before enabling IPS."
        else
            warn "  rules file present but contains NO active signatures. Run suricata-update before enabling IDS/IPS."
        fi
    else
        warn "  rules file is empty — IDS has NO signature coverage yet. Operator must run suricata-update before enabling IDS/IPS."
    fi
else
    info "  suricata not installed — IDS feature is unavailable on this appliance."
fi

section "4b. Production preflight checks"

# Fail fast if the codebase can't byte-compile, fails a release check, has
# route registration problems, or trips the route security linter. Better to
# abort the install than to leave a broken appliance that 500s on first boot.
PYBIN="${VENV}/bin/python"

info "Byte-compiling app/routes/scripts/tools..."
if ! "${PYBIN}" -m compileall -q "${APP_ROOT}/app" "${APP_ROOT}/routes" "${APP_ROOT}/scripts" "${APP_ROOT}/tools"; then
    fatal "compileall failed — syntax errors present. Aborting install."
fi

if [ -f "${APP_ROOT}/tools/release_check.py" ]; then
    info "Running release_check.py..."
    if ! ( cd "${APP_ROOT}" && "${PYBIN}" tools/release_check.py --json ); then
        fatal "release_check.py failed — environment not production-ready. Aborting install."
    fi
fi

if [ -f "${APP_ROOT}/tools/check_manifest.py" ]; then
    info "Running check_manifest.py..."
    if ! ( cd "${APP_ROOT}" && "${PYBIN}" tools/check_manifest.py ); then
        fatal "python_runtime.json out of sync with requirements.txt — see diff above. Aborting install."
    fi
fi

if [ -f "${APP_ROOT}/tools/check_tab_render.py" ]; then
    info "Running check_tab_render.py..."
    if ! ( cd "${APP_ROOT}" && "${PYBIN}" tools/check_tab_render.py ); then
        fatal "check_tab_render.py failed — blank-tab antipattern detected. Aborting install."
    fi
fi

if [ -f "${APP_ROOT}/tools/check_routes.py" ]; then
    info "Running check_routes.py..."
    if ! ( cd "${APP_ROOT}" && "${PYBIN}" tools/check_routes.py ); then
        fatal "check_routes.py failed — route registration problem. Aborting install."
    fi
fi

if [ -f "${APP_ROOT}/tools/security_lint_routes.py" ]; then
    info "Running security_lint_routes.py..."
    if ! ( cd "${APP_ROOT}" && "${PYBIN}" tools/security_lint_routes.py ); then
        fatal "security_lint_routes.py failed — unprotected route detected. Aborting install."
    fi
fi

# Minimal app-startup check: the factory must import and build without error.
info "Verifying the Flask app factory imports cleanly..."
if ! ( cd "${APP_ROOT}" && "${PYBIN}" -c "import app; app.create_app()" >/dev/null 2>&1 ); then
    # Re-run without suppression so the operator sees the traceback.
    ( cd "${APP_ROOT}" && "${PYBIN}" -c "import app; app.create_app()" ) || true
    fatal "Flask app failed to start — see traceback above. Aborting install."
fi

# Fv11 review §P0-06: runtime_preflight.py is the production-safe variant of
# the create_app() smoke test. It force-sets SMARTSHIELD_ENABLE_NETWORK_APPLY=0
# / DISABLE_BACKGROUND=1 before importing the app, so the preflight cannot
# trigger live PF/network mutation even if the env file is misconfigured. The
# basic import check above is kept as a leading guard — runtime_preflight then
# proves the app boots with the same environment overrides production uses.
if [ -f "${APP_ROOT}/tools/runtime_preflight.py" ]; then
    info "Running runtime_preflight.py (production env overrides)..."
    if ! ( cd "${APP_ROOT}" && "${PYBIN}" tools/runtime_preflight.py ); then
        fatal "runtime_preflight failed — app would not boot under production env. Aborting install."
    fi
fi

# Fv11 review §P1-09: pip metadata sanity. `pip check` catches incompatible
# version pins that compileall would miss (e.g. werkzeug major bump breaking
# flask). Treated as a fatal install error because Smart Shield ships its own
# requirements.lock and operator drift breaks support.
info "Running pip dependency consistency check..."
if ! "${VENV}/bin/pip" check; then
    fatal "pip check reported dependency conflicts — fix requirements.txt before shipping."
fi

# Probe the critical third-party imports separately so the failure log points
# at the actual missing module (pip check only flags *conflicts*, not e.g. a
# successfully-installed-but-unimportable cryptography wheel).
if ! APP_ROOT="${APP_ROOT}" "${VENV}/bin/python" - <<'PY'
import json
import os
import sys
# Single source of truth — keep this list in sync with requirements.txt by
# editing app/manifests/python_runtime.json instead of duplicating it here.
manifest_path = os.path.join(os.environ.get("APP_ROOT", ""),
                             "app", "manifests", "python_runtime.json")
try:
    with open(manifest_path, "r") as f:
        modules = json.load(f).get("imports") or []
except Exception as exc:
    sys.stderr.write(f"[FATAL] cannot read {manifest_path}: {exc}\n")
    sys.exit(1)
if not modules:
    sys.stderr.write("[FATAL] python_runtime.json has empty imports list\n")
    sys.exit(1)
for mod in modules:
    try:
        __import__(mod)
    except Exception as exc:
        sys.stderr.write(f"[FATAL] cannot import {mod}: {exc}\n")
        sys.exit(1)
print(f"dependency import check ok ({len(modules)} modules)")
PY
then
    fatal "Required Python module missing — see error above. Aborting install."
fi

info "Application preflight checks passed."

section "5. Service + CLI Tools"

# rc.d service script
RCD_SRC="${APP_ROOT}/bsd/rc.d/smart_shield"
RCD_DEST="/usr/local/etc/rc.d/smart_shield"
if [ -f "${RCD_SRC}" ]; then
    install -m 0555 "${RCD_SRC}" "${RCD_DEST}"
    info "Installed rc.d script: ${RCD_DEST}"
else
    warn "rc.d script not found at ${RCD_SRC}"
fi

# Operator tools
for TOOL in smartshieldctl smartshield-cli; do
    SRC="${APP_ROOT}/bsd/sbin/${TOOL}"
    DEST="/usr/local/sbin/${TOOL}"
    if [ -f "${SRC}" ]; then
        install -m 0555 "${SRC}" "${DEST}"
        info "Installed: ${DEST}"
    else
        warn "Tool not found: ${SRC}"
    fi
done

# MRTG probe script — install to /usr/local/sbin for cron use
MRTG_PROBE_SRC="${APP_ROOT}/bsd/mrtg-probe.sh"
MRTG_PROBE_DEST="/usr/local/sbin/mrtg-probe.sh"
if [ -f "${MRTG_PROBE_SRC}" ]; then
    install -m 0555 "${MRTG_PROBE_SRC}" "${MRTG_PROBE_DEST}"
    info "Installed MRTG probe: ${MRTG_PROBE_DEST}"
else
    warn "mrtg-probe.sh not found at ${MRTG_PROBE_SRC}"
fi

# First-boot recovery script
FB_SRC="${APP_ROOT}/bsd/firstboot/smart_shield_firstboot"
FB_DEST="/usr/local/libexec/smart_shield_firstboot"
install -d -m 0755 /usr/local/libexec 2>/dev/null || true
if [ -f "${FB_SRC}" ]; then
    install -m 0555 "${FB_SRC}" "${FB_DEST}"
    info "Installed: ${FB_DEST}"
else
    warn "First-boot script not found at ${FB_SRC}"
fi

# rc.d wrapper for the firstboot script. Only useful on appliance images
# where install.sh runs on the build host and the operator boots the VM/USB
# without re-running install.sh. The wrapper checks a sentinel file and
# disables itself after a successful first run, so subsequent boots are a
# no-op. We stage the rcvar but leave it OFF by default — image builders
# explicitly opt-in with `sysrc smart_shield_firstboot_enable=YES` in their
# build pipeline.
FB_RCD_SRC="${APP_ROOT}/bsd/rc.d/smart_shield_firstboot"
FB_RCD_DEST="/usr/local/etc/rc.d/smart_shield_firstboot"
if [ -f "${FB_RCD_SRC}" ]; then
    install -m 0555 "${FB_RCD_SRC}" "${FB_RCD_DEST}"
    info "Installed firstboot rc.d wrapper: ${FB_RCD_DEST}"
fi

# Console recovery menu
CONSOLE_SRC="${APP_ROOT}/bsd/console_menu/smart_shield_console"
CONSOLE_DEST="/usr/local/sbin/smart_shield_console"
if [ -f "${CONSOLE_SRC}" ]; then
    install -m 0700 "${CONSOLE_SRC}" "${CONSOLE_DEST}"
    info "Installed: ${CONSOLE_DEST}"
else
    warn "Console menu not found at ${CONSOLE_SRC}"
fi

# Bootstrap MRTG: write initial config and run two passes to create .log files + first PNGs.
# The web UI "Regenerate Config" will update this later with wizard-configured interface names.
MRTG_CONF="/usr/local/etc/mrtg/mrtg.cfg"
MRTG_LOCK="${RUN_DIR}/mrtg.lock"
MRTG_BIN="/usr/local/bin/mrtg"

if [ ! -f "${MRTG_CONF}" ]; then
    cat << 'MRTGEOF' | stage_write "${MRTG_CONF}"
# Smart Shield MRTG Configuration (bootstrap defaults — regenerate via web UI after wizard)
WorkDir: /var/db/smartshield/mrtg
Refresh: 300
Interval: 5
Language: English
Options[_]: growright, bits

Target[em0]: `/usr/local/sbin/mrtg-probe.sh em0`
MaxBytes[em0]: 125000000
Title[em0]: WAN Traffic — em0
PageTop[em0]: <h1>WAN — em0</h1>
Options[em0]: bits, growright, noinfo

Target[em1]: `/usr/local/sbin/mrtg-probe.sh em1`
MaxBytes[em1]: 125000000
Title[em1]: LAN Traffic — em1
PageTop[em1]: <h1>LAN — em1</h1>
Options[em1]: bits, growright, noinfo
MRTGEOF
    info "Bootstrap MRTG config written: ${MRTG_CONF}"
fi

# Install cron job unconditionally — the entry uses the full binary path with
# 2>/dev/null, so it silently does nothing when the package is absent.
# This prevents the common failure where the cron was never created because
# install.sh ran before the net-mgmt/mrtg package was installed.
CRON_FILE="/etc/cron.d/smartshield-mrtg"
CRON_LINE="*/5 * * * * root env LANG=C /usr/local/bin/mrtg /usr/local/etc/mrtg/mrtg.cfg --lock-file ${MRTG_LOCK} 2>/dev/null"
printf '%s\n' "${CRON_LINE}" | stage_write "${CRON_FILE}"
run_live chmod 0644 "${CRON_FILE}"
info "MRTG cron job installed: ${CRON_FILE}"

if [ -x "${MRTG_BIN}" ]; then
    # Pass 1: creates .log RRD files (non-zero exit on new files is expected)
    env LANG=C "${MRTG_BIN}" "${MRTG_CONF}" --lock-file "${MRTG_LOCK}" --log-level 0 2>/dev/null || true
    sleep 5  # MRTG needs a time delta between runs to compute rates
    # Pass 2: reads .log files and generates initial PNG graph images
    env LANG=C "${MRTG_BIN}" "${MRTG_CONF}" --lock-file "${MRTG_LOCK}" --log-level 0 2>/dev/null || true
    info "MRTG initialised — initial graphs generated in ${DATA_DIR}/mrtg"
else
    warn "MRTG binary not found at ${MRTG_BIN} — cron job installed; graphs will appear once net-mgmt/mrtg is installed"
fi

# ── Nginx TLS reverse proxy ────────────────────────────────────────────────────
section "5a. Nginx TLS & Reverse Proxy"

# SSL directory (mode 0700 — private key must not be world-readable)
SSL_DIR="${ETC_DIR}/ssl"
install -d -m 0700 "${SSL_DIR}" 2>/dev/null || true

# Generate a self-signed certificate if none exists yet.
# Replace with a CA-signed or ACME cert in production.
SSL_CERT="${SSL_DIR}/cert.pem"
SSL_KEY="${SSL_DIR}/key.pem"
if [ ! -f "${SSL_CERT}" ] || [ ! -f "${SSL_KEY}" ]; then
    if command -v openssl >/dev/null 2>&1; then
        openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
            -keyout "${SSL_KEY}" \
            -out    "${SSL_CERT}" \
            -subj   "/CN=smartshield.local"
        if [ ! -f "${SSL_CERT}" ] || [ ! -f "${SSL_KEY}" ]; then
            warn "openssl failed — TLS certificate not generated. Nginx cannot start."
            warn "Re-run install or place cert.pem / key.pem in ${SSL_DIR} manually."
        else
            chmod 0600 "${SSL_KEY}"
            chmod 0644 "${SSL_CERT}"
            info "Self-signed TLS certificate generated (rsa:2048, valid 10 years): ${SSL_CERT}"
        fi
    else
        warn "openssl not found — TLS certificate not generated. Place cert.pem / key.pem in ${SSL_DIR}"
    fi
else
    info "TLS certificate already exists — skipping generation."
fi

# Write a complete nginx.conf (replaces the default pkg stub).
# server_name _ = catch-all (works for any IP or hostname on this appliance).
# proxy_read_timeout 300s to accommodate Groq AI agentic loops.
# /terminal/ws REQUIRES the Upgrade/Connection headers — without them the Live
# CLI shows "[WebSocket connection error]".
# Port 80 routes through Flask (NOT a 301 to HTTPS) so the content-policy
# intercept and captive portal can respond on plain HTTP to DNS-redirected
# blocked-domain requests.
#
# Phase 2.6 fix: bind explicitly to the LAN IP (and 127.0.0.1 for healthchecks)
# rather than every interface. The placeholders __SS_LISTEN_HTTP__ and
# __SS_LISTEN_HTTPS__ are substituted below with concrete listen directives so
# the single-quoted heredoc still leaves nginx's own $variables untouched.
# When the setup wizard later changes LAN_IP, it MUST regenerate this file
# (see routes/setup.py → §5.3 in the plan).
NGINX_CONF_TMP="$(mktemp)"
cat > "${NGINX_CONF_TMP}" << 'NGINXEOF'
user www;
worker_processes auto;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include       /usr/local/etc/nginx/mime.types;
    default_type  application/octet-stream;

    sendfile          on;
    keepalive_timeout 65;
    server_tokens     off;

    access_log /var/log/nginx/access.log;
    error_log  /var/log/nginx/error.log warn;

    # ── HTTP (admin vhost) — the admin UI is HTTPS-only ──────────────────────
    # Requests addressed to the appliance itself (its LAN IP / hostname) are
    # redirected to HTTPS so admin login is never served over plain HTTP.
    # Captive-portal and static assets stay on HTTP because unauthenticated
    # clients are PF/DNS-redirected to them before they can reach HTTPS.
    server {
__SS_LISTEN_HTTP__
        server_name __SS_HTTP_ADMIN_NAMES__;

        location /portal/ {
            proxy_pass         http://127.0.0.1:5000;
            proxy_http_version 1.1;
            proxy_set_header   Host              $host;
            proxy_set_header   X-Real-IP         $remote_addr;
            proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
            proxy_set_header   X-Forwarded-Proto http;
            proxy_read_timeout 60s;
        }

        location /static/ {
            proxy_pass         http://127.0.0.1:5000;
            proxy_http_version 1.1;
            proxy_set_header   Host $host;
        }

        # Everything else (login, dashboard, APIs, setup, terminal) → HTTPS.
        location / {
            return 301 https://$host$request_uri;
        }
    }

    # ── HTTP (default vhost) — content-policy block pages + captive redirects ──
    # DNS-redirected blocked domains arrive here with a foreign Host header and
    # must be answered on plain HTTP (an HTTPS redirect would trip a cert
    # mismatch for the blocked domain). Flask's content-filter intercept turns
    # these into the block / captive-portal page.
    server {
__SS_LISTEN_HTTP_DEFAULT__
        server_name _;

        location / {
            proxy_pass         http://127.0.0.1:5000;
            proxy_http_version 1.1;
            proxy_set_header   Host              $host;
            proxy_set_header   X-Real-IP         $remote_addr;
            proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
            proxy_set_header   X-Forwarded-Proto http;
            proxy_read_timeout 60s;
        }
    }

    # ── HTTPS — Smart Shield dashboard ───────────────────────────────────────
    server {
__SS_LISTEN_HTTPS__
        server_name _;

        ssl_certificate     /usr/local/etc/smartshield/ssl/cert.pem;
        ssl_certificate_key /usr/local/etc/smartshield/ssl/key.pem;

        ssl_protocols             TLSv1.2 TLSv1.3;
        ssl_ciphers               ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
        ssl_prefer_server_ciphers on;
        ssl_session_cache         shared:SSL:10m;
        ssl_session_timeout       1d;
        ssl_session_tickets       off;

        add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
        add_header X-Frame-Options           DENY                                           always;
        add_header X-Content-Type-Options    nosniff                                        always;
        add_header X-XSS-Protection          "1; mode=block"                                always;
        add_header Referrer-Policy           "strict-origin-when-cross-origin"              always;

        client_max_body_size 260m;

        # ── Live CLI WebSocket — long-lived connection with upgrade headers ──
        location /terminal/ws {
            proxy_pass         http://127.0.0.1:5000;
            proxy_http_version 1.1;
            proxy_set_header   Upgrade    $http_upgrade;
            proxy_set_header   Connection "upgrade";
            proxy_set_header   Host              $host;
            proxy_set_header   X-Real-IP         $remote_addr;
            proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
            proxy_set_header   X-Forwarded-Proto $scheme;
            proxy_read_timeout 3600s;
            proxy_send_timeout 3600s;
        }

        # ── Captive portal — also reachable over HTTPS ──────────────────────
        location /portal/ {
            proxy_pass         http://127.0.0.1:5000;
            proxy_http_version 1.1;
            proxy_set_header   Host              $host;
            proxy_set_header   X-Real-IP         $remote_addr;
            proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
            proxy_set_header   X-Forwarded-Proto https;
            proxy_read_timeout 60s;
        }

        location / {
            proxy_pass         http://127.0.0.1:5000;
            proxy_http_version 1.1;

            proxy_set_header   Host              $host;
            proxy_set_header   X-Real-IP         $remote_addr;
            proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
            proxy_set_header   X-Forwarded-Proto $scheme;

            proxy_connect_timeout  90s;
            proxy_read_timeout    300s;
            proxy_send_timeout     90s;
        }
    }

    # SOC Team Portal virtual host (auto-generated by Smart Shield settings).
    # Activated when bind_ip is set in System → SOC Portal Settings; the
    # placeholder file below keeps `nginx -t` happy on first install.
    include /usr/local/etc/nginx/soc-portal.conf;
}
NGINXEOF

# Substitute the listen-directive placeholders. We bind explicitly to the LAN
# IP plus 127.0.0.1 so an exposed appliance does not surface the admin UI to
# WAN even if PF rules are not yet loaded. When LAN_IP itself is loopback,
# emit only one set of listen lines to avoid `duplicate listen options`.
LAN_IP_ESC=$(printf '%s' "${LAN_IP}" | sed 's/[\/&]/\\&/g')
if [ "${LAN_IP}" = "127.0.0.1" ]; then
    sed -i '' \
        -e "s|__SS_LISTEN_HTTP__|        listen      127.0.0.1:80;|" \
        -e "s|__SS_LISTEN_HTTP_DEFAULT__|        listen      127.0.0.1:80 default_server;|" \
        -e "s|__SS_HTTP_ADMIN_NAMES__|smartshield.local localhost 127.0.0.1|" \
        -e "s|__SS_LISTEN_HTTPS__|        listen      127.0.0.1:443 ssl;|" \
        "${NGINX_CONF_TMP}"
else
    sed -i '' \
        -e "s|__SS_LISTEN_HTTP__|        listen      ${LAN_IP_ESC}:80;\n        listen      127.0.0.1:80;|" \
        -e "s|__SS_LISTEN_HTTP_DEFAULT__|        listen      ${LAN_IP_ESC}:80 default_server;\n        listen      127.0.0.1:80 default_server;|" \
        -e "s|__SS_HTTP_ADMIN_NAMES__|smartshield.local localhost 127.0.0.1 ${LAN_IP_ESC}|" \
        -e "s|__SS_LISTEN_HTTPS__|        listen      ${LAN_IP_ESC}:443 ssl;\n        listen      127.0.0.1:443 ssl;|" \
        "${NGINX_CONF_TMP}"
fi

# Ensure the soc-portal include target exists so `nginx -t` doesn't fail before
# the admin enables the SOC portal (which writes a real soc-portal.conf via
# app/services/soc_portal_writer.py). Created BEFORE the nginx test so the
# include directive in NGINX_CONF_TMP resolves.
SOC_PORTAL_CONF="/usr/local/etc/nginx/soc-portal.conf"
if [ ! -f "${SOC_PORTAL_CONF}" ]; then
    printf '# Placeholder — replaced when admin enables System → SOC Portal Settings.\n' \
        | stage_write "${SOC_PORTAL_CONF}"
    info "Created placeholder: ${SOC_PORTAL_CONF}"
fi

# `nginx -t` actually OPENS the listen sockets, not just parses syntax. The
# LAN IP isn't assigned to ${LAN_IFACE} until §6b runs, so validating the real
# LAN-IP-bound config here returns EADDRNOTAVAIL(49). Build a loopback-only
# sibling for the test — syntax/TLS/include resolution are still exercised,
# only the live bind is deferred to `service nginx start` (by which point
# §6b has plumbed the interface). Mirror this in app/services/nginx_writer.py
# (_to_validation_variant) for the runtime wizard regeneration path.
if [ "${LAN_IP}" != "127.0.0.1" ] && ! ifconfig 2>/dev/null | grep -qw "${LAN_IP}"; then
    warn "${LAN_IP} not yet on any interface."
    warn "nginx will not bind until §6b plumbs ${LAN_IFACE} (or run:"
    warn "    ifconfig ${LAN_IFACE} inet ${LAN_IP} netmask ${LAN_MASK} alias )"
fi

NGINX_CONF_VALIDATE="$(mktemp)"
# Reuse the same regex-based rewriter the runtime wizard uses
# (app/services/nginx_writer._to_validation_variant) so default_server,
# multi-IP, and future listen-directive variants are all handled.
"${PYBIN}" "${APP_ROOT}/tools/nginx_validation_variant.py" \
    < "${NGINX_CONF_TMP}" > "${NGINX_CONF_VALIDATE}"

if [ ! -x /usr/local/sbin/nginx ]; then
    warn "nginx binary missing at /usr/local/sbin/nginx — installing config unvalidated; nginx will validate on first start."
    stage_write /usr/local/etc/nginx/nginx.conf < "${NGINX_CONF_TMP}"
    run_live sysrc nginx_enable=YES
elif /usr/local/sbin/nginx -t -c "${NGINX_CONF_VALIDATE}" >/dev/null 2>&1; then
    stage_write /usr/local/etc/nginx/nginx.conf < "${NGINX_CONF_TMP}"
    info "Nginx configuration written to /usr/local/etc/nginx/nginx.conf"
    info "nginx bound to ${LAN_IP}:{80,443} + 127.0.0.1 — setup wizard regenerates this when LAN IP changes"
    run_live sysrc nginx_enable=YES
    info "nginx_enable=YES staged for rc.conf"
    # NOTE: nginx is NOT started here. Its config binds to ${LAN_IP}:{80,443},
    # and that IP is not assigned to ${LAN_IFACE} until §6b. Starting now would
    # fail to bind (EADDRNOTAVAIL) and the failure would be masked. The actual
    # start is deferred to §6c, which runs after §6b plumbs the LAN interface.
    info "Nginx config installed; service start deferred to §6c (after LAN IP assignment)."
else
    warn "Nginx config test FAILED — generated config NOT installed."
    warn "Inspect ${NGINX_CONF_TMP} (real) / ${NGINX_CONF_VALIDATE} (validated) and re-run after fixing."
    /usr/local/sbin/nginx -t -c "${NGINX_CONF_VALIDATE}" 2>&1 | sed 's/^/    /' || true
fi
rm -f "${NGINX_CONF_TMP}" "${NGINX_CONF_VALIDATE}"

# ── Privilege separation: sudoers allowlist ───────────────────────────────────
section "5b. sudo / Sudoers (optional fallback)"

SUDOERS_DIR="/usr/local/etc/sudoers.d"
SUDOERS_SRC="${APP_ROOT}/bsd/etc/sudoers.d/smartshield"
SUDOERS_DEST="${SUDOERS_DIR}/smartshield"

mkdir -p "${SUDOERS_DIR}"
chmod 0750 "${SUDOERS_DIR}"
info "Ensured: ${SUDOERS_DIR} (mode 0750)"

if [ -f "${SUDOERS_SRC}" ]; then
    # Validate syntax before installing. An invalid sudoers fragment can wedge
    # sudo system-wide, so a failed check must abort the install.
    if visudo -c -f "${SUDOERS_SRC}" >/dev/null 2>&1; then
        install -m 0440 "${SUDOERS_SRC}" "${SUDOERS_DEST}"
        info "Installed sudoers allowlist: ${SUDOERS_DEST}"
    else
        # Surface the diagnostic, then abort.
        visudo -c -f "${SUDOERS_SRC}" 2>&1 | sed 's/^/    /' || true
        fatal "sudoers syntax check failed for ${SUDOERS_SRC} — aborting install."
    fi
else
    warn "sudoers source not found: ${SUDOERS_SRC}"
fi

# Ensure sudoers.d is included in /usr/local/etc/sudoers
SUDOERS_MAIN="/usr/local/etc/sudoers"
if [ -f "${SUDOERS_MAIN}" ]; then
    if ! grep -q "sudoers.d" "${SUDOERS_MAIN}" 2>/dev/null; then
        if [ "${DEPLOY_LIVE:-0}" -eq 1 ]; then
            _sudoers_tmp="$(mktemp)"
            cat "${SUDOERS_MAIN}" > "${_sudoers_tmp}"
            printf '\n@includedir %s\n' "${SUDOERS_DIR}" >> "${_sudoers_tmp}"
            install -m 0440 "${_sudoers_tmp}" "${SUDOERS_MAIN}"
            rm -f "${_sudoers_tmp}"
            info "Added @includedir ${SUDOERS_DIR} to ${SUDOERS_MAIN}"
        else
            printf "${YELLOW}[DRY-RUN]${NC} would append @includedir %s to %s\n" \
                "${SUDOERS_DIR}" "${SUDOERS_MAIN}"
        fi
    else
        info "sudoers.d already included in ${SUDOERS_MAIN}"
    fi
fi

# Note: the smartshield system user is not created in root-runtime deployments.
# If reverting to unprivileged operation, add: pw useradd -n smartshield ...

section "6. Enable Service"

# Phase 2.1 fix: every sysrc/sysctl that writes to rc.conf or kernel state
# must go through run_live so dry-run leaves /etc/rc.conf untouched.
run_live sysrc smart_shield_enable=YES
info "smart_shield_enable=YES staged for rc.conf"

# unbound must be running for content policy DNS blocking to work
run_live sysrc unbound_enable=YES
info "unbound_enable=YES staged for rc.conf"

# The FreeBSD base `local_unbound` must NOT own :53 — the pkg `unbound` (which
# Smart Shield manages) does. A running base resolver can win the port and let
# the pkg rc script exit 0 while the real resolver is dead, giving the classic
# "working NAT but dead DNS" failure (LAN clients ping IPs but can't browse).
run_live sysrc local_unbound_enable=NO
run_live service local_unbound onestop >/dev/null 2>&1 || true
info "base local_unbound disabled (pkg unbound owns :53)"

# Minimal bootstrap unbound.conf so `service unbound onestart` below has something
# to load. The wizard's apply_unbound() overwrites this with the real config the
# first time it runs — guarded with [ ! -f ] so we never clobber a live config.
if [ ! -f /usr/local/etc/unbound/unbound.conf ]; then
    cat << 'UNBOUNDEOF' | stage_write /usr/local/etc/unbound/unbound.conf
# Smart Shield bootstrap unbound.conf — wizard replaces this on first apply.
server:
    verbosity: 1
    interface: 127.0.0.1
    access-control: 127.0.0.0/8 allow
    do-ip4: yes
    do-ip6: no
    do-udp: yes
    do-tcp: yes
    hide-identity: yes
    hide-version: yes
UNBOUNDEOF
    run_live chmod 0644 /usr/local/etc/unbound/unbound.conf
    info "Created bootstrap /usr/local/etc/unbound/unbound.conf (wizard will replace)"
fi

# ntpd — keep the clock accurate; required for TLS certificate validation.
run_live sysrc ntpd_enable=YES
run_live sysrc ntpd_sync_on_start=YES
info "ntpd_enable + ntpd_sync_on_start staged for rc.conf"

# PF packet filter — must be enabled for firewall and NAT to work
run_live sysrc pf_enable=YES
run_live sysrc pflog_enable=YES
info "pf_enable + pflog_enable staged for rc.conf"

# IP forwarding — required so LAN clients can reach the internet through this box
run_live sysrc gateway_enable=YES
info "gateway_enable=YES staged for rc.conf"
if [ "${DEPLOY_LIVE:-0}" -eq 1 ]; then
    sysctl net.inet.ip.forwarding=1 >/dev/null
    info "IP forwarding activated immediately (net.inet.ip.forwarding=1)"
else
    printf "${YELLOW}[DRY-RUN]${NC} sysctl net.inet.ip.forwarding=1\n"
fi

# IPv6 forwarding — IPv6 routing, DHCPv6 (Kea), and Router Advertisement (rtadvd)
# are first-class features, so route IPv6 too (mirrors gateway_enable for v4).
run_live sysrc ipv6_gateway_enable=YES
info "ipv6_gateway_enable=YES staged for rc.conf"
if [ "${DEPLOY_LIVE:-0}" -eq 1 ]; then
    sysctl net.inet6.ip6.forwarding=1 >/dev/null
    info "IPv6 forwarding activated immediately (net.inet6.ip6.forwarding=1)"
else
    printf "${YELLOW}[DRY-RUN]${NC} sysctl net.inet6.ip6.forwarding=1\n"
fi

# Kernel-module policy: pf/pflog are loaded below (§6b) as the always-on baseline.
# Feature-dependent modules (netmap for IPS, dummynet for limiters, carp/pfsync
# for HA) are intentionally NOT loaded here — they are loaded on demand via
# priv_helper.kldload when the operator enables the corresponding feature, so a
# fresh appliance doesn't carry inline-capture/HA modules it isn't using.

# DHCP server — installer prepares the stub config but does NOT enable
# isc-dhcpd. The setup wizard owns DHCP enablement: once the admin has
# chosen a LAN subnet and DHCP range, the wizard flips
# dhcpd_enable=YES (the rcvar the pkg rc script reads — NOT
# `isc_dhcpd_enable`, which is a no-op) and regenerates /etc/dhcpd.conf.
# Enabling DHCP here would put a hardcoded 192.168.1.0/24 stub on the
# wire before the admin has approved it.
if [ ! -f /etc/dhcpd.conf ]; then
    printf '# Smart Shield placeholder — replaced by setup wizard\nnot authoritative;\nsubnet 192.168.1.0 netmask 255.255.255.0 {}\n' \
        | stage_write /etc/dhcpd.conf
    info "Created stub /etc/dhcpd.conf (wizard will replace)"
fi
info "dhcpd_enable left OFF — setup wizard will enable it after LAN/DHCP config"

# bsnmpd — only enable when SNMP is configured via the web UI
# MRTG uses mrtg-probe.sh (direct ifconfig), not bsnmpd, so this is not required for graphs
# sysrc bsnmpd_enable=YES  (deferred — enable via Services → SNMP in web UI)

section "6b. Live Network Activation"

# ── LAN interface ─────────────────────────────────────────────────────────────
run_live sysrc "ifconfig_${LAN_IFACE}=inet ${LAN_IP} netmask ${LAN_MASK}"
info "ifconfig_${LAN_IFACE} staged for rc.conf (${LAN_IP}/${LAN_MASK})"

# Bind gunicorn to loopback only — nginx proxies from 127.0.0.1:5000.
run_live sysrc smart_shield_bind=127.0.0.1:5000
info "smart_shield_bind=127.0.0.1:5000 staged for rc.conf"

if [ "${DEPLOY_LIVE:-0}" -eq 1 ]; then
    if ifconfig "${LAN_IFACE}" 2>/dev/null | grep -q "flags="; then
        ifconfig "${LAN_IFACE}" inet "${LAN_IP}" netmask "${LAN_MASK}" up 2>/dev/null \
            && info "Assigned ${LAN_IP}/${LAN_MASK} to ${LAN_IFACE}" \
            || warn "ifconfig assign failed — interface may not be present; rc.conf updated"
        service netif restart "${LAN_IFACE}" 2>/dev/null \
            && info "netif restarted for ${LAN_IFACE}" || true
    else
        warn "${LAN_IFACE} not present — IP assignment skipped (rc.conf updated for next boot)"
    fi
else
    info "Dry-run: LAN IP written to rc.conf only; run in LIVE mode to apply ifconfig immediately."
fi

# Load PF and pflog kernel modules if not already loaded (required on VMs / fresh installs).
# Phase 5.1: gated by DEPLOY_LIVE so dry-run does not load kernel modules.
if [ "${DEPLOY_LIVE:-0}" -eq 1 ]; then
    kldload pf    2>/dev/null || true
    kldload pflog 2>/dev/null || true
else
    printf "${YELLOW}[DRY-RUN]${NC} kldload pf; kldload pflog\n"
fi

# ── PF ────────────────────────────────────────────────────────────────────────
if [ "${DEPLOY_LIVE:-0}" -eq 1 ]; then
    if pfctl -s info 2>/dev/null | grep -q "^Status: Enabled"; then
        pfctl -f /etc/pf.conf 2>/dev/null \
            && info "PF rules reloaded from /etc/pf.conf" \
            || warn "PF reload failed — check /etc/pf.conf syntax"
    else
        pfctl -f /etc/pf.conf 2>/dev/null && pfctl -e 2>/dev/null \
            && info "PF loaded and enabled" \
            || warn "PF enable failed — check /etc/pf.conf"
    fi
else
    printf "${YELLOW}[DRY-RUN]${NC} pfctl -f /etc/pf.conf; pfctl -e (if not already enabled)\n"
fi

# ── pflog ─────────────────────────────────────────────────────────────────────
if [ "${DEPLOY_LIVE:-0}" -eq 1 ]; then
    if service pflog status 2>/dev/null | grep -q running; then
        info "pflog already running"
    else
        service pflog start 2>/dev/null && info "pflog started" || warn "pflog start failed"
    fi
else
    printf "${YELLOW}[DRY-RUN]${NC} service pflog start (if not running)\n"
fi

section "6c. Always-On Service Start"

# Start every "needed by default" daemon so the box is fully live when the
# setup wizard hits step 4. Services that are config-dependent (isc_dhcpd,
# openvpn, strongswan, mpd5, suricata, miniupnpd, ddclient, igmpproxy) stay
# disabled until the admin configures them through the wizard.
#
# `onestart` bypasses the foo_enable=YES sanity check so we don't race with
# the sysrc writes earlier in this script.
if [ "${DEPLOY_LIVE:-0}" -eq 1 ]; then
    for _svc in unbound ntpd nginx; do
        # nginx binds ${LAN_IP}:{80,443}; starting it before §6b plumbs the
        # interface yields a silent EADDRNOTAVAIL. Skip with a clear note so
        # the operator can finish the LAN setup and start nginx manually.
        if [ "${_svc}" = "nginx" ] && [ "${LAN_IP}" != "127.0.0.1" ]; then
            if ! ifconfig "${LAN_IFACE}" 2>/dev/null | grep -qw "${LAN_IP}"; then
                warn "  nginx start skipped — ${LAN_IP} not yet on ${LAN_IFACE}."
                warn "       Assign LAN IP, then run: service nginx start"
                continue
            fi
        fi
        if service "${_svc}" status >/dev/null 2>&1; then
            info "  ${_svc} already running"
        else
            if service "${_svc}" onestart >/dev/null 2>&1; then
                info "  ${_svc} started"
            else
                warn "  ${_svc} failed to start — inspect: service ${_svc} status"
            fi
        fi
    done
    # syslogd + cron are part of the base system and already running on a
    # default FreeBSD install — just nudge them so they pick up the smartshield
    # newsyslog drop-in and the MRTG cron entry written in section 2.
    service syslogd reload >/dev/null 2>&1 && info "  syslogd reloaded" || true
    service cron    reload >/dev/null 2>&1 && info "  cron reloaded"    || true
else
    printf "${YELLOW}[DRY-RUN]${NC} service unbound|ntpd|nginx onestart; reload syslogd + cron\n"
fi

section "7. Preflight Verification"

info "Running Python preflight check..."
cd "${APP_ROOT}"
. "${ENV_FILE}" 2>/dev/null || true
"${VENV}/bin/python3" - << 'PYEOF'
import sys
sys.path.insert(0, '.')
from app.services.freebsd_setup import preflight_check
r = preflight_check()

ok_dirs   = sum(1 for d in r["dirs"] if d["ok"])
total_dirs = len(r["dirs"])
ok_tools  = sum(1 for t in r["tools"] if t["present"])
total_tools = len(r["tools"])
missing_req = r["missing_required"]
dir_errors  = r["dir_errors"]

print(f"  Directories : {ok_dirs}/{total_dirs} OK")
print(f"  Tools       : {ok_tools}/{total_tools} present")
if missing_req:
    print(f"  MISSING (required): {', '.join(missing_req)}")
if dir_errors:
    print(f"  DIR ERRORS: {', '.join(dir_errors)}")
if r["overall_ok"]:
    print("\n  ✓ All checks passed — Smart Shield is ready to start.")
else:
    print("\n  ⚠ Some checks failed. Review the output above.")
    sys.exit(1)
PYEOF

section "8. Start Smart Shield"

# Auto-start the app now that preflight passed. Operators historically had to
# run `service smart_shield start` themselves, but on a fresh install there is
# nothing to inspect first — the wizard runs in-browser and is the next step.
if [ "${DEPLOY_LIVE:-0}" -eq 1 ]; then
    if service smart_shield status >/dev/null 2>&1; then
        service smart_shield restart >/dev/null 2>&1 \
            && info "smart_shield restarted" \
            || warn "smart_shield restart failed — check ${LOG_DIR}/"
    else
        service smart_shield start >/dev/null 2>&1 \
            && info "smart_shield started" \
            || warn "smart_shield start failed — check ${LOG_DIR}/"
    fi
    # `daemon -f` returns before gunicorn finishes importing 22 blueprints.
    # Wait up to 15s for the bind so the wizard URL printed at §Done responds
    # on the first hit instead of connection-refused.
    _i=0
    while [ "${_i}" -lt 15 ]; do
        if sockstat -4 -l 2>/dev/null | grep -q ":5000 "; then
            info "smart_shield listening on 127.0.0.1:5000"
            break
        fi
        sleep 1
        _i=$((_i + 1))
    done
    if [ "${_i}" -eq 15 ]; then
        warn "smart_shield did not bind 127.0.0.1:5000 within 15s — check ${LOG_DIR}/"
    fi
else
    printf "${YELLOW}[DRY-RUN]${NC} service smart_shield start\n"
fi

section "Done"

if [ "${DEPLOY_LIVE:-0}" -eq 1 ]; then
    MODE_LINE="${GREEN}LIVE${NC} — PF rules and network changes apply immediately"
else
    MODE_LINE="${YELLOW}DRY-RUN${NC} — config files written; no live PF/network changes"
    MODE_LINE="${MODE_LINE}\n         Edit ${ENV_FILE} and set SMARTSHIELD_NETWORK_DRY_RUN=0 for live operation"
fi

printf "\n${BOLD}Smart Shield installation complete.${NC}\n"
printf "  Mode: "; printf "${MODE_LINE}\n\n"

# Loud router-readiness warning when install finished without going live. Without
# this, an operator can finish install.sh and not realize that PF/NAT/routing
# are NOT actually applied — the appliance will not route any traffic until the
# env flag is flipped and services are restarted.
if [ "${DEPLOY_LIVE:-0}" -ne 1 ]; then
    printf "${YELLOW}${BOLD}"
    printf "============================================================\n"
    printf " ROUTER WARNING — LIVE NETWORK APPLY IS OFF\n"
    printf "============================================================${NC}\n"
    printf "  This appliance will ${BOLD}NOT route traffic${NC} until live mode\n"
    printf "  is enabled. To go live:\n"
    printf "    1. Edit ${ENV_FILE} and set:\n"
    printf "         SMARTSHIELD_ENABLE_NETWORK_APPLY=1\n"
    printf "         SMARTSHIELD_NETWORK_DRY_RUN=0\n"
    printf "    2. Restart Smart Shield:\n"
    printf "         service smart_shield restart\n"
    printf "    3. Re-run setup Step 4 (Apply) from the web UI to load PF/NAT.\n\n"
fi

# ── First-boot setup claim token ──────────────────────────────────────────────
# The rc.d prestart (smart_shield_prestart) generates a one-time claim token on
# a fresh, unclaimed appliance and prints it ONLY to /dev/console. An operator
# running install.sh over SSH never sees that console, so surface it here too.
# rc.d remains the single source of truth — we only read the file it created
# (mode 0600; readable because install.sh runs as root).
CLAIM_TOKEN_FILE="${DATA_DIR}/setup_claim_token"
CLAIM_TOKEN=""
if [ -f "${CLAIM_TOKEN_FILE}" ]; then
    CLAIM_TOKEN="$(tr -d '[:space:]' < "${CLAIM_TOKEN_FILE}" 2>/dev/null || true)"
fi
if [ -n "${CLAIM_TOKEN}" ]; then
    printf "${BOLD}━━━ Setup Claim Token ━━━${NC}\n"
    printf "The first-boot wizard is protected by this one-time token:\n\n"
    printf "    ${GREEN}%s${NC}\n\n" "${CLAIM_TOKEN}"
    printf "Enter it at https://%s (or /setup) when prompted, to claim this appliance.\n" "${LAN_IP}"
    printf "It is consumed automatically once setup completes.\n"
    printf "If this output scrolls past, the token is also readable at:\n"
    printf "    %s   (mode 0600, deleted on setup completion)\n\n" "${CLAIM_TOKEN_FILE}"
elif [ "${DEPLOY_LIVE:-0}" -eq 1 ]; then
    warn "No setup claim token at ${CLAIM_TOKEN_FILE} — appliance may already be claimed."
    warn "  If setup is not yet done, the token is (re)generated and printed to the"
    warn "  console on the next 'service smart_shield start'."
fi

# ── Optional: email the claim code to the address collected in §3 ───────────
# Runs only when the operator typed an address at the install-time prompt AND
# the token file actually contains a code. The console output above still
# carries the code regardless, so a mail failure never blocks the operator.
if [ -n "${ADMIN_WELCOME_EMAIL}" ] && [ -s "${CLAIM_TOKEN_FILE}" ]; then
    printf "${BOLD}━━━ Sending welcome email ━━━${NC}\n"
    if "${VENV}/bin/python3" "${APP_ROOT}/tools/send_welcome_email.py" \
            --to "${ADMIN_WELCOME_EMAIL}" \
            --lan-ip "${LAN_IP}" \
            --token-file "${CLAIM_TOKEN_FILE}"; then
        : # script prints its own success line
    else
        warn "Welcome email to ${ADMIN_WELCOME_EMAIL} failed — the claim code above is still valid."
    fi
    printf "\n"
fi

# ── IPS-mode hint ─────────────────────────────────────────────────────────────
# Feature-dependent kernel modules (netmap for IPS, dummynet for limiters, etc.)
# are left unloaded at install time by design (see §6a). The GUI now loads
# netmap on demand via priv_helper.kldload when IPS is enabled, and persists
# netmap_load="YES" to /boot/loader.conf so reboots survive. Operators do NOT
# need to run kldload manually — say so out loud so they don't try.
printf "${BOLD}━━━ IPS mode ━━━${NC}\n"
printf "Switching Threat Detection to IPS in the GUI will auto-load netmap.ko\n"
printf "and persist netmap_load=\"YES\" to /boot/loader.conf for reboot survival.\n"
printf "No manual 'kldload netmap' or loader.conf edit is required.\n\n"

# ── Post-install readiness summary ─────────────────────────────────────────
# One glanceable table so the operator immediately sees what is in place and
# what still needs attention. Best-effort: every probe is guarded and never
# aborts the installer. Only FAIL (a required item, or a present-but-broken
# service config) increments POSTCHECK_FAILS; SKIP/NO are informational and do
# not (e.g. LAN IP not yet on an interface is expected in prepare mode).
POSTCHECK_FAILS=0
pc() {
    _st="$1"; _lbl="$2"; _dt="${3:-}"
    case "$_st" in
        OK|YES)  _c="${GREEN}" ;;
        FAIL)    _c="${RED}"; POSTCHECK_FAILS=$((POSTCHECK_FAILS + 1)) ;;
        NO|SKIP) _c="${YELLOW}" ;;
        *)       _c="${NC}" ;;
    esac
    printf "  ${_c}%-4s${NC} %-22s %s\n" "$_st" "$_lbl" "$_dt"
}

printf "\n${BOLD}━━━ Post-install Check ━━━${NC}\n"

# Python venv (required)
_py="${VENV}/bin/python"
[ -x "$_py" ] || _py="${VENV}/bin/python3"
if [ -x "$_py" ]; then pc OK "Python venv" "${VENV}"; else pc FAIL "Python venv" "missing at ${VENV}"; fi

# Flask import (required)
if [ -x "$_py" ] && "$_py" -c "import flask" >/dev/null 2>&1; then
    pc OK "Flask import" "$("$_py" -c 'import flask; print("v"+flask.__version__)' 2>/dev/null)"
else
    pc FAIL "Flask import" "venv python cannot import flask"
fi

# rc.d service script (required)
if [ -f /usr/local/etc/rc.d/smart_shield ]; then pc OK "rc.d script"; else pc FAIL "rc.d script" "not installed"; fi

# smart_shield_enable rcvar (informational)
_sse="$(sysrc -n smart_shield_enable 2>/dev/null || echo '')"
if [ "$_sse" = "YES" ] || [ "$_sse" = "yes" ]; then pc YES "smart_shield_enable"; else pc NO "smart_shield_enable" "sysrc smart_shield_enable=YES"; fi

# nginx config (FAIL only if nginx is present but its config is broken)
if command -v nginx >/dev/null 2>&1; then
    if nginx -t >/dev/null 2>&1; then pc OK "nginx config"; else pc FAIL "nginx config" "nginx -t failed"; fi
else
    pc SKIP "nginx config" "nginx not installed"
fi

# pfctl syntax
if command -v pfctl >/dev/null 2>&1 && [ -f /etc/pf.conf ]; then
    if pfctl -nf /etc/pf.conf >/dev/null 2>&1; then pc OK "pfctl syntax"; else pc FAIL "pfctl syntax" "pfctl -nf /etc/pf.conf failed"; fi
else
    pc SKIP "pfctl syntax" "pfctl or /etc/pf.conf absent"
fi

# unbound config
if command -v unbound-checkconf >/dev/null 2>&1; then
    if unbound-checkconf >/dev/null 2>&1; then pc OK "unbound config"; else pc FAIL "unbound config" "unbound-checkconf failed"; fi
else
    pc SKIP "unbound config" "unbound-checkconf absent"
fi

# dhcpd config (ISC)
if command -v dhcpd >/dev/null 2>&1 && [ -f /usr/local/etc/dhcpd.conf ]; then
    if dhcpd -t -cf /usr/local/etc/dhcpd.conf >/dev/null 2>&1; then pc OK "dhcpd config"; else pc FAIL "dhcpd config" "dhcpd -t failed"; fi
else
    pc SKIP "dhcpd config" "dhcpd or config absent"
fi

# suricata config
_suri_yaml="/usr/local/etc/suricata/suricata.yaml"
if command -v suricata >/dev/null 2>&1 && [ -f "$_suri_yaml" ]; then
    if suricata -T -c "$_suri_yaml" >/dev/null 2>&1; then pc OK "suricata config"; else pc FAIL "suricata config" "suricata -T failed"; fi
else
    pc SKIP "suricata config" "suricata or yaml absent"
fi

# suricata-update (optional)
if [ -x "${VENV}/bin/suricata-update" ] || command -v suricata-update >/dev/null 2>&1; then
    pc OK "suricata-update"
else
    pc SKIP "suricata-update" "not installed (optional)"
fi

# LAN IP present on an interface (informational — expected NO in prepare mode)
if ifconfig 2>/dev/null | grep -qw "${LAN_IP}"; then pc YES "LAN IP present" "${LAN_IP}"; else pc NO "LAN IP present" "${LAN_IP} not on any iface yet"; fi

# IPv4 forwarding (informational)
if [ "$(sysctl -n net.inet.ip.forwarding 2>/dev/null || echo 0)" = "1" ]; then pc YES "forwarding enabled"; else pc NO "forwarding enabled" "net.inet.ip.forwarding=0"; fi

printf "\n"
if [ "${POSTCHECK_FAILS}" -eq 0 ]; then
    info "Post-install check: all required items OK."
else
    warn "Post-install check: ${POSTCHECK_FAILS} required item(s) need attention (see FAIL above)."
fi

cat << EOF
Next steps:
  1. Confirm the daemon is up (started automatically above):
       service smart_shield status

  2. Open the web UI (HTTPS, LAN only) and complete the setup wizard:
       https://${LAN_IP}
       (Accept the self-signed certificate warning — replace with a CA cert for production.)
       Enter the setup claim token shown above, then create your admin account in step 3.

  3. Check the Preflight page in the web UI:
       System → Preflight Check

  4. Set your Abuse.ch key in ${ENV_FILE}:
       ABUSECH_AUTH_KEY=<your-key>   (get it at https://abuse.ch/)
       Leave ABUSECH_DRY_RUN=1 until you want live threat intel lookups.

EOF
