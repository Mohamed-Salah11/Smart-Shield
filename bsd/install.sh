#!/bin/sh
# =============================================================================
# Smart Shield — FreeBSD One-Shot Installation Script
# =============================================================================
# Usage:
#   1. Copy the project to /usr/local/share/smart-shield
#   2. Run as root: sh /usr/local/share/smart-shield/bsd/install.sh
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

APP_ROOT="/usr/local/share/smart-shield"
ETC_DIR="/usr/local/etc/smart-shield"
DATA_DIR="/var/db/smart-shield"
LOG_DIR="/var/log/smart-shield"
RUN_DIR="/var/run/smart-shield"
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
printf "\n${BOLD}━━━ Deployment Mode ━━━${NC}\n"
printf "  ${GREEN}live${NC}  — Apply real PF rules, interface config, and service control\n"
printf "  ${YELLOW}dry${NC}   — Safe mode: writes config files but does NOT touch PF/network\n"
printf "${YELLOW}[?]${NC} Enable LIVE network apply now? [y/N]: "
read -r _LIVE_ANS
case "${_LIVE_ANS}" in
    [Yy]|[Yy][Ee][Ss]) DEPLOY_LIVE=1; info "Live mode selected." ;;
    *)                  DEPLOY_LIVE=0; info "Dry-run mode selected — safe for initial testing." ;;
esac
DRY_RUN_VAL=$([ "${DEPLOY_LIVE}" -eq 1 ] && echo 0 || echo 1)

section "1. Package Installation"

info "Updating pkg repository..."
pkg update -q

REQUIRED_PKGS="python3 git sqlite3 ca_root_nss unbound isc-dhcp44-server openvpn strongswan suricata nano mrtg nginx"
info "Installing required packages: ${REQUIRED_PKGS}"
# shellcheck disable=SC2086
pkg install -y ${REQUIRED_PKGS}

# Python sqlite3 extension (required for the app database)
PYTHON_VER=$(python3 -c "import sys; print('%d%d' % sys.version_info[:2])" 2>/dev/null || echo "311")
pkg install -y "py${PYTHON_VER}-sqlite3" 2>/dev/null \
    || pkg install -y py311-sqlite3 \
    || warn "py${PYTHON_VER}-sqlite3 not found — sqlite3 module may already be bundled."

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

# Nginx
install -d -m 0755 /usr/local/etc/nginx  2>/dev/null && info "Created: /usr/local/etc/nginx" || true
install -d -m 0755 /var/log/nginx        2>/dev/null && info "Created: /var/log/nginx" || true
install -d -m 0755 /var/run/nginx        2>/dev/null && info "Created: /var/run/nginx" || true

# MRTG
install -d -m 0755 /usr/local/etc/mrtg             2>/dev/null && info "Created: /usr/local/etc/mrtg" || true
install -d -m 0755 /var/db/smart-shield/mrtg       2>/dev/null && info "Created: /var/db/smart-shield/mrtg" || true

# ── Required runtime files ───────────────────────────────────────────────────
# dhcpd refuses to start if dhcpd.leases doesn't exist as a file
if [ ! -f /var/db/dhcpd/dhcpd.leases ]; then
    touch /var/db/dhcpd/dhcpd.leases
    chmod 0644 /var/db/dhcpd/dhcpd.leases
    info "Created: /var/db/dhcpd/dhcpd.leases"
fi

# Minimal PF ruleset — wizard overwrites with generated rules; without this PF can't load
if [ ! -f /etc/pf.conf ]; then
    printf '# Smart Shield bootstrap — wizard replaces this\nset skip on lo0\npass all\n' > /etc/pf.conf
    info "Created: /etc/pf.conf (minimal bootstrap — wizard will replace)"
fi

section "3. Environment Configuration"

ENV_FILE="${ETC_DIR}/smart-shield.env"
ENV_EXAMPLE="${APP_ROOT}/.env.example"

if [ ! -f "${ENV_FILE}" ]; then
    if [ -f "${ENV_EXAMPLE}" ]; then
        cp "${ENV_EXAMPLE}" "${ENV_FILE}"
        # Inject a fresh random SECRET_KEY
        SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))" 2>/dev/null || true)
        if [ -n "${SECRET}" ]; then
            sed -i '' "s|replace-this-with-a-long-random-secret|${SECRET}|" "${ENV_FILE}"
            sed -i '' "s|replace-with-long-random-secret|${SECRET}|" "${ENV_FILE}"
        fi
        # Set FreeBSD production paths
        cat >> "${ENV_FILE}" << 'ENVEOF'

# ── FreeBSD production paths (appended by install.sh) ──
SMARTSHIELD_DB_PATH=/var/db/smart-shield/data.db
SMARTSHIELD_CONFIG_PATH=/usr/local/etc/smart-shield/config.json
SMARTSHIELD_UPLOAD_DIR=/var/db/smart-shield/uploads/profile_pictures
SMARTSHIELD_AUDIT_LOG_PATH=/var/log/smart-shield/audit.log
FLASK_DEBUG=0
ENVEOF
        printf 'SMARTSHIELD_ENABLE_NETWORK_APPLY=%s\n' "${DEPLOY_LIVE}" >> "${ENV_FILE}"
        printf 'SMARTSHIELD_NETWORK_DRY_RUN=%s\n'      "${DRY_RUN_VAL}" >> "${ENV_FILE}"
        chmod 0600 "${ENV_FILE}"
        info "Created: ${ENV_FILE} (SECRET_KEY set automatically, mode 0600)"
        info "Admin account will be created on first run via the setup wizard."
    else
        warn "No .env.example found — creating minimal env file."
        SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))" 2>/dev/null || echo "changeme")
        cat > "${ENV_FILE}" << EOF
SECRET_KEY=${SECRET}
FLASK_DEBUG=0
SMARTSHIELD_DB_PATH=/var/db/smart-shield/data.db
SMARTSHIELD_CONFIG_PATH=/usr/local/etc/smart-shield/config.json
SMARTSHIELD_UPLOAD_DIR=/var/db/smart-shield/uploads/profile_pictures
SMARTSHIELD_AUDIT_LOG_PATH=/var/log/smart-shield/audit.log
SMARTSHIELD_ENABLE_NETWORK_APPLY=${DEPLOY_LIVE}
SMARTSHIELD_NETWORK_DRY_RUN=${DRY_RUN_VAL}
# Abuse.ch threat intelligence — set your Auth-Key from https://abuse.ch/
ABUSECH_AUTH_KEY=
ABUSECH_DRY_RUN=1
EOF
        chmod 0600 "${ENV_FILE}"
        info "Admin account will be created on first run via the setup wizard."
    fi
else
    info "Env file already exists: ${ENV_FILE}"
    chmod 0600 "${ENV_FILE}"
fi

# Prompt for ABUSECH_AUTH_KEY if not already set in the env file
if ! grep -q "^ABUSECH_AUTH_KEY=.\+" "${ENV_FILE}" 2>/dev/null; then
    printf "\n${BOLD}━━━ Abuse.ch Threat Intelligence ━━━${NC}\n"
    printf "Abuse.ch provides URLhaus / MalwareBazaar / ThreatFox threat feeds.\n"
    printf "Get your free API key at: https://abuse.ch/\n"
    printf "${YELLOW}[?]${NC} Enter your ABUSECH_AUTH_KEY (press Enter to skip): "
    read -r ABUSE_KEY
    if [ -n "${ABUSE_KEY}" ]; then
        sed -i '' "s|^ABUSECH_AUTH_KEY=.*|ABUSECH_AUTH_KEY=${ABUSE_KEY}|" "${ENV_FILE}"
        info "Abuse.ch Auth Key saved to ${ENV_FILE}"
    else
        warn "ABUSECH_AUTH_KEY not set — threat intel features disabled until you add it to ${ENV_FILE}"
    fi
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
        2>/dev/null || warn "Could not pre-generate master.key — will auto-generate on first app start."
    chmod 0600 "${MASTER_KEY_FILE}" 2>/dev/null || true
    info "Generated: ${MASTER_KEY_FILE} (mode 0600)"
fi

section "4. Python Virtual Environment"

# cryptography requires Rust to build from source — install rust before pip
if ! command -v rustc >/dev/null 2>&1; then
    info "Installing rust (required to build cryptography)..."
    pkg install -y rust
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

# MRTG cron job (every 5 minutes)
CRON_FILE="/etc/cron.d/smart-shield-mrtg"
CRON_LINE="*/5 * * * * root /usr/local/bin/mrtg /usr/local/etc/mrtg/mrtg.cfg --lock-file /var/run/smart-shield/mrtg.lock 2>/dev/null"
printf '%s\n' "${CRON_LINE}" > "${CRON_FILE}"
chmod 0644 "${CRON_FILE}"
info "MRTG cron job installed: ${CRON_FILE}"

# ── Privilege separation: sudoers allowlist ───────────────────────────────────
section "5a. sudo / Sudoers (optional fallback)"

# Ensure sudo is installed
if ! command -v sudo >/dev/null 2>&1; then
    pkg install -y sudo
    info "sudo installed."
fi

SUDOERS_DIR="/usr/local/etc/sudoers.d"
SUDOERS_SRC="${APP_ROOT}/bsd/etc/sudoers.d/smartshield"
SUDOERS_DEST="${SUDOERS_DIR}/smartshield"

mkdir -p "${SUDOERS_DIR}"
chmod 0750 "${SUDOERS_DIR}"
info "Ensured: ${SUDOERS_DIR} (mode 0750)"

if [ -f "${SUDOERS_SRC}" ]; then
    # Validate syntax before installing
    if visudo -c -f "${SUDOERS_SRC}" >/dev/null 2>&1; then
        install -m 0440 "${SUDOERS_SRC}" "${SUDOERS_DEST}"
        info "Installed sudoers allowlist: ${SUDOERS_DEST}"
    else
        warn "sudoers syntax check failed — NOT installing ${SUDOERS_DEST}"
        warn "Run 'visudo -c -f ${SUDOERS_SRC}' to diagnose."
    fi
else
    warn "sudoers source not found: ${SUDOERS_SRC}"
fi

# Ensure sudoers.d is included in /usr/local/etc/sudoers
SUDOERS_MAIN="/usr/local/etc/sudoers"
if [ -f "${SUDOERS_MAIN}" ]; then
    if ! grep -q "sudoers.d" "${SUDOERS_MAIN}" 2>/dev/null; then
        echo "" >> "${SUDOERS_MAIN}"
        echo "@includedir ${SUDOERS_DIR}" >> "${SUDOERS_MAIN}"
        info "Added @includedir ${SUDOERS_DIR} to ${SUDOERS_MAIN}"
    else
        info "sudoers.d already included in ${SUDOERS_MAIN}"
    fi
fi

# Note: the smartshield system user is not created in root-runtime deployments.
# If reverting to unprivileged operation, add: pw useradd -n smartshield ...

section "6. Enable Service"

sysrc smart_shield_enable=YES
info "smart_shield_enable=YES written to rc.conf"

# unbound must be running for content policy DNS blocking to work
sysrc unbound_enable=YES
info "unbound_enable=YES written to rc.conf"

# PF packet filter — must be enabled for firewall and NAT to work
sysrc pf_enable=YES
sysrc pflog_enable=YES
info "pf_enable + pflog_enable written to rc.conf"

# IP forwarding — required so LAN clients can reach the internet through this box
sysrc gateway_enable=YES
info "gateway_enable=YES written to rc.conf"
sysctl net.inet.ip.forwarding=1 >/dev/null
info "IP forwarding activated immediately (net.inet.ip.forwarding=1)"

# DHCP server
sysrc isc_dhcpd_enable=YES
info "isc_dhcpd_enable=YES written to rc.conf"

# SNMP daemon (bsnmpd) — used by MRTG for bandwidth graphs
sysrc bsnmpd_enable=YES
info "bsnmpd_enable=YES written to rc.conf"

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

section "Done"

if [ "${DEPLOY_LIVE:-0}" -eq 1 ]; then
    MODE_LINE="${GREEN}LIVE${NC} — PF rules and network changes apply immediately"
else
    MODE_LINE="${YELLOW}DRY-RUN${NC} — config files written; no live PF/network changes"
    MODE_LINE="${MODE_LINE}\n         Edit ${ENV_FILE} and set SMARTSHIELD_NETWORK_DRY_RUN=0 for live operation"
fi

printf "\n${BOLD}Smart Shield installation complete.${NC}\n"
printf "  Mode: "; printf "${MODE_LINE}\n\n"

cat << EOF
Next steps:
  1. Start the service:
       service smart_shield start
       service smart_shield status

  2. Open the web UI and complete the setup wizard:
       http://<LAN-IP>:5000
       (You will be redirected to the setup wizard — create your admin account in step 3.)

  3. Check the Preflight page in the web UI:
       System → Preflight Check

  4. Set your Abuse.ch key in ${ENV_FILE}:
       ABUSECH_AUTH_KEY=<your-key>   (get it at https://abuse.ch/)
       Leave ABUSECH_DRY_RUN=1 until you want live threat intel lookups.

  5. (Optional) Configure nginx as TLS reverse proxy:
       See bsd/FREEBSD_DEPLOYMENT.md Step 9

EOF
