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

section "1. Package Installation"

info "Updating pkg repository..."
pkg update -q

REQUIRED_PKGS="python3 git sqlite3 ca_root_nss unbound isc-dhcp44-server openvpn strongswan suricata nginx"
info "Installing required packages: ${REQUIRED_PKGS}"
# shellcheck disable=SC2086
pkg install -y ${REQUIRED_PKGS}

# suricata-update: package name varies by Python version
PYTHON_VER=$(python3 -c "import sys; print('%d%d' % sys.version_info[:2])" 2>/dev/null || echo "311")
SURICATA_UPDATE_PKG="py${PYTHON_VER}-suricata-update"
pkg install -y "${SURICATA_UPDATE_PKG}" 2>/dev/null \
    || pkg install -y py311-suricata-update \
    || fatal "suricata-update package not found — cannot continue."

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

# Suricata
install -d -m 0755 /usr/local/etc/suricata       2>/dev/null && info "Created: /usr/local/etc/suricata" || true
install -d -m 0755 /usr/local/etc/suricata/rules  2>/dev/null && info "Created: /usr/local/etc/suricata/rules" || true
install -d -m 0755 /var/log/suricata              2>/dev/null && info "Created: /var/log/suricata" || true
install -d -m 0755 /var/run/suricata              2>/dev/null && info "Created: /var/run/suricata" || true

# Nginx
install -d -m 0755 /usr/local/etc/nginx  2>/dev/null && info "Created: /usr/local/etc/nginx" || true
install -d -m 0755 /var/log/nginx        2>/dev/null && info "Created: /var/log/nginx" || true
install -d -m 0755 /var/run/nginx        2>/dev/null && info "Created: /var/run/nginx" || true

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
        cat >> "${ENV_FILE}" << 'EOF'

# ── FreeBSD production paths (appended by install.sh) ──
SMARTSHIELD_DB_PATH=/var/db/smart-shield/data.db
SMARTSHIELD_CONFIG_PATH=/usr/local/etc/smart-shield/config.json
SMARTSHIELD_UPLOAD_DIR=/var/db/smart-shield/uploads/profile_pictures
SMARTSHIELD_AUDIT_LOG_PATH=/var/log/smart-shield/audit.log
FLASK_DEBUG=0
SMARTSHIELD_ENABLE_NETWORK_APPLY=0
SMARTSHIELD_NETWORK_DRY_RUN=0
EOF
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
SMARTSHIELD_ENABLE_NETWORK_APPLY=0
SMARTSHIELD_NETWORK_DRY_RUN=0
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

# Warn (non-fatal) when ABUSECH_AUTH_KEY is not yet configured
if ! grep -q "^ABUSECH_AUTH_KEY=.\+" "${ENV_FILE}" 2>/dev/null; then
    warn "ABUSECH_AUTH_KEY is not set in ${ENV_FILE}."
    warn "Abuse.ch threat intelligence (URLhaus / MalwareBazaar / ThreatFox) will"
    warn "be unavailable until you add:  ABUSECH_AUTH_KEY=<your-key>"
    warn "Get your key at: https://abuse.ch/"
fi

CONFIG_FILE="${ETC_DIR}/config.json"
CONFIG_EXAMPLE="${APP_ROOT}/config.example.json"
if [ ! -f "${CONFIG_FILE}" ] && [ -f "${CONFIG_EXAMPLE}" ]; then
    cp "${CONFIG_EXAMPLE}" "${CONFIG_FILE}"
    info "Created: ${CONFIG_FILE}"
else
    info "Config already exists or example missing — skipping."
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
"${VENV}/bin/pip" install -r "${APP_ROOT}/requirements.txt" -q
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
printf "\n${BOLD}Smart Shield installation complete.${NC}\n\n"
cat << EOF
Next steps:
  1. Edit ${ENV_FILE}
       — Set SMARTSHIELD_ENABLE_NETWORK_APPLY=1 when ready for live network changes
       — Set ABUSECH_AUTH_KEY=<your-key>  (get it at https://abuse.ch/)
         Leave ABUSECH_DRY_RUN=1 until you want live threat intel lookups.
         Store the key here (mode 0600) or in your secret manager — never in Git.

  2. Start the service:
       service smart_shield start
       service smart_shield status

  3. Open the web UI and complete the setup wizard:
       http://<LAN-IP>:5000
       (You will be redirected to the setup wizard on first visit — create your
        admin account in step 3 of the wizard.)

  4. Check the Preflight page in the web UI:
       System → Preflight Check

  5. (Optional) Configure nginx as TLS reverse proxy:
       See bsd/FREEBSD_DEPLOYMENT.md Step 9

EOF
