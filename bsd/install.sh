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

REQUIRED_PKGS="python3 git sqlite3 ca_root_nss unbound isc-dhcp44-server openvpn strongswan suricata sudo nano mrtg nginx kea mpd5 miniupnpd igmpproxy ddclient bind-tools tcpdump"
info "Installing required packages: ${REQUIRED_PKGS}"
# shellcheck disable=SC2086
pkg install -y ${REQUIRED_PKGS}

# Verify optional service binaries are available
info "Verifying service binary availability..."
for bin in kea-dhcp6 mpd5 miniupnpd igmpproxy ddclient nsupdate; do
    command -v "$bin" >/dev/null 2>&1 \
        && info "  OK: $bin ($(command -v "$bin"))" \
        || warn "  MISSING: $bin — feature depending on this daemon will be unavailable"
done

# Python sqlite3 extension (required for the app database)
PYTHON_VER=$(python3 -c "import sys; print('%d%d' % sys.version_info[:2])" 2>/dev/null || echo "311")
pkg install -y "py${PYTHON_VER}-sqlite3" 2>/dev/null \
    || pkg install -y py311-sqlite3 \
    || warn "py${PYTHON_VER}-sqlite3 not found — sqlite3 module may already be bundled."

# suricata-update is a separate Python tool not bundled with the suricata pkg
info "Installing suricata-update..."
pkg install -y "py${PYTHON_VER}-suricata-update" 2>/dev/null \
    || pip install --break-system-packages suricata-update 2>/dev/null \
    || warn "suricata-update could not be installed via pkg/pip — install manually if needed"

# Initialise the source index so 'Update Rules' works on first use
if command -v suricata-update >/dev/null 2>&1; then
    suricata-update update-sources --no-merge 2>/dev/null || true
    info "suricata-update source index initialised"
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
install -d -m 0755 /var/db/smart-shield/mrtg       2>/dev/null && info "Created: /var/db/smart-shield/mrtg" || true

# Log rotation (newsyslog)
_NEWSYSLOG_SRC="$(dirname "$0")/etc/newsyslog.d/smart-shield.conf"
if [ -f "${_NEWSYSLOG_SRC}" ]; then
    install -d -m 0755 /usr/local/etc/newsyslog.d 2>/dev/null || true
    install -m 0644 "${_NEWSYSLOG_SRC}" /usr/local/etc/newsyslog.d/smart-shield.conf
    info "Log rotation config installed → /usr/local/etc/newsyslog.d/smart-shield.conf"
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
        # Update deployment-mode flags (.env.example already has all paths; only update dynamic values)
        sed -i '' "s|^SMARTSHIELD_ENABLE_NETWORK_APPLY=.*|SMARTSHIELD_ENABLE_NETWORK_APPLY=${DEPLOY_LIVE}|" "${ENV_FILE}"
        sed -i '' "s|^SMARTSHIELD_NETWORK_DRY_RUN=.*|SMARTSHIELD_NETWORK_DRY_RUN=${DRY_RUN_VAL}|"          "${ENV_FILE}"
        info "Deployment flags set: ENABLE_NETWORK_APPLY=${DEPLOY_LIVE}  DRY_RUN=${DRY_RUN_VAL}"
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
# SmartShield AI chatbot (Groq) — get a free key at https://console.groq.com/keys
GROQ_API_KEY=
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
        sed -i '' "s|^ABUSECH_DRY_RUN=.*|ABUSECH_DRY_RUN=0|"              "${ENV_FILE}"
        info "Abuse.ch Auth Key saved and live API calls enabled (dry-run disabled)."
    else
        warn "ABUSECH_AUTH_KEY not set — threat intel features disabled until you add it to ${ENV_FILE}"
    fi
fi

# Prompt for GROQ_API_KEY (SmartShield AI chatbot — Groq)
if ! grep -q "^GROQ_API_KEY=.\+" "${ENV_FILE}" 2>/dev/null; then
    printf "\n${BOLD}━━━ SmartShield AI Chatbot (Groq) ━━━${NC}\n"
    printf "SmartShield includes an AI security assistant powered by Groq (llama-3.3-70b).\n"
    printf "It can analyse logs, explain rules, and answer firewall questions.\n"
    printf "Get a free API key at: https://console.groq.com/keys\n"
    printf "${YELLOW}[?]${NC} Enter your GROQ_API_KEY (press Enter to skip): "
    read -r GROQ_KEY
    if [ -n "${GROQ_KEY}" ]; then
        sed -i '' "s|^GROQ_API_KEY=.*|GROQ_API_KEY=${GROQ_KEY}|" "${ENV_FILE}"
        info "Groq API key saved — SmartShield AI chatbot is enabled."
    else
        warn "GROQ_API_KEY not set — AI chatbot disabled until you add it via Admin → Settings → SmartShield AI."
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
MRTG_LOCK="/var/run/smart-shield/mrtg.lock"
MRTG_BIN="/usr/local/bin/mrtg"

if [ ! -f "${MRTG_CONF}" ]; then
    cat > "${MRTG_CONF}" << 'MRTGEOF'
# Smart Shield MRTG Configuration (bootstrap defaults — regenerate via web UI after wizard)
WorkDir: /var/db/smart-shield/mrtg
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

if [ -x "${MRTG_BIN}" ]; then
    # Install cron job only when MRTG binary exists
    CRON_FILE="/etc/cron.d/smart-shield-mrtg"
    CRON_LINE="*/5 * * * * root env LANG=C /usr/local/bin/mrtg /usr/local/etc/mrtg/mrtg.cfg --lock-file /var/run/smart-shield/mrtg.lock 2>/dev/null"
    printf '%s\n' "${CRON_LINE}" > "${CRON_FILE}"
    chmod 0644 "${CRON_FILE}"
    info "MRTG cron job installed: ${CRON_FILE}"
    # Pass 1: creates .log RRD files (non-zero exit on new files is expected)
    env LANG=C "${MRTG_BIN}" "${MRTG_CONF}" --lock-file "${MRTG_LOCK}" --log-level 0 2>/dev/null || true
    sleep 5  # MRTG needs a time delta between runs to compute rates
    # Pass 2: reads .log files and generates initial PNG graph images
    env LANG=C "${MRTG_BIN}" "${MRTG_CONF}" --lock-file "${MRTG_LOCK}" --log-level 0 2>/dev/null || true
    info "MRTG initialised — initial graphs generated in /var/db/smart-shield/mrtg"
else
    warn "MRTG binary not found at ${MRTG_BIN} — ensure net-mgmt/mrtg is installed"
fi

# ── Nginx TLS reverse proxy ────────────────────────────────────────────────────
section "5a. Nginx TLS & Reverse Proxy"

# SSL directory (mode 0700 — private key must not be world-readable)
SSL_DIR="/usr/local/etc/smart-shield/ssl"
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
            -subj   "/CN=smart-shield.local"
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
cat > /usr/local/etc/nginx/nginx.conf << 'NGINXEOF'
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

    # ── HTTP → HTTPS redirect ─────────────────────────────────────────────────
    server {
        listen      80;
        server_name _;
        return 301  https://$host$request_uri;
    }

    # ── HTTPS — Smart Shield dashboard ───────────────────────────────────────
    server {
        listen      443 ssl;
        server_name _;

        ssl_certificate     /usr/local/etc/smart-shield/ssl/cert.pem;
        ssl_certificate_key /usr/local/etc/smart-shield/ssl/key.pem;

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
}
NGINXEOF
info "Nginx configuration written to /usr/local/etc/nginx/nginx.conf"

info "nginx listening on all interfaces — PF restricts LAN-only access to port 443"

# Test nginx config BEFORE writing to rc.conf — prevents a broken config surviving a reboot
if /usr/local/sbin/nginx -t; then
    sysrc nginx_enable=YES
    info "nginx_enable=YES written to rc.conf"
    service nginx restart 2>/dev/null || service nginx start 2>/dev/null || true
    info "Nginx started — dashboard now available over HTTPS."
else
    warn "Nginx config test FAILED — nginx NOT enabled in rc.conf."
    warn "Fix /usr/local/etc/nginx/nginx.conf then run:"
    warn "  /usr/local/sbin/nginx -t && sysrc nginx_enable=YES && service nginx start"
fi

# ── Privilege separation: sudoers allowlist ───────────────────────────────────
section "5b. sudo / Sudoers (optional fallback)"

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

# DHCP server — only enable after the wizard generates /etc/dhcpd.conf
# A stub placeholder prevents dhcpd from logging "file not found" errors on boot
if [ ! -f /etc/dhcpd.conf ]; then
    printf '# Smart Shield placeholder — replaced by setup wizard\nnot authoritative;\nsubnet 192.168.1.0 netmask 255.255.255.0 {}\n' \
        > /etc/dhcpd.conf
    info "Created stub /etc/dhcpd.conf (wizard will replace)"
fi
sysrc isc_dhcpd_enable=YES
info "isc_dhcpd_enable=YES written to rc.conf"

# bsnmpd — only enable when SNMP is configured via the web UI
# MRTG uses mrtg-probe.sh (direct ifconfig), not bsnmpd, so this is not required for graphs
# sysrc bsnmpd_enable=YES  (deferred — enable via Services → SNMP in web UI)

section "6b. Live Network Activation"

# ── LAN interface ─────────────────────────────────────────────────────────────
sysrc "ifconfig_${LAN_IFACE}=inet ${LAN_IP} netmask ${LAN_MASK}"
info "ifconfig_${LAN_IFACE} written to rc.conf (${LAN_IP}/${LAN_MASK})"

# Bind gunicorn to loopback only — nginx proxies from 127.0.0.1:5000.
sysrc smart_shield_bind=127.0.0.1:5000
info "smart_shield_bind=127.0.0.1:5000 written to rc.conf"

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

# Load PF and pflog kernel modules if not already loaded (required on VMs / fresh installs)
kldload pf    2>/dev/null || true
kldload pflog 2>/dev/null || true

# ── PF ────────────────────────────────────────────────────────────────────────
if pfctl -s info 2>/dev/null | grep -q "^Status: Enabled"; then
    pfctl -f /etc/pf.conf 2>/dev/null \
        && info "PF rules reloaded from /etc/pf.conf" \
        || warn "PF reload failed — check /etc/pf.conf syntax"
else
    pfctl -f /etc/pf.conf 2>/dev/null && pfctl -e 2>/dev/null \
        && info "PF loaded and enabled" \
        || warn "PF enable failed — check /etc/pf.conf"
fi

# ── pflog ─────────────────────────────────────────────────────────────────────
if service pflog status 2>/dev/null | grep -q running; then
    info "pflog already running"
else
    service pflog start 2>/dev/null && info "pflog started" || warn "pflog start failed"
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

  2. Open the web UI (HTTPS, LAN only) and complete the setup wizard:
       https://${LAN_IP}
       (Accept the self-signed certificate warning — replace with a CA cert for production.)
       You will be redirected to the setup wizard; create your admin account in step 3.

  3. Check the Preflight page in the web UI:
       System → Preflight Check

  4. Set your Abuse.ch key in ${ENV_FILE}:
       ABUSECH_AUTH_KEY=<your-key>   (get it at https://abuse.ch/)
       Leave ABUSECH_DRY_RUN=1 until you want live threat intel lookups.

EOF
