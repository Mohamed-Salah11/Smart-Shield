# Smart Shield 🛡️

**Smart Shield** is a Flask-based firewall/router administration panel inspired by pfSense-style appliance UIs. It provides a full-featured web management interface for network configuration, firewall rules, NAT, VPN, and services — built to run on **FreeBSD** as a real network appliance.

> ⚠️ **Current Status:** Smart Shield is a strong UI/data-model prototype with growing FreeBSD system integration. Most configuration is persisted to SQLite/JSON. Full pf/service rendering and end-to-end OS control is an active build area. See [What's Not Yet Wired](#whats-not-yet-wired) before deploying in production.

---

## Table of Contents

- [Features](#features)
- [Architecture Overview](#architecture-overview)
- [Directory Layout (FreeBSD)](#directory-layout-freebsd)
- [Requirements](#requirements)
- [Local Development Setup](#local-development-setup)
- [FreeBSD Appliance Deployment](#freebsd-appliance-deployment)
- [Environment Variables Reference](#environment-variables-reference)
- [Operator Tools](#operator-tools)
- [What's Not Yet Wired](#whats-not-yet-wired)
- [Roadmap](#roadmap)
- [Running Tests](#running-tests)

---

## Features

### Authentication & Users
- Session-based login/logout with password hashing (Werkzeug)
- User and group management with profile picture support
- Full audit logging for session events, page views, and API mutations

### Interfaces & Networking
- LAN/WAN interface assignment and IPv4 configuration persistence
- Live FreeBSD apply via `ifconfig` and `route` (guarded by env flag)
- DHCP pool and static lease management
- ARP-based host discovery with LAN/WAN classification and firewall coverage hints

### Firewall & NAT
- Floating, WAN, and LAN rules (CRUD)
- Port forwards, 1:1 NAT, Outbound NAT, NPt
- Aliases, schedules, traffic shaper, limiters, virtual IPs

### VPN
- OpenVPN server/client/CSO configuration persistence
- IPsec Phase 1, PSK, and advanced settings
- L2TP settings (encrypted secrets at rest)

### Services
- DHCP server/relay, DHCPv6
- DNS Resolver/Forwarder
- NTP, IGMP Proxy, SNMP
- Dynamic DNS, UPnP/IGD, Wake-on-LAN
- Captive Portal, Auto Config Backup

### System
- Dashboard with live summary from audit log and database
- General system configuration persisted to JSON
- Advanced settings (firewall tuning, VPN packet processing)
- Status logs with browsing + system + session audit categories
- Setup wizard for first-boot configuration

---

## Architecture Overview

```
Browser / Admin Client
        │
        ▼
  Flask Web App (Python)
  ├── routes/          — page + API route handlers
  ├── app/services/    — FreeBSD system integration layer
  │   └── network_service.py  (ifconfig, route, pf wrappers)
  ├── app/database.py  — SQLite schema + helpers
  ├── templates/       — Jinja2 HTML templates
  └── static/          — CSS, JS, icons
        │
        ▼
  SQLite DB  +  config.json
        │
        ▼
  FreeBSD Host OS
  ├── pf              — packet filter (firewall + NAT)
  ├── ifconfig/route  — interface/routing management
  ├── dhcpd / unbound — DHCP / DNS services
  └── openvpn / ipsec — VPN daemons
```

---

## Directory Layout (FreeBSD)

| Path | Purpose |
|------|---------|
| `/usr/local/share/smart-shield/` | Application source code |
| `/usr/local/etc/smart-shield/` | Config files (`smart-shield.env`, `config.json`) |
| `/var/db/smart-shield/` | SQLite database + uploaded profile pictures |
| `/var/log/smart-shield/` | App log, audit log |
| `/usr/local/etc/rc.d/smart_shield` | rc.d service script |
| `/usr/local/sbin/smartshieldctl` | Operator control tool |
| `/usr/local/sbin/smartshield-cli` | Interactive console menu |

---

## Requirements

### FreeBSD Host
- FreeBSD 13.x or 14.x (amd64 recommended)
- At least **2 network interfaces** (WAN + LAN)
- Python 3.9+
- `sqlite3` CLI (for `smartshieldctl` interface helpers)
- `pkg` package manager

### Python Packages
```
Flask
Flask-Session
Werkzeug
python-dotenv
Jinja2
cachelib
blinker
click
itsdangerous
MarkupSafe
```

---

## Local Development Setup

```bash
# Clone the repo
git clone <repo-url>
cd smart-shield

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
# Optional: test tooling
# pip install -r requirements-dev.txt

# Set up environment and config
cp .env.example .env
cp config.example.json config.json

# Edit .env — at minimum set SECRET_KEY and admin password
nano .env

# Run the development server
python run.py
```

Open http://localhost:5000 and log in with your `BOOTSTRAP_ADMIN_USERNAME` / `BOOTSTRAP_ADMIN_PASSWORD`.

> Keep `SMARTSHIELD_ENABLE_NETWORK_APPLY=0` during development. Live network commands only run on a real FreeBSD host.

### Example `.env`
```env
SECRET_KEY=replace-this-with-a-long-random-secret
FLASK_DEBUG=1
SMARTSHIELD_DB_PATH=data.db
SMARTSHIELD_CONFIG_PATH=config.json
SMARTSHIELD_UPLOAD_DIR=static/uploads/profile_pictures
SMARTSHIELD_AUDIT_LOG_PATH=logs/audit.log
SMARTSHIELD_ENABLE_NETWORK_APPLY=0
SMARTSHIELD_NETWORK_DRY_RUN=1
BOOTSTRAP_ADMIN_USERNAME=admin
BOOTSTRAP_ADMIN_PASSWORD=change-this-before-first-run
```

---

## FreeBSD Appliance Deployment

### Step 1 — Prepare the FreeBSD host

```sh
# Update packages and install base requirements
pkg update
pkg install -y python3 git sqlite3 ca_root_nss
python3 -m ensurepip --upgrade

# Create runtime directory layout
install -d -m 0755 /usr/local/share/smart-shield
install -d -m 0755 /usr/local/etc/smart-shield
install -d -m 0755 /var/db/smart-shield/uploads/profile_pictures
install -d -m 0755 /var/log/smart-shield
```

### Step 2 — Deploy the application

```sh
# Option A: clone from git
git clone <repo-url> /usr/local/share/smart-shield

# Option B: copy from archive
tar -xzf smart-shield.tar.gz -C /usr/local/share/smart-shield

# Build Python virtual environment
cd /usr/local/share/smart-shield
python3 -m venv .venv
. .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 3 — Configure the environment

Create `/usr/local/etc/smart-shield/smart-shield.env`:

```env
SECRET_KEY=replace-with-a-long-random-secret
FLASK_DEBUG=0

SMARTSHIELD_DB_PATH=/var/db/smart-shield/data.db
SMARTSHIELD_CONFIG_PATH=/usr/local/etc/smart-shield/config.json
SMARTSHIELD_UPLOAD_DIR=/var/db/smart-shield/uploads/profile_pictures
SMARTSHIELD_AUDIT_LOG_PATH=/var/log/smart-shield/audit.log

# Keep OFF until you are ready for live network changes:
SMARTSHIELD_ENABLE_NETWORK_APPLY=0
SMARTSHIELD_NETWORK_DRY_RUN=0

BOOTSTRAP_ADMIN_USERNAME=admin
BOOTSTRAP_ADMIN_PASSWORD=change-this-now
```

Copy the example config:
```sh
cp /usr/local/share/smart-shield/config.example.json \
   /usr/local/etc/smart-shield/config.json
```

### Step 4 — Install the rc.d service and operator tools

```sh
# Install the rc.d service script
install -m 0555 /usr/local/share/smart-shield/bsd/rc.d/smart_shield \
                /usr/local/etc/rc.d/smart_shield

# Install operator CLI tools
install -m 0555 /usr/local/share/smart-shield/bsd/sbin/smartshieldctl \
                /usr/local/sbin/smartshieldctl
install -m 0555 /usr/local/share/smart-shield/bsd/sbin/smartshield-cli \
                /usr/local/sbin/smartshield-cli

# Enable and start the service
sysrc smart_shield_enable=YES
service smart_shield start
service smart_shield status
```

The web UI will be available at **http://<LAN-IP>:5000**.

### Step 5 — Enable PF (packet filter)

```sh
# Enable PF and pflog at boot
sysrc pf_enable=YES
sysrc pflog_enable=YES

# Start services now
service pf start
service pflog start
```

Add a minimal `/etc/pf.conf` to get PF running (required for firewall features):

```
# Example minimal pf.conf — replace em0/em1 with your actual interfaces
WAN = "em0"
LAN = "em1"

set block-policy drop
set skip on lo0

scrub in all

# NAT outbound traffic from LAN to WAN
nat on $WAN from { $LAN:network } to any -> ($WAN)

# Default deny, allow established
block all
pass out quick keep state
pass in on $LAN keep state
```

Validate and load:
```sh
pfctl -nf /etc/pf.conf   # dry-run validation
pfctl -f /etc/pf.conf    # load rules
pfctl -e                  # enable PF if not yet enabled
```

### Step 6 — Assign LAN/WAN interfaces

Either through the **web UI** (`Interfaces > Assignments`) or directly via the CLI:

```sh
# Check what physical interfaces are available
ifconfig -l

# Assign and configure LAN
smartshieldctl iface-set LAN static 192.168.1.1/24 --apply

# Assign and configure WAN (DHCP from ISP)
smartshieldctl iface-set WAN dhcp --apply

# Or static WAN
smartshieldctl iface-set WAN static 203.0.113.2/24 203.0.113.1 --apply

# Verify
smartshieldctl iface-show LAN
smartshieldctl iface-show WAN
```

### Step 7 — Verify logging and host tracking

```sh
# Check app is running and logs are flowing
smartshieldctl logs 50
smartshieldctl audit 50

# Check PF filter log
smartshieldctl filterlog 50
```

In the web UI: open `Diagnostics > ARP Table (Host Tracking)` and click **Refresh Hosts** to see discovered LAN/WAN peers and their firewall coverage status.

### Step 8 — Enable live network apply

Only when you are confident the configuration is correct:

```sh
# Edit env file
nano /usr/local/etc/smart-shield/smart-shield.env

# Change this line:
SMARTSHIELD_ENABLE_NETWORK_APPLY=1

# Restart service
service smart_shield restart
```

> ⚠️ Always test from a console/KVM session first. Enabling live apply without a working console fallback can lock you out of the box.

### Step 9 — Appliance hardening

```sh
# 1. Put Smart Shield behind nginx with TLS (recommended)
pkg install -y nginx
# Configure nginx as reverse proxy to 127.0.0.1:5000

# 2. Set strong admin password in env file and rotate SECRET_KEY

# 3. Restrict UI access to management VLAN/interface via pf rules

# 4. Schedule backups of critical paths
#    /var/db/smart-shield/
#    /usr/local/etc/smart-shield/
#    /var/log/smart-shield/

# 5. Configure log rotation
# Add to /etc/newsyslog.conf:
# /var/log/smart-shield/app.log    644  7  1000  *  JC
# /var/log/smart-shield/audit.log  644  30 *     @T00 JC
```

---

## Environment Variables Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | *(required)* | Flask session signing key — must be set |
| `FLASK_DEBUG` | `0` | Set to `1` for development only |
| `SMARTSHIELD_DB_PATH` | `/var/db/smart-shield/data.db` | SQLite database path |
| `SMARTSHIELD_CONFIG_PATH` | `/usr/local/etc/smart-shield/config.json` | JSON config file path |
| `SMARTSHIELD_UPLOAD_DIR` | `/var/db/smart-shield/uploads/profile_pictures` | Profile picture upload directory |
| `SMARTSHIELD_AUDIT_LOG_PATH` | `/var/log/smart-shield/audit.log` | Audit log path |
| `SMARTSHIELD_ENABLE_NETWORK_APPLY` | `0` | Set to `1` to allow live network changes on FreeBSD |
| `SMARTSHIELD_NETWORK_DRY_RUN` | `0` | Set to `1` to log commands without executing |
| `BOOTSTRAP_ADMIN_USERNAME` | `admin` | Initial admin username (created on first boot) |
| `BOOTSTRAP_ADMIN_PASSWORD` | *(required)* | Initial admin password |

---

## Operator Tools

### `smartshieldctl` — service control and interface management

```sh
smartshieldctl start|stop|restart|status
smartshieldctl enable|disable          # boot persistence
smartshieldctl logs [N]                # tail app log (default 100 lines)
smartshieldctl audit [N]               # tail audit log
smartshieldctl filterlog [N]           # tail PF traffic log
smartshieldctl iface-show [LAN|WAN]    # show interface config
smartshieldctl iface-set LAN static 192.168.1.1/24 [--apply]
smartshieldctl iface-set WAN dhcp [--apply]
smartshieldctl health                  # HTTP probe against local UI
smartshieldctl menu                    # launch interactive console
```

### `smartshield-cli` — interactive console menu

Run `smartshield-cli` for a pfSense-style console menu covering service control, interface configuration, log tailing, and system reboot/shutdown. Useful for headless appliance management without a browser.

---

## What's Not Yet Wired

The following features are **configuration persistence only** — they save to the database but do not yet apply to the live FreeBSD system:

- **pf rule generation** — firewall/NAT rules are stored in SQLite but not yet translated to `pf.conf` anchors and loaded via `pfctl`
- **DHCP server config writing** — DHCP settings are stored but `dhcpd.conf` is not yet generated/reloaded
- **DNS resolver/forwarder config writing** — DNS settings do not yet write `unbound.conf` or `named.conf`
- **VPN daemon configs** — OpenVPN/IPsec/L2TP data is persisted but config files for daemons are not yet generated
- **Service start/stop integration** — the Services pages do not yet trigger `service X start/stop/reload`
- **Read-from-host sync** — the UI does not yet discover live interface state, active leases, pf tables, or VPN session state from the OS

See `bsd/FREEBSD_DEPLOYMENT.md` for the full gap analysis and development phases.

---

## Roadmap

### Phase 1 — Clean and deterministic ✅
- [x] FreeBSD-aware filesystem defaults
- [x] Bootstrap admin from environment
- [x] CSRF protection for all mutating requests
- [x] Initial automated tests
- [x] Repository hygiene (no runtime artifacts in source)

### Phase 2 — FreeBSD integration layer ✅
- [x] `network_service.py` with `ifconfig`/`route` wrappers
- [x] `smartshieldctl` and `smartshield-cli` operator tools
- [x] ARP-based host discovery and firewall coverage hints
- [x] `pf.conf` anchor generator from DB firewall rules (`app/services/pf_generator.py`)
- [x] `pfctl` syntax validation + safe reload
- [x] `sysrc` / `service` wrappers for all daemons (`app/services/service_manager.py`)

### Phase 3 — Interfaces end-to-end ✅
- [x] Physical NIC discovery from `ifconfig` (`list_physical_nics()` in `network_service.py`)
- [x] Interface assignment → live apply with rollback (`apply_interface_with_rollback()` in `network_service.py`)
- [x] Read-back of actual interface state into UI (`get_interface_state()` in `network_service.py`)

### Phase 4 — Service-backed features ✅
- [x] DHCP config writer + reload (`app/services/dhcp_writer.py`)
- [x] DNS (unbound) config writer + reload (`app/services/dns_writer.py`)
- [x] OpenVPN config generator + daemon control (`app/services/openvpn_writer.py`)
- [x] IPsec (strongSwan) config generator (`app/services/ipsec_writer.py`)
- [x] Production WSGI stack — gunicorn added to `requirements.txt`; rc.d updated to use gunicorn

### Phase 5 — IDS / IPS ✅
### Phase 6 — First-run setup + tooling guarantee ✅
- [x] `app/services/freebsd_setup.py` — authoritative directory + tool registry; `ensure_dirs()` called on every startup to create missing paths; `check_tools()` inspects every binary/package; `preflight_check()` returns full report
- [x] `bsd/install.sh` — one-shot install script: installs all pkg packages, creates all dirs, seeds env + config, builds venv, installs rc.d + CLI tools, runs Python preflight
- [x] `System → Preflight Check` page in web UI — shows dir status + per-tool install status with `pkg install` commands for anything missing
- [x] Directories created automatically on startup: all app-data dirs (DB, uploads, audit log, config) on every platform; all FreeBSD service dirs on FreeBSD

### Phase 5 — IDS / IPS ✅
- [x] Suricata integration (`app/services/ids_writer.py`) — YAML config generator, rule update, toggle
- [x] IDS/IPS routes (`routes/ids.py`) — config save, enable/disable API, ruleset CRUD, alert viewer, status
- [x] IDS/IPS UI (`templates/ids.html`) — status banner, alert table, config form, ruleset manager
- [x] Sidebar entry under "IDS / IPS" group
- [x] Database tables `ids_config` + `ids_rulesets` with default ET Open / abuse.ch rulesets seeded
- [x] FreeBSD install: `pkg install suricata` → service managed via `service_manager.py`

---

## Running Tests

```bash
python -m unittest tests/test_app_unittest.py -v
```

Tests cover authentication flows, firewall rule CRUD, VPN CRUD, and network apply guardrails (dry-run safety checks).

---

## License

See `LICENSE` file in the repository root.

---

## Contributing

Pull requests targeting the `freebsd-migration-prep` branch are welcome. Focus areas that move the needle most: pf rule generation, service config writers, and read-from-host state sync.
