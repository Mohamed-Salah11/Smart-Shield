# Smart Shield

A web-based network appliance management system built on Flask and designed for FreeBSD. Smart Shield provides a full-featured GUI for managing firewalls, routing, VPN, DHCP/DNS, IDS/IPS, content filtering, and system monitoring.

---

## Features

### Network & Interfaces
- WAN / LAN / VLAN configuration
- PPPoE, GRE/GIF tunnels, LAGG bonding, Bridge
- Static routes, default gateway, gateway groups
- ARP / NDP neighbor table, interface rollback

### Firewall
- PF (Packet Filter) rules — WAN, LAN, floating
- Outbound NAT, 1:1 NAT, port forwarding
- IP/port aliases, time-based schedules
- Advanced PF tunables and state tracking

### VPN
- OpenVPN (server, clients, client-specific overrides)
- IPsec / IKEv2 via strongSwan (mobile clients, PSK management)
- L2TP/IPsec
- X.509 certificate and CA management

### Services
- ISC DHCP / Kea DHCPv6 with static mappings
- Unbound DNS resolver with custom host overrides
- NTP server/client, SNMP agent, UPnP/NAT-PMP
- Dynamic DNS (ddclient), IGMP proxy, Router Advertisements
- Captive portal, traffic shaper (ALTQ queues)

### Security
- Suricata IDS/IPS with rule management
- DNS-based and web content filtering
- Application-layer filtering
- AES-256-GCM encryption for stored secrets (VPN PSKs, RADIUS passwords)

### System & Monitoring
- Dashboard with live service status
- Audit log (NDJSON) for all configuration changes and logins
- Config version history with rollback for every applied config
- Schema migration with pre-migration backups
- Health monitoring (disk, CPU, service drift detection)
- Backup / restore, factory reset, shutdown/reboot

### Diagnostics
- Ping, traceroute, DNS lookup
- Packet capture (tcpdump)
- PF log viewer, pftop, active states, open sockets

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3 |
| Web Framework | Flask 3.1.2 (Blueprints) |
| Templating | Jinja2 |
| Database | SQLite 3 (raw SQL, no ORM) |
| Encryption | cryptography (AES-256-GCM, X.509) |
| Production Server | Gunicorn 22 |
| Firewall | pfctl (PF) |
| DHCP | isc-dhcp44 / Kea |
| DNS | Unbound |
| VPN | OpenVPN, strongSwan |
| IDS/IPS | Suricata |

---

## Quick Start (Development)

**Requirements:** Python 3.10+, Windows or Linux (network apply is disabled by default on non-FreeBSD)

```bash
# Clone the repo
git clone <repo-url>
cd smart-shield

# Create and activate a virtual environment
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux/macOS
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env — set SECRET_KEY and BOOTSTRAP_ADMIN_PASSWORD at minimum

# Run the development server
python run.py
```

Open `http://localhost:5000` in your browser. The bootstrap admin account is created on first run using `BOOTSTRAP_ADMIN_USERNAME` / `BOOTSTRAP_ADMIN_PASSWORD` from `.env`.

---

## Environment Variables

Copy `.env.example` to `.env` and set the following:

| Variable | Description | Required |
|---|---|---|
| `SECRET_KEY` | Flask session signing key (long random string) | Yes |
| `BOOTSTRAP_ADMIN_USERNAME` | Username for the initial admin account | Yes |
| `BOOTSTRAP_ADMIN_PASSWORD` | Password for the initial admin account | Yes |
| `FLASK_DEBUG` | Enable debug mode (`1` / `0`) | No (default: `0`) |
| `SMARTSHIELD_DB_PATH` | SQLite database file path | No (auto) |
| `SMARTSHIELD_CONFIG_PATH` | `config.json` path | No (auto) |
| `SMARTSHIELD_ENABLE_NETWORK_APPLY` | Actually write system configs (`1` / `0`) | No (default: `0`) |
| `SMARTSHIELD_NETWORK_DRY_RUN` | Dry-run mode for config writers | No (default: `0`) |
| `SMARTSHIELD_MASTER_KEY` | Base64-encoded 32-byte key for secret encryption | No (auto-generated) |
| `ABUSECH_AUTH_KEY` | Personal Auth-Key for abuse.ch APIs (URLhaus / MalwareBazaar / ThreatFox) | Yes (for threat intel) |
| `ABUSECH_DRY_RUN` | `1` = log-only, no blocking actions (default); `0` = live API calls | No (default: `1`) |

Generate a secure secret key:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Generate a master key for secret encryption:
```bash
python -c "import secrets,base64; print(base64.b64encode(secrets.token_bytes(32)).decode())"
```

---

## Abuse.ch Threat Intelligence Setup

Smart Shield integrates with three abuse.ch feeds: **URLhaus** (malicious URLs/hosts), **MalwareBazaar** (file hashes), and **ThreatFox** (IOCs).  
The integration defaults to **dry-run mode** — lookups are logged but no blocking actions are taken until you explicitly enable live mode.

### 1. Get your Auth-Key

Sign up or log in at [https://abuse.ch/](https://abuse.ch/) and copy your personal Auth-Key from your account dashboard.

### 2. Add the key to your local `.env`

```bash
# .env (never commit this file — it is listed in .gitignore)
ABUSECH_AUTH_KEY=your_real_key_here
ABUSECH_DRY_RUN=1   # keep as 1 until you're ready for live lookups
```

### 3. Production deployment

Store the key in your server's secret manager rather than a file on disk.  
On FreeBSD you can set it as an rc.conf variable:

```sh
# /etc/rc.conf.d/smart_shield
smart_shield_env="ABUSECH_AUTH_KEY=your_real_key_here"
```

Or inject it via your hosting platform's secret manager (AWS Secrets Manager, HashiCorp Vault, etc.) as the environment variable `ABUSECH_AUTH_KEY`.

### 4. Security rules

| Rule | Detail |
|---|---|
| Never hardcode the key | The key is always read from `ABUSECH_AUTH_KEY` at call time |
| Header only | The key is sent exclusively as `Auth-Key: <value>` in HTTP request headers |
| Logs are redacted | The key value never appears in app logs or error messages |
| Dry-run by default | Set `ABUSECH_DRY_RUN=0` only when you want live blocking |
| Tests use a fake key | `ABUSECH_AUTH_KEY=test_key_123` — the real key is never in the test suite |

---

## FreeBSD Deployment

See [bsd/FREEBSD_DEPLOYMENT.md](bsd/FREEBSD_DEPLOYMENT.md) for the full deployment checklist.

The automated installer handles dependency installation, user creation, sudo allowlist, and rc.d service setup:

```bash
# On FreeBSD as root
chmod +x bsd/install.sh
./bsd/install.sh
```

The installer:
- Creates a dedicated `smartshield` service user
- Installs Python dependencies into a virtualenv
- Configures a sudo allowlist for privilege-separated operations
- Registers `smart_shield` as an rc.d service
- Sets up log rotation and gunicorn as the WSGI server

---

## Running Tests

```bash
pip install pytest
pytest tests/
```

The test suite covers:
- Unit tests: PF generator, DHCP/DNS writers, OpenVPN/IPsec/L2TP writers, certificate manager, secret store, validators
- Route integration tests: firewall, services, interfaces, VPN, system routes
- Config apply pipeline tests
- FreeBSD integration tests (require a real FreeBSD host)

---

## Project Structure

```
smart-shield/
├── app/                    # Flask application factory and core modules
│   ├── __init__.py         # App factory, CSRF, audit logging, blueprint registration
│   ├── config.py           # Configuration classes (Dev/Prod/Test)
│   ├── database.py         # SQLite schema (40+ tables)
│   ├── migrations.py       # Schema migration system
│   ├── validators.py       # Input validation
│   ├── secret_store.py     # AES-256-GCM secret encryption
│   ├── audit_log.py        # Structured audit logging (NDJSON)
│   └── services/           # Config writers and system service integrations
│       ├── pf_generator.py
│       ├── openvpn_writer.py
│       ├── ipsec_writer.py
│       ├── dhcp_writer.py
│       ├── dns_writer.py
│       ├── ids_writer.py
│       └── ...             # 30 service modules total
├── routes/                 # Flask blueprint route handlers (15 modules)
│   ├── auth.py
│   ├── firewall.py
│   ├── vpn.py
│   ├── services.py
│   └── ...
├── templates/              # Jinja2 HTML templates (150+)
├── static/                 # CSS and images
│   ├── css/base.css
│   └── images/
├── tests/                  # Pytest test suite (21 modules)
├── docs/                   # Admin guide and service matrix
├── bsd/                    # FreeBSD deployment scripts
│   ├── install.sh
│   └── FREEBSD_DEPLOYMENT.md
├── run.py                  # Development server entry point
├── wsgi.py                 # Production WSGI entry point (gunicorn)
├── requirements.txt
├── .env.example
└── config.example.json
```

---

## Architecture Highlights

- **Privilege separation:** The Flask app runs as an unprivileged user. All privileged system operations (pfctl, ifconfig, service commands) go through `sudo` with a strict allowlist defined in `app/services/priv_helper.py`.
- **Config versioning:** Every applied configuration (PF, DHCP, DNS, VPN) is stored in the database with a timestamp, enabling rollback from the UI.
- **Secret management:** Reversible secrets (VPN PSKs, RADIUS passwords) are encrypted at rest with AES-256-GCM using a key stored outside the database.
- **Audit logging:** Every login attempt, configuration change, and API call is written to a structured NDJSON audit log.
- **Schema migrations:** The database schema is versioned; migrations run automatically on startup with a pre-migration backup.

---

## Documentation

- [docs/ADMIN_GUIDE.md](docs/ADMIN_GUIDE.md) — Administrator guide (users, backup, logs, upgrades, troubleshooting)
- [docs/SERVICE_MATRIX.md](docs/SERVICE_MATRIX.md) — Implementation status for every feature
- [bsd/FREEBSD_DEPLOYMENT.md](bsd/FREEBSD_DEPLOYMENT.md) — FreeBSD production deployment checklist
