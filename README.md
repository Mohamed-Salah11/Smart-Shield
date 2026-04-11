# Smart Shield

Smart Shield is a Flask-based web administration panel for a firewall/router appliance style product. The project currently behaves as a **management UI and configuration store** with a growing number of backed endpoints, while most appliance actions are **not yet applied to the host operating system**.

The repository appears to be in a **migration-preparation stage for FreeBSD** rather than a finished FreeBSD appliance.

---

## What this project is right now

- **Backend:** Python + Flask
- **Storage:** SQLite
- **Frontend:** Jinja templates with a desktop-style firewall appliance UI
- **Focus areas already wired:**
  - Authentication and sessions
  - User and group management
  - General system configuration
  - Advanced settings pages
  - Interface assignment/config persistence
  - Firewall/NAT CRUD persistence
  - VPN CRUD persistence for OpenVPN/IPsec/L2TP data models
  - Audit logging and dashboard summaries

In its current form, Smart Shield is best described as:

> **A pfSense-like admin panel prototype with real persistence, partial API coverage, and limited live FreeBSD integration.**

---

## Current FreeBSD preparation already present

The `freebsd-migration-prep` branch has already introduced several changes that clearly move the app toward FreeBSD compatibility:

### 1) FreeBSD-aware filesystem defaults
The app now switches important runtime paths based on platform/environment:

- Database: `/var/db/smart-shield/data.db`
- General config: `/usr/local/etc/smart-shield/config.json`
- Uploads: `/var/db/smart-shield/uploads/profile_pictures`
- Audit log: `/var/log/smart-shield/audit.log`

These defaults can also be overridden with environment variables.

### 2) Safer app bootstrap
- `SECRET_KEY` is required from environment.
- Bootstrap admin creation is env-driven.
- Passwords are hashed using Werkzeug.
- Audit logging was added for login/logout activity.

### 3) Initial FreeBSD live-network hooks
There is a small but real FreeBSD integration surface in `routes/network_api.py`:

- Uses `ifconfig` to apply IPv4 interface settings
- Uses `route` to update the default gateway
- Uses `sockstat -46` to list live connections
- Live apply is protected behind `SMARTSHIELD_ENABLE_NETWORK_APPLY`
- Live apply is explicitly restricted to FreeBSD

This is a good sign: the branch is no longer purely UI-only.

---

## Implemented areas

### Authentication
- Login/logout flow
- Session-based auth
- Password hash verification
- Audit log events

### Users and groups
- Add/edit/delete users
- Change passwords
- Add/edit/delete groups
- Group membership management
- Profile picture uploads

### System configuration
- General setup persisted to JSON config
- Dashboard summary built from audit log and database objects
- Advanced settings persisted in SQLite

### Interfaces and networking
- LAN/WAN configuration persistence
- Interface assignment persistence
- DHCP pool and static lease persistence
- Limited FreeBSD live apply for interface IPv4/gateway configuration

### Firewall and NAT
- CRUD APIs for:
  - Floating rules
  - WAN rules
  - LAN rules
  - Port forwards
  - 1:1 NAT
  - Outbound NAT
  - NPt
  - Aliases
  - Schedules
  - Traffic shaper records
  - Limiters
  - Virtual IP records

### VPN
- OpenVPN server/client/CSO persistence
- IPsec phase 1, PSK, and advanced settings persistence
- L2TP settings persistence

---

## Important limitation

Most saved settings are stored in SQLite or JSON only.

That means **many pages currently configure Smart Shield's internal data model, not the real FreeBSD system state**.

Examples of what is **not fully implemented yet**:

- Generating and applying `pf` rules from firewall/NAT records
- Managing FreeBSD service configs for DHCP/DNS/VPN
- Starting/reloading OS services after config changes
- Building a real appliance boot/runtime environment
- Syncing UI state with real interface/service state on the host

---

## What is missing before serious FreeBSD work can continue

### 1) A real system abstraction layer
Right now, host integration is scattered and minimal. The project needs a dedicated service layer for FreeBSD operations, for example:

- `pfctl` / anchor generation and reload
- `ifconfig` inventory and interface status
- routing table reads/writes
- `service` / `sysrc` wrappers
- config file writers under `/usr/local/etc`
- safe command execution + rollback behavior

Without this, the UI stays a database editor instead of a firewall appliance.

### 2) Firewall engine translation
This is the biggest missing piece.

The project stores firewall and NAT rules, but it does **not** yet:

- translate DB records into `pf.conf` or anchor files
- validate rule conflicts against real interfaces
- run `pfctl -nf` validation before apply
- load or reload rules safely
- show real pf state/tables/rules from the host

Until this exists, the firewall section is configuration persistence only.

### 3) Service configuration writers
The Services and VPN pages need real writers/generators for FreeBSD services such as:

- DHCP server / relay
- DNS resolver / forwarder
- NTP
- IGMP proxy
- OpenVPN
- IPsec / strongSwan
- L2TP
- possibly UPnP / dynamic DNS if those features remain in scope

Each service needs:

- canonical config model
- config file renderer
- syntax validation
- service start/stop/reload integration
- UI-to-runtime status feedback

### 4) Read-from-host support
The current app mostly writes to its own DB. A FreeBSD appliance also needs to **discover actual state**:

- physical NICs from `ifconfig`
- interface addresses and link state
- routes from the kernel routing table
- active leases
- running daemons and health
- pf states/tables/rules
- VPN tunnel/session state

Otherwise the UI will drift away from the machine’s real condition.

### 5) Privilege and security design
If this will actually manage a FreeBSD box, the app needs a clear privilege model:

- how Flask gains permission to run network/system commands
- whether commands run through `sudo`, a root helper, or a daemon
- input validation before shelling out
- CSRF protection for mutating forms/APIs
- session hardening
- secret handling for VPN keys and passwords

At the moment, this is still prototype territory.

### 6) Deployment and appliance packaging
A FreeBSD move also needs OS-level packaging and startup artifacts, which are currently missing from the repo:

- rc.d service script
- production WSGI/web server setup guidance
- package/port structure
- install layout
- permissions/ownership plan
- upgrade path for DB/config files

### 7) Tests and migration safety
The repository now includes initial automated tests under `tests/`.

Before touching real FreeBSD networking, the project should have:

- route/API tests
- DB initialization tests
- config renderer tests
- command wrapper tests
- dry-run validation tests for firewall/service apply
- migration/versioning strategy for SQLite schema changes

### 8) Repository cleanup
The uploaded zip includes runtime and local-development artifacts that should not be part of a clean GitHub repo snapshot:

- `.env`
- `.venv/`
- `data.db`
- `logs/`
- `__pycache__/`
- tracked local modifications across many files

These should be removed from versioned source or regenerated locally.

---

## Recommended next steps for the FreeBSD branch

### Phase 1 — make the app clean and deterministic
- Remove local artifacts from the repository
- Normalize `requirements.txt` and verify install flow
- Refresh README and setup docs
- Add `.env.example` driven bootstrap instructions
- Confirm app boots cleanly in a fresh environment

### Phase 2 — build the FreeBSD integration layer
- Continue extending the dedicated network/system service layer in `app/services/network_service.py`
- Add wrappers for:
  - interface discovery
  - address apply
  - route management
  - service control
  - pf syntax check + reload
- Add dry-run mode and structured error reporting

### Phase 3 — make one subsystem real end-to-end
The best first candidate is **Interfaces + Routing**, because part of it already exists.

Recommended first milestone:
- discover real interfaces from FreeBSD
- assign LAN/WAN to actual ports
- apply IPv4 settings safely
- read back resulting state
- expose rollback/error feedback in UI

After that, move to **Firewall/NAT → pf**.

### Phase 4 — implement service-backed features
Start with the services that are core to an appliance:
- DHCP
- DNS
- OpenVPN or IPsec
- system status / logs / service health

---

## Local development

### Requirements
The repository uses UTF-8 `requirements.txt` and includes security/test dependencies used by the current codebase.

Packages currently referenced include:
- Flask
- Flask-Session
- Werkzeug
- python-dotenv
- Jinja2
- cachelib
- blinker
- click
- itsdangerous
- MarkupSafe

### Example setup
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
# Optional for tests:
# pip install -r requirements-dev.txt
cp .env.example .env
cp config.example.json config.json
python run.py
```

### Run tests
```bash
python -m unittest tests/test_app_unittest.py -v
```

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

> Keep `SMARTSHIELD_ENABLE_NETWORK_APPLY=0` during development unless you are intentionally testing on a FreeBSD host.

---

## Running on FreeBSD

A sensible target layout for FreeBSD is already implied by the code:

- App data: `/var/db/smart-shield/`
- Config: `/usr/local/etc/smart-shield/`
- Logs: `/var/log/smart-shield/`

For actual production use, the project still needs:

- a production WSGI stack
- an rc.d service definition
- privilege separation for host operations
- a hardened reverse proxy/web server in front of Flask

---

## Current project status

Smart Shield is **not yet a completed FreeBSD firewall appliance**.

It is a **strong UI/data-model prototype with early FreeBSD-aware pathing and a small amount of real network integration**.

That means the branch is in a good place to start the FreeBSD port properly, but the next work should focus on **system integration, pf/service generation, host state discovery, and deployment design** rather than adding more HTML pages.

---

## Recent hardening updates

- Added a FreeBSD-oriented network service layer in `app/services/network_service.py` and routed `/api/network/apply` through structured command helpers.
- Added CSRF protection for mutating requests (forms + JSON APIs), including automatic token attachment for frontend fetch calls.
- Added encrypted-at-rest handling for sensitive VPN secrets and hashed L2TP user passwords.
- Consolidated duplicate IPsec API behavior by mapping legacy endpoints to the primary `/vpn/api/ipsec/p1` flow.
- Removed duplicate schema declarations in `app/database.py` (for `ipsec_phase1` and `firewall_schedules`) and added `service_state` for persistent service-side UI state.
- Added initial automated tests under `tests/` for auth, firewall CRUD, VPN CRUD, and network apply guardrails.
- Repository hygiene improvements:
  - `data.db` and `config.json` removed from tracked source
  - `config.example.json` added as a safe config template
  - `.gitignore` expanded for runtime/log/test artifacts
  - `requirements.txt` normalized to UTF-8 and `requirements-dev.txt` added for test tooling

---

## Suggested GitHub description

**Smart Shield** is a Flask-based firewall/router administration panel inspired by appliance-style UIs. It currently provides configuration persistence, dashboarding, and partial FreeBSD networking integration, and is being prepared for deeper FreeBSD system management support.
