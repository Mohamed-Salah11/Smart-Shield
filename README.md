# Smart Shield Firewall Panel

A **Flask + SQLite** web application that provides an appliance-inspired, desktop-focused **firewall/router management panel** branded as **Smart Shield**.

It includes UI pages (Jinja templates) for common firewall appliance areas like **System**, **Interfaces**, **Routing**, **Services**, **Firewall**, **VPN**, **Status**, and **Diagnostics**. Some areas are fully wired to a database/API (notably *Users*, *Advanced settings*, and *Firewall/NAT*), while others are currently UI stubs/placeholders that render pages without persistent backend logic.

---

## What’s in this repository

### Main features (implemented)
- **Authentication**
  - Simple login using the `users` table in SQLite.
- **User Manager**
  - CRUD users & groups.
  - Upload profile pictures (stored under `static/uploads/profile_pictures/`).
- **System → General Setup**
  - Edits a JSON config file (`config.json`) for hostname, DNS, timezone, UI theme, etc.
- **System → Advanced**
  - Multiple “advanced” configuration pages backed by SQLite tables:
    - Admin Access
    - Firewall & NAT
    - Network
    - Miscellaneous
    - System Tunables (add/edit/delete)
- **Firewall Rules + NAT (backend + frontend)**
  - UI pages in `templates/rules.html` and `templates/nat.html`
  - JSON CRUD APIs under `/firewall/api/...` backed by SQLite tables:
    - Floating/WAN/LAN rules
    - Port forwards, 1:1 NAT, outbound NAT, NPt (IPv6 prefix translation)
    - Firewall Aliases

### UI pages / placeholders (mostly template-only)
Many routes simply `render_template(...)` without backend persistence yet, for example:
- Interfaces, routing pages, various services pages (DHCP, SNMP, NTP, etc.)
- Status & diagnostics pages
- Portions of VPN (see the “Known gaps” section below)

---

## Quick start

### Prerequisites
- Python **3.11+** recommended
- pip

### Install dependencies
There is no `requirements.txt` in this repo. The code imports:
- `flask`
- `werkzeug` (for `secure_filename` used in uploads)

Example setup:

```bash
python -m venv .venv
source .venv/bin/activate
pip install flask werkzeug
```

### Run
```bash
python run.py
```

This starts Flask in **debug mode** on `http://127.0.0.1:5000/`.

> The app writes to `data.db` and `config.json` in the project root. Make sure the process has write permissions.

---

## Default credentials

On first run (when `users` table is empty), `app/database.py:init_db()` inserts a default admin user:

- **Username:** `admin`
- **Password:** `1234`

> ⚠️ Passwords are stored in **plain text** in SQLite in this prototype. Do not use this as-is in production.

---

## Project layout

```
Smart-Shield/
├─ run.py                     # Flask entrypoint
├─ config.json                # General setup configuration (JSON file)
├─ data.db                    # SQLite database (created/updated on startup)
├─ app/
│  ├─ __init__.py            # create_app(), blueprint registration, DB init calls
│  ├─ config.py              # Config class (currently minimal)
│  └─ database.py            # SQLite connection + schema creation + defaults
├─ routes/
│  ├─ auth.py                # Login/logout
│  ├─ users.py               # User Manager CRUD + uploads
│  ├─ system.py              # System pages + Advanced settings persistence
│  ├─ interfaces.py          # Interfaces pages (template-only)
│  ├─ routing.py             # Routing pages (mostly template-only)
│  ├─ services.py            # Services pages (some session-based temporary storage)
│  ├─ firewall.py            # Firewall UI + JSON CRUD APIs (rules/NAT/aliases)
│  ├─ vpn.py                 # VPN pages (OpenVPN/IPsec/L2TP; depends on missing modules)
│  ├─ status.py              # Status pages (template-only)
│  ├─ diagnostics.py         # Diagnostics pages (template-only)
│  └─ dns.py                 # Minimal DNS blueprint (not registered by default)
├─ templates/                 # Jinja2 templates (132 HTML files)
└─ static/
   ├─ css/                    # base.css, login.css
   ├─ images/                 # SS.png logo
   └─ uploads/profile_pictures/
```

---

## How the app boots

`run.py` imports `create_app()` from `app/__init__.py`.

`create_app()`:
1. Creates the Flask app with `templates/` and `static/` folders at the project root.
2. Sets `app.secret_key` (currently hard-coded).
3. Calls database initialization functions (see “Known gaps” below).
4. Registers blueprints:
   - `auth`, `users`, `system`, `interfaces`, `routing`, `services`, `firewall`, `vpn`, `status`, `diagnostics`

---

## Routes overview (high level)

### Auth
- `GET /` → redirects to login
- `GET|POST /login` → authenticate against `users`
- `GET /logout` → clear session

### System (prefix: `/system`)
- Dashboard: `/system/dashboard`
- General Setup (JSON config): `/system/general-setup`
- Advanced pages (SQLite-backed):
  - `/system/admin-access`
  - `/system/advanced/firewall-nat`
  - `/system/advanced/network`
  - `/system/advanced/miscellaneous`
  - `/system/advanced/system-tunables` (+ add/edit/delete routes)

### Users (prefix: `/system/user-manager`)
- List users/groups: `GET /system/user-manager/`
- Add user: `POST /system/user-manager/add`
- Edit user: `POST /system/user-manager/edit/<user_id>`
- Delete user: `POST /system/user-manager/delete/<user_id>`
- Change password: `POST /system/user-manager/change-password/<user_id>`
- Add group: `POST /system/user-manager/add-group`

### Firewall (prefix: `/firewall`)
UI pages:
- `/firewall/rules` → rules UI (tabs: Floating/WAN/LAN)
- `/firewall/nat` → NAT UI
- `/firewall/aliases`, `/firewall/schedules`, `/firewall/traffic-shaper`, `/firewall/virtual-ips`

JSON API endpoints (CRUD):
- Rules:
  - `GET|POST /firewall/api/rules/floating`
  - `PUT|DELETE /firewall/api/rules/floating/<rule_id>`
  - `GET|POST /firewall/api/rules/wan`
  - `PUT|DELETE /firewall/api/rules/wan/<rule_id>`
  - `GET|POST /firewall/api/rules/lan`
  - `PUT|DELETE /firewall/api/rules/lan/<rule_id>`
- NAT:
  - `GET|POST /firewall/api/nat/pf` (port forwards)
  - `PUT|DELETE /firewall/api/nat/pf/<rule_id>`
  - `GET|POST /firewall/api/nat/1to1`
  - `PUT|DELETE /firewall/api/nat/1to1/<rule_id>`
  - `GET|POST /firewall/api/nat/outbound`
  - `PUT|DELETE /firewall/api/nat/outbound/<rule_id>`
  - `GET|POST /firewall/api/nat/npt`
  - `PUT|DELETE /firewall/api/nat/npt/<rule_id>`
- Aliases:
  - `GET|POST /firewall/api/aliases`
  - `PUT|DELETE /firewall/api/aliases/<alias_id>`

### Services (prefix: `/services`)
Primarily template-driven pages. A few pages store temporary edits in the **Flask session** (not in SQLite yet), such as:
- DNS Resolver host/domain overrides and access lists
- Dynamic DNS clients and “check IP” services

### VPN (prefix: `/vpn`)
UI pages:
- `/vpn/openvpn`
- `/vpn/ipsec`
- `/vpn/l2tp`

> Note: the VPN blueprint imports several missing backend modules (see below). The route handlers reference tables like `openvpn_servers`, `openvpn_clients`, IPsec tunnels, PSKs, etc.

### Status (prefix: `/status`) and Diagnostics (prefix: `/diagnostics`)
Template-only pages that resemble an appliance UI.

---

## Persistence

### 1) SQLite (`data.db`)
The app uses SQLite for users and several configuration categories. `app/database.py` creates (if missing) these tables:

- **users** — local users
- **groups** — user groups
- **user_groups** — many-to-many user↔group links

Advanced settings:
- **advanced_admin_access**
- **advanced_firewall_nat**
- **advanced_network**
- **advanced_miscellaneous**
- **advanced_system_tunables**

Firewall/NAT:
- **nat_pf** — port forward rules
- **nat_1to1** — 1:1 NAT mappings
- **nat_outbound** — outbound NAT rules
- **nat_npt** — IPv6 NPt rules
- **firewall_rules_floating**
- **firewall_rules_wan**
- **firewall_rules_lan**
- **firewall_aliases**

> The shipped `data.db` may not include every table until the app runs `init_db()`.

### 2) JSON config (`config.json`)
System → General Setup reads/writes `config.json` in the project root.

---

## Included scripts

Located under `scripts/`:

- `list_wizard_tables.py` / `drop_extra_wizard_tables.py`
  - Look for and delete wizard-related tables in `data.db`.
- `inspect_psks.py` / `inspect_ipsec_adv_settings.py`
  - Inspect certain IPsec-related tables (expected by the VPN subsystem).
- `smoke_l2tp_config_db.py` / `smoke_l2tp_users_db.py`
  - Smoke tests for L2TP config/users persistence.

> These scripts reference modules like `app.l2configdb` and `app.l2users` which are **not present** in this repo (see next section).

---

## Known gaps / issues

### Missing backend modules referenced by the app
`app/__init__.py` and `routes/vpn.py` import modules that are **not included** as `.py` sources in this repository, for example:
- `app.vpndb`
- `app.vpn_servers_db`
- `app.cscdb`
- `app.wizardsdb`
- `app.tunnelsdb`
- `app.mobclientsdb`
- `app.pskdb`
- `app.advs`
- `app.l2configdb`
- `app.l2users`

Because of this, **running the app as-is may fail at import time**, especially around VPN initialization and routes.

You’ll likely want to either:
1. Add/restore those missing modules, or
2. Temporarily remove/comment their imports and any routes that depend on them.

### Security / production readiness
This is clearly a prototype/demo UI:
- Plain-text passwords in SQLite
- Hard-coded Flask `secret_key`
- Debug mode enabled in `run.py`
- No global login-required guard on most routes

Do not expose this app to untrusted networks without hardening.

---

## Development notes / suggested improvements
- Add `requirements.txt` (or `pyproject.toml`) to pin dependencies.
- Hash passwords (e.g., `werkzeug.security.generate_password_hash()`).
- Add an `@login_required` decorator / middleware for protected pages.
- Move secret key and other settings into environment variables.
- Implement persistence for session-only sections (DNS resolver, Dynamic DNS, etc.).
- Restore/implement the missing VPN-related modules so `/vpn/*` routes work.

---

## License
No license file is included. If you intend to redistribute this project, add a LICENSE file and clarify usage terms.


## Appendix: SQLite schema created by `app/database.py`

### `users`

Columns: `id`, `username`, `password`, `full_name`, `status`, `profile_picture`, `email`, `created_at`

### `groups`

Columns: `id`, `name`, `description`

### `user_groups`

Columns: `user_id`, `group_id`

### `advanced_admin_access`

Columns: `id`, `protocol`, `ssl_cert`, `tcp_port`, `max_processes`, `webgui_redirect`, `ocsp_stapling`, `webgui_autocomplete`, `gui_login_messages`, `roaming`, `hsts`, `anti_lockout`, `dns_rebind`, `alternate_hostnames`, `http_referer`, `browser_tab_text`, `enable_ssh`, `ssh_key_only`, `ssh_agent_forwarding`, `ssh_port`, `threshold`, `blocktime`, `detection_time`, `pass_list`, `serial_terminal`, `serial_speed`, `primary_console`, `console_menu`

### `advanced_firewall_nat`

Columns: `id`, `ip_fragment`, `ip_random`, `firewall_optimization`, `disable_scrub`, `adaptive_start`, `adaptive_end`, `firewall_max_states`, `firewall_max_table`, `firewall_max_fragment`, `vpn_ip_fragment`, `ip_fragment_reassemble`, `enable_mss`, `maximum_mss`, `disable_firewall`, `firewall_state_policy`, `disable_static_policy`, `static_route_filtering`, `disable_auto_added_vpn`, `disable_reply_to`, `disable_negate_rules`, `allow_apipa`, `aliases_hostnames_interval`, `check_certificate_aliases_urls`, `update_frequency`, `nat_reflection_mode`, `reflection_timeout`, `enable_nat_reflection`, `enable_automatic_outbound`, `tftp_proxy_wan`, `tftp_proxy_lan`, `tcp_first`, `tcp_opening`, `tcp_established`, `tcp_closing`, `tcp_fin_wait`, `tcp_closed`, `tcp_tsdiff`, `sctp_first`, `sctp_opening`, `sctp_established`, `sctp_closing`, `sctp_closed`, `udp_first`, `udp_single`, `udp_multiple`, `icmp_first`, `icmp_error`, `other_first`, `other_single`, `other_multiple`

### `advanced_network`

Columns: `id`, `server_backend`, `ignore_deprecation`, `radvd_debug`, `dhcp6_debug`, `do_not_allow_release`, `dhcpv6_duid`, `raw_duid`, `allow_ipv6`, `ipv6_over_ipv4_tunneling`, `ipv4_address_tunnel_peer`, `prefer_ipv4_over_ipv6`, `ipv6_dns_entry`, `hardware_checksum_offloading`, `hardware_tcp_segmentation`, `hardware_large_receive`, `hn_altq_support`, `arp_handling`, `reset_all_states`, `if_pppoe_kernel`

### `advanced_miscellaneous`

Columns: `id`, `proxy_url`, `proxy_port`, `proxy_username`, `proxy_password`, `load_balancing`, `sticky_timeout`, `powerd`, `ac_power`, `battery_power`, `unknown_power`, `cryptographic_hardware`, `thermal_sensors`, `kernel_pti`, `mds_mode`, `schedule_states`, `state_killing_on_gateway_recovery`, `dont_kill_policy_routing`, `state_killing_on_gateway_failure`, `skip_rules_gateway_down`, `static_routes`, `memory_limit`, `use_ram_disks`, `tmp_ram_disk`, `var_ram_disk`, `rrd_data_backup`, `dhcp_leases_backup`, `log_directory_backup`, `captive_portal_data_backup`, `hard_disk_standby_time`, `smart_shield_device_id`

### `advanced_system_tunables`

Columns: `id`, `name`, `description`, `value`

### `nat_pf`

Columns: `id`, `disabled`, `interface`, `protocol`, `src_type`, `src_address`, `dst_type`, `dst_address`, `redirect_ip`, `description`, `nat_reflection`

### `nat_1to1`

Columns: `id`, `disabled`, `interface`, `external_address`, `internal_address`, `destination_address`, `description`

### `nat_outbound`

Columns: `id`, `disabled`, `interface`, `src_address`, `dst_address`, `nat_address`, `static_port`, `description`

### `nat_npt`

Columns: `id`, `disabled`, `interface`, `src_not`, `src_prefix`, `src_prefix_length`, `dst_not`, `dst_type`, `dst_prefix`, `dst_prefix_length`, `description`

### `firewall_rules_floating`

Columns: `id`, `disabled`, `interface`, `protocol`, `source`, `source_port`, `destination`, `dest_port`, `gateway`, `queue`, `schedule`, `description`, `rule_order`

### `firewall_rules_wan`

Columns: `id`, `action`, `disabled`, `protocol`, `source`, `destination`, `description`, `rule_order`

### `firewall_rules_lan`

Columns: `id`, `disabled`, `interface`, `protocol`, `source`, `destination`, `description`, `rule_order`

### `firewall_aliases`

Columns: `id`, `name`, `type`, `alias_values`, `description`



## Appendix: Route index (generated)

### auth

- `GET` `/`
- `GET,POST` `/login`
- `GET` `/logout`

### diagnostics

- `GET` `/diagnostics/`
- `GET` `/diagnostics/arp-table`
- `GET` `/diagnostics/authentication`
- `GET` `/diagnostics/backup-restore`
- `GET` `/diagnostics/command-prompt`
- `GET` `/diagnostics/dns-lookup`
- `GET` `/diagnostics/edit-file`
- `GET` `/diagnostics/factory-defaults`
- `GET` `/diagnostics/halt-system`
- `GET` `/diagnostics/limiter-info`
- `GET` `/diagnostics/ndp-table`
- `GET` `/diagnostics/packet-capture`
- `GET` `/diagnostics/pfinfo`
- `GET` `/diagnostics/pftop`
- `GET` `/diagnostics/ping`
- `GET` `/diagnostics/reboot`
- `GET` `/diagnostics/routes`
- `GET` `/diagnostics/smart-status`
- `GET` `/diagnostics/sockets`
- `GET` `/diagnostics/states`
- `GET` `/diagnostics/status-summary`
- `GET` `/diagnostics/system-activity`
- `GET` `/diagnostics/tables`
- `GET` `/diagnostics/test-port`
- `GET` `/diagnostics/tunnels`

### dns

- `GET` `/services/dns-resolver`

### firewall

- `GET` `/firewall/`
- `GET` `/firewall/aliases`
- `GET` `/firewall/aliases/<tab>`
- `GET` `/firewall/api/aliases`
- `POST` `/firewall/api/aliases`
- `PUT` `/firewall/api/aliases/<int:alias_id>`
- `DELETE` `/firewall/api/aliases/<int:alias_id>`
- `GET` `/firewall/api/nat/1to1`
- `POST` `/firewall/api/nat/1to1`
- `PUT` `/firewall/api/nat/1to1/<int:rule_id>`
- `DELETE` `/firewall/api/nat/1to1/<int:rule_id>`
- `POST` `/firewall/api/nat/npt`
- `GET` `/firewall/api/nat/npt`
- `PUT` `/firewall/api/nat/npt/<int:rule_id>`
- `DELETE` `/firewall/api/nat/npt/<int:rule_id>`
- `POST` `/firewall/api/nat/outbound`
- `GET` `/firewall/api/nat/outbound`
- `PUT` `/firewall/api/nat/outbound/<int:rule_id>`
- `DELETE` `/firewall/api/nat/outbound/<int:rule_id>`
- `GET` `/firewall/api/nat/pf`
- `POST` `/firewall/api/nat/pf`
- `PUT` `/firewall/api/nat/pf/<int:rule_id>`
- `DELETE` `/firewall/api/nat/pf/<int:rule_id>`
- `GET` `/firewall/api/rules/floating`
- `POST` `/firewall/api/rules/floating`
- `PUT` `/firewall/api/rules/floating/<int:rule_id>`
- `DELETE` `/firewall/api/rules/floating/<int:rule_id>`
- `GET` `/firewall/api/rules/lan`
- `POST` `/firewall/api/rules/lan`
- `PUT` `/firewall/api/rules/lan/<int:rule_id>`
- `DELETE` `/firewall/api/rules/lan/<int:rule_id>`
- `GET` `/firewall/api/rules/wan`
- `POST` `/firewall/api/rules/wan`
- `PUT` `/firewall/api/rules/wan/<int:rule_id>`
- `DELETE` `/firewall/api/rules/wan/<int:rule_id>`
- `GET` `/firewall/home`
- `GET` `/firewall/nat`
- `GET` `/firewall/rules`
- `GET` `/firewall/schedules`
- `GET` `/firewall/traffic-shaper`
- `GET` `/firewall/virtual-ips`

### interfaces

- `GET` `/interfaces/`
- `GET` `/interfaces/assignments`
- `GET` `/interfaces/interfaces`
- `GET` `/interfaces/lan`
- `GET` `/interfaces/wan`

### routing

- `GET` `/system/routing/`
- `GET` `/system/routing/gateway/edit`
- `GET` `/system/routing/gateway/edit/<int:index>`
- `POST` `/system/routing/group/delete/<int:index>`
- `GET` `/system/routing/group/edit`
- `GET` `/system/routing/group/edit/<int:index>`
- `GET` `/system/routing/groups`
- `POST` `/system/routing/save`
- `GET` `/system/routing/static`
- `POST` `/system/routing/static/delete/<int:index>`
- `GET` `/system/routing/static/edit`
- `GET` `/system/routing/static/edit/<int:index>`

### services

- `GET` `/services/`
- `GET` `/services/auto-config-backup`
- `GET` `/services/captive-portal`
- `GET` `/services/dhcp-relay`
- `GET` `/services/dhcp-server`
- `GET` `/services/dhcp-server-lan`
- `GET` `/services/dhcp-server-lan/static-mapping`
- `GET` `/services/dhcp-server/static-mapping`
- `GET` `/services/dhcpv6-relay`
- `GET` `/services/dhcpv6-server`
- `GET,POST` `/services/dns-domain-edit`
- `GET` `/services/dns-forwarder`
- `GET,POST` `/services/dns-forwarder/edit-domain-override`
- `GET,POST` `/services/dns-forwarder/edit-host-override`
- `GET,POST` `/services/dns-host-edit`
- `GET` `/services/dns-resolver`
- `GET` `/services/dns-resolver/access-lists`
- `GET,POST` `/services/dns-resolver/access-lists/edit`
- `GET,POST` `/services/dns-resolver/advanced`
- `GET,POST` `/services/dns-resolver/edit-domain`
- `GET,POST` `/services/dns-resolver/edit-host`
- `GET` `/services/dynamic-dns`
- `GET` `/services/dynamic-dns/checkip`
- `GET,POST` `/services/dynamic-dns/checkip/edit`
- `GET,POST` `/services/dynamic-dns/edit`
- `GET` `/services/dynamic-dns/rfc2136`
- `GET,POST` `/services/dynamic-dns/rfc2136/edit`
- `GET` `/services/igmp-proxy`
- `GET` `/services/ntp`
- `GET` `/services/openvpn-server`
- `GET` `/services/router-advertisement`
- `GET` `/services/services`
- `GET` `/services/snmp`
- `GET` `/services/upnp-igd-pcp`
- `GET` `/services/wake-on-lan`

### status

- `GET` `/status/`
- `GET` `/status/carp-failover`
- `GET` `/status/dhcp-leases`
- `GET` `/status/dhcpv6-leases`
- `GET` `/status/filter-reload`
- `GET` `/status/gateways`
- `GET` `/status/monitoring`
- `GET` `/status/queues`
- `GET` `/status/system-logs`
- `GET` `/status/traffic-graph`

### system

- `GET` `/system/`
- `GET` `/system/about`
- `GET` `/system/add_ca`
- `GET` `/system/add_certificate`
- `GET,POST` `/system/admin-access`
- `GET` `/system/advanced`
- `GET,POST` `/system/advanced/firewall-nat`
- `GET,POST` `/system/advanced/miscellaneous`
- `GET,POST` `/system/advanced/network`
- `GET` `/system/advanced/system-tunables`
- `POST` `/system/advanced/system-tunables/delete/<int:index>`
- `GET,POST` `/system/advanced/system-tunables/edit`
- `GET,POST` `/system/advanced/system-tunables/edit/<int:index>`
- `POST` `/system/advanced/system-tunables/save`
- `GET` `/system/bug`
- `GET` `/system/certificates`
- `GET,POST` `/system/copyright`
- `GET` `/system/dashboard`
- `GET` `/system/docs`
- `GET` `/system/forum`
- `GET` `/system/freebsd`
- `GET,POST` `/system/general-setup`
- `GET` `/system/help`
- `GET` `/system/high-availability`
- `GET` `/system/logout`
- `GET,POST` `/system/notifications`
- `GET` `/system/package-manager`
- `GET` `/system/paid-support`
- `GET` `/system/smart-shield-book`
- `GET` `/system/register`
- `GET` `/system/setup-wizard`
- `GET` `/system/setup-wizard/step/<int:step>`
- `GET` `/system/survey`
- `GET,POST` `/system/update`
- `GET` `/system/upgrade`

### users

- `GET` `/system/user-manager/`
- `POST` `/system/user-manager/add`
- `POST` `/system/user-manager/add-group`
- `POST` `/system/user-manager/change-password/<int:user_id>`
- `POST` `/system/user-manager/delete/<int:user_id>`
- `POST` `/system/user-manager/edit/<int:user_id>`

### vpn

- `GET` `/vpn/`
- `GET` `/vpn/ipsec`
- `POST` `/vpn/ipsec/advanced-settings/save`
- `POST` `/vpn/ipsec/mobile-clients/save`
- `POST` `/vpn/ipsec/psk/add`
- `POST` `/vpn/ipsec/psk/delete/<int:psk_id>`
- `POST` `/vpn/ipsec/psk/edit/<int:psk_id>`
- `POST` `/vpn/ipsec/tunnels/add`
- `POST` `/vpn/ipsec/tunnels/delete/<int:tunnel_id>`
- `POST` `/vpn/ipsec/tunnels/edit/<int:tunnel_id>`
- `GET,POST` `/vpn/l2tp`
- `POST` `/vpn/l2tp/users/add`
- `POST` `/vpn/l2tp/users/delete/<int:user_id>`
- `POST` `/vpn/l2tp/users/edit/<int:user_id>`
- `GET` `/vpn/openvpn`
- `GET,POST` `/vpn/openvpn/add`
- `GET,POST` `/vpn/openvpn/client/add`
- `POST` `/vpn/openvpn/client/delete/<int:client_id>`
- `GET,POST` `/vpn/openvpn/client/edit/<int:client_id>`
- `POST` `/vpn/openvpn/csc/add`
- `POST` `/vpn/openvpn/csc/delete/<int:override_id>`
- `POST` `/vpn/openvpn/csc/edit/<int:override_id>`
- `POST` `/vpn/openvpn/delete/<int:server_id>`
- `GET,POST` `/vpn/openvpn/edit/<int:server_id>`
- `POST` `/vpn/openvpn/wizard/ca/add`

