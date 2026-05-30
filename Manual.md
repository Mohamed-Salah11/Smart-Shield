# Smart Shield — User Manual

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Installation](#2-installation)
3. [First-Run Setup Wizard](#3-first-run-setup-wizard)
4. [CLI Reference — smartshieldctl](#4-cli-reference--smartshieldctl)
5. [Console Recovery Menu](#5-console-recovery-menu)
6. [Web GUI Reference](#6-web-gui-reference)
   - 6.1 [Command Center (Dashboard)](#61-command-center-dashboard)
   - 6.2 [Network — Interfaces and Routing](#62-network--interfaces-and-routing)
   - 6.3 [Firewall](#63-firewall)
   - 6.4 [Network Services](#64-network-services)
   - 6.5 [VPN Tunnels](#65-vpn-tunnels)
   - 6.6 [Threat Detection — IDS/IPS](#66-threat-detection--idsips)
   - 6.7 [Content Policy (DNS / Web / App)](#67-content-policy-dns--web--app)
   - 6.8 [Captive Portal](#68-captive-portal)
   - 6.9 [SIEM and Event Log](#69-siem-and-event-log)
   - 6.10 [Monitoring](#610-monitoring)
   - 6.11 [Users and Groups](#611-users-and-groups)
   - 6.12 [Certificates](#612-certificates)
   - 6.13 [Backup and Restore](#613-backup-and-restore)
   - 6.14 [AI Assistant](#614-ai-assistant)
   - 6.15 [System Settings](#615-system-settings)
   - 6.16 [Smart Shield SOC Portal](#616-smart-shield-soc-portal)
   - 6.17 [Appliance Console (Hardened Terminal)](#617-appliance-console-hardened-terminal)
7. [Environment Variables Reference](#7-environment-variables-reference)
8. [Log Files Reference](#8-log-files-reference)
9. [Directory Structure Reference](#9-directory-structure-reference)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. Introduction

Smart Shield is a web-managed network security appliance for FreeBSD. A single
HTTPS interface and an operator CLI (`smartshieldctl`) cover the full lifecycle
of a security gateway: provisioning, day-to-day firewall and policy
management, real-time monitoring, captive portal authentication, and SOC
incident handling through a separate analyst portal.

### Audience

- **Network administrators** deploying Smart Shield as an edge gateway.
- **Security practitioners** using Smart Shield as a research / testing platform.
- **Educators** running Smart Shield in a lab or classroom network.
- **SOC analysts** (L1 / L2 / L3) using the dedicated SOC portal — their work is kept separate from the firewall log so analyst events never pollute the appliance dashboard.

### Conventions

| Convention | Meaning |
|---|---|
| `monospace` | Commands to type exactly as shown |
| `<placeholder>` | Replace with the actual value for your environment |
| `[optional]` | Optional argument |
| *(FreeBSD only)* | Feature requires a FreeBSD host; unavailable in development mode |

---

## 2. Installation

### 2.1 System Requirements

| Component | Minimum |
|---|---|
| Operating System | FreeBSD 13.0 or newer |
| Python | 3.10 or newer |
| RAM | 512 MB (1 GB recommended) |
| Disk | 4 GB available (SSD recommended) |
| Network interfaces | 2 physical NICs (WAN + LAN) |

Smart Shield runs in **development mode** on Linux, macOS, and Windows for UI
work and dry-run policy testing. Network enforcement requires FreeBSD.

### 2.2 Running the Installer

Clone to the target FreeBSD host and run the installer as root:

```sh
git clone https://github.com/Mohamed-Salah11/Smart-Shield.git /usr/local/share/smartshield
cd /usr/local/share/smartshield
sh bsd/install.sh
```

What the installer does:

1. Installs FreeBSD packages: `nginx python3 suricata unbound isc-dhcp44-server kea openvpn strongswan mpd5 mrtg miniupnpd igmpproxy ddclient sudo git sqlite3 ca_root_nss bind-tools tcpdump nano`.
2. Creates `/usr/local/share/smartshield/.venv` and installs `requirements.txt`.
3. Creates every required runtime directory (see §9).
4. Generates a random `SECRET_KEY` (64 hex chars) and `SMARTSHIELD_MASTER_KEY` (AES-256, base64) and writes them to `/usr/local/etc/smartshield/smartshield.env` with mode `0600`, owner `root:wheel`.
5. Installs the `smart_shield` rc.d unit and enables it with `sysrc`. The unit **exports** `SMARTSHIELD_ENV_FILE` so the Flask app and every Gunicorn worker read the same env file regardless of working directory.
6. Generates a self-signed TLS cert at `/usr/local/etc/smartshield/ssl/cert.pem`.
7. Writes the nginx reverse proxy + WebSocket upgrade configuration and starts nginx.
8. Installs the MRTG cron job (`*/5 * * * *`).
9. Installs `smartshieldctl` to `/usr/local/sbin/smartshieldctl` and the recovery menu to `/usr/local/sbin/smart_shield_console`.
10. Runs two MRTG passes to seed graph files.
11. Starts the Smart Shield service.

### 2.3 Verifying the Installation

```sh
smartshieldctl status
sockstat -4 -l | grep 443
smartshieldctl health
```

### 2.4 Environment File

The environment file lives at `/usr/local/etc/smartshield/smartshield.env`.
Edit it to configure optional features (see §7):

```sh
nano /usr/local/etc/smartshield/smartshield.env
smartshieldctl restart
```

If you run the app outside the default path (e.g. local development), set
`SMARTSHIELD_ENV_FILE` to your env file:

```sh
SMARTSHIELD_ENV_FILE=/srv/smart-shield/dev.env .venv/bin/python wsgi.py
```

In production, `app/config.py` fails fast (raises `RuntimeError`) when
`APP_ENV=production` is set without a `SECRET_KEY` — this is intentional, so
an incomplete env file never silently boots with an insecure default.

---

## 3. First-Run Setup Wizard

On the first visit to `https://<appliance-IP>`, Smart Shield redirects to the
four-step setup wizard.

### 3.1 Step 1 — Interface Assignment

Select which physical NIC is **WAN** and which is **LAN** from the detected
interfaces (`em0`, `em1`, etc.). Click **Save & Continue**.

### 3.2 Step 2 — IP Configuration

- **LAN**: enter a CIDR (e.g. `192.168.1.1/24`). The DHCP pool is derived automatically.
- **WAN**: choose DHCP, Static, or PPPoE; enter the matching credentials.

Click **Save & Continue**.

### 3.3 Step 3 — Admin Password

Set the `admin` superuser password (8 chars minimum). Click **Set Password & Continue**.

### 3.4 Step 4 — Apply and Finish

Review the summary, click **Apply**. Smart Shield:

- Writes interface configuration to `rc.conf`.
- Generates and loads `pf.conf`.
- Starts DHCP and DNS.
- Generates the initial MRTG configuration.

You are then redirected to the Command Center at `https://<LAN-IP>`.

---

## 4. CLI Reference — smartshieldctl

`smartshieldctl` is installed at `/usr/local/sbin/smartshieldctl`. All commands
require root unless noted.

### 4.1 Service Control

| Command | Description |
|---|---|
| `smartshieldctl start` | Start the web service |
| `smartshieldctl stop` | Stop the web service |
| `smartshieldctl restart` | Restart the web service |
| `smartshieldctl status` | Show service state (PID, uptime) |
| `smartshieldctl enable` | Enable at boot |
| `smartshieldctl disable` | Prevent boot start |
| `smartshieldctl health` | HTTP health probe |

### 4.2 Interface Management *(FreeBSD only)*

| Command | Description |
|---|---|
| `smartshieldctl list-nics` | List physical NICs with link state |
| `smartshieldctl assign <LAN\|WAN> <port>` | Assign a NIC to the LAN or WAN role |
| `smartshieldctl iface-show [LAN\|WAN]` | Show configuration and live IP |
| `smartshieldctl iface-set <LAN\|WAN> dhcp [--apply]` | Configure DHCP mode |
| `smartshieldctl iface-set <LAN\|WAN> static <CIDR> [gateway] [--apply]` | Configure static |

### 4.3 Diagnostics

| Command | Description |
|---|---|
| `smartshieldctl ping [host] [count]` | ICMP ping |
| `smartshieldctl pf-status` | PF rule count, states, NAT entries |
| `smartshieldctl apply-pf` | Regenerate + reload `pf.conf` |
| `smartshieldctl preflight` | Check directories, binaries, kernel features |
| `smartshieldctl vpn-status` | OpenVPN / IPsec / L2TP daemon state |
| `smartshieldctl dhcp-status` | ISC DHCPd status + active lease count |
| `smartshieldctl dns-status` | Unbound status |
| `smartshieldctl sysinfo` | CPU, memory, disk, uptime |

### 4.4 Log Access

| Command | Description |
|---|---|
| `smartshieldctl logs [N]` | Tail the application log (default 100 lines) |
| `smartshieldctl audit [N]` | Tail the SIEM audit log |
| `smartshieldctl access [N]` | Tail the nginx access log |

### 4.5 Administration

| Command | Description |
|---|---|
| `smartshieldctl passwd [username]` | Reset a user password |
| `smartshieldctl factory-reset` | Wipe all configuration (irreversible) |
| `smartshieldctl ssh <enable\|disable\|status>` | Control sshd |
| `smartshieldctl shell` | Drop to a root shell |
| `smartshieldctl menu` | Launch the console recovery menu |

---

## 5. Console Recovery Menu

`smart_shield_console` provides emergency access over serial or out-of-band SSH.

```sh
smartshieldctl menu
# or directly:
/usr/local/sbin/smart_shield_console
```

| Option | Action |
|---|---|
| `1` | Service status |
| `2` | Start the service |
| `3` | Stop the service |
| `4` | Restart the service |
| `5` | View the last 50 lines of the application log |
| `6` | View the last 50 lines of the audit log |
| `7` | Reset the admin password interactively |
| `8` | Reload PF rules from the database |
| `9` | Run the first-boot setup sequence again (re-creates missing directories) |
| `0` | Open a root shell |
| `q` | Quit |

---

## 6. Web GUI Reference

The GUI is at `https://<LAN-IP>`. The left sidebar navigates every section.

---

### 6.1 Command Center (Dashboard)

**URL:** `/system/dashboard`

The Command Center is the firewall admin landing page:

- **KPI strip** — user / group / rule / NAT / alias counts.
- **Service health** — colour-coded indicators for PF, DHCP, Unbound, OpenVPN, IPsec, Suricata, nginx, SIEM, MRTG.
- **Interface statistics** — live RX/TX bytes and packets.
- **Recent events** — last entries from the appliance audit log. SOC analyst events (`details.soc_origin = true`) are excluded by default — they appear only in the SOC portal.

The dashboard polls `/status/api/logs` for live updates. The endpoint defaults
to hiding SOC events; a superuser can fetch them with `?hide_soc=0`.

---

### 6.2 Network — Interfaces and Routing

#### Interface Assignments (`/interfaces/assignments`)

Map physical NIC names (`em0`, `em1`, …) to the WAN and LAN logical roles.

#### LAN Interface (`/interfaces/lan`)

- **IP Mode:** Static or DHCP.
- **IP Address / Prefix Length:** `192.168.1.1 / 24`.
- **MTU:** Default 1500.
- **Description:** Free-text label.

#### WAN Interface (`/interfaces/wan`)

- **IP Mode:** DHCP / Static / PPPoE.
- **Static settings:** IP / prefix, gateway, DNS.
- **PPPoE settings:** username, password, service name, dial-on-demand.

#### VLANs

Add 802.1Q tags on a parent interface (`em0.10`). Each VLAN is then assignable
like a physical NIC.

#### Routing (`/routing/`)

- **Gateways** — upstream router IPs, ICMP-monitored for loss / latency.
- **Static Routes** — `<destination CIDR> via <gateway>`.
- **Gateway Groups** — load balancing or failover for use in firewall rules.

---

### 6.3 Firewall

#### 6.3.1 Rules (`/firewall/rules`)

Three tabs: **Floating**, **WAN**, **LAN**.

- **Floating rules** match traffic on any interface and take effect before interface-specific rules.
- **WAN rules** match inbound traffic on WAN.
- **LAN rules** match traffic originating on LAN.

Add a rule:

1. Click **Add rule**.
2. Set **Action** (`pass`, `block`, `reject`), **Protocol**, **Source**, **Destination**.
3. Optionally set ports, schedule, queue.
4. Add a description; **Save**.

Rules are evaluated top-to-bottom (`quick` semantics). Drag to reorder.

**Apply Changes** runs: `generate → pfctl -nf → known-good backup → atomic write → pfctl -f → roll back on failure`. **Rollback** restores the last good `pf.conf`. **Preview** shows the generated text without applying.

#### 6.3.2 NAT (`/firewall/nat`)

- **Port Forwarding (rdr)** — external port → internal host.
- **1:1 NAT** — one external IP ↔ one internal IP.
- **Outbound NAT** — control masquerade per-source.
- **NPt** — translate IPv6 prefixes.

#### 6.3.3 Aliases (`/firewall/aliases`)

| Type | Example |
|---|---|
| Host | `192.168.1.100`, `10.0.0.5` |
| Network | `192.168.10.0/24`, `172.16.0.0/12` |
| Port | `80`, `443`, `8080:8090` |
| URL | A remote text file fetched periodically |

#### 6.3.4 Schedules (`/firewall/schedules`)

Time windows attachable to firewall rules.

#### 6.3.5 Traffic Shaper / Limiters (`/firewall/traffic-shaper`)

- **ALTQ** — bandwidth class scheduling.
- **dummynet** — per-flow rate / delay limiters referenced from rules' In/Out pipe fields.

#### 6.3.6 Virtual IPs / CARP (`/firewall/virtual-ips`)

Add IP aliases or CARP virtual IPs (shared across an HA pair).

#### 6.3.7 Apply, Preview, and Rollback

| Action | Effect |
|---|---|
| Preview | Show the generated `pf.conf` |
| Apply Changes | Validate + load into the running kernel |
| Rollback | Restore the most recent good `pf.conf` |

---

### 6.4 Network Services

#### 6.4.1 DHCP Server — IPv4 (`/services/dhcp-server`)

Standard ISC DHCPd configuration: pool range, lease times, gateway, DNS push,
optional domain. Static leases bind MAC → IP. Configs are validated with
`dhcpd -t` before reload.

#### 6.4.2 DHCPv6 Server (`/services/dhcpv6-server`)

Kea-based IPv6 — prefix pool, lifetimes, RA M-bit / O-bit flags.

#### 6.4.3 DNS Resolver (`/services/dns-resolver`)

Unbound configuration:

- **Forwarding** — empty for recursion, or upstream DNS list.
- **DNS-over-TLS** — encrypt upstream queries.
- **DNSSEC** — validate signed responses.
- **Host overrides** — local A/AAAA records.
- **Domain overrides** — forward specific zones elsewhere.
- **Query logging** — enables the DNS SIEM collector tailing `/var/log/unbound/query.log`.

Apply runs `apply_unbound()` — validate, atomic write, reload, rollback on failure.

#### 6.4.4 Dynamic DNS (`/services/dynamic-dns`)

ddclient credentials per provider, with update interval.

#### 6.4.5 NTP (`/services/ntp`)

Upstream NTP server list.

#### 6.4.6 SNMP (`/services/snmp`)

bsnmpd community / port / allow-list.

#### 6.4.7 UPnP / PCP (`/services/upnp-igd-pcp`)

miniupnpd interface restrictions and optional external IP override.

#### 6.4.8 IGMP Proxy (`/services/igmp-proxy`)

Upstream + downstream interface mapping.

#### 6.4.9 Wake on LAN (`/services/wake-on-lan`)

Saved MAC + broadcast IP entries with a one-click **Send**.

---

### 6.5 VPN Tunnels

#### 6.5.1 OpenVPN (`/vpn/openvpn`)

Server, client, CSO, and wizard tabs. The certificate manager backs the
required PKI.

#### 6.5.2 IPsec / IKEv2 (`/vpn/ipsec`)

Phase 1 + Phase 2 editor, mobile clients (road-warrior), PSK manager,
advanced (DPD, fragmentation, logging) tab.

#### 6.5.3 L2TP / IPsec (`/vpn/l2tp`)

mpd5-based L2TP — server address, client pool, local or RADIUS auth, users.

---

### 6.6 Threat Detection — IDS/IPS

#### 6.6.1 Enabling Suricata

On `/ids/` click **Enable**. Smart Shield generates `suricata.yaml`, validates
with `suricata -T`, writes `suricata_enable=YES` to `rc.conf`, and starts the
service. The DB only marks Suricata enabled after the service has actually
come up.

#### 6.6.2 IDS vs IPS Mode

- **IDS** — Suricata reads pcap from a BPF socket.
- **IPS** — Suricata is inserted inline via `netmap(4)`. Requires a netmap-compatible NIC driver (`em`, `igb`, `ixgbe`, `ixl`, `re`, `vtnet`, `vmx`, `bnxt`, `ix`). The startup path automatically falls back to IDS mode if netmap fails.

#### 6.6.3 Managing Rulesets

The **Rulesets** tab lists installed sources (`et/open`, custom URLs).
**Update Rules** runs `suricata-update`.

#### 6.6.4 Threat Intelligence Feeds

Enter an abuse.ch Personal Auth-Key and toggle dry-run. When live, Smart
Shield fetches recent IOCs every 4 h and replaces the `ss_threat_intel` PF
table via `pfctl -t ss_threat_intel -T replace`.

#### 6.6.5 Alert Viewer

The **Status & Alerts** tab parses `/var/log/suricata/eve.json` directly.
Filter by severity and time window.

---

### 6.7 Content Policy (DNS / Web / App)

Three filters share a single deduplication pass before Unbound writes
`unbound.conf`. When the same domain appears in two filters, the higher
precedence wins:

```
allow (whitelist-only)  >  SOC emergency block  >  App filter  >  Web filter  >  DNS manual
```

Implementation lives in [app/services/content_policy.py](app/services/content_policy.py)
(`DomainPolicy` dataclass + `build_domain_policy_map()` + `emit_unbound_policy_zones()`).
Exactly one `local-zone` + `local-data` record is emitted per blocked
domain, which means `unbound-checkconf` never trips on duplicate rules.

#### 6.7.1 DNS Filtering (`/filters/dns`)

Block / allow / redirect domains. Block rules redirect to the LAN IP so the
browser hits Smart Shield's block page; falls back to `always_nxdomain` when
no LAN IP is configured.

#### 6.7.2 Web Filtering (`/filters/web`)

Domain-level blocking organised around URL pattern / category. Full
URL-path blocking would require an HTTP proxy and is out of scope.

#### 6.7.3 Application Filtering (`/filters/app`)

Block by application signature — ports, protocol, and (optionally) domain
list. App-filter PF rules are now **scoped to LAN ingress** (`block in log
quick on $LAN_IFACE`) so the rule only affects downstream LAN clients and
never the WAN side or other interfaces. Admin bypass and device whitelist
PF tables (`<admin_bypass_clients>`, `<device_whitelist>`) take precedence.

---

### 6.8 Captive Portal

**URL:** `/services/captive-portal`

#### 6.8.1 Configuration

Enable, pick the LAN/VLAN, mode (soft / strict), session timeout, optional
per-session bandwidth limit, then **Save** + **Apply**.

#### 6.8.2 Soft vs Strict Mode

| Mode | Behaviour |
|---|---|
| **Soft** | Only HTTP (port 80) is redirected to the portal. HTTPS, DNS, DHCP, and other traffic pass without authentication |
| **Strict** | All traffic is blocked until login. DNS and DHCP are permitted pre-auth |

#### 6.8.3 HTTPS Block Page Limitation

HTTP sites can render Smart Shield's block page directly. **HTTPS sites may
show a browser certificate or connection warning** instead — this is normal
behaviour for any captive portal that does not perform TLS interception with
a trusted local CA. The block page itself now states this so end-users are
not confused.

#### 6.8.4 Vouchers

The **Vouchers** tab generates time-limited guest codes with optional
bandwidth caps. Distribute the code, guest enters it on the portal login.

---

### 6.9 SIEM and Event Log

**URL:** `/status/system-logs`

#### 6.9.1 Live Event Stream

The page polls `/status/api/logs` every few seconds and renders events
newest-first. SOC-origin events (`details.soc_origin = true`) are filtered
out by default — they belong in the SOC portal. A superuser can pass
`?hide_soc=0` if they need a merged view for incident review.

#### 6.9.2 Categories and Severity Levels

| Category | Events |
|---|---|
| `connection` | New LAN connections (PF), DHCP leases, DNS queries |
| `security` | Failed logins, brute-force, insecure protocol alerts, IDS floods |
| `ids` | Suricata IDS/IPS alerts |
| `session` | Admin login, logout, re-authentication |
| `system` | Config changes, firewall rule edits, PF reloads, service applies |
| `privileged` | Appliance Console session events and individual command audits |

| Severity | Meaning |
|---|---|
| `critical` | Suricata severity-1 |
| `high` | Brute-force, IDS flood, IPS inline block, insecure protocol; Suricata severity-2 |
| `medium` | Suricata severity-3; RDP, DB protocol connections |
| `low` | Suricata severity-4; low-risk connections |
| `info` | Normal connections, config changes, DHCP events |

#### 6.9.3 Filtering and Search

Category pills, severity pills, time range (Live, 1h, 6h, 24h, 7d), free-text
search across action / IP / hostname / username / details.

#### 6.9.4 Exporting Logs

**Export** downloads the filtered events as `smart-shield-siem-YYYY-MM-DD.json`.

---

### 6.10 Monitoring

#### 6.10.1 System Metrics (`/status/monitoring`)

Live interface counters; live CPU / memory / disk from the health monitor API.

#### 6.10.2 Live Bandwidth Graph (`/status/traffic-graph`)

Real-time chart of inbound/outbound bytes per interface, updated every 2s.

#### 6.10.3 Historical Traffic — MRTG (`/status/mrtg`)

MRTG runs every 5 minutes via cron. Pages: Daily, Weekly, Monthly, Yearly. A
status bar reports cron, graph directory, and lock file conditions.

#### 6.10.4 Service Health

`/status/api/health/full` returns the live state of every managed service plus
disk, memory, CPU.

---

### 6.11 Users and Groups

#### 6.11.1 Creating Users (`/users/`)

Username, password (≥8 chars), display name, optional superuser flag.

#### 6.11.2 Managing Groups (`/users/groups`)

Group name, members, page-level permissions per blueprint endpoint.

#### 6.11.3 Permissions

A user has access if they are a superuser **or** any group they belong to has
been granted that endpoint. Wildcards like `firewall.*` are supported.

---

### 6.12 Certificates

#### 6.12.1 Certificate Authorities (`/system/certificates`)

Add CA — common name, 2048 / 4096-bit key, validity period. Keys are stored
AES-256-GCM-encrypted at rest.

#### 6.12.2 Server / Client Certificates

Pick a CA, choose type (server / client), set CN + validity. Available to
OpenVPN configs and IPsec Phase 1 settings. The Certificates page warns when
a cert is within 30 days of expiry.

---

### 6.13 Backup and Restore

**URL:** `/diagnostics/backup-restore`

#### 6.13.1 Creating a Backup

Click **Create Backup**, optionally enter an AES-256-GCM passphrase (PBKDF2
key), **Download**.

#### 6.13.2 Restoring from a Backup

Choose a backup file, enter the passphrase if encrypted, **Restore**. The
schema version is validated before the DB is replaced.

#### 6.13.3 Config Version History

Every apply saves a snapshot. **Config History** lists per-service versions
with content view and one-click rollback.

---

### 6.14 AI Assistant

**URL:** `/chatbot/`

Powered by the Groq inference API. Enable by setting `GROQ_API_KEY` in the
env file or via Admin → Settings → SmartShield AI.

**Read-only tools** cover health, firewall, NAT, aliases, DHCP, tracked
devices, IDS alerts, content policy, VPN status, audit log.

**Write tools** (add firewall block, block / unblock domain) require explicit
confirmation — "yes" / "apply" / "go ahead" — before execution.

Example prompts:

```
"Show me the last 5 IDS alerts"
"What devices are connected to the LAN?"
"Block the domain malicious.example.com"
"Is Suricata running?"
```

---

### 6.15 System Settings

#### 6.15.1 General Setup (`/system/general-setup`)

Hostname, domain, timezone, theme, login message.

#### 6.15.2 Admin Access (`/system/admin-access`)

- **Brute-force protection** — failed-attempt threshold, lockout duration.
- **Whitelist IPs** — CIDR exemptions.
- **Console Options** — Password-protect Console Menu, **Enable web Appliance Console** (see §6.17).

#### 6.15.3 Advanced Settings (`/system/advanced`)

- **Firewall/NAT** — state-table tuning, MSS clamping, NAT-reflection.
- **Network** — IPv6, hardware checksum offload, ARP proxy, SLAAC.
- **Miscellaneous** — power management, thermal sensors, MTU discovery.
- **System Tunables** — arbitrary `sysctl` knobs applied at boot.

#### 6.15.4 Preflight Check (`/system/preflight`)

Validates the deployment: kernel features, daemon binaries, validator
binaries (`pfctl -nf`, `dhcpd -t`, `unbound-checkconf`, `suricata -T`),
environment secrets, DB schema version.

---

### 6.16 Smart Shield SOC Portal

The SOC Portal is a **separate** web surface for L1 / L2 / L3 analysts. It
shares the appliance database (one audit log, one event store) but is
designed so analyst activity never bleeds into the firewall dashboard.

#### 6.16.1 Architecture

- Optional — enable in **System → SOC Portal Settings**.
- Optionally bind on a dedicated LAN VIP / port so analysts and admins never share the same URL.
- Has its own login (`/soc-portal/login`) and templates under `templates/soc_portal/`.
- L1 / L2 / L3 tier model — page-level permissions hang off the `groups.soc_tier` column added in Phase 19.
- Every SOC action is recorded by `log_soc_event()` which stamps `details.soc_origin = true`.

#### 6.16.2 Separation Guarantees

- `/status/api/logs` (used by the Command Center and the firewall log view) hides SOC-origin events by default. A superuser may pass `hide_soc=0` to merge views during an incident.
- The Command Center shows a small **SOC Portal service** card (status + enable + quick link) but never streams SOC analyst events.
- The SOC Portal has its own dashboard, alerts, investigations, blocklist, escalations, and audit pages.

#### 6.16.3 Operator Workflow

1. SOC portal admin enables the portal under System → SOC Portal Settings.
2. SOC users are created normally under Users + assigned to a group whose `soc_tier` is `L1`, `L2`, or `L3`.
3. Analysts visit `https://<VIP>:<port>/soc-portal/login`.
4. Their actions appear in the SOC portal's own activity stream and are flagged `soc_origin` in the shared event store.

---

### 6.17 Appliance Console (Hardened Terminal)

**Off by default.** A superuser turns it on under System → Admin Access →
Console Options → **Enable web Appliance Console**. Until then, the
WebSocket endpoint returns 404 and the navbar Console button is hidden — so
the feature is not even probable.

When enabled, a superuser can open the floating **Console** widget in the
top-right navbar. The widget connects to a live PTY shell on the FreeBSD
host.

#### 6.17.1 What protects the console

1. **Enable flag** — `terminal_enabled` on `advanced_admin_access`; default 0.
2. **Superuser-only** — non-superusers get permission denied.
3. **Recent reauth** — must have re-authenticated within 300 s before the WebSocket can be opened. The endpoint that issues the WS ticket re-checks this; the WS handler re-checks it again on connect.
4. **WebSocket Origin check** — cross-site WebSocket hijacking is blocked.
5. **Single-use signed ticket** — `/terminal/api/ws-ticket` returns an HMAC-SHA256 ticket bound to user-id + remote IP. The WS upgrade must present it within 60 s. Replays are rejected.
6. **Audit logging with secret redaction** — every typed command is recorded under category `privileged`, with `password=…`, `secret_key=…`, `token=…`, `Authorization: Bearer …`, and `-----BEGIN … PRIVATE KEY-----` blocks replaced by `[REDACTED]`.
7. **Visible warning** — the in-browser console banner reminds operators that every command is audited.

#### 6.17.2 When to use

- Emergency PF inspection (`pfctl -sr`, `pfctl -t <table> -T show`).
- Service troubleshooting that the GUI does not already cover.
- One-off filesystem checks.

For everything else, prefer the relevant GUI page so the change is tracked
through Smart Shield's normal apply/rollback path.

---

## 7. Environment Variables Reference

The environment file is at `/usr/local/etc/smartshield/smartshield.env`. To
load a different file (development, custom path), set `SMARTSHIELD_ENV_FILE`
**before** starting the app — `app/__init__.py` consults it before evaluating
`config.py`.

| Variable | Default | Required | Description |
|---|---|---|---|
| `SMARTSHIELD_ENV_FILE` | `/usr/local/etc/smartshield/smartshield.env` | No | Explicit env file path consulted first by the app |
| `APP_ENV` | `production` | No | `production` enables strict cookie + secret-key handling |
| `SECRET_KEY` | *(none)* | **Yes** in production | Flask session signing key |
| `FLASK_DEBUG` | `0` | No | `1` for dev hot-reload |
| `SMARTSHIELD_DB_PATH` | `/var/db/smartshield/data.db` | No | SQLite path |
| `SMARTSHIELD_CONFIG_PATH` | `/usr/local/etc/smartshield/config.json` | No | JSON config path |
| `SMARTSHIELD_UPLOAD_DIR` | `/var/db/smartshield/uploads/profile_pictures` | No | Profile picture storage |
| `SMARTSHIELD_AUDIT_LOG_PATH` | `/var/log/smartshield/audit.log` | No | Append-only SIEM log |
| `SMARTSHIELD_APP_LOG_PATH` | `/var/log/smartshield/app.log` | No | Application log |
| `SMARTSHIELD_ENABLE_NETWORK_APPLY` | `0` | No | `1` to allow live OS changes |
| `SMARTSHIELD_NETWORK_DRY_RUN` | `1` | No | `0` to leave dry-run mode |
| `SMARTSHIELD_DISABLE_BACKGROUND` | `0` | No | `1` in CI / `tools/runtime_preflight.py` to skip starting daemon threads (SIEM collectors, threat-intel updater, mail-alert worker, gateway monitor, schedule enforcer, …) while still booting a full Flask app |
| `SMARTSHIELD_MASTER_KEY` | *(auto-generated)* | No | AES-256-GCM key for at-rest secret encryption |
| `ABUSECH_AUTH_KEY` | *(empty)* | No | abuse.ch personal Auth-Key |
| `ABUSECH_DRY_RUN` | `1` | No | `0` to fetch live IOCs every 4h |
| `GROQ_API_KEY` | *(empty)* | No | Enables the AI assistant |
| `GOOGLE_CSE_KEY` / `GOOGLE_CSE_CX` | *(empty)* | No | Optional Programmable Search keys for the AI assistant |
| `BOOTSTRAP_ADMIN_USERNAME` | `admin` | No | First-run bootstrap admin username |
| `BOOTSTRAP_ADMIN_PASSWORD` | *(empty)* | No | First-run bootstrap admin password (otherwise set via the wizard) |

**Note:** Set both `SMARTSHIELD_ENABLE_NETWORK_APPLY=1` and
`SMARTSHIELD_NETWORK_DRY_RUN=0` to enable full live mode where firewall
changes are applied immediately.

---

## 8. Log Files Reference

| Path | Content | Rotation |
|---|---|---|
| `/var/log/smartshield/audit.log` | SIEM event log — NDJSON, one event per line | Daily, 90-day retention, 10 MB max, bzip2 |
| `/var/log/smartshield/app.log` | Application log (gunicorn stdout) | Daily, 30-day retention, bzip2 |
| `/var/log/smartshield/access.log` | HTTP access log (gunicorn) | Daily, 30-day retention, 50 MB max, bzip2 |
| `/var/log/smartshield/error.log` | Application error log (gunicorn stderr) | Daily, 30-day retention, bzip2 |
| `/var/log/nginx/access.log` | nginx access log | Managed by nginx |
| `/var/log/nginx/error.log` | nginx error log | Managed by nginx |
| `/var/log/suricata/eve.json` | Suricata EVE JSON alert / event stream | Configure via Suricata |
| `/var/log/suricata/fast.log` | Suricata one-line alert summary | Configure via Suricata |
| `/var/log/suricata/suricata.log` | Suricata startup / runtime | Configure via Suricata |
| `/var/log/unbound/query.log` | Unbound DNS query log when enabled | Configure via Unbound |
| `/var/log/openvpn/status*.log` | OpenVPN connection status | Configure via OpenVPN |

Log rotation is handled by newsyslog(8) via
`/usr/local/etc/newsyslog.d/smart-shield.conf`, installed by `bsd/install.sh`.

---

## 9. Directory Structure Reference

| Path | Purpose |
|---|---|
| `/usr/local/share/smartshield/` | Application code root |
| `/usr/local/share/smartshield/.venv/` | Python virtual environment |
| `/usr/local/etc/smartshield/` | Env file, config.json, master.key, SSL certificates |
| `/usr/local/etc/smartshield/smartshield.env` | Generated env file (root:wheel `0600`) |
| `/usr/local/etc/smartshield/master.key` | AES-256 master key (root:wheel `0600`) |
| `/usr/local/etc/smartshield/ssl/` | TLS cert / key |
| `/usr/local/etc/mrtg/` | MRTG configuration |
| `/usr/local/etc/suricata/` | Suricata configuration / rules |
| `/usr/local/etc/unbound/` | Unbound configuration |
| `/usr/local/etc/openvpn/` | OpenVPN configuration |
| `/usr/local/etc/openvpn/keys/` | OpenVPN key material (mode 0700) |
| `/usr/local/etc/nginx/nginx.conf` | nginx TLS reverse proxy |
| `/var/db/smartshield/` | SQLite database + application data |
| `/var/db/smartshield/data.db` | SQLite database |
| `/var/db/smartshield/mrtg/` | MRTG PNG output |
| `/var/db/smartshield/uploads/` | User profile pictures |
| `/var/db/smartshield/threat_intel_ips.txt` | Latest threat intelligence IP list |
| `/var/log/smartshield/` | Application, audit, access, error logs |
| `/var/run/smartshield/` | PID file, worker lock, MRTG lock (tmpfs) |
| `/etc/cron.d/smart-shield-mrtg` | MRTG cron job |
| `/etc/pf.conf` | Active PF firewall ruleset |
| `/usr/local/etc/rc.d/smart_shield` | FreeBSD rc.d service script |
| `/usr/local/sbin/smartshieldctl` | Operator CLI utility |
| `/usr/local/sbin/smart_shield_console` | Console recovery menu |
| `/usr/local/sbin/mrtg-probe.sh` | netstat-based MRTG data probe |
| `/usr/local/etc/sudoers.d/smartshield` | sudo allowlist for privileged operations |
| `/usr/local/etc/newsyslog.d/smart-shield.conf` | Log rotation |

---

## 10. Troubleshooting

### Captive portal block page references "Content Policy"

Older builds typoed this as "Content Police" both in the captive-portal block
HTML and in the redirect-page generator. The current build uses "Content
Policy" everywhere — if you still see the typo, you are running an outdated
appliance image; pull the latest source and `smartshieldctl restart`.

### HTTPS sites do not show the captive portal block page

This is expected. Smart Shield does not perform TLS interception by default,
so HTTPS clients see a browser certificate / connection warning instead of
the block page. The block page itself now states this so end users know what
they are seeing. To get a clean HTTPS block page you must configure TLS
interception with a trusted local CA — out of scope for the default install.

### The "Console" button is missing from the navbar

By design — the Appliance Console is **off by default** (§6.17). A superuser
must enable it under System → Admin Access → Console Options.

### "Re-authentication required" when opening the Appliance Console

Recent reauth (last 300 s) is required by the WebSocket ticket endpoint. Open
any password-protected action (e.g. Diagnostics → Halt System) to refresh
your reauth, then reopen the console.

### SOC events appear in the firewall log

They shouldn't — `/status/api/logs` defaults to filtering them out (§6.16.2).
Confirm:

- Events come from the SOC portal, not from a non-SOC route.
- They were logged via `log_soc_event()` which stamps `details.soc_origin = true`.
- The viewer is not appending `?hide_soc=0` (only superusers can opt back in).

### Smart Shield service won't start after edits to the env file

```sh
# Check syntax — every line should be KEY=VALUE.
grep -n '=' /usr/local/etc/smartshield/smartshield.env

# Reload + tail logs.
service smart_shield restart
tail -50 /var/log/smartshield/app.log
```

In production, the app refuses to start if `SECRET_KEY` is missing (this is
intentional). The error message tells you which env file to fix.

### IDS shows as disabled after navigating away from Threat Detection

The Threat Detection save form historically had an "Enable IDS" checkbox that
could overwrite the enabled state. The current schema manages the enabled
state exclusively through the toggle button. If you still see this, you are
on an older build — pull the latest source and reload.

### MRTG graphs not showing

The Traffic History status bar shows a specific badge per problem:

| Badge | Cause | Fix |
|---|---|---|
| "Stale lock file detected" | `/var/run/smartshield/mrtg.lock` left by a crashed run | Click **Reinitialize MRTG** |
| "Cron job missing" | `/etc/cron.d/smart-shield-mrtg` not installed | Click **Regenerate Config** |
| "Graph directory missing" | `/var/db/smartshield/mrtg/` absent | `install -d -m 0755 /var/db/smartshield/mrtg` |
| "No graphs yet" (cron installed) | MRTG hasn't run yet | Wait up to 5 minutes |

Manual diagnostics:

```sh
cat /etc/cron.d/smart-shield-mrtg
ls /var/db/smartshield/mrtg/*.png 2>/dev/null || echo "No PNGs"
env LANG=C /usr/local/bin/mrtg /usr/local/etc/mrtg/mrtg.cfg --log-level 4
```

### Cannot reach the web GUI from a LAN client

```sh
sockstat -4 -l | grep 443
smartshieldctl status
pfctl -sr | grep 443
ping 192.168.1.1
```

If the LAN client cannot reach the LAN IP at all, verify the interface
assignment (`smartshieldctl iface-show LAN`).

### DHCP leases not being assigned

```sh
smartshieldctl dhcp-status
pgrep -x dhcpd
tail -30 /var/log/messages | grep dhcpd
dhcpd -t -cf /usr/local/etc/dhcpd.conf
```

Ensure the DHCP pool is inside the LAN subnet and does not overlap the LAN
appliance IP.

### DNS resolution failing for LAN clients

```sh
smartshieldctl dns-status
pgrep -x unbound
dig @127.0.0.1 google.com
unbound-checkconf /usr/local/etc/unbound/unbound.conf
```

LAN clients must use the appliance LAN IP as their DNS server (this is
normally pushed by DHCP).

### Suricata fails to start (IPS mode)

1. `kldstat | grep netmap`
2. `tail -50 /var/log/suricata/suricata.log`
3. `suricata -T -c /usr/local/etc/suricata/suricata.yaml`
4. Switch to IDS mode and retry.

Smart Shield falls back to IDS automatically if netmap-based IPS startup
fails.

### Backup restore fails with "schema version mismatch"

Restore backups only to the same Smart Shield version that created them, or
let the app's automatic schema migration run first.

---

## 11. Schema Migration Map

Smart Shield carries its full migration history in `app/migrations.py`. On
boot, `init_db()` runs every migration whose version number is greater than
the value stored in the `schema_version` PRAGMA — so an appliance can be
upgraded across many releases in one shot without operator intervention.

**Safety model.** On FreeBSD, the migration runner snapshots the active
database file to `data.db.bak-YYYYMMDDTHHMMSS` **once**, before applying any
pending migration. Each individual migration is idempotent — every
structural change is `ALTER TABLE … ADD COLUMN` (wrapped in `try/except` so
re-runs on a fresh install are a no-op), `CREATE TABLE IF NOT EXISTS`, or
`INSERT OR IGNORE`. There are no destructive `DROP` / `ALTER … RENAME` /
`DELETE` operations in the migration history.

That means every row below is **safe to apply in-place** without taking the
appliance down for a manual backup-then-restore cycle. The pre-run snapshot
gives you a recoverable artifact if the host loses power mid-migration.

**Ship dates.** Per-migration ship dates are not tracked in source; the
authoritative timeline is `git log app/migrations.py`. The version numbers
are strictly increasing in the order migrations are added to the
`MIGRATIONS` list at the bottom of `app/migrations.py`.

| Version | What it adds / changes |
|---|---|
| v1 | Initial schema baseline — `users`, `lan_config`, `wan_config`, `pf_rules`, `dhcp_pools`, and every other table created by `init_db()` on a fresh install. Applied by `database.py`, not by a `_migration_v*` function. |
| v2 | `pending_interface_changes` table — staging area for interface edits before `Apply`. |
| v3 | `certificates` table — internal CA + per-cert metadata. |
| v4 | DHCPv6, RA, WoL, and Captive Portal tables. |
| v5 | `config_versions` and `health_snapshots` tables. |
| v6 | `ids_threat_feeds` table for encrypted abuse.ch Auth-Key storage. |
| v7 | Adds `disabled` flag to `captive_vouchers` for temporary suspension. |
| v8 | Adds `abusech_dry_run` flag to `ids_threat_feeds` for GUI control of dry-run mode. |
| v9 | Adds missing columns to `dhcpv6_pools` (fixes the v4 column-list gap). |
| v10 | `siem_state` table for SIEM collector offset persistence. |
| v11 | Fixes column-name mismatches in the `certificates` table. |
| v12 | Adds firewall-hardening toggle columns to `advanced_firewall_nat`. |
| v13 | Applied-state tracking tables (`config_apply_jobs`, `feature_applied_state`). |
| v14 | Policy-based routing table + new columns on `advanced_firewall_nat`. |
| v15 | Adds CARP-specific columns to `virtual_ips_configs` (vhid, advskew, password). |
| v16 | Adds gateway health-tracking columns to the `gateways` table. |
| v17 | SIEM case management tables for SOC incident tracking. |
| v18 | `siem_alert_actions` table for SOC L1 triage tracking. |
| v19 | SOC Team Portal — tier assignment on groups + `soc_portal_config` table. |
| v20 | SOC case escalation + closure-type tracking. |
| v21 | Per-user SOC tier assignment. |
| v22 | Indexed event store. |
| v23 | User-defined correlation rule engine. |
| v24 | SOC portal binds to a dedicated virtual IP alias on LAN. |
| v25 | SOC portal hardening — TOTP MFA per user account. |
| v26 | SOC SIEM platform extensions. |
| v27 | SOC maturity layer. |
| v28 | IDS self-healing watchdog opt-out flag. |
| v29 | VPN — finishes the OpenVPN server schema and adds a self-service portal user table. |
| v30 | Outbound mail-alert service (Gmail app-password SMTP). |
| v31 | SOC Team Portal improvements. |
| v32 | SOC Portal Control runtime fields + response-recommendation table. |
| v33 | Captive portal authentication rate-limit table. |
| v34 | Stable `event_uuid` + normalized event fields (Wave A foundations). |
| v35 | Stable `event_uuid` join key for SOC alert actions / assignments. |
| v36 | Specialised `firewall_events` table + per-rule `log_enabled` toggle (Wave B foundations). |
| v37 | Persistent SOC alerts lifecycle (Wave C foundations). |
| v38 | Collector reliability — health table + dead-letter queue (Wave D foundations). |
| v39 | Specialised `dns_events` table (Wave E). |
| v40 | `dns_events.policy_source` for log classification via the unified domain-policy resolver (Wave J). |
| v41 | `alert_observations` table so dedup doesn't hide per-event evidence (Wave K). |
| v42 | Richer `firewall_events` columns (Wave L). |
| v43 | Defaults abuse.ch threat feeds to safe dry-run mode for existing installs. |
| v44 | Turns mail alerts on by default when the admin hasn't configured SMTP. |
| v45 | IPS inline peer interface + degraded-rules opt-in for the IDS. |
| v46 | Stores the full source log on a SOC case so it can be investigated end-to-end. |
| v47 | Records why an IPS apply auto-demoted to IDS. |
| v48 | IDS block-on-alert bookkeeping for the `<ss_ids_blocks>` PF table. |
| v49 | `ddns_status` table — per-hostname DDNS update bookkeeping. |
| v50 | Mail-alert per-source cooldown + optional alert-digest window. |

If you are upgrading from an older release and want to know which
migrations will run before they execute, query the live `schema_version`
PRAGMA on the running appliance:

```sh
sqlite3 /var/db/smartshield/data.db "PRAGMA user_version;"
```

Any pending migration above that number will be applied on the next
`service smart_shield restart`.
