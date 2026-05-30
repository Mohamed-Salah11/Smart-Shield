# Smart Shield

![CI](https://github.com/Mohamed-Salah11/Smart-Shield/actions/workflows/ci.yml/badge.svg)

> A web-managed network security appliance built on FreeBSD — firewall, IDS/IPS, VPN, DNS, DHCP, SIEM, content policy, captive portal, a hardened appliance console, and a separate SOC team portal in a single platform.

---

## Overview

Smart Shield turns a FreeBSD host into a managed network gateway. Every configuration surface — firewall rules, NAT, VPN tunnels, DNS filtering, intrusion detection, captive portal, content policy, SOC operations — is driven from one SQLite database, exposed through a modern HTTPS web interface and an operator CLI (`smartshieldctl`), and applied to the OS through the daemons FreeBSD ships natively (PF, Suricata, Unbound, ISC DHCPd, Kea, strongSwan, OpenVPN, mpd5).

The platform targets three audiences:

- **Network administrators** who need a reproducible, scriptable, auditable gateway.
- **Security practitioners** who want a self-contained appliance to test policies, captive flows, and detection signatures.
- **Educators** running a teaching lab where students can change rules safely (dry-run mode) before applying them.

Two operator surfaces ship with the appliance:

- A **firewall/admin web UI** for everyday gateway management.
- A separate **Smart Shield SOC Portal** for L1/L2/L3 analyst workflows. SOC activity is tagged with `details.soc_origin = true` so analyst events stay out of the firewall dashboard and the appliance log by default.

Three runtime modes:

- **live** — `SMARTSHIELD_ENABLE_NETWORK_APPLY=1` and `SMARTSHIELD_NETWORK_DRY_RUN=0`; all generated configs are validated, written atomically, and reloaded on the live kernel.
- **dry-run** — `SMARTSHIELD_NETWORK_DRY_RUN=1`; configs are validated only.
- **development** — running on Linux / macOS / Windows; full UI for design and policy work, no OS-level changes.

---

## Key Features

| Category | Capability |
|---|---|
| **Firewall** | PF packet filter with floating / WAN / LAN rulesets; aliases, schedules, anti-spoof, bogon blocking |
| **NAT** | Port forward (rdr), 1:1 binat, outbound NAT, IPv6 NPt, NAT reflection |
| **Traffic shaping** | ALTQ queues (HFSC, CBQ, PRIQ, FAIRQ); dummynet limiters with per-flow pipes |
| **IDS / IPS** | Suricata passive IDS (pcap) or inline IPS (netmap); Emerging Threats rule management via `suricata-update` |
| **SIEM collectors** | Background threads for IDS alerts, DHCP events, DNS queries, PF state tracking, anomaly detection |
| **Threat intelligence** | abuse.ch URLhaus / MalwareBazaar / ThreatFox integration — auto-pushes IOC IPs to a PF table |
| **VPN** | OpenVPN (server + client + CSO), IPsec/IKEv2 via strongSwan, L2TP/IPsec via mpd5 |
| **DNS** | Unbound recursive resolver with DNSSEC validation, DNS-over-TLS upstream, host & domain overrides, per-subnet ACLs |
| **Content Policy** | Unified DNS / Web / Application filtering — duplicate domains across filters are deduplicated and resolved by precedence before Unbound writes a single set of `local-zone` records |
| **Captive Portal** | HTTP redirect to a login / block page, with soft and strict enforcement modes, voucher codes, and superuser bypass |
| **Shield SOC Portal** | Optional separate web portal for SOC L1/L2/L3 analysts; event store is shared but the appliance log hides SOC-origin events by default |
| **Appliance Console** | Off by default. When a superuser enables it under System → Admin Access, a hardened in-browser PTY shell becomes available (recent reauth, single-use signed WebSocket ticket, Origin check, secret-redacting audit) |
| **DHCP** | ISC DHCPd (IPv4, static leases, relay); Kea (DHCPv6, prefix delegation, RA) |
| **CARP / HA** | Virtual IPs, CARP failover, pfsync state sync |
| **Monitoring** | Per-interface live bandwidth, MRTG historical graphs (daily / weekly / monthly / yearly) |
| **AI assistant** | Optional Groq-powered assistant with read-only tools across every subsystem and write tools (firewall block, domain block / unblock) gated by explicit user confirmation |
| **Backup / Restore** | AES-256-GCM encrypted snapshots; per-component config version history; one-click rollback |
| **Users & Groups** | Multi-user RBAC, page-level group permissions, profile pictures, brute-force lockout, TOTP-ready re-auth |
| **Dynamic DNS / SNMP** | ddclient for WAN IP updates; bsnmpd MIB exposure |

---

## Architecture

```
Browser (HTTPS)
      │
      ▼
  nginx (TLS 1.2/1.3, port 443)
      │ reverse proxy + WebSocket upgrade
      ▼
  Gunicorn (gevent workers, 127.0.0.1:5000)
      │ WSGI + Sock WebSockets
      ▼
  Flask application (app/__init__.py)
  ├── Route blueprints — packaged under routes/
  │     firewall/  system/  services/  vpn/  diagnostics/  network_api/
  │     plus standalone: auth, status, ids, filters, portal, soc, soc_portal,
  │     terminal, setup, users, chatbot, interfaces, routing, hec, vpn_portal,
  │     dns_logs, firewall_logs
  ├── SQLite database (/var/db/smartshield/data.db)
  ├── Audit log (/var/log/smartshield/audit.log — NDJSON, indexed mirror in `events`)
  └── Background threads
      ├── SIEM: IDS, DHCP, DNS, PF, anomaly collectors
      └── Threat intel updater (4h)
              │
              ▼
      FreeBSD kernel & daemons
      ├── PF (pf_generator.py → pf.conf)
      ├── Suricata (ids_writer.py → suricata.yaml)
      ├── Unbound (dns_writer.py → unbound.conf)
      ├── ISC DHCPd (dhcp_writer.py)
      ├── Kea DHCPv6 (dhcpv6_writer.py)
      ├── strongSwan (ipsec_writer.py)
      ├── OpenVPN (openvpn_writer.py)
      ├── mpd5 / L2TP (l2tp_writer.py)
      ├── MRTG (mrtg_writer.py — cron every 5 min)
      └── nginx, NTP, SNMP, miniupnpd, igmpproxy, ddclient, rtadvd
```

Every writer follows the same pipeline:

```
generate → validate (pfctl -nf / unbound-checkconf / dhcpd -t / suricata -T)
         → backup known-good
         → atomic write
         → reload service
         → roll back on failure
         → record state in apply_state.py
```

The unified `ApplyResult` dataclass (added in Phase 8) gives the UI a typed status per component — validation output, rollback flag, message, and timestamp.

---

## Requirements

### Platform

| Component | Minimum |
|---|---|
| Operating system | FreeBSD 13.0 or newer |
| Python | 3.10 or newer |
| RAM | 512 MB (1 GB recommended) |
| Storage | 4 GB (SSD recommended) |
| NICs | 2 physical interfaces (WAN + LAN) |

### FreeBSD packages (installed automatically)

```
python3  git  sqlite3  ca_root_nss  nginx  sudo  nano
pkgconf  curl  rsync
unbound  isc-dhcp44-server  kea
openvpn  strongswan  mpd5
suricata
mrtg  miniupnpd  igmpproxy  ddclient  bind-tools  tcpdump
```

### Python dependencies

```
Flask==3.1.2          Werkzeug==3.1.3       gunicorn==22.0.0
cryptography==46.0.3  requests==2.32.3      PyYAML==6.0.3
python-dotenv==1.0.1  groq>=0.9.0           Jinja2==3.1.6
flask-sock>=0.7       gevent>=24.0          fpdf2>=2.7.9
```

---

## Installation

```sh
# 1. Clone onto the FreeBSD host (run as root).
git clone https://github.com/Mohamed-Salah11/Smart-Shield.git /usr/local/share/smartshield

# 2. Run the installer.
cd /usr/local/share/smartshield
sh bsd/install.sh

# 3. Open the GUI from any host on the LAN.
#    Default URL:  https://192.168.1.1
#    Accept the self-signed certificate warning, then complete the wizard.
```

The installer:

- `pkg install`s every required FreeBSD package.
- Builds `/usr/local/share/smartshield/.venv` and installs Python deps.
- Creates `/var/db/smartshield`, `/var/log/smartshield`, `/var/run/smartshield`, `/usr/local/etc/smartshield`, `/usr/local/etc/mrtg`.
- Writes `/usr/local/etc/smartshield/smartshield.env` with a generated `SECRET_KEY` and a generated `SMARTSHIELD_MASTER_KEY` (both root-owned, `0600`).
- Installs the `smart_shield` rc.d service. The service exports `SMARTSHIELD_ENV_FILE` so the Flask app and every Gunicorn worker load the same env file regardless of working directory.
- Generates a self-signed TLS certificate.
- Writes the nginx reverse proxy + WebSocket upgrade configuration.
- Installs the MRTG cron job (`*/5 * * * *`).
- Installs `smartshieldctl` to `/usr/local/sbin/`.
- Starts every service.

---

## Project Layout

```
Smart-Shield/
├── app/
│   ├── __init__.py             Flask app factory; loads SMARTSHIELD_ENV_FILE before config
│   ├── config.py               Config classes; fails fast in production without SECRET_KEY
│   ├── database.py             SQLite schema (90+ tables) + init_db()
│   ├── audit_log.py            Append-only NDJSON log + indexed events mirror + redact_secrets()
│   ├── auth_utils.py           login_required, superuser_required, reauth_required
│   ├── security.py             CSRF token store, validate_csrf_or_abort
│   ├── secret_store.py         AES-256-GCM at-rest secret encryption
│   ├── soc_portal_auth.py      L1/L2/L3 SOC tier auth helpers + soc_portal_enabled()
│   ├── totp.py                 TOTP enrolment / verification
│   ├── vpn_portal_auth.py      OpenVPN portal user auth
│   ├── api_auth.py / api_tokens.py    Bearer-token API surface
│   └── services/
│       ├── pf_generator.py     PF rules + NAT + anchors; validate + atomic write + rollback
│       ├── dns_writer.py       unbound.conf generator + apply_unbound() (validate / write / reload / rollback)
│       ├── dhcp_writer.py / dhcpv6_writer.py     ISC DHCPd / Kea generators
│       ├── ids_writer.py       Suricata yaml + enable/disable
│       ├── openvpn_writer.py / ipsec_writer.py / l2tp_writer.py     VPN configs
│       ├── content_policy.py   Domain normalisation, DomainPolicy dedup, build_domain_policy_map()
│       ├── dns_filter.py / web_filter.py / app_filter.py            Per-source filter modules
│       ├── captive_portal.py   Portal logic, PF anchor management, HTTPS redirect daemon
│       ├── siem_collector.py   Background threads (IDS, DHCP, DNS, PF, anomaly)
│       ├── abusech_client.py   URLhaus / MalwareBazaar / ThreatFox client
│       ├── apply_state.py      ApplyResult dataclass + per-component apply-state tracker
│       ├── feature_registry.py Feature manifest used by the UI
│       ├── mail_alerts.py / playbooks.py / chatbot_service.py
│       ├── soc_portal_writer.py / soc_blocklist.py / soc_recommendations.py
│       └── (more — see app/services/)
├── routes/
│   ├── firewall/  rules, NAT, aliases, schedules, traffic-shaper, apply
│   ├── system/    dashboard, settings, certificates, admin-access, advanced, soc-mail
│   ├── services/  DHCP, DNS, NTP, SNMP, UPnP, IGMP, captive
│   ├── vpn/       OpenVPN, IPsec, L2TP, portal-users
│   ├── diagnostics/  backup-restore, packet-capture, command-prompt, factory-reset, halt-system
│   ├── network_api/  interface/routing JSON for the UI
│   ├── auth.py    login / logout / re-auth
│   ├── status.py  dashboard cards + SIEM /api/logs (hides SOC events by default)
│   ├── dns_logs.py / firewall_logs.py    log viewers for DNS queries / PF events
│   ├── ids.py / filters.py / portal.py / chatbot.py / setup.py / users.py
│   ├── soc.py / soc_portal.py / vpn_portal.py
│   ├── terminal.py    Hardened web console (enable flag + reauth + WS ticket)
│   └── hec.py     HTTP event collector
├── templates/                  Jinja2 HTML templates (175+ files)
│   ├── soc_portal/             Separate SOC analyst UI
│   └── portal/                 Captive-portal block / login / success pages
├── static/                     CSS, JS, fonts, xterm.js
├── bsd/
│   ├── install.sh              Full FreeBSD installer
│   ├── rc.d/smart_shield       FreeBSD rc.d unit (exports SMARTSHIELD_ENV_FILE)
│   ├── sbin/smartshieldctl     Operator CLI
│   ├── console_menu/           Serial / SSH emergency recovery menu
│   ├── mrtg-probe.sh           netstat-based MRTG data collector
│   └── etc/                    newsyslog, sudoers.d
├── tests/                      Pytest suite
├── tools/                      Standalone helper scripts
├── requirements.txt
└── wsgi.py                     Gunicorn WSGI entry point
```

---

## Runtime Modes

| Mode | Trigger | Behaviour |
|---|---|---|
| `live`        | FreeBSD + `SMARTSHIELD_ENABLE_NETWORK_APPLY=1` + `SMARTSHIELD_NETWORK_DRY_RUN=0` | All changes validated + applied immediately |
| `dry-run`     | `SMARTSHIELD_NETWORK_DRY_RUN=1` | Configs validated only; the kernel is never touched |
| `degraded`    | FreeBSD + required daemon binaries missing | UI works; apply reports the missing binary |
| `development` | Non-FreeBSD host | Full UI + config generation; no OS operations |

---

## Key Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `SMARTSHIELD_ENV_FILE` | `/usr/local/etc/smartshield/smartshield.env` | The Flask app loads this file before any local `.env`. Set explicitly when running outside FreeBSD or from a non-default install path |
| `APP_ENV` | `development` | `production` enables strict config (`SECRET_KEY` required, secure cookies on) |
| `SECRET_KEY` | *(required in production)* | Flask session signing key |
| `SMARTSHIELD_DB_PATH` | `/var/db/smartshield/data.db` | SQLite path |
| `SMARTSHIELD_MASTER_KEY` | *(auto-generated)* | AES-256-GCM key for at-rest secret encryption |
| `SMARTSHIELD_ENABLE_NETWORK_APPLY` | `0` | Set to `1` to allow live OS changes |
| `SMARTSHIELD_NETWORK_DRY_RUN` | `1` | Set to `0` to leave dry-run mode |
| `ABUSECH_AUTH_KEY` | *(empty)* | abuse.ch personal Auth-Key |
| `ABUSECH_DRY_RUN` | `1` | Set to `0` to fetch live IOCs every 4h |
| `GROQ_API_KEY` | *(empty)* | Optional Groq key — enables the AI assistant |

Full reference is in [Manual.md](Manual.md) §7.

---

## License

This project is licensed under the Apache License 2.0. See `LICENSE` for details.

---

## Testing

The test suite runs offline on any OS (in-memory SQLite, mocked system calls):

```sh
pip install -r requirements-dev.txt
pytest -q
```

---

## Contributing

1. Fork the repository and create a feature branch.
2. Run in development mode (`APP_ENV=development FLASK_DEBUG=1` on a non-FreeBSD host).
3. Validate generator output with dry-run mode — no FreeBSD host required for most changes.
4. Submit a pull request describing the change and its purpose.

All contributions must pass `pytest tests/` and must not introduce new dependencies without justification.

See `CONTRIBUTING.md` and `CODE_OF_CONDUCT.md`.

---

## Support

- Usage and installation: see `Manual.md` and `Testing.md`.
- Questions / bugs: open a GitHub issue.
- Security vulnerabilities: see `SECURITY.md` (do not open a public issue).
