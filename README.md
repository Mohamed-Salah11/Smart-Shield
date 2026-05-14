# Smart Shield

> A web-managed network security appliance built on FreeBSD — firewall, IDS/IPS, VPN, DNS, DHCP, SIEM, and threat intelligence in a single unified platform.

---

## Overview

Smart Shield is a full-stack network security appliance that turns a FreeBSD machine into a managed network gateway. It exposes every configuration surface — firewall rules, NAT, VPN tunnels, DNS filtering, intrusion detection, and more — through a modern HTTPS web interface, while keeping all enforcement on battle-tested FreeBSD kernel primitives (PF, Suricata, Unbound, strongSwan, OpenVPN).

The platform is designed for network administrators, security practitioners, and educators who need a reproducible, scriptable, and auditable gateway that can be deployed from source on any FreeBSD 13+ host. A four-step setup wizard provisions the appliance from a blank install in minutes; every subsequent change is made through the GUI or the `smartshieldctl` CLI without touching configuration files by hand.

Smart Shield runs in **live mode** (all changes applied to the OS in real time), **dry-run mode** (configurations are generated and validated but never loaded into the kernel — ideal for staging or testing), and **development mode** (full UI on non-FreeBSD platforms for UI work and testing). An immutable audit log records every user action and every system event detected by the SIEM collectors.

---

## Key Features

| Category | Capability |
|---|---|
| **Firewall** | PF packet filter — floating, WAN, and LAN rule sets; policy-based routing; schedules; anti-spoof; bogon blocking |
| **NAT** | Port forwarding, 1:1 binat, outbound masquerade, IPv6 NPt, NAT reflection |
| **Traffic Shaping** | ALTQ queues (HFSC, CBQ, PRIQ, FAIRQ); dummynet bandwidth limiters with per-flow pipe control |
| **IDS / IPS** | Suricata in passive IDS mode (BPF pcap) or inline IPS mode (netmap); Emerging Threats rule management via suricata-update |
| **SIEM** | Five background collectors: IDS alerts, DHCP events, DNS queries, PF connection tracking, anomaly detection (brute-force + IDS-flood); persistent file-offset resumption |
| **Threat Intelligence** | abuse.ch URLhaus, MalwareBazaar, ThreatFox integration; auto-pushes malicious IPs to a PF table every 4 hours |
| **VPN** | OpenVPN server + client (multi-instance, TUN/TAP, AES-256-GCM); IPsec / IKEv2 via strongSwan (Phase 1/2, mobile clients, PSK); L2TP/IPsec via mpd5 |
| **DNS** | Unbound recursive resolver with DNSSEC validation, DNS-over-TLS upstream, host/domain overrides, per-subnet ACLs, query logging |
| **DHCP** | ISC DHCPd (IPv4 pools, static leases, relay); Kea DHCPv6 with prefix delegation and RA |
| **Content Filtering** | DNS-layer domain blocking/redirecting; web URL pattern filtering; application-layer blocking by port and signature |
| **Captive Portal** | HTTP/HTTPS redirect gateway with soft and strict enforcement modes; local user auth; voucher codes; RADIUS support |
| **Traffic Monitoring** | Live per-interface bandwidth graphs; MRTG historical graphs (daily, weekly, monthly, yearly) |
| **CARP / HA** | Virtual IP CARP failover; pfsync state synchronisation for active-passive high availability |
| **AI Assistant** | Groq-powered natural language assistant; read-only tools for all subsystems; write tools (firewall rules, DNS blocks) with explicit user confirmation |
| **Backup / Restore** | AES-256-GCM encrypted full backups; incremental config version history with one-click rollback |
| **Users & Groups** | Multi-user RBAC; per-group page-level permission control; profile pictures; brute-force lockout |
| **Dynamic DNS** | ddclient integration for automatic WAN IP updates |
| **SNMP** | bsnmpd agent for integration with network management systems |

---

## Architecture

```
Browser (HTTPS)
      │
      ▼
  nginx (TLS 1.2/1.3, port 443)
      │ reverse proxy
      ▼
  Gunicorn (2 workers, 127.0.0.1:5000)
      │ WSGI
      ▼
  Flask application
  ├── 17 route blueprints (firewall, vpn, ids, services, …)
  ├── SQLite database  (/var/db/smart-shield/data.db)
  ├── Audit log        (/var/log/smart-shield/audit.log)
  └── Background threads
      ├── SIEM: IDS collector      (10 s)
      ├── SIEM: DHCP collector     (30 s)
      ├── SIEM: DNS collector      (15 s)
      ├── SIEM: PF state tracker   (60 s)
      ├── SIEM: Anomaly detector   (60 s)
      └── Threat intel updater     (4 h)
              │
              ▼
      FreeBSD kernel & daemons
      ├── PF (packet filter)       — pf.conf
      ├── Suricata                 — suricata.yaml
      ├── Unbound                  — unbound.conf
      ├── ISC DHCPd                — dhcpd.conf
      ├── OpenVPN                  — /usr/local/etc/openvpn/
      ├── strongSwan               — ipsec.conf + ipsec.secrets
      ├── mpd5 (L2TP)              — mpd.conf
      ├── MRTG                     — mrtg.cfg  (cron, every 5 min)
      └── nginx, NTP, SNMP, UPnP, IGMP, DDNS, Kea DHCPv6
```

Configuration changes are validated (`pfctl -nf`, `dhcpd -t`, `unbound-checkconf`, `suricata -T`) before being applied. Every service write is atomic — a known-good backup is kept and automatically restored on reload failure.

---

## Requirements

### Platform

| Component | Minimum |
|---|---|
| Operating System | FreeBSD 13.0 or newer |
| Python | 3.10 or newer |
| RAM | 512 MB (1 GB recommended) |
| Storage | 4 GB (SSD recommended for database I/O) |
| NICs | 2 physical interfaces (WAN + LAN) |

### FreeBSD Packages (installed automatically)

```
python3  git  sqlite3  ca_root_nss  nginx  sudo  nano
unbound  isc-dhcp44-server  kea
openvpn  strongswan  mpd5
suricata
mrtg  miniupnpd  igmpproxy  ddclient  bind-tools  tcpdump
```

### Python Dependencies

```
Flask==3.1.2          Werkzeug==3.1.3       gunicorn==22.0.0
cryptography==46.0.3  requests==2.32.3      PyYAML==6.0.3
python-dotenv==1.0.1  groq>=0.9.0           Jinja2==3.1.6
```

---

## Installation

```sh
# 1. Clone the repository onto the FreeBSD host (as root)
git clone https://github.com/<org>/Smart-Shield.git /usr/local/share/smart-shield

# 2. Run the installer
cd /usr/local/share/smart-shield
sh bsd/install.sh

# 3. Open the web interface from any machine on the LAN
#    Default URL: https://192.168.1.1
#    Accept the self-signed certificate warning, then complete the 4-step wizard
```

The installer performs the following automatically:

- Installs all required FreeBSD packages via `pkg install`
- Creates a Python virtual environment and installs pip dependencies
- Creates all runtime directories under `/var/db/smart-shield`, `/var/log/smart-shield`, `/var/run/smart-shield`, `/usr/local/etc/smart-shield`, and `/usr/local/etc/mrtg`
- Generates a random `SECRET_KEY` and `SMARTSHIELD_MASTER_KEY` and writes them to the environment file
- Installs the `smart_shield` rc.d service and enables it at boot
- Generates a self-signed TLS certificate (RSA 2048-bit, valid 10 years)
- Writes the nginx TLS reverse proxy configuration and starts nginx
- Installs the MRTG cron job (`*/5 * * * *`)
- Installs `smartshieldctl` to `/usr/local/sbin/`
- Starts all services

---

## Project Layout

```
Smart-Shield/
├── app/
│   ├── __init__.py             # Flask application factory, blueprint registration
│   ├── database.py             # SQLite schema (60+ tables) + init_db()
│   ├── audit_log.py            # Append-only NDJSON event log
│   ├── auth_utils.py           # Session management, login_required decorator
│   ├── security.py             # CSRF, session timeout, security headers
│   └── services/
│       ├── pf_generator.py     # PF firewall + NAT config generation
│       ├── ids_writer.py       # Suricata YAML + enable/disable logic
│       ├── dns_writer.py       # Unbound configuration generator
│       ├── dhcp_writer.py      # ISC DHCPd configuration generator
│       ├── openvpn_writer.py   # OpenVPN server and client configs
│       ├── ipsec_writer.py     # strongSwan ipsec.conf generator
│       ├── siem_collector.py   # Five background SIEM collector threads
│       ├── abusech_client.py   # abuse.ch threat intelligence API client
│       ├── health_monitor.py   # Service health checks + system metrics
│       ├── feature_registry.py # Feature capability manifest (30+ features)
│       ├── mrtg_writer.py      # MRTG config generator and cron installer
│       └── captive_portal.py   # Captive portal session and PF anchor management
├── routes/
│   ├── firewall.py             # Firewall rules, NAT, aliases, traffic shaping
│   ├── ids.py                  # IDS/IPS, rulesets, alerts, threat feeds
│   ├── vpn.py                  # OpenVPN, IPsec, L2TP
│   ├── services.py             # DHCP, DNS, NTP, SNMP, UPnP, IGMP, DDNS
│   ├── status.py               # Monitoring, SIEM stream, MRTG, health API
│   ├── diagnostics.py          # Backup/restore, diagnostics, config history
│   ├── setup.py                # 4-step first-run setup wizard
│   ├── users.py                # User and group management
│   ├── system.py               # Dashboard, platform settings, certificates
│   └── filters.py              # DNS, web, and application content filtering
├── templates/                  # Jinja2 HTML templates (145+ files)
├── static/                     # CSS, JavaScript, fonts, images
├── bsd/
│   ├── install.sh              # Full FreeBSD deployment installer
│   ├── rc.d/smart_shield       # FreeBSD rc.d service control script
│   ├── sbin/smartshieldctl     # Operator CLI utility
│   ├── console_menu/           # Serial/SSH emergency recovery menu
│   ├── mrtg-probe.sh           # netstat-based MRTG data collector
│   └── etc/                    # newsyslog rotation, sudoers.d allowlist
├── requirements.txt            # Python package list
└── wsgi.py                     # Gunicorn WSGI entry point
```

---

## Runtime Modes

| Mode | Condition | Behaviour |
|---|---|---|
| `live` | FreeBSD + `SMARTSHIELD_ENABLE_NETWORK_APPLY=1` | All changes applied to the OS immediately |
| `dry-run` | FreeBSD + `SMARTSHIELD_NETWORK_DRY_RUN=1` | Configs validated but not applied to the kernel |
| `degraded` | FreeBSD + required daemon binaries missing | UI functional; apply operations report missing binaries |
| `development` | Non-FreeBSD host | Full UI, config generation; no OS-level changes |

---

## Key Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `SECRET_KEY` | *(required)* | Flask session encryption key |
| `SMARTSHIELD_DB_PATH` | `/var/db/smart-shield/data.db` | SQLite database path |
| `SMARTSHIELD_ENABLE_NETWORK_APPLY` | `0` | Set to `1` to allow live OS changes |
| `SMARTSHIELD_NETWORK_DRY_RUN` | `1` | Set to `0` to disable dry-run safety |
| `SMARTSHIELD_MASTER_KEY` | *(auto-generated)* | AES-256 key for encrypting secrets at rest |
| `ABUSECH_AUTH_KEY` | *(empty)* | abuse.ch personal auth key for threat intelligence |
| `GROQ_API_KEY` | *(empty)* | Groq API key to enable the AI assistant |

Full environment variable reference is in [Manual.md](Manual.md).

---

## License

This project is licensed under the MIT License. See `LICENSE` for details.

---

## Contributing

1. Fork the repository and create a feature branch.
2. Run the application in development mode (`FLASK_DEBUG=1` on a non-FreeBSD host).
3. Test configuration generation logic using dry-run mode — no FreeBSD host required for most changes.
4. Submit a pull request with a clear description of the change and its purpose.

All contributions must pass the existing test suite (`pytest tests/`) and must not introduce new dependencies without justification.
