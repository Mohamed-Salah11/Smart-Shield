---
title: 'Smart Shield: A Web-Managed Network Security Appliance for FreeBSD'
tags:
  - network security
  - firewall
  - intrusion detection
  - FreeBSD
  - Python
  - Flask
  - SIEM
  - VPN
  - SOC
authors:
  - name: Mohamed Salah
    affiliation: 1
affiliations:
  - name: Independent Researcher
    index: 1
date: 2026-05-19
bibliography: paper.bib
---

# Summary

Smart Shield is an open-source network security appliance framework that
transforms a FreeBSD host into a fully managed security gateway. It exposes
every major network security function — packet filtering, network address
translation, intrusion detection and prevention, virtual private networking,
DNS resolution, DHCP serving, content policy (DNS / web / application
filtering), captive portal authentication, real-time SIEM monitoring, and
threat intelligence integration — through a unified web interface and a
command-line operator tool. Two distinct operator surfaces ship in one
deployment: a firewall/admin web GUI for everyday gateway management and a
**Smart Shield SOC Portal** for L1/L2/L3 security analysts, with a strict
separation so analyst activity never bleeds into the appliance dashboard.

The platform is built on the Flask Python web framework and communicates
with FreeBSD's native security infrastructure: the PF packet filter,
Suricata for signature-based intrusion detection and netmap-accelerated
inline prevention, Unbound for validating DNS resolution, strongSwan for
IPsec IKEv2 tunnels, OpenVPN for SSL/TLS-based remote access, ISC DHCPd and
Kea for address assignment, and MRTG for historical traffic graphing. All
subsystem configurations are generated from a central SQLite database,
validated against the daemon's own syntax checker, written atomically via
temporary-file rename, and automatically rolled back to a known-good backup
when a daemon reload fails. A unified `ApplyResult` data class wraps every
writer's outcome — validation output, rollback flag, message — so the UI
can show a consistent per-component apply status.

Smart Shield targets three primary audiences: network administrators who
need to deploy and manage a FreeBSD-based security gateway through a
structured web interface rather than shell configuration; security
practitioners and researchers who require an auditable, reproducible
gateway environment for network security experimentation and policy
testing; and educators who need a platform that makes enterprise-grade
network security concepts accessible and operable in a laboratory or
classroom setting.

---

# Statement of Need

Deploying a multi-function FreeBSD network security gateway has historically
required deep familiarity with a large set of independent configuration file
formats: `pf.conf`, `suricata.yaml`, `unbound.conf`, `dhcpd.conf`,
`ipsec.conf`, `openvpn/*.conf`, and individual `rc.conf` directives. Each
daemon is configured independently, lacks awareness of changes in the
others, and requires manual coordination to enforce a consistent security
policy.

Smart Shield addresses this with a unified data model — one SQLite
database — that serves as the authoritative source for every subsystem.
Defining a firewall alias makes it available to firewall rules, NAT, and
traffic shaping. Assigning a DHCP lease enriches subsequent IDS and
connection events with the device's hostname and MAC. Adding a domain to a
content filter routes through a single deduplication pipeline before
Unbound writes `local-zone` records, so the same domain appearing in
multiple filters never produces conflicting daemon directives. This
cross-subsystem coherence is difficult to achieve and maintain when each
daemon is configured by hand in its own file.

The platform also addresses the operational burden of configuration
validation and rollback. Each daemon provides a syntax-checking mode
(`pfctl -nf`, `dhcpd -t`, `unbound-checkconf`, `suricata -T`); Smart
Shield invokes these automatically before every apply operation and
discards any configuration that fails validation. A known-good backup is
maintained for each managed file and is restored automatically if the
daemon fails to restart.

A third operational concern — analyst workflow — is met by the integrated
SOC Portal. Many SMB deployments share a single appliance between gateway
administration and SOC operations. Without separation, analyst activity
(investigations, emergency blocks, escalations) pollutes the firewall log
and obscures genuine appliance events. Smart Shield tags every SOC action
with `details.soc_origin = true` and filters those events out of the
firewall log API by default. The result is two clean operator views over a
single shared audit store.

For education and research, Smart Shield's dry-run mode allows full
exploration of the web interface and configuration generation on any
platform (including non-FreeBSD development machines) without requiring a
live network or a physical appliance. The entire policy model — firewall
rules, NAT, IDS profiles, VPN tunnels, content policy, SOC tier
permissions — can be designed and reviewed before deployment.

---

# Implementation

## Application Architecture

Smart Shield is structured as a Flask WSGI application served by Gunicorn
(gevent workers) behind an nginx TLS reverse proxy. The application factory
registers route blueprints organised by feature area:

- Package-style blueprints under `routes/`: `firewall/`, `system/`,
  `services/`, `vpn/`, `diagnostics/`, `network_api/`.
- Standalone blueprints: `auth`, `status`, `ids`, `filters`, `portal`,
  `soc`, `soc_portal`, `terminal`, `setup`, `users`, `chatbot`,
  `interfaces`, `routing`, `hec`, `vpn_portal`.

All user-facing state lives in a SQLite database containing 70+ tables.
Sensitive values (VPN pre-shared keys, PPPoE passwords, RADIUS secrets,
API tokens) are encrypted at rest with AES-256-GCM using a PBKDF2-derived
master key stored in the environment file (`/usr/local/etc/smart-shield/
smart-shield.env`). The rc.d service explicitly **exports** the
`SMARTSHIELD_ENV_FILE` path so the Flask application and every Gunicorn
worker load the same env file irrespective of working directory — a
consistency property required for reproducible production startup.

## Configuration Generation and Application

Each managed daemon has a corresponding writer module (`pf_generator.py`,
`ids_writer.py`, `dns_writer.py`, `dhcp_writer.py`, `openvpn_writer.py`,
`ipsec_writer.py`, `mrtg_writer.py`, and others) that reads the database
and produces the daemon's native configuration. Writers follow a uniform
pipeline:

1. Generate the configuration text in memory.
2. Validate by invoking the daemon's syntax checker on a temporary file.
3. On success, save the current on-disk config as a known-good backup.
4. Atomically replace the live config via temporary-file rename.
5. Reload the service.
6. On failure, restore the known-good backup and reload the previous config.
7. Record the outcome via `apply_state.py`.

The `ApplyResult` data class (`app/services/apply_state.py`) provides a
typed return shape — `ok`, `component`, `action`, `message`,
`validation_output`, `rollback_performed` — that every writer can adapt
its legacy dict result into. Per-component apply state (saved, pending,
applying, applied, failed, rolled_back, dry-run, unsupported) is persisted
to `feature_applied_state` so the UI shows a stable badge per component.

The system supports three runtime modes controlled by environment
variables: **live mode** (changes applied immediately), **dry-run mode**
(generated and validated but never written to the kernel), and
**development mode** (full UI on non-FreeBSD hosts; no OS operations).

## Content Policy Deduplication

DNS, web, and application filtering each express rules in their own
table, but ultimately funnel into the same Unbound `local-zone` /
`local-data` directive surface. Overlapping domains across the three
filters would otherwise produce duplicate `local-zone` entries that
`unbound-checkconf` rejects.

The `content_policy.py` module solves this with a unified
`DomainPolicy` data class and a `build_domain_policy_map(conn)`
function. Every enabled rule is normalised (lowercased, stripped of
scheme/path/wildcard prefixes, validated against domain label syntax)
and inserted into a single dictionary keyed by the normalised domain.
When two filters name the same domain, the resolver picks the
higher-precedence rule using the order:

```
allow (whitelist-only)  >  SOC emergency block  >  App filter
                       >  Web filter            >  DNS manual
```

`emit_unbound_policy_zones()` then produces exactly one `local-zone` and
(where applicable) one `local-data` record per blocked domain. The
generator output is alphabetically sorted, which yields stable diffs
across runs — useful for the apply/rollback story since a known-good
backup is a textual comparison target.

## SIEM Collection

Five daemon threads run in the background and feed a central
append-only NDJSON audit log mirrored into an indexed `events` SQLite
table:

1. **IDS alert collector** tails `/var/log/suricata/eve.json` every 10 s
   using persistent byte-offset tracking; events are enriched with the
   tracked-host inventory (hostname + MAC).
2. **DHCP event collector** parses `/var/db/dhcpd/dhcpd.leases` every 30 s
   and maintains the tracked-host inventory used by the other
   collectors.
3. **DNS query collector** tails `/var/log/unbound/query.log` every 15 s;
   only blocked, NXDOMAIN, and SERVFAIL responses are logged to control
   volume.
4. **PF state tracker** runs `pfctl -s states` every 60 s, identifies new
   LAN-originated connections by delta against the previous snapshot, and
   raises security alerts for plaintext protocols (Telnet, FTP, VNC,
   NetBIOS).
5. **Anomaly detector** analyses a sliding 5-minute window over the 300
   most recent audit events every 60 s; raises high-severity alerts for
   brute-force patterns and IDS floods with per-source cooldown.

File offsets for the IDS and DNS collectors are persisted in the
`siem_state` table and survive application restarts.

## Threat Intelligence

A background thread queries the abuse.ch ThreatFox API every four hours,
extracts IPv4 indicators of compromise, deduplicates them, and pushes the
result into the `ss_threat_intel` PF table via
`pfctl -t ss_threat_intel -T replace`. The integration is dry-run by
default; flipping `ABUSECH_DRY_RUN=0` enables live ingestion. Users can
also manually look up URLs, hashes, and domains against URLhaus,
MalwareBazaar, and ThreatFox through the Threat Detection page.

## Smart Shield SOC Portal

The SOC Portal is a separate Flask blueprint (`routes/soc_portal.py`)
rendering templates from `templates/soc_portal/` over an independent
visual identity. It shares the appliance database — there is one audit
log, one event store — but every action originating from a SOC user is
logged via `log_soc_event()` which stamps `details.soc_origin = true`.
The firewall-side log API (`/status/api/logs`) filters those records out
by default; a superuser may explicitly opt back in with `?hide_soc=0`.
The portal supports an L1/L2/L3 tier model implemented as the
`groups.soc_tier` column added during a later database migration.

## Security Hardening

The nginx configuration enforces TLS 1.2/1.3 with a curated cipher suite,
HSTS with a two-year max-age, `X-Frame-Options: DENY`,
`X-Content-Type-Options: nosniff`, and
`Referrer-Policy: strict-origin-when-cross-origin`. All state-mutating
HTTP requests are protected by a per-session CSRF token validated by an
application-level `before_request` hook. Brute-force protection tracks
failed login attempts per IP and per username and enforces configurable
lockout thresholds. Sensitive database columns are encrypted with
AES-256-GCM.

The optional web Appliance Console — a browser PTY shell — is off by
default and ships with a layered protection model:

1. A database flag (`advanced_admin_access.terminal_enabled`) that the
   superuser must explicitly turn on; until then both the page and the
   WebSocket endpoint return 404.
2. Superuser-only access on both the HTTP and WebSocket paths.
3. Recent reauth check (≤300 s) re-evaluated at the time the WebSocket
   ticket is issued and again at the time the WS connects.
4. WebSocket Origin check rejects cross-site WebSocket hijacking.
5. Single-use HMAC-SHA256 ticket bound to user id + remote address,
   valid for ≤60 s, with a per-process replay guard.
6. Command-level audit logging via a `redact_secrets()` helper that
   replaces `password=…`, `secret_key=…`, `token=…`, `Authorization:
   Bearer …`, and `-----BEGIN … PRIVATE KEY-----` blocks before the
   record reaches the audit log.

## AI Assistant

An optional AI assistant backed by the Groq inference API
(llama-3.3-70b-versatile) provides natural-language access to the
platform. The assistant is given read-only tools to query all major
subsystems (health, firewall rules, DHCP leases, IDS alerts, content
policy, VPN tunnels, tracked hosts, audit log) and three write tools —
adding a firewall block rule, blocking a domain, and unblocking a
domain — each of which requires explicit user confirmation before
execution. The agent operates in a bounded function-calling loop with a
maximum of eight iterations per query.

## CLI and Console Access

The `smartshieldctl` operator utility provides service control, network
interface management, diagnostics, log access, and administration. An
interactive console recovery menu (`smart_shield_console`) provides
equivalent access over a serial console or out-of-band SSH session when
the web interface is unavailable. Both are installed under
`/usr/local/sbin/` and remain available even when the web Appliance
Console is disabled — they are independent operator surfaces.

---

# Features

## Firewall and NAT

The PF generator produces a complete `pf.conf` from the database,
including macros for aliases, table declarations (bogons, private
networks, threat-intelligence IPs, authenticated portal clients, admin
bypass clients, device whitelist, SOC blocklist), floating rules,
interface-specific ingress rules, outbound NAT, port forwarding, 1:1
binat, IPv6 NPt, ALTQ traffic shaping, dummynet limiter assignments,
CARP virtual IP rules, and policy-based routing via `route-to`. Every
rule change is previewed through `pfctl -nf` before the live ruleset is
replaced. Application-filter rules are scoped to LAN ingress
(`block in log quick on $LAN_IFACE …`) so they only affect downstream
clients and never WAN-side or inter-VLAN traffic.

## VPN

Smart Shield manages three VPN technologies in parallel. OpenVPN supports
multiple server instances (UDP or TCP, configurable port and encryption
suite) backed by an in-database PKI, plus client instances and
client-specific overrides for per-user routing. IPsec is configured
through strongSwan's swanctl interface, supporting IKEv2 with certificate
or PSK authentication, configurable Phase 1 and Phase 2 algorithm suites,
perfect forward secrecy, dead peer detection, and mobile-client
(roadwarrior) mode. L2TP/IPsec is managed through mpd5.

## DNS, Content Policy, and Captive Portal

Unbound is configured as a recursive or forwarding resolver with optional
DNSSEC validation, DNS-over-TLS upstream, host and domain overrides,
per-subnet ACLs, and query logging. The content-policy pipeline
deduplicates DNS, web, and application-filter rules into a single
`local-zone` set and emits redirect zones pointing at the LAN IP so
blocked HTTP traffic lands on Smart Shield's block page.

The captive portal intercepts unauthenticated LAN traffic at the PF level
in two modes — soft (only HTTP redirected) and strict (all traffic
blocked pre-auth except DNS and DHCP). HTTPS traffic cannot be cleanly
intercepted without TLS interception; the block page now explicitly
documents this limitation so end users understand why their HTTPS
attempts fail with a certificate warning rather than landing on the block
page.

---

# Acknowledgements

Smart Shield is built on and would not be possible without the following
open-source projects and services: the FreeBSD operating system and its
PF packet filter; Suricata and the OISF community; Unbound from NLnet
Labs; strongSwan; OpenVPN; ISC DHCP; Kea from ISC; MRTG by Tobias
Oetiker; Flask, Werkzeug, Jinja2, Gunicorn, and the broader Python
packaging ecosystem; nginx; the Groq inference platform; xterm.js; and
the abuse.ch project and its threat intelligence services (URLhaus,
MalwareBazaar, ThreatFox).

---

# References

- Belshe, M., Peon, R., & Thomson, M. (2015). *Hypertext Transfer Protocol Version 2 (HTTP/2)*. RFC 7540. IETF.
- OISF. (2024). *Suricata Open Source IDS/IPS/NSM engine*. Open Information Security Foundation. https://suricata.io
- Wijngaards, W. (2010). *Unbound: Validating, Recursive, and Caching DNS Resolver*. NLnet Labs. https://www.nlnetlabs.nl/projects/unbound/
- Steffen, A., & Tschofenig, H. (2024). *strongSwan: The OpenSource IPsec-based VPN Solution*. https://www.strongswan.org
- OpenVPN Inc. (2024). *OpenVPN 2.x Manual*. https://openvpn.net
- Internet Systems Consortium. (2024). *ISC DHCP 4.4 Administrator Reference Manual*. https://www.isc.org
- Oetiker, T., & Rand, D. (1998). *MRTG — The Multi Router Traffic Grapher*. https://oss.oetiker.ch/mrtg/
- Pallets Projects. (2024). *Flask: web development, one drop at a time*. https://flask.palletsprojects.com
- Rekhter, Y., Moskowitz, B., Karrenberg, D., de Groot, G., & Lear, E. (1996). *Address Allocation for Private Internets*. RFC 1918. IETF.
- Abley, J., Savola, P., & Neville-Neil, G. (2006). *Deprecation of Type 0 Routing Headers in IPv6*. RFC 5095. IETF.
