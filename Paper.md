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
authors:
  - name: Mohamed Salah
    affiliation: 1
affiliations:
  - name: Independent Researcher
    index: 1
date: 2026-05-14
bibliography: paper.bib
---

# Summary

Smart Shield is an open-source network security appliance framework that transforms a FreeBSD
host into a fully managed security gateway. It provides a web-based graphical user interface
and a command-line operator tool that expose every major network security function — packet
filtering, network address translation, intrusion detection and prevention, virtual private
networking, DNS resolution, DHCP serving, content filtering, captive portal authentication,
real-time security event monitoring, and threat intelligence integration — as a cohesive,
auditable, and reproducible system managed without direct filesystem or daemon interaction.

The platform is built on the Flask Python web framework and communicates with FreeBSD's native
security infrastructure: the PF packet filter for stateful firewall and NAT enforcement,
Suricata for signature-based intrusion detection and netmap-accelerated inline prevention,
Unbound for validating DNS resolution, strongSwan for IPsec IKEv2 tunnels, OpenVPN for
SSL/TLS-based remote access, ISC DHCPd and Kea for address assignment, and MRTG for historical
traffic graphing. All subsystem configurations are generated from a central SQLite database,
validated against the daemon's own syntax checker before application, and written atomically
with automatic rollback on failure.

Smart Shield targets three primary audiences: network administrators who need to deploy and
manage a FreeBSD-based security gateway through a structured web interface rather than
shell configuration; security practitioners and researchers who require an auditable,
reproducible gateway environment for network security experimentation and policy testing; and
educators who need a platform that makes enterprise-grade network security concepts accessible
and operable in a laboratory or classroom setting.

---

# Statement of Need

Deploying a multi-function FreeBSD network security gateway traditionally requires deep
familiarity with a large set of independent configuration file formats: `pf.conf` for the
packet filter, `suricata.yaml` for the IDS engine, `unbound.conf` for DNS, `dhcpd.conf` for
address assignment, `ipsec.conf` and `ipsec.secrets` for IPsec, `openvpn/*.conf` for VPN
tunnels, and individual rc.conf directives for service management. Each daemon is configured
independently, lacks awareness of changes in the others, and requires manual coordination to
enforce a consistent security policy.

Smart Shield addresses this by providing a unified data model — a single SQLite relational
database — that serves as the authoritative source for all subsystem configurations. When an
administrator defines a firewall alias, that alias is automatically available to firewall
rules, NAT policies, and traffic shaping queues. When a DHCP lease is assigned, the SIEM
collector enriches subsequent IDS and connection events with the device's hostname and MAC
address. When a domain is added to the DNS blocklist, the same rule set feeds both the Unbound
response policy and the optional PF anchor. This cross-subsystem coherence is difficult to
achieve and maintain manually across independent daemon configuration files.

The platform also addresses the operational burden of configuration validation and rollback.
Each daemon provides a syntax-checking mode (`pfctl -nf`, `dhcpd -t`, `unbound-checkconf`,
`suricata -T`); Smart Shield invokes these checks automatically before every apply operation
and discards any configuration that fails validation. A known-good backup is maintained for
each managed file and is restored automatically if the daemon fails to restart after a
configuration change.

For security education and research, Smart Shield's dry-run mode enables full exploration of
the web interface and configuration generation on any platform (including non-FreeBSD
development machines) without requiring a live network or a physical appliance. The entire
policy model — firewall rules, NAT, IDS profiles, VPN tunnels, content filters — can be
designed and reviewed before deployment.

---

# Implementation

## Application Architecture

Smart Shield is structured as a Flask WSGI application served by Gunicorn (two workers by
default) behind an nginx TLS reverse proxy. The application factory registers seventeen route
blueprints, each responsible for a major feature area: firewall, NAT, VPN, services (DHCP,
DNS, NTP, SNMP, UPnP), interfaces, routing, IDS, content filters, status and monitoring,
diagnostics, users, setup wizard, captive portal, and the AI assistant.

All user-facing state is stored in a SQLite database containing over sixty tables. The schema
covers network interface configuration, firewall rules (floating, WAN, LAN), NAT (port
forwarding, 1:1, outbound, NPt), routing, DHCP pools, DNS overrides, VPN profiles, IDS
settings, content filter rules, user accounts, group permissions, session data, and audit
records. Sensitive values (VPN pre-shared keys, SNMP community strings, API tokens) are
encrypted at rest using AES-256-GCM with a PBKDF2-derived master key stored in the
environment file.

## Configuration Generation and Application

Each managed daemon has a corresponding writer module (`pf_generator.py`,
`ids_writer.py`, `dns_writer.py`, `dhcp_writer.py`, `openvpn_writer.py`, `ipsec_writer.py`,
`mrtg_writer.py`, and others) that reads the database and produces the daemon's native
configuration format as a string. Configuration files are written atomically via a
temporary-file rename pattern. A backup of the previous configuration is kept for each service
and is automatically restored if the daemon fails to start after a reload.

The system supports three runtime modes controlled by environment variables: **live mode**
(changes are applied to the OS), **dry-run mode** (changes are validated but not applied to
the kernel), and **development mode** (full UI on non-FreeBSD hosts; no OS operations).

## SIEM Collection

Five daemon threads run in the background and feed a central append-only NDJSON audit log:

1. **IDS alert collector** tails `/var/log/suricata/eve.json` every 10 seconds using persistent
   byte-offset tracking; events are enriched with hostname and MAC address from the DHCP
   lease inventory.
2. **DHCP event collector** parses `/var/db/dhcpd/dhcpd.leases` every 30 seconds and
   maintains the tracked-host inventory.
3. **DNS query collector** tails `/var/log/unbound/query.log` every 15 seconds; only blocked
   queries, NXDOMAIN, and SERVFAIL responses are logged to control volume.
4. **PF state tracker** runs `pfctl -s states` every 60 seconds, identifies new LAN-originated
   connections by delta against the previous snapshot, and raises security alerts for
   plaintext protocols (Telnet, FTP, VNC, NetBIOS).
5. **Anomaly detector** analyzes a sliding 5-minute window over the 300 most recent audit
   events every 60 seconds; it raises high-severity alerts for brute-force patterns
   (five or more failed logins from the same IP) and IDS floods (ten or more alerts from
   the same source IP), with a 10-minute per-source cooldown.

File offsets for the IDS and DNS collectors are persisted in the `siem_state` database table
and survive application restarts.

## Threat Intelligence

An additional background thread queries the abuse.ch ThreatFox API every four hours, extracts
IPv4 indicators of compromise, deduplicates them, and pushes the result to the `ss_threat_intel`
PF table via `pfctl -t ss_threat_intel -T replace`. This integrates live threat intelligence
directly into the packet filter without administrator interaction. Users can also manually
look up URLs, file hashes, and domains against URLhaus, MalwareBazaar, and ThreatFox through
the Threat Detection page.

## Security Hardening

The nginx configuration enforces TLS 1.2/1.3-only with a curated cipher suite, HSTS with a
two-year max-age, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and
`Referrer-Policy: strict-origin-when-cross-origin`. All state-mutating HTTP requests are
protected by a per-session CSRF token. Brute-force protection tracks failed login attempts
per IP address and per username and enforces configurable lockout thresholds. Sensitive
database columns are encrypted with AES-256-GCM.

## AI Assistant

An optional AI assistant backed by the Groq inference API (llama-3.3-70b-versatile) provides
natural-language access to the platform. The assistant is given read-only tools to query all
major subsystems (health status, firewall rules, DHCP leases, IDS alerts, content policy,
VPN tunnels, tracked hosts) and three write tools — adding a firewall block rule, blocking a
domain, and unblocking a domain — each of which requires explicit user confirmation before
execution. The agent operates in a bounded function-calling loop with a maximum of eight
iterations per query.

## CLI and Console Access

The `smartshieldctl` operator utility provides service control (`start`, `stop`, `restart`,
`status`, `enable`, `disable`), network interface management (`list-nics`, `assign`,
`iface-show`, `iface-set`), diagnostics (`ping`, `pf-status`, `apply-pf`, `preflight`,
`vpn-status`, `dhcp-status`, `dns-status`, `sysinfo`), log access (`logs`, `audit`, `access`),
and administration (`passwd`, `factory-reset`, `ssh`, `shell`, `menu`). An interactive
console recovery menu (`smart_shield_console`) provides equivalent access over a serial
console or out-of-band SSH session when the web interface is unavailable.

---

# Features

## Firewall and NAT

The PF generator produces a complete `pf.conf` from the database, including macro definitions
for aliases, table declarations (bogons, private networks, threat intelligence IPs), floating
rules, interface-specific ingress rules, outbound NAT with masquerade or static mapping, port
forwarding, 1:1 binat, IPv6 NPt, ALTQ traffic shaping queues, dummynet limiter assignments,
CARP virtual IP rules, and policy-based routing via `route-to` directives. Firewall schedules
integrate with rules to enable time-based activation. Every rule change is previewed through
`pfctl -nf` before the live table is updated.

## VPN

Smart Shield manages three VPN technologies simultaneously. OpenVPN supports multiple server
instances (UDP or TCP, configurable port and encryption suite) with a PKI backed by the
certificate manager, plus client instances and client-specific overrides for per-user routing.
IPsec is configured through strongSwan's swanctl interface supporting IKEv2 with
certificate or PSK authentication, configurable Phase 1 and Phase 2 algorithm suites,
perfect forward secrecy, dead peer detection, and mobile client (roadwarrior) mode.
L2TP/IPsec is managed through mpd5.

## DNS and Content Filtering

Unbound is configured as a recursive or forwarding resolver with optional DNSSEC validation,
DNS-over-TLS upstream, host and domain overrides, per-subnet access control, and query
logging for SIEM integration. The DNS filter layer adds response policy entries that redirect
or block domains defined in the content policy database. Web and application filters extend
this with URL pattern and port/signature matching.

## Captive Portal

The captive portal intercepts unauthenticated LAN traffic at the PF level, redirecting HTTP
to a login page and TLS to a block page on port 5443. Two enforcement modes are available:
soft mode redirects only HTTP while passing other traffic, and strict mode blocks all traffic
except DNS and DHCP until the user authenticates. Sessions track bandwidth and time limits;
pre-generated voucher codes provide time-bounded guest access.

---

# Acknowledgements

Smart Shield is built on and would not be possible without the following open-source projects
and services: the FreeBSD operating system and its PF packet filter; Suricata and the OISF
community; Unbound from NLnet Labs; strongSwan; OpenVPN; ISC DHCP; Kea from ISC; MRTG by
Tobias Oetiker; Flask, Werkzeug, Jinja2, Gunicorn, and the broader Python packaging
ecosystem; nginx; the Groq inference platform; and the abuse.ch project and its threat
intelligence services (URLhaus, MalwareBazaar, ThreatFox).

---

# References

- Belshe, M., Peon, R., & Thomson, M. (2015). *Hypertext Transfer Protocol Version 2
  (HTTP/2)*. RFC 7540. IETF.
- OISF. (2024). *Suricata Open Source IDS/IPS/NSM engine*. Open Information Security
  Foundation. https://suricata.io
- Wijngaards, W. (2010). *Unbound: Validating, Recursive, and Caching DNS Resolver*.
  NLnet Labs. https://unenlabs.net
- Steffen, A., & Tschofenig, H. (2024). *strongSwan: The OpenSource IPsec-based VPN
  Solution*. https://www.strongswan.org
- OpenVPN Inc. (2024). *OpenVPN 2.x Manual*. https://openvpn.net
- Internet Systems Consortium. (2024). *ISC DHCP 4.4 Administrator Reference Manual*.
  https://www.isc.org
- Oetiker, T., & Rand, D. (1998). *MRTG — The Multi Router Traffic Grapher*.
  https://oss.oetiker.ch/mrtg/
- Pallets Projects. (2024). *Flask: web development, one drop at a time*.
  https://flask.palletsprojects.com
- Rekhter, Y., Moskowitz, B., Karrenberg, D., de Groot, G., & Lear, E. (1996).
  *Address Allocation for Private Internets*. RFC 1918. IETF.
- Abley, J., Savola, P., & Neville-Neil, G. (2006). *Deprecation of Type 0 Routing
  Headers in IPv6*. RFC 5095. IETF.
