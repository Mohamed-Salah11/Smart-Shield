---
title: 'Smart-Shield: An Open-Source, Web-Managed Network Security Operations Platform with Integrated Firewall, IDS/IPS, SIEM, Threat Intelligence, VPN, and AI-Assisted Administration'
tags:
  - network security
  - firewall
  - FreeBSD
  - VPN
  - IDS/IPS
  - SIEM
  - threat intelligence
  - open-source
  - Python
  - cybersecurity
  - SOC
authors:
  - name: Mohamed Salah Eldein
    orcid: <<FILL_IN: ORCID for corresponding author, e.g. 0000-0002-1825-0097>>
    corresponding: true
    affiliation: 1
  - name: Amin Abd El-Hamid Salem
    affiliation: 1
  - name: Fady Ayman Metry
    affiliation: 1
  - name: Yehia Mahmoud Mohamed
    affiliation: 1
  - name: Ahmed Adel Mohamed
    affiliation: 1
  - name: Kirollos Nader Hanna
    affiliation: 1
  - name: Sami Khaled El Masri
    affiliation: 1
  - name: Ahmed Sayed Younis
    affiliation: 1
  - name: Ahmed Gaber Abuabdullah
    affiliation: 1
affiliations:
  - name: The Higher Canadian Institute for Engineering Technology and Business, Egypt
    index: 1
date: 30 May 2026
bibliography: paper.bib
---

# Summary

Smart-Shield is a research prototype of an open-source, hardware-independent network security platform built on FreeBSD and administered through a web browser. It functions as a firewall appliance, a full-featured network router, and an integrated Security Operations Center (SOC) portal — three roles traditionally requiring separate products — in a single unified system. It targets small organizations, academic networks, research labs, and home users, replacing multiple commercial products: a stateful firewall, NAT and traffic shaping, intrusion detection and prevention (IDS/IPS), a built-in SIEM engine with seven concurrent log collectors, automated threat intelligence feeds from abuse.ch, VPN management (OpenVPN, IPsec/IKEv2, L2TP), DNSSEC-validating DNS, content filtering, a captive portal, high-availability failover, encrypted backup and rollback, role-based access control, and an AI-powered assistant that answers security questions in plain English. The integrated SOC module allows security teams to triage, assign, and resolve incidents without leaving the platform. The platform exposes approximately 700 routes across 23 route blueprints, backed by a SQLite database, with an installer script, CLI control tool, and recovery console [@freebsd2024; @groq2024].

# Statement of Need

Effective network security operations require a layered stack of capabilities — firewalling, intrusion detection, log aggregation and correlation, threat intelligence, encrypted remote access, and team-based incident response — that are typically delivered by separate commercial products at significant cost [@lamdakkar2024; @patel2024]. For small enterprises, university research networks, and independent security researchers, assembling and operating such a stack is prohibitively expensive and demands dedicated specialist staff.

Existing open-source alternatives like pfSense and OPNsense address firewalling and VPN but do not provide an integrated SIEM, automated threat intelligence ingestion, SOC team workflows, or AI-assisted administration. Research on intelligent and adaptive security systems [@ahmadi2025; @haydari2023; @apruzzese2022] demonstrates the value of these capabilities but has not produced openly deployable, unified implementations with usable, integrated management interfaces.

This gap creates a direct barrier for security research as well. Researchers studying firewall policy effectiveness, VPN fingerprinting attacks [@xue2024], anomaly detection algorithms, or AI-driven threat response need a fully instrumented, controllable security platform to run experiments on. Smart-Shield fills this gap by providing a freely deployable, fully open-source security operations platform that serves both as a network gateway and as a research and education testbed. It is designed for network administrators, security researchers, system integrators, and students who need comprehensive, integrated security capabilities without licensing costs.

# State of the field

The most widely deployed open-source firewall distributions — **pfSense** and its fork **OPNsense** — offer capable packet filtering, NAT, and VPN support, but are packaged as closed, self-contained operating system distributions that are difficult to extend with custom application logic, external AI services, or integrated SOC workflows. Studies confirm that despite their capabilities, these tools present significant usability and integration barriers in resource-constrained environments [@lamdakkar2024].

Research on intelligent firewalls and adaptive security has proposed machine-learning-driven rule generation [@haydari2023], reinforcement learning for dynamic policy optimization [@ahmadi2025], machine-learning-based intrusion detection [@apruzzese2022], deep-learning anomaly detection [@almuhanna2025], NLP-based malware detection in firewalls [@moila2026], and ML-based firewall log classification [@faker2023]. These works establish compelling directions but have not produced publicly deployable systems with usable management interfaces. Research on VPN security has demonstrated real vulnerabilities such as traffic fingerprinting [@xue2024] that require integrated log monitoring and AI-assisted analysis to detect reliably.

Smart-Shield's contribution is a unified, extensible, hardware-independent platform that integrates all of these capabilities into a single deployable system with a clean Python backend open to modification. Full documentation, installation instructions, usage examples, and a test suite of more than 1,300 test cases are provided in the repository.

# Software Design and Functionality

Smart-Shield is built around a Flask web application (Python 3, Gunicorn, Nginx reverse proxy) backed by a SQLite database. All system configuration is persisted in the database and applied to the OS through a transaction pipeline of more than 15 configuration writers that generate and atomically apply daemon configuration files, with syntax validation and automatic rollback to a known-good state on failure.

![Smart-Shield login page providing secure administrator authentication before granting access to the management interface.](login.png)

![Smart-Shield main dashboard with the navigation sidebar expanded, showing system status widgets for firewall rules, VPN servers, users, security rules, and interface status.](dashboard.png)

![Smart-Shield widget manager allowing administrators to customize the dashboard by enabling or disabling monitoring widgets for firewall rules, VPN servers, users, security rules, and traffic monitoring.](widgets.png)

## Firewall, NAT, and Traffic Shaping

The firewall module manages FreeBSD's PF packet filter through 43 API endpoints, supporting floating, WAN, and LAN rule sets; policy-based routing; anti-spoof protection; bogon blocking; and PF anchors for subsystem isolation. Every ruleset change is validated with `pfctl -nf` before applying, and a `.known_good` backup is restored automatically on failure. Network address translation covers port forwarding, 1:1 binat, outbound masquerade, IPv6 NPt, and NAT reflection. Traffic shaping is implemented through ALTQ queue disciplines (HFSC, CBQ, PRIQ, FAIRQ) and dummynet bandwidth limiters with per-flow pipe control for quality-of-service enforcement.

## Network Interfaces, Routing, and High Availability

The platform manages the full range of FreeBSD virtual interface types: VLANs (802.1Q), bridges, LAGG bonding, GRE and GIF tunnels, and PPPoE WAN connections. An interface assignment wizard maps physical NICs to WAN, LAN, and optional interface roles. Gateway management supports static routes, tiered failover groups, load-balanced equal-cost multi-path routing, and a background ICMP health monitor that updates gateway status in the database every 30 seconds. High-availability deployments are supported through CARP virtual IP failover and pfsync state synchronization for active-passive node pairs.

## Intrusion Detection and Prevention

Smart-Shield integrates Suricata [@suricata2024], which operates in passive IDS mode via BPF packet capture or in active inline IPS mode via netmap for wire-speed in-path blocking. Suricata YAML configuration is generated programmatically and validated with `suricata -T` before being applied. Rule sets are managed through the Emerging Threats feed via suricata-update, with support for additional custom URL sources.

![Smart-Shield IDS/IPS configuration page showing mode selection between passive IDS (BPF capture) and inline IPS (netmap bridging), interface assignment, HOME_NET and EXTERNAL_NET definitions, and EVE JSON logging options.](ids_ips_config.png)

![Smart-Shield Threat Detection status page showing Suricata running in IDS mode on interface em1 with 49,874 active signatures across 2 rulesets, zero alerts today, and a live-refreshing daemon log.](ids_ips_status.png)

## SIEM and Anomaly Detection

A built-in SIEM engine runs seven concurrent background collection threads covering: IDS alerts (EVE JSON, polled every 10 seconds), DHCP lease events (30 seconds), DNS query logs (15 seconds), PF connection states (60 seconds), SSH and authentication logs (15 seconds), system messages (30 seconds), and pattern-based anomaly detection targeting brute-force attempts and IDS flood patterns (60 seconds). All collectors use persistent file-offset tracking in the database to prevent duplicate event ingestion across restarts. A live SIEM event stream is available from the dashboard, and the complete audit log is exportable as filtered JSON.

## Threat Intelligence

Smart-Shield automatically ingests threat intelligence from three abuse.ch feeds every four hours: URLhaus (malicious URLs and hosts), MalwareBazaar (file hashes), and ThreatFox (IP, domain, and hash indicators of compromise). Newly identified malicious IP addresses are atomically pushed into a live PF table (`ss_threat_intel`), causing the firewall to block them without administrator intervention and keeping defenses current against newly published threats.

## VPN

The VPN module manages OpenVPN server and client instances (multi-instance, TUN/TAP, AES-256-GCM), IPsec/IKEv2 via strongSwan (Phase 1 and 2, roadwarrior mobile clients, EAP-MSCHAPv2, PSK), and L2TP/IPsec via mpd5. A three-step OpenVPN setup wizard automates certificate authority creation, server certificate signing, and server configuration. All private keys and pre-shared secrets are encrypted at rest using AES-256-GCM. All VPN traffic passes through the same firewall and IDS/IPS enforcement pipeline as other network flows.

## DNS, DHCP, and Content Filtering

The DNS module provides an Unbound recursive resolver with DNSSEC validation, DNS-over-TLS upstream forwarding, per-subnet access control lists, host and domain overrides, and full query logging. DHCP services cover ISC DHCPd for IPv4 (address pools, static leases, relay) and Kea for DHCPv6 with prefix delegation and router advertisement. Content filtering operates at three layers: DNS-level blocking and redirection via Unbound local-zone directives applied without service restart through `unbound-control`, web URL pattern filtering, and application-layer blocking with 18 built-in signatures covering major consumer platforms. A conflict detection engine identifies cross-layer allow/block contradictions before applying policy.

## Captive Portal and Network Services

The captive portal provides HTTP/HTTPS redirect gateway functionality with soft and strict enforcement modes, local user authentication, time- and bandwidth-limited voucher codes, session tracking by MAC and IP address, and RADIUS authentication support. Additional network services include Dynamic DNS via ddclient (10+ providers and RFC 2136 nsupdate), NTP, SNMP via bsnmpd, UPnP/NAT-PMP via miniupnpd, IGMP multicast proxy, Wake-on-LAN, and MRTG traffic graphs at daily, weekly, monthly, and yearly resolutions.

## Certificate Management

An integrated certificate authority supports CA creation, server and client certificate signing with SAN support, certificate revocation and CRL generation, PKCS#12 and PEM export, Let's Encrypt / ACME certificate issuance via certbot, and OCSP stapling. All private keys are encrypted at rest.

## Security, Authentication, and SOC Collaboration

The platform implements session-based authentication with signed cookies, PBKDF2 password hashing, per-IP and per-username brute-force lockout, CSRF protection on all state-changing requests, API key authentication with per-key permission scoping, idle session timeout, re-authentication for sensitive operations, and a complete NDJSON audit log of every state-changing action with user identity, IP address, and timestamp. Role-based access control allows multi-user deployments with per-group, page-level permissions and wildcard permission grants. The integrated SOC module provides a separate login realm for security operations staff, within which analysts can triage IDS and SIEM alerts, assign incidents to team members, track investigation status, and log response actions.

![Smart-Shield SOC Portal Control page, where administrators configure the dedicated SOC analyst endpoint, bind IP address, HTTPS port, and TLS certificate separately from the main firewall console.](soc_portal_control.png)

![Smart-Shield SOC Portal login screen, showing the dedicated authentication interface for L1, L2, and L3 analyst tiers, separate from the administrator UI.](soc_login.png)

![Smart-Shield SOC Overview dashboard displaying live case counts, alert queue, threat feed status, and open incidents for an authenticated L1 analyst.](soc_overview.png)

## AI Assistant

The AI assistant is built on the Groq API (llama-3.3-70b-versatile model) [@groq2024] and is accessible from the dashboard as a natural language interface. More than 12 read-only tools give the assistant access to live system state: firewall rules, IDS alerts, DHCP leases, VPN status, audit logs, tracked hosts, content policy, and network configuration. Write tools (block/unblock a domain, add a firewall rule) use a two-stage confirmation flow in which the assistant presents its intended action and waits for explicit user approval before executing, ensuring no system modification occurs without human confirmation.

# Testing and Validation

Smart-Shield includes a test suite of more than 1,300 test cases covering unit, integration, and acceptance tests executed in isolated virtual network environments. Benchmarks showed that the firewall adds less than 0.2 milliseconds of latency for LAN-to-LAN traffic and less than 0.6 milliseconds for LAN-to-WAN forwarded traffic; VPN tunnels operated at under 4 milliseconds round-trip; the web dashboard responded in under 300 milliseconds; and a ruleset of 200 rules applied in under 2 seconds. The system ran continuously for 48 hours without service failures and handled up to 50 VPN configurations without performance degradation. The full test suite is included in the repository and is executable by reviewers locally.

# Availability

The Smart-Shield source code is available on GitHub at [https://github.com/Mohamed-Salah11/Smart-Shield](https://github.com/Mohamed-Salah11/Smart-Shield) and is released under the Apache License 2.0. A software archive with a permanent DOI is available on Zenodo at [https://doi.org/10.5281/zenodo.<<FILL_IN: real Zenodo DOI minted at release>>](https://doi.org/10.5281/zenodo.<<FILL_IN: real Zenodo DOI minted at release>>).

# Acknowledgements

The authors thank Dr. Ahmed Gaber Abuabdullah for his academic supervision, methodological guidance, and technical review throughout the development of this project. The authors also acknowledge the faculty and staff of The Higher Canadian Institute for Engineering Technology and Business for the academic environment and resources that supported this work.

# References
