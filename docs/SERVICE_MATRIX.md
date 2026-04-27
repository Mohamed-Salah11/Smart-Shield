# Smart Shield — Service Matrix

> Last updated: Phase 5

## Legend

| Status     | Meaning                                          |
|------------|--------------------------------------------------|
| ✅ Done     | Fully implemented, validated, tested             |
| 🔶 Partial  | Core logic complete; some edge cases missing     |
| 🔲 Planned  | Designed but not yet implemented                 |

---

## Network & Interface Management

| Service / Feature          | Status   | Backend / Tool        | Config Path                             | FreeBSD Service      |
|----------------------------|----------|-----------------------|-----------------------------------------|----------------------|
| WAN interface (static/DHCP)| ✅ Done  | ifconfig, dhclient    | `/etc/rc.conf`                          | N/A (rc.conf)        |
| LAN interface              | ✅ Done  | ifconfig              | `/etc/rc.conf`                          | N/A                  |
| VLAN                       | ✅ Done  | ifconfig vlan         | `/etc/rc.conf`                          | N/A                  |
| PPPoE                      | ✅ Done  | mpd5                  | `/usr/local/etc/mpd5/mpd.conf`          | mpd5                 |
| GRE / GIF tunnels          | 🔶 Partial | ifconfig            | `/etc/rc.conf`                          | N/A                  |
| LAGG (bonding)             | 🔶 Partial | lagg                | `/etc/rc.conf`                          | N/A                  |
| Bridge                     | 🔶 Partial | bridge              | `/etc/rc.conf`                          | N/A                  |
| Interface rollback         | ✅ Done  | Internal snapshot     | DB: `pending_interface_changes`         | N/A                  |
| ARP neighbor table         | ✅ Done  | arp                   | N/A                                     | N/A                  |

---

## Routing

| Feature               | Status   | Backend     | Config Path      |
|-----------------------|----------|-------------|------------------|
| Static routes         | ✅ Done  | route(8)    | `/etc/rc.conf`   |
| Default gateway       | ✅ Done  | route(8)    | `/etc/rc.conf`   |
| Gateway monitoring    | 🔶 Partial | ping      | N/A              |
| Gateway groups (ECMP) | 🔲 Planned | pf / rtable | N/A             |
| Policy-based routing  | 🔲 Planned | pf + rtable | N/A             |

---

## Firewall (PF)

| Feature                    | Status   | Backend | Config Path          |
|----------------------------|----------|---------|----------------------|
| WAN rules                  | ✅ Done  | pfctl   | `/etc/pf.conf`       |
| LAN rules                  | ✅ Done  | pfctl   | `/etc/pf.conf`       |
| Floating rules             | ✅ Done  | pfctl   | `/etc/pf.conf`       |
| Outbound NAT               | ✅ Done  | pfctl   | `/etc/pf.conf`       |
| 1:1 NAT                    | ✅ Done  | pfctl   | `/etc/pf.conf`       |
| Port forwarding            | ✅ Done  | pfctl   | `/etc/pf.conf`       |
| IPv6 NPt                   | ✅ Done  | pfctl   | `/etc/pf.conf`       |
| Aliases                    | ✅ Done  | pfctl   | `/etc/pf.conf`       |
| Schedules                  | ✅ Done  | DB only | N/A                  |
| Rollback (known-good)      | ✅ Done  | pfctl   | `/etc/pf.conf.known_good` |
| Config version history     | ✅ Done  | DB      | DB: `config_versions`|
| PF table (captive portal)  | ✅ Done  | pfctl   | `/etc/pf.captive_portal.conf` |

---

## DHCP

| Feature             | Status   | Backend        | Config Path                   | FreeBSD Service |
|---------------------|----------|----------------|-------------------------------|-----------------|
| DHCPv4 server       | ✅ Done  | isc-dhcp44     | `/usr/local/etc/dhcpd.conf`   | isc-dhcpd       |
| Static leases       | ✅ Done  | isc-dhcp44     | `/usr/local/etc/dhcpd.conf`   | isc-dhcpd       |
| DHCP relay          | 🔶 Partial | isc-dhcpd   | `/usr/local/etc/dhcpd.conf`   | isc-dhcpd       |
| Live lease viewer   | ✅ Done  | File parser    | `/var/db/dhcpd/dhcpd.leases`  | N/A             |
| DHCPv6 server       | ✅ Done  | Kea DHCPv6     | `/usr/local/etc/kea/kea-dhcp6.conf` | kea-dhcp6  |
| DHCPv6 leases       | ✅ Done  | Kea            | `/var/db/kea/kea-leases6.csv` | N/A             |

---

## DNS

| Feature              | Status   | Backend  | Config Path                          | FreeBSD Service |
|----------------------|----------|----------|--------------------------------------|-----------------|
| Recursive resolver   | ✅ Done  | Unbound  | `/usr/local/etc/unbound/unbound.conf`| unbound         |
| DNS filtering        | ✅ Done  | Unbound  | local-zone directives in unbound.conf| unbound         |
| Web content filter   | ✅ Done  | Unbound  | local-zone redirects                 | unbound         |
| App content filter   | ✅ Done  | Unbound + PF | Combined zones + PF rules          | unbound         |
| Filter conflict detection | ✅ Done | Internal | N/A                             | N/A             |
| DNS test endpoint    | ✅ Done  | drill/dig | N/A                                 | N/A             |

---

## VPN

| Feature              | Status   | Backend      | Config Path                             | FreeBSD Service |
|----------------------|----------|--------------|-----------------------------------------|-----------------|
| OpenVPN server       | ✅ Done  | openvpn      | `/usr/local/etc/openvpn/*.conf`         | openvpn         |
| OpenVPN client       | ✅ Done  | openvpn      | `/usr/local/etc/openvpn/*.conf`         | openvpn         |
| OpenVPN client-CSO   | ✅ Done  | openvpn      | `/usr/local/etc/openvpn/ccd/`           | openvpn         |
| IPsec IKEv2          | ✅ Done  | strongSwan   | `/usr/local/etc/ipsec.conf`             | strongswan      |
| L2TP/IPsec           | ✅ Done  | mpd5         | `/usr/local/etc/mpd5/mpd.conf`          | mpd5            |
| X.509 certificates   | ✅ Done  | cryptography | DB: `certificates`                      | N/A             |
| PKCS#12 export       | ✅ Done  | cryptography | N/A (download)                          | N/A             |
| Certificate revocation | ✅ Done | DB only     | DB: `certificates`                      | N/A             |

---

## IDS / IPS

| Feature              | Status   | Backend   | Config Path                             | FreeBSD Service |
|----------------------|----------|-----------|-----------------------------------------|-----------------|
| IDS mode             | ✅ Done  | Suricata  | `/usr/local/etc/suricata/suricata.yaml` | suricata        |
| IPS mode (inline)    | ✅ Done  | Suricata + netmap | As above                          | suricata        |
| Rule management      | ✅ Done  | DB        | DB: `ids_rulesets`                      | N/A             |
| YAML validation      | ✅ Done  | suricata -T | N/A                                   | N/A             |
| IPS safety check     | ✅ Done  | Internal  | N/A                                     | N/A             |

---

## Advanced Services (Phase 4)

| Service              | Status   | Backend      | Config Path                                    | FreeBSD Service |
|----------------------|----------|--------------|------------------------------------------------|-----------------|
| NTP server/client    | ✅ Done  | ntpd (base)  | `/etc/ntp.conf`                                | ntpd            |
| Router Advertisements| ✅ Done  | rtadvd (base)| `/etc/rtadvd.conf`                             | rtadvd          |
| Dynamic DNS          | ✅ Done  | ddclient     | `/usr/local/etc/ddclient.conf`                 | ddclient        |
| Dynamic DNS RFC2136  | ✅ Done  | nsupdate     | Generated per-client                           | N/A             |
| SNMP                 | ✅ Done  | bsnmpd (base)| `/etc/snmpd.config`                            | bsnmpd          |
| UPnP / NAT-PMP       | ✅ Done  | miniupnpd    | `/usr/local/etc/miniupnpd/miniupnpd.conf`      | miniupnpd       |
| IGMP proxy           | ✅ Done  | igmpproxy    | `/usr/local/etc/igmpproxy.conf`                | igmpproxy       |
| Wake-on-LAN          | ✅ Done  | Python socket| N/A (UDP broadcast)                            | N/A             |
| Captive portal       | ✅ Done  | PF tables    | `/etc/pf.captive_portal.conf`                  | pf              |
| Traffic shaper       | 🔲 Planned | HFSC / ALTQ | `/etc/pf.conf` (queues)                       | pf              |

---

## Production / Operations (Phase 5)

| Feature                    | Status   | Component           | Notes                                     |
|----------------------------|----------|---------------------|-------------------------------------------|
| Least-privilege (sudo)     | ✅ Done  | priv_helper.py      | Allowlist of ~20 permitted commands       |
| Sudoers rules              | ✅ Done  | sudoers.d/smartshield | Installed by install.sh                 |
| Secret redaction in logs   | ✅ Done  | network_service.py  | Redacts -p / --password / --key args     |
| Config version history     | ✅ Done  | config_history.py   | DB: `config_versions`                    |
| Config rollback API        | ✅ Done  | routes/status.py    | POST /status/api/config-history/<id>/rollback |
| Formal migration system    | ✅ Done  | migrations.py       | Versioned, backed up before apply        |
| Schema version guard       | ✅ Done  | migrations.py       | Raises if DB newer than code             |
| Health monitor (disk/CPU)  | ✅ Done  | health_monitor.py   | DB: `health_snapshots`                   |
| Config drift detection     | ✅ Done  | health_monitor.py   | Compares applied hash to generated       |
| Structured app log         | ✅ Done  | app_log.py          | NDJSON operational log (separate from audit) |
| Log viewer (audit)         | ✅ Done  | routes/status.py    | Pagination + filters + live poll         |
| Log viewer (app log)       | ✅ Done  | routes/status.py    | GET /status/api/app-logs                 |
| Release builder            | ✅ Done  | tools/build_release.py | Whitelist tarball + SHA256 + version.json |
| FreeBSD integration tests  | ✅ Done  | test_freebsd_integration.py | Skipped on non-FreeBSD            |
| Backup before migration    | ✅ Done  | migrations.py       | FreeBSD file DB only                     |
| Admin guide                | ✅ Done  | docs/ADMIN_GUIDE.md | —                                        |
| Service matrix             | ✅ Done  | docs/SERVICE_MATRIX.md | This file                             |

---

## Known Limitations & Manual FreeBSD Steps

| Area                        | Limitation / Manual Step                                                |
|-----------------------------|-------------------------------------------------------------------------|
| Traffic shaper (HFSC/ALTQ)  | Not implemented — requires careful PF queue design per deployment        |
| PPPoE reconnect             | mpd5 reconnect logic is basic; no idle-reset timer yet                  |
| Suricata IPS netmap mode    | Requires `device_type: netmap` in suricata.yaml and a supported NIC     |
| DHCPv6 prefix delegation    | Kea config is generated but PD routes are not automatically installed   |
| RADIUS authentication       | Captive portal uses local users only; RADIUS is out of scope            |
| Certificate CRL             | Revocation is DB-only; no CRL/OCSP endpoint is published automatically  |
| Log rotation                | Must configure newsyslog manually (see docs/ADMIN_GUIDE.md)             |
| Health alert notifications  | Health snapshots are stored; external alerting is not implemented        |
| Sudoers on upgrade          | Re-run `install -m 0440 bsd/etc/sudoers.d/smartshield /usr/local/etc/sudoers.d/smartshield` after upgrades |
