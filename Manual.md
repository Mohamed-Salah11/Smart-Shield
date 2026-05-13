# Smart Shield — User Manual

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Installation](#2-installation)
3. [First-Run Setup Wizard](#3-first-run-setup-wizard)
4. [CLI Reference — smartshieldctl](#4-cli-reference--smartshieldctl)
5. [Console Recovery Menu](#5-console-recovery-menu)
6. [Web GUI Reference](#6-web-gui-reference)
   - 6.1 [Dashboard](#61-dashboard)
   - 6.2 [Network — Interfaces and Routing](#62-network--interfaces-and-routing)
   - 6.3 [Firewall](#63-firewall)
   - 6.4 [Network Services](#64-network-services)
   - 6.5 [VPN Tunnels](#65-vpn-tunnels)
   - 6.6 [Threat Detection — IDS/IPS](#66-threat-detection--idsips)
   - 6.7 [Content Filtering](#67-content-filtering)
   - 6.8 [Captive Portal](#68-captive-portal)
   - 6.9 [SIEM and Event Log](#69-siem-and-event-log)
   - 6.10 [Monitoring](#610-monitoring)
   - 6.11 [Users and Groups](#611-users-and-groups)
   - 6.12 [Certificates](#612-certificates)
   - 6.13 [Backup and Restore](#613-backup-and-restore)
   - 6.14 [AI Assistant](#614-ai-assistant)
   - 6.15 [System Settings](#615-system-settings)
7. [Environment Variables Reference](#7-environment-variables-reference)
8. [Log Files Reference](#8-log-files-reference)
9. [Directory Structure Reference](#9-directory-structure-reference)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. Introduction

Smart Shield is a web-managed network security appliance for FreeBSD. It provides a single
HTTPS interface and an operator CLI (`smartshieldctl`) that together cover the full lifecycle
of a network security gateway: initial provisioning, day-to-day firewall and policy management,
real-time security monitoring, and incident response.

### Audience

This manual is intended for:

- **Network administrators** deploying Smart Shield as an edge security gateway.
- **Security practitioners** using Smart Shield as a research or testing environment.
- **Educators** running Smart Shield in a laboratory or classroom network.

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

Smart Shield operates in **development mode** on Linux and macOS (or Windows via WSL) for
UI development and dry-run testing. All network enforcement features require FreeBSD.

### 2.2 Running the Installer

Clone the repository to the target FreeBSD host and run the installer as root:

```sh
git clone https://github.com/<org>/Smart-Shield.git /usr/local/share/smart-shield
cd /usr/local/share/smart-shield
sh bsd/install.sh
```

The installer performs these steps automatically:

1. Installs FreeBSD packages: `nginx`, `python3`, `suricata`, `unbound`, `isc-dhcp44-server`,
   `kea`, `openvpn`, `strongswan`, `mpd5`, `mrtg`, `miniupnpd`, `igmpproxy`, `ddclient`,
   `sudo`, `git`, `sqlite3`, `ca_root_nss`, `bind-tools`, `tcpdump`, `nano`.
2. Creates a Python virtual environment at `/usr/local/share/smart-shield/.venv` and installs
   all pip dependencies from `requirements.txt`.
3. Creates all required runtime directories (see §9).
4. Generates a random `SECRET_KEY` (64 hex characters) and `SMARTSHIELD_MASTER_KEY`
   (AES-256 base64 key) and writes them to the environment file.
5. Installs the `smart_shield` FreeBSD rc.d service and enables it with `sysrc`.
6. Generates a self-signed TLS certificate (RSA 2048-bit, valid 10 years) at
   `/usr/local/etc/smart-shield/ssl/cert.pem`.
7. Writes the nginx reverse proxy configuration and starts nginx.
8. Installs the MRTG cron job (`*/5 * * * * root /usr/local/bin/mrtg …`).
9. Installs `smartshieldctl` to `/usr/local/sbin/smartshieldctl`.
10. Installs the `smart_shield_console` recovery menu to `/usr/local/sbin/`.
11. Runs two MRTG passes to initialize log files and generate first-run graphs.
12. Starts the Smart Shield service.

### 2.3 Verifying the Installation

After the installer completes:

```sh
# Check service status
smartshieldctl status

# Check nginx is listening on 443
sockstat -4 -l | grep 443

# Test the web UI is reachable
smartshieldctl health
```

### 2.4 Environment File

The environment file is at `/usr/local/etc/smart-shield/smart-shield.env`. Edit it to
configure optional features (see §7 for the full variable reference):

```sh
nano /usr/local/etc/smart-shield/smart-shield.env
```

After editing, restart the service:

```sh
smartshieldctl restart
```

---

## 3. First-Run Setup Wizard

On the first visit to `https://<appliance-IP>`, Smart Shield redirects to the setup wizard.
The wizard configures the minimum required settings to bring the appliance online.

### 3.1 Step 1 — Interface Assignment

Select which physical NIC is the **WAN** (internet-facing) interface and which is the
**LAN** (internal network) interface. The page lists all detected physical interfaces with
their names (e.g., `em0`, `em1`) and current link state.

- Click **Assign as WAN** next to the internet-facing interface.
- Click **Assign as LAN** next to the internal interface.
- Click **Save & Continue**.

### 3.2 Step 2 — IP Configuration

Configure addressing for both interfaces.

**LAN Configuration:**
- Enter the LAN IP address in CIDR notation (e.g., `192.168.1.1/24`).
- Smart Shield derives the DHCP pool automatically from the entered subnet.

**WAN Configuration:**
- **DHCP** — the appliance obtains an IP from the upstream provider automatically.
- **Static** — enter the WAN IP/CIDR, gateway, and DNS servers.
- **PPPoE** — enter the username, password, and optional service name provided by the ISP.

Click **Save & Continue**.

### 3.3 Step 3 — Admin Password

Set the password for the `admin` superuser account. The password must be at least 8
characters. Click **Set Password & Continue**.

### 3.4 Step 4 — Apply and Finish

Review the configuration summary and click **Apply**. The appliance:

- Writes interface configuration to `rc.conf`.
- Generates and loads `pf.conf`.
- Starts DHCP and DNS services.
- Generates the initial MRTG configuration.

After apply completes, the browser is redirected to the dashboard at `https://<LAN-IP>`.

### 3.5 Accessing the Dashboard

The dashboard is available at `https://<LAN-IP>` from any device on the LAN. Accept the
self-signed certificate warning on first access, or install the certificate into the browser's
trust store.

Default login credentials: username `admin`, password set in Step 3.

---

## 4. CLI Reference — smartshieldctl

`smartshieldctl` is an operator utility installed at `/usr/local/sbin/smartshieldctl`.
It provides service control, interface management, diagnostics, and administration without
requiring a browser.

All commands require root privileges unless noted.

### 4.1 Service Control

| Command | Description |
|---|---|
| `smartshieldctl start` | Start the Smart Shield web service |
| `smartshieldctl stop` | Stop the Smart Shield web service |
| `smartshieldctl restart` | Restart the Smart Shield web service |
| `smartshieldctl status` | Show whether the service is running (PID, uptime) |
| `smartshieldctl enable` | Enable the service to start at boot |
| `smartshieldctl disable` | Prevent the service from starting at boot |
| `smartshieldctl health` | Check whether the web UI is reachable (HTTP health check) |

**Example — restart and verify:**

```sh
smartshieldctl restart
smartshieldctl status
smartshieldctl health
```

### 4.2 Interface Management

*(FreeBSD only)*

| Command | Description |
|---|---|
| `smartshieldctl list-nics` | List all physical NICs with name, link state, and IP |
| `smartshieldctl assign <LAN\|WAN> <port>` | Assign a physical NIC to the LAN or WAN role |
| `smartshieldctl iface-show [LAN\|WAN]` | Display configuration and live IP for one or both interfaces |
| `smartshieldctl iface-set <LAN\|WAN> dhcp [--apply]` | Configure DHCP mode; `--apply` applies immediately |
| `smartshieldctl iface-set <LAN\|WAN> static <CIDR> [gateway] [--apply]` | Configure a static IP |

**Examples:**

```sh
# List available NICs
smartshieldctl list-nics

# Assign em0 as WAN, em1 as LAN
smartshieldctl assign WAN em0
smartshieldctl assign LAN em1

# Set LAN to static 192.168.1.1/24 and apply immediately
smartshieldctl iface-set LAN static 192.168.1.1/24 --apply

# Set WAN to DHCP
smartshieldctl iface-set WAN dhcp --apply
```

### 4.3 Diagnostics

*(FreeBSD only, except ping and sysinfo)*

| Command | Description |
|---|---|
| `smartshieldctl ping [host] [count]` | ICMP ping (default: `8.8.8.8`, 4 packets) |
| `smartshieldctl pf-status` | Show PF rule count, state table, NAT entries, and active interface |
| `smartshieldctl apply-pf` | Regenerate `pf.conf` from the database and reload PF |
| `smartshieldctl preflight` | Check directory permissions, binary availability, and kernel capabilities |
| `smartshieldctl vpn-status` | Show OpenVPN, IPsec (strongSwan), and L2TP (mpd5) daemon status |
| `smartshieldctl dhcp-status` | Show ISC DHCPd status and active lease count |
| `smartshieldctl dns-status` | Show Unbound resolver status |
| `smartshieldctl sysinfo` | Display CPU load, memory usage, disk usage, and uptime |

**Examples:**

```sh
# Test connectivity
smartshieldctl ping 1.1.1.1 5

# Verify PF is running and show state counts
smartshieldctl pf-status

# Check all service binaries are present and kernel features are loaded
smartshieldctl preflight

# Show disk and memory usage
smartshieldctl sysinfo
```

### 4.4 Log Access

| Command | Description |
|---|---|
| `smartshieldctl logs [N]` | Tail the application log (default: last 100 lines) |
| `smartshieldctl audit [N]` | Tail the SIEM audit log (default: last 100 lines) |
| `smartshieldctl access [N]` | Tail the nginx access log (default: last 100 lines) |

**Examples:**

```sh
# View last 50 audit events
smartshieldctl audit 50

# Watch application log in real time (use standard tail -f after getting the path)
smartshieldctl logs 200
```

### 4.5 Administration

| Command | Description |
|---|---|
| `smartshieldctl passwd [username]` | Interactively reset a web UI user password |
| `smartshieldctl factory-reset` | Wipe all configuration from the database (irreversible) |
| `smartshieldctl ssh <enable\|disable\|status>` | Control the sshd daemon |
| `smartshieldctl shell` | Drop to an interactive root shell |
| `smartshieldctl menu` | Launch the interactive console recovery menu |

**Examples:**

```sh
# Reset the admin password
smartshieldctl passwd admin

# Enable SSH for remote access
smartshieldctl ssh enable

# Open the recovery menu
smartshieldctl menu
```

---

## 5. Console Recovery Menu

The interactive console recovery menu (`smart_shield_console`) is designed for emergency
access over a serial console or out-of-band SSH session. Launch it with:

```sh
smartshieldctl menu
# or directly:
/usr/local/sbin/smart_shield_console
```

### Menu Options

| Option | Action |
|---|---|
| `1` | Show Smart Shield service status |
| `2` | Start the Smart Shield service |
| `3` | Stop the Smart Shield service |
| `4` | Restart the Smart Shield service |
| `5` | View the last 50 lines of the application log |
| `6` | View the last 50 lines of the audit log |
| `7` | Reset the admin password interactively |
| `8` | Reload PF rules from the database (regenerate and apply `pf.conf`) |
| `9` | Run the first-boot setup sequence again (re-creates missing directories) |
| `0` | Open a root shell |
| `q` | Quit the menu |

Each action displays output, then pauses with a "Press Enter to continue" prompt before
returning to the menu.

---

## 6. Web GUI Reference

The web GUI is accessible at `https://<LAN-IP>`. The left sidebar provides navigation to all
major sections.

---

### 6.1 Dashboard

**URL:** `/system/dashboard`

The dashboard provides an at-a-glance view of the appliance state:

- **KPI strip:** User count, group count, firewall rule counts (floating / WAN / LAN), NAT rule count, alias count.
- **Service health:** Color-coded indicators for PF, DHCP, Unbound, OpenVPN, IPsec, Suricata, nginx, SIEM, and MRTG.
- **Interface statistics:** Real-time RX/TX packet and byte counts per interface.
- **Recent events:** Last few security events from the audit log (logins, rule changes, IDS alerts).

The dashboard refreshes automatically via Server-Sent Events (SSE) without reloading the page.

---

### 6.2 Network — Interfaces and Routing

#### Interface Assignments (`/interfaces/assignments`)

Maps physical NIC names (e.g., `em0`, `em1`) to the WAN and LAN logical roles. After
changing assignments, click **Save** and then apply the change.

#### LAN Interface (`/interfaces/lan`)

Configure the LAN interface:

- **IP Mode:** Static (most common) or DHCP.
- **IP Address / Prefix Length:** e.g., `192.168.1.1 / 24`.
- **MTU:** Leave at 1500 unless your network requires jumbo frames.
- **Description:** A human-readable label for this interface.

Click **Save** then **Apply** to activate the new configuration.

#### WAN Interface (`/interfaces/wan`)

Configure the WAN interface:

- **IP Mode:** DHCP (from upstream ISP), Static (fixed IP), or PPPoE (DSL/fiber with credentials).
- **Static settings:** WAN IP/prefix, gateway IP, upstream DNS servers.
- **PPPoE settings:** Username, password, service name (if required), dial-on-demand.

#### VLANs (`/interfaces/` → VLAN tab)

Add 802.1Q VLAN tags on a physical parent interface. Each VLAN appears as a separate logical
interface (e.g., `em0.10`) that can be assigned an IP and treated like a physical NIC for
firewall, DHCP, and routing purposes.

#### Routing (`/routing/`)

**Gateways** — Define upstream router IP addresses. Each gateway entry can be monitored via
ICMP ping; Smart Shield reports latency and packet loss in the status page.

**Static Routes** — Add routes of the form `<destination CIDR> via <gateway>` for networks
reachable through a specific next-hop.

**Gateway Groups** — Combine multiple gateways into a group for load balancing (round-robin)
or failover (tier-based priority). Reference a gateway group in a firewall rule to distribute
or fail-over traffic automatically.

---

### 6.3 Firewall

#### 6.3.1 Rules (`/firewall/rules`)

The rule editor has three tabs: **Floating**, **WAN**, and **LAN**.

- **Floating rules** match traffic on any interface and take effect before interface-specific rules. Use floating rules for global policy (e.g., block all Telnet everywhere).
- **WAN rules** match inbound traffic arriving on the WAN interface.
- **LAN rules** match traffic originating from the LAN.

**Adding a rule:**

1. Click **Add rule** (top of the table).
2. Set the **Action**: `pass`, `block`, or `reject`.
3. Set the **Protocol**: `any`, `TCP`, `UDP`, `ICMP`, `TCP/UDP`.
4. Set **Source** and **Destination** (any, network, single host, alias, or interface address).
5. Optionally set **Source port** and **Destination port**.
6. Optionally assign a **Schedule** (time-based activation) or **Queue** (traffic shaping).
7. Add a **Description** and click **Save**.

Rules are evaluated top-to-bottom; the first matching rule wins (PF "quick" semantics).
Drag rules to reorder them.

**Applying changes:**

Click **Apply Changes** in the top-right banner. Smart Shield:
1. Generates `pf.conf` from the database.
2. Validates it with `pfctl -nf`.
3. If validation passes, reloads PF with `pfctl -f`.
4. If the reload fails, automatically restores the previous known-good configuration.

**Rolling back:** Click **Rollback** to restore the last successfully applied `pf.conf`.

**Previewing:** Click **Preview** to see the generated `pf.conf` without applying it.

#### 6.3.2 NAT (`/firewall/nat`)

**Port Forwarding (NAT PF):** Redirect an external port to an internal host.

1. Click **Add** under the Port Forwarding tab.
2. Set **Interface** (typically WAN), **Protocol**, **Destination port**, **Redirect IP**, and **Redirect port**.
3. Enable **NAT reflection** to allow LAN-to-LAN access via the WAN IP.

**1:1 NAT:** Map a single external IP address to a single internal IP address bidirectionally.

**Outbound NAT:** Control how internal traffic is masqueraded when leaving the WAN. By default,
all LAN traffic is translated to the WAN IP. Add custom outbound rules for specific sources or
to disable masquerade for particular subnets.

**NPt (Network Prefix Translation):** Translate IPv6 prefixes at the border — useful when the
internal prefix differs from the delegated upstream prefix.

#### 6.3.3 Aliases (`/firewall/aliases`)

Aliases are named sets of IP addresses, networks, ports, or URLs referenced in rules.

| Type | Example content |
|---|---|
| Host | `192.168.1.100`, `10.0.0.5` |
| Network | `192.168.10.0/24`, `172.16.0.0/12` |
| Port | `80`, `443`, `8080:8090` |
| URL | A remote text file listing IPs or networks (fetched periodically) |

Create an alias once, reference it in any number of rules. Updating the alias automatically
updates all rules that use it on the next PF apply.

#### 6.3.4 Schedules (`/firewall/schedules`)

Define time windows that can be attached to firewall rules. A rule with a schedule is active
only during the specified periods.

1. Click **Add Schedule**.
2. Set a **Name** and optionally restrict by **Month**, **Day of week**, and **Start/End time**.
3. Assign the schedule to a firewall rule in the rule editor.

#### 6.3.5 Traffic Shaper and Limiters (`/firewall/traffic-shaper`)

**Traffic Shaper (ALTQ):** Assign bandwidth allocations and priorities to traffic classes.

1. Enable shaping on an interface and choose a scheduler (HFSC, CBQ, PRIQ, or FAIRQ).
2. Create queues with bandwidth percentages and priority levels.
3. Assign firewall rules to queues.

**Limiters (dummynet):** Apply per-flow bandwidth, delay, and queue constraints.

1. Create a limiter with a bandwidth rate (e.g., 10 Mbit/s) and mask type (per-source IP,
   per-destination, or per flow).
2. Reference the limiter in a firewall rule's **In/Out pipe** fields.

#### 6.3.6 Virtual IPs / CARP (`/firewall/virtual-ips`)

Add IP aliases or CARP virtual IPs. CARP virtual IPs are shared between two appliances in
a high-availability pair — the primary holds the IP; the backup takes it over if the primary
fails. Configure CARP in **System → High Availability** first.

#### 6.3.7 Apply, Preview, and Rollback

These controls appear in the top-right banner whenever there are unapplied changes:

| Action | Effect |
|---|---|
| **Preview** | Show the generated `pf.conf` in a modal without applying |
| **Apply Changes** | Validate and load `pf.conf` into the running kernel |
| **Rollback** | Restore the most recent successfully applied `pf.conf` |

---

### 6.4 Network Services

#### 6.4.1 DHCP Server — IPv4 (`/services/dhcp-server`)

Smart Shield uses ISC DHCPd to assign IPv4 addresses to LAN clients.

- **Pool range:** Start and end IP within the LAN subnet.
- **Default lease time / Max lease time:** In seconds (e.g., 3600 / 86400).
- **Gateway:** Pushed to clients (defaults to LAN IP).
- **DNS servers:** Pushed to clients (defaults to LAN IP for local resolution).
- **Domain name:** Optional domain suffix pushed to clients.

**Static Leases:** Click **Add Static Lease** to map a specific MAC address to a fixed IP.
Enter the MAC address, desired IP, and optional hostname.

After saving, click **Apply** to regenerate `dhcpd.conf` and restart DHCPd. The config is
validated with `dhcpd -t` before the daemon is restarted.

#### 6.4.2 DHCPv6 Server (`/services/dhcpv6-server`)

Smart Shield uses Kea to assign IPv6 addresses and prefixes.

- Configure an IPv6 prefix pool and lease lifetimes.
- Enable Router Advertisements (RA) with the appropriate flags (M-bit, O-bit) for the
  desired addressing mode (SLAAC, stateful, or stateless DHCPv6).

#### 6.4.3 DNS Resolver (`/services/dns-resolver`)

Smart Shield uses Unbound as the recursive resolver for all LAN clients.

- **Forwarding:** Leave empty for full recursive resolution, or enter upstream DNS server IPs
  to forward queries.
- **DNS-over-TLS:** Enable encrypted upstream queries (requires forwarding to a DoT-capable
  server such as 1.1.1.1 or 9.9.9.9).
- **DNSSEC:** Enable cryptographic validation of DNS responses.
- **Host overrides:** Add static A/AAAA records for local hostnames.
- **Domain overrides:** Forward specific domains to a different DNS server (e.g., internal
  corporate domain to an internal resolver).
- **Query logging:** Enable logging of all queries to `/var/log/unbound/query.log` for SIEM
  integration. This setting activates the DNS SIEM collector.

Click **Apply** after saving to regenerate `unbound.conf` and restart Unbound.

#### 6.4.4 Dynamic DNS (`/services/dynamic-dns`)

Configure ddclient to update a dynamic DNS hostname with the current WAN IP address whenever
it changes. Enter the provider credentials (username, password, hostname) and the update
interval.

#### 6.4.5 NTP (`/services/ntp`)

Configure the NTP daemon to synchronize the appliance clock with upstream time servers. Enter
one or more NTP server hostnames (e.g., `0.freebsd.pool.ntp.org`).

#### 6.4.6 SNMP (`/services/snmp`)

Enable bsnmpd to expose standard MIB data (system info, interface counters) to network
management systems. Set a community string (avoid `public` or `private`), the listen port
(default 161), and the allowed management host subnet.

#### 6.4.7 UPnP / PCP (`/services/upnp-igd-pcp`)

Enable miniupnpd to process Universal Plug and Play port mapping requests from LAN devices.
Restrict which LANs can make mapping requests and set an optional external IP override.

#### 6.4.8 IGMP Proxy (`/services/igmp-proxy`)

Configure igmpproxy to forward multicast traffic between interfaces. Define upstream
(internet-side) and downstream (LAN-side) interfaces.

#### 6.4.9 Wake on LAN (`/services/wake-on-lan`)

Store MAC addresses and broadcast IPs for devices you want to wake remotely. Click **Send**
next to a saved host to transmit the magic packet.

---

### 6.5 VPN Tunnels

#### 6.5.1 OpenVPN (`/vpn/openvpn`)

**Server instances (Servers tab):**

1. Click **Add Server**.
2. Set the **Protocol** (UDP recommended), **Port** (default 1194), and **Device type** (TUN for routing, TAP for bridging).
3. Select the **Server certificate** from the certificate manager.
4. Configure the **Tunnel network** (the IP pool for VPN clients, e.g., `10.8.0.0/24`).
5. Optionally enable **Redirect gateway** to route all client traffic through the VPN.
6. Optionally push DNS server and domain name to clients.
7. Click **Save** then **Apply** to start the OpenVPN server.

**Client instances (Clients tab):**

Used when Smart Shield itself connects outbound to a remote VPN server.

1. Click **Add Client**.
2. Enter the **Remote server** hostname or IP and port.
3. Select the client certificate and configure the cipher suite.
4. Click **Save** then **Apply**.

**Client-Specific Overrides (CSO tab):**

Assign a fixed tunnel IP or push specific routes to individual VPN clients by common name.

**Wizard:** A three-step wizard under the Wizards tab guides you through creating a
complete OpenVPN server with a new CA, server certificate, and basic client profile.

#### 6.5.2 IPsec / IKEv2 (`/vpn/ipsec`)

**Tunnels (Phase 1 tab):**

1. Click **Add P1** to create a new IKE connection.
2. Set the **Remote gateway** (peer IP or hostname), **Authentication method** (PSK or certificate), and the **Encryption/hash/DH group** algorithms.
3. Under the Phase 1 entry, click **Add P2** to define Phase 2 (ESP child SA):
   - Set **Local network** and **Remote network** (the subnets to be tunneled).
   - Choose encryption and hash algorithms and optionally enable PFS.
4. Click **Save** then **Apply** to push the configuration to strongSwan.

**Mobile Clients tab:** Configure the IKEv2 roadwarrior profile for remote users connecting
from laptops or mobile devices. Set the virtual IP pool and authentication method (PSK or EAP).

**Pre-Shared Keys tab:** Manage PSK entries used for IKE authentication. Each entry can be
scoped to a specific peer identifier.

**Advanced Settings tab:** Tune logging verbosity, fragmentation, and DPD (dead peer
detection) timers for all tunnels.

#### 6.5.3 L2TP / IPsec (`/vpn/l2tp`)

Configure the L2TP server via mpd5 for legacy remote-access clients that require L2TP/IPsec.

1. Enable the L2TP server.
2. Set the **Server address** (LAN IP), **Client address pool**, and **Authentication method** (local or RADIUS).
3. Under the **Users** tab, add L2TP user accounts with usernames and passwords.
4. Click **Apply** to regenerate the mpd5 configuration and start the service.

---

### 6.6 Threat Detection — IDS/IPS

#### 6.6.1 Enabling Suricata

On the Threat Detection page (`/ids/`):

1. Click **Enable** in the top-right toggle. Smart Shield:
   - Generates `suricata.yaml` from the database.
   - Validates the configuration with `suricata -T`.
   - Sets `suricata_enable=YES` in `rc.conf`.
   - Starts the Suricata service.
   - Updates the database to reflect the enabled state only after the service starts successfully.

2. The status banner at the top of the page shows whether Suricata is running and the current mode.

#### 6.6.2 IDS vs IPS Mode

Navigate to **Configuration** tab to set the mode:

- **IDS (Detection only):** Suricata listens passively on the selected interface using the
  BPF pcap socket. Matching traffic is logged but not blocked.
- **IPS (Inline prevention):** Suricata is inserted inline using FreeBSD netmap(4). Matching
  traffic is blocked at wire speed. **Requires netmap kernel support** and a netmap-compatible
  NIC driver (`em`, `igb`, `ixgbe`, `ixl`, `re`, `vtnet`, `vmx`, `bnxt`, `ix`). Smart Shield
  validates netmap compatibility before enabling IPS mode and automatically falls back to IDS
  mode if the inline start fails.

#### 6.6.3 Managing Rulesets

On the **Rulesets** tab:

- View installed rule sources (e.g., `et/open` for Emerging Threats Open).
- Toggle individual rulesets on or off.
- Add custom rule sources by URL using the **Add Source** button.
- Click **Update Rules** to run `suricata-update` and download the latest signatures.

After changing rulesets, restart Suricata (toggle Disable then Enable, or use `smartshieldctl restart` — note: Suricata has its own restart from the toggle button).

#### 6.6.4 Threat Intelligence Feeds (`/ids/` → Threat Feeds tab)

Smart Shield integrates with abuse.ch to enrich threat detection:

1. Enter your abuse.ch **Personal Auth-Key** (obtain from https://abuse.ch/api/ after
   creating a free account).
2. Optionally enable **Dry-run mode** to test API calls without pushing data to PF.
3. Use the **Lookup** tool to query a URL, IP, domain, or file hash against URLhaus,
   MalwareBazaar, and ThreatFox.
4. Click **Recent Samples** to view the latest IOCs from ThreatFox.

When a valid API key is configured and dry-run is disabled, Smart Shield automatically fetches
recent threat IOCs every 4 hours and pushes the extracted IPs to the `ss_threat_intel` PF
table, blocking them at the packet filter level.

#### 6.6.5 Alert Viewer

The **Status & Alerts** tab shows recent Suricata detections parsed directly from
`/var/log/suricata/eve.json`:

- Filter alerts by **severity** (1 = Critical, 2 = High, 3 = Info) and **time window** (last
  1h, 6h, 24h, or all).
- Search by signature name or IP address.
- The **Alerts Today** KPI counter updates automatically.

#### 6.6.6 Verifying IDS Operation

From the BSD shell:

```sh
# Is Suricata running?
pgrep -x suricata && echo "Running" || echo "Stopped"

# Did it start cleanly?
tail -50 /var/log/suricata/suricata.log

# Is EVE JSON being written?
ls -lh /var/log/suricata/eve.json

# Validate config without restarting
suricata -T -c /usr/local/etc/suricata/suricata.yaml

# Generate a test alert from a Kali or test host on the LAN:
curl -A "Nikto" http://<BSD-LAN-IP>/
tail -5 /var/log/suricata/fast.log
```

---

### 6.7 Content Filtering

#### 6.7.1 DNS Filtering (`/filters/dns`)

Block or redirect domains at the DNS resolver level. Matching queries return NXDOMAIN or
a redirect IP, preventing clients from reaching the domain.

1. Click **Add Rule**.
2. Enter the **Domain** (exact match or wildcard, e.g., `*.example.com`).
3. Set the **Action**: `block` (return NXDOMAIN), `allow` (whitelist override), or
   `redirect` (return a specific IP, e.g., a block page server).
4. Add a **Category** and **Description** for organization.
5. Click **Save**, then click **Apply DNS Filter** to push the updated rules to Unbound.

#### 6.7.2 Web Filtering (`/filters/web`)

Block URL patterns at the application level. Add URL patterns (regex supported) with an
action (block or allow). Apply changes after saving.

#### 6.7.3 Application Filtering (`/filters/app`)

Block or throttle network traffic by application signature (destination port, protocol, or
domain). These rules generate PF match entries that invoke dummynet limiters or block actions.

---

### 6.8 Captive Portal

**URL:** `/services/captive-portal`

#### 6.8.1 Configuration

1. Enable the captive portal.
2. Set the **Interface** (the LAN or VLAN that requires authentication).
3. Choose the **Mode**: `soft` or `strict` (see §6.8.2).
4. Set a **Session timeout** in minutes (0 = no timeout).
5. Optionally configure a **Bandwidth limit** per authenticated session (kbps).
6. Click **Save** then **Apply**.

#### 6.8.2 Soft vs. Strict Mode

| Mode | Behaviour |
|---|---|
| **Soft** | Only HTTP (port 80) is redirected to the portal login. Other traffic (HTTPS, DNS, DHCP) passes without authentication. |
| **Strict** | All traffic is blocked until the user authenticates. DNS and DHCP are permitted pre-authentication; all other traffic is redirected or blocked. |

#### 6.8.3 Vouchers

Vouchers provide time-limited guest access without creating permanent user accounts.

1. Navigate to the **Vouchers** tab.
2. Click **Generate** and set a duration (minutes) and optional bandwidth limit.
3. Distribute the generated codes to guests.
4. Guests enter the code on the portal login page to activate their session.

---

### 6.9 SIEM and Event Log

**URL:** `/status/system-logs`

#### 6.9.1 Live Event Stream

The SIEM page shows a real-time stream of security events collected by the five background
collector threads. Events are displayed newest-first in a dark-theme log viewport and
refreshed automatically every 5 seconds by polling `/status/api/logs`.

#### 6.9.2 Categories and Severity Levels

| Category | Events Included |
|---|---|
| `connection` | New LAN connections (PF), DHCP leases, DNS queries |
| `security` | Failed logins, brute-force detections, insecure protocol alerts, IDS floods |
| `ids` | Suricata IDS/IPS alert events |
| `session` | Admin login, logout, re-authentication |
| `system` | Config changes, firewall rule edits, PF reloads, service applies |

| Severity | Meaning |
|---|---|
| `critical` | Suricata severity-1 alerts |
| `high` | Brute-force detected, IDS flood, IPS inline block, insecure protocol; Suricata severity-2 |
| `medium` | Suricata severity-3; RDP, database protocol connections |
| `low` | Suricata severity-4; low-risk protocol connections |
| `info` | Normal connections, config changes, DHCP events |

Note: Admin GUI page-view events (`browsing` category) are not shown in the live SIEM
feed — they are recorded to the audit log for export purposes only.

#### 6.9.3 Filtering and Search

- **Category pills:** All Events, Network Traffic, Security Alerts, Firewall (firewall rule
  changes + PF reloads + new connections), Config Changes, Sessions.
- **Severity pills:** Filter by Critical, High, Medium, or Low.
- **Time range:** Live (streaming), 1h, 6h, 24h, 7d (snapshot modes).
- **Search box:** Free-text search against action name, IP address, hostname, username, and
  event details.

Click any row to expand it and view the full JSON event payload.

#### 6.9.4 Exporting Logs

Click **Export** in the footer bar to download a filtered JSON file
(`smart-shield-siem-YYYY-MM-DD.json`) containing all events matching the current filters.
The export includes all log lines including `page_view` events that are excluded from the
live stream.

---

### 6.10 Monitoring

#### 6.10.1 System Metrics (`/status/monitoring`)

Displays a live interface statistics table (RX/TX packets, bytes, and errors per interface,
refreshed every 10 seconds) and real-time CPU, memory, and disk utilisation from the health
monitor API.

#### 6.10.2 Live Bandwidth Graph (`/status/traffic-graph`)

A real-time chart of inbound and outbound bytes per second on each interface, updated every
2 seconds.

#### 6.10.3 Historical Traffic — MRTG (`/status/mrtg`)

MRTG runs via cron every 5 minutes and generates PNG graphs for each configured interface.
The Traffic History page displays:

- **Daily** (5-minute intervals, 2 days shown)
- **Weekly** (30-minute averages, 2 weeks shown)
- **Monthly** (2-hour averages, 10 weeks shown)
- **Yearly** (1-day averages, 400 days shown)

A countdown timer shows the time until the next graph update.

If graphs are not appearing:

1. Click **Reinitialize MRTG** to run two MRTG passes immediately.
2. Check the status bar — it shows whether the cron job is installed, whether the graph
   directory is writable, and whether a stale lock file is present.
3. See §10 (Troubleshooting) for additional steps.

#### 6.10.4 Service Health (`/status/` → health section)

The health API at `/status/api/health/full` returns the live state of every managed service,
disk, memory, and CPU. Individual service health is available at `/status/api/health/<name>`.

---

### 6.11 Users and Groups

#### 6.11.1 Creating Users (`/users/`)

1. Click **Add User**.
2. Enter **Username**, **Password** (8 characters minimum), and **Display name**.
3. Optionally mark as **Superuser** (full access to all pages and APIs).
4. Click **Save**.

#### 6.11.2 Managing Groups (`/users/groups`)

Groups collect users and define page-level permissions.

1. Click **Add Group**, enter a name, and save.
2. Add users to the group via the **Members** tab.
3. Set page-level permissions on the **Permissions** tab — select which routes the group
   members are allowed to access.

#### 6.11.3 Permissions

A user has access to a page if they are a superuser, or if any group they belong to has
been granted permission for that page. The permission model operates at the blueprint
endpoint level.

---

### 6.12 Certificates

#### 6.12.1 Certificate Authorities (`/system/certificates` → CA tab)

1. Click **Add CA**.
2. Set the **Common Name**, key length (2048 or 4096 bits), and validity period.
3. Click **Generate**. The CA key is generated and stored (AES-256-GCM encrypted) in the database.

#### 6.12.2 Server and Client Certificates

1. Click **Add Certificate**.
2. Select the **CA** to sign the certificate.
3. Set the **Type** (server or client), **Common Name**, and validity period.
4. Click **Generate**.

Certificates are available for selection in OpenVPN server and client configurations and in
the IPsec Phase 1 settings. The Certificates page shows the expiry date for each certificate
and warns when a certificate is within 30 days of expiry.

---

### 6.13 Backup and Restore

**URL:** `/diagnostics/backup-restore`

#### 6.13.1 Creating a Backup

1. Click **Create Backup**.
2. Optionally enter an **Encryption passphrase** — if provided, the backup is encrypted with
   AES-256-GCM using a PBKDF2-derived key.
3. Click **Download**. The browser downloads a `.json` backup file.

The backup contains the full database dump, the environment configuration, all service state,
and the audit log.

#### 6.13.2 Restoring from a Backup

1. Click **Restore from File** and select a backup file.
2. Enter the decryption passphrase if the backup is encrypted.
3. Click **Restore**. Smart Shield validates the backup integrity and schema version before
   replacing the database.

**Warning:** Restoring overwrites the current configuration. Ensure the backup was created
from a compatible Smart Shield version before restoring.

#### 6.13.3 Config Version History

Every time a service configuration is applied, Smart Shield saves a snapshot. Navigate to
**Config History** to:

- List all saved versions for each service (firewall, DNS, DHCP, etc.).
- View the content of any historical version.
- Click **Rollback** to restore a specific version and re-apply it.

---

### 6.14 AI Assistant

**URL:** `/chatbot/`

The AI assistant is powered by the Groq inference API. To enable it, set the `GROQ_API_KEY`
environment variable (see §7) and restart the service.

**Capabilities:**

The assistant can answer questions and report on the live state of the appliance using
read-only data tools:

- System health and service status
- Firewall rules, NAT, and aliases
- DHCP leases and static reservations
- Tracked devices and their whitelist status
- IDS/IPS recent alerts
- DNS, web, and application content policy
- VPN tunnel status (OpenVPN, IPsec, L2TP)
- Audit log events

**Write operations** (adding firewall block rules, blocking or unblocking domains) are
supported with a two-step confirmation: the assistant first shows you the planned change, then
requires explicit approval ("yes", "apply", "go ahead") before executing.

**Usage examples:**

```
"Show me the last 5 IDS alerts"
"What devices are connected to the LAN?"
"Block the domain malicious.example.com"
"Is Suricata running?"
"What are my current floating firewall rules?"
```

---

### 6.15 System Settings

#### 6.15.1 General Setup (`/system/general-setup`)

- **Hostname** and **Domain** — set the appliance's FQDN.
- **Timezone** — used by the NTP daemon and event timestamps.
- **Theme** — light or dark UI theme.
- **Login message** — displayed on the login page.

#### 6.15.2 Security Hardening (`/system/admin-access`)

- **Brute-force protection:** Set the maximum failed login attempts (per IP or per username)
  before triggering a lockout, and the lockout duration in seconds.
- **Whitelist IPs:** CIDR ranges that bypass brute-force lockout (e.g., the admin workstation).

#### 6.15.3 Advanced Settings (`/system/advanced`)

Nested tabs provide access to:

- **Firewall/NAT:** PF state table tuning (maximum states, state timeouts, fragment handling),
  MSS clamping, NAT reflection global settings.
- **Network:** IPv6 global enable/disable, hardware TCP checksum offload, ARP proxy, SLAAC.
- **Miscellaneous:** Power management, thermal sensors, MTU discovery, swap usage.
- **System Tunables:** Arbitrary sysctl knobs — add, edit, or delete kernel parameter
  overrides that are applied at boot.

#### 6.15.4 Preflight Check (`/system/preflight`)

The preflight check validates the deployment environment:

- FreeBSD kernel capabilities: PF, ALTQ, CARP, netmap, BPF.
- Required daemon binaries: pfctl, dhcpd, unbound, openvpn, charon, suricata.
- Config validators: pfctl -nf, dhcpd -t, unbound-checkconf, suricata -T.
- Environment secrets: SECRET_KEY entropy, SMARTSHIELD_MASTER_KEY presence.
- Database schema version.

Review the preflight results before moving to live mode to ensure all required components
are present and functional.

---

## 7. Environment Variables Reference

The environment file is at `/usr/local/etc/smart-shield/smart-shield.env`.

| Variable | Default | Required | Description |
|---|---|---|---|
| `APP_ENV` | `production` | No | Set to `development` to enable Flask debug mode |
| `SECRET_KEY` | *(none)* | **Yes** | Flask session encryption key; must be long and random |
| `FLASK_DEBUG` | `0` | No | Set to `1` to enable Flask auto-reloader (development only) |
| `SMARTSHIELD_DB_PATH` | `/var/db/smart-shield/data.db` | No | SQLite database file path |
| `SMARTSHIELD_CONFIG_PATH` | `/usr/local/etc/smart-shield/config.json` | No | JSON configuration file path |
| `SMARTSHIELD_UPLOAD_DIR` | `/var/db/smart-shield/uploads/profile_pictures` | No | Profile picture storage directory |
| `SMARTSHIELD_AUDIT_LOG_PATH` | `/var/log/smart-shield/audit.log` | No | Append-only SIEM audit log path |
| `SMARTSHIELD_APP_LOG_PATH` | `/var/log/smart-shield/app.log` | No | Application log path |
| `SMARTSHIELD_ENABLE_NETWORK_APPLY` | `0` | No | Set to `1` to allow live OS-level changes (live mode) |
| `SMARTSHIELD_NETWORK_DRY_RUN` | `1` | No | Set to `0` to disable dry-run safety and allow actual network changes |
| `SMARTSHIELD_MASTER_KEY` | *(auto-generated)* | No | Base64-encoded 32-byte AES-256 key for encrypting secrets in the database |
| `ABUSECH_AUTH_KEY` | *(empty)* | No | abuse.ch personal auth key; enables threat intelligence integration |
| `ABUSECH_DRY_RUN` | `1` | No | Set to `0` to enable live abuse.ch API calls; default is log-only |
| `GROQ_API_KEY` | *(empty)* | No | Groq API key; enables the AI assistant chatbot |

**Note:** Set both `SMARTSHIELD_ENABLE_NETWORK_APPLY=1` and `SMARTSHIELD_NETWORK_DRY_RUN=0`
to enable full live mode where firewall changes are applied immediately to the running kernel.

---

## 8. Log Files Reference

| Path | Content | Rotation |
|---|---|---|
| `/var/log/smart-shield/audit.log` | SIEM event log — NDJSON, one event per line | Daily, 90-day retention, 10 MB max, bzip2 compressed |
| `/var/log/smart-shield/app.log` | Application log (gunicorn stdout) | Daily, 30-day retention, bzip2 |
| `/var/log/smart-shield/access.log` | HTTP access log (gunicorn) | Daily, 30-day retention, 50 MB max, bzip2 |
| `/var/log/smart-shield/error.log` | Application error log (gunicorn stderr) | Daily, 30-day retention, bzip2 |
| `/var/log/nginx/access.log` | nginx access log | Managed by nginx; review `/etc/newsyslog.conf` |
| `/var/log/nginx/error.log` | nginx error log | Managed by nginx |
| `/var/log/suricata/eve.json` | Suricata EVE JSON alert and event stream | Not managed by Smart Shield; configure via Suricata |
| `/var/log/suricata/fast.log` | Suricata one-line alert summary | Not managed by Smart Shield |
| `/var/log/suricata/suricata.log` | Suricata startup and runtime log | Not managed by Smart Shield |
| `/var/log/unbound/query.log` | Unbound DNS query log (when enabled) | Not managed by Smart Shield |
| `/var/log/openvpn/status*.log` | OpenVPN connection status files | Not managed by Smart Shield |

Log rotation is handled by newsyslog(8) via
`/usr/local/etc/newsyslog.d/smart-shield.conf`, installed during setup.

---

## 9. Directory Structure Reference

| Path | Purpose |
|---|---|
| `/usr/local/share/smart-shield/` | Application code root |
| `/usr/local/share/smart-shield/.venv/` | Python virtual environment |
| `/usr/local/etc/smart-shield/` | Environment file, config.json, SSL certificates |
| `/usr/local/etc/smart-shield/ssl/` | TLS certificate (`cert.pem`) and private key (`key.pem`) |
| `/usr/local/etc/mrtg/` | MRTG configuration (`mrtg.cfg`) |
| `/usr/local/etc/suricata/` | Suricata configuration and rules |
| `/usr/local/etc/unbound/` | Unbound configuration |
| `/usr/local/etc/openvpn/` | OpenVPN server and client configuration files |
| `/usr/local/etc/openvpn/keys/` | OpenVPN key and certificate files (mode 0700) |
| `/usr/local/etc/nginx/nginx.conf` | nginx TLS reverse proxy configuration |
| `/var/db/smart-shield/` | SQLite database and application data |
| `/var/db/smart-shield/data.db` | SQLite database (all configuration) |
| `/var/db/smart-shield/mrtg/` | MRTG graph PNG output |
| `/var/db/smart-shield/uploads/` | User profile picture uploads |
| `/var/db/smart-shield/threat_intel_ips.txt` | Latest threat intelligence IP list |
| `/var/log/smart-shield/` | Application, audit, access, and error logs |
| `/var/run/smart-shield/` | PID file, worker lock, MRTG lock (tmpfs — cleared on reboot) |
| `/etc/cron.d/smart-shield-mrtg` | MRTG cron job (`*/5 * * * *`) |
| `/etc/pf.conf` | Active PF firewall ruleset |
| `/usr/local/etc/rc.d/smart_shield` | FreeBSD rc.d service script |
| `/usr/local/sbin/smartshieldctl` | Operator CLI utility |
| `/usr/local/sbin/smart_shield_console` | Interactive console recovery menu |
| `/usr/local/sbin/mrtg-probe.sh` | netstat-based MRTG data probe script |
| `/usr/local/etc/sudoers.d/smartshield` | sudo allowlist for privileged operations |
| `/usr/local/etc/newsyslog.d/smart-shield.conf` | Log rotation configuration |

---

## 10. Troubleshooting

### IDS shows as disabled after navigating away from the Threat Detection page

**Cause:** The configuration save form previously included an "Enable IDS" checkbox that could
overwrite the enabled state if the form was submitted while the checkbox appeared unchecked
(e.g., after browser form state restoration). This has been fixed: the enabled state is now
managed exclusively through the Enable/Disable toggle button and is never touched by the
configuration save form.

**Resolution:** Ensure you are running the current version. If the issue persists:

```sh
# Check DB state
sqlite3 /var/db/smart-shield/data.db "SELECT enabled, mode FROM ids_config;"
# If enabled=0 unexpectedly, use the toggle button in the GUI to re-enable.
```

### MRTG graphs not showing in the browser

**Check the status bar** on the Traffic History page — it shows a specific badge for each
possible problem:

| Badge | Cause | Fix |
|---|---|---|
| "Stale lock file detected" | `/var/run/smart-shield/mrtg.lock` left by a crashed MRTG run | Click **Reinitialize MRTG** |
| "Cron job missing" | `/etc/cron.d/smart-shield-mrtg` not installed | Click **Regenerate Config** |
| "Graph directory missing" | `/var/db/smart-shield/mrtg/` absent or not writable | Run `install -d -m 0755 /var/db/smart-shield/mrtg` as root |
| "No graphs yet" (with cron installed) | MRTG hasn't run yet | Wait up to 5 minutes for the first cron tick |

Manual check:

```sh
# Is the cron job installed?
cat /etc/cron.d/smart-shield-mrtg

# Do PNG files exist?
ls /var/db/smart-shield/mrtg/*.png 2>/dev/null || echo "No PNGs"

# Run MRTG manually with verbose output
env LANG=C /usr/local/bin/mrtg /usr/local/etc/mrtg/mrtg.cfg --log-level 4
```

### Cannot reach the web GUI from a LAN client

```sh
# Is nginx listening on 443?
sockstat -4 -l | grep 443

# Is the Smart Shield service running?
smartshieldctl status

# Is there a PF rule blocking port 443 on LAN?
pfctl -sr | grep 443

# Can the LAN client ping the appliance LAN IP?
ping 192.168.1.1
```

If the LAN client cannot reach the LAN IP at all, verify the interface assignment
(`smartshieldctl iface-show LAN`) and confirm the LAN interface has the expected IP.

### DHCP leases not being assigned to LAN clients

```sh
# Is DHCPd running?
smartshieldctl dhcp-status
pgrep -x dhcpd

# Check the DHCPd log for errors
tail -30 /var/log/messages | grep dhcpd

# Validate the config
dhcpd -t -cf /usr/local/etc/dhcpd.conf
```

Ensure the DHCP pool range is within the LAN subnet and does not overlap with the static
LAN IP of the appliance.

### DNS resolution failing for LAN clients

```sh
# Is Unbound running?
smartshieldctl dns-status
pgrep -x unbound

# Test resolution from the appliance itself
dig @127.0.0.1 google.com

# Check Unbound logs
tail -20 /var/log/messages | grep unbound

# Validate the config
unbound-checkconf /usr/local/etc/unbound/unbound.conf
```

Ensure LAN clients are configured to use the appliance LAN IP as their DNS server (typically
pushed via DHCP).

### Suricata fails to start (IPS mode)

If Suricata fails to start in IPS mode:

1. Check that your NIC driver supports netmap: `kldstat | grep netmap`.
2. Review the startup log: `tail -50 /var/log/suricata/suricata.log`.
3. Run the config test: `suricata -T -c /usr/local/etc/suricata/suricata.yaml`.
4. Switch to IDS mode via the Configuration tab and try enabling again.

Smart Shield automatically falls back to IDS (pcap) mode if the netmap-based IPS start fails.

### Backup restore fails with "schema version mismatch"

This occurs when restoring a backup created by a different version of Smart Shield. Restore
backups only to the same version that created them, or migrate to the new schema version
first by running the application normally (it applies schema migrations automatically on
startup).
