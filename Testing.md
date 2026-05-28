# Smart Shield — FreeBSD Deployment & Manual Testing Guide

> **Platform target:** FreeBSD 14.x (amd64)  
> **Tested stack:** Python 3.11, Gunicorn 22, PF, OpenVPN, strongSwan, mpd5  
> **Author:** Smart Shield Project Team

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Moving Smart Shield to FreeBSD](#2-moving-smart-shield-to-freebsd)
   - 2.1 [System Preparation](#21-system-preparation)
   - 2.2 [Transfer the Codebase](#22-transfer-the-codebase)
   - 2.3 [Python Environment](#23-python-environment)
   - 2.4 [Directory Layout & Permissions](#24-directory-layout--permissions)
   - 2.5 [Environment & Configuration Files](#25-environment--configuration-files)
   - 2.6 [Master Encryption Key](#26-master-encryption-key)
   - 2.7 [rc.d Service & Auto-start](#27-rcd-service--auto-start)
   - 2.8 [Sudoers Allowlist](#28-sudoers-allowlist)
   - 2.9 [Log Rotation](#29-log-rotation)
   - 2.10 [First Boot Verification](#210-first-boot-verification)
3. [Testing: Authentication & Session](#3-testing-authentication--session)
4. [Testing: Setup Wizard](#4-testing-setup-wizard)
5. [Testing: Dashboard & System](#5-testing-dashboard--system)
6. [Testing: User Management](#6-testing-user-management)
7. [Testing: Network Interfaces](#7-testing-network-interfaces)
8. [Testing: Routing](#8-testing-routing)
9. [Testing: Firewall & NAT](#9-testing-firewall--nat)
10. [Testing: DHCP & DNS](#10-testing-dhcp--dns)
11. [Testing: VPN — OpenVPN](#11-testing-vpn--openvpn)
12. [Testing: VPN — IPsec](#12-testing-vpn--ipsec)
13. [Testing: VPN — L2TP/IPsec](#13-testing-vpn--l2tpipsec)
14. [Testing: Certificates & PKI](#14-testing-certificates--pki)
15. [Testing: IDS/IPS (Suricata)](#15-testing-idsips-suricata)
16. [Testing: Content Filtering](#16-testing-content-filtering)
17. [Testing: Services (DHCP, DNS, NTP, DDNS, SNMP, UPnP)](#17-testing-services)
18. [Testing: Diagnostics](#18-testing-diagnostics)
19. [Testing: Audit Logs & Status](#19-testing-audit-logs--status)
20. [Testing: Config Versioning & Rollback](#20-testing-config-versioning--rollback)
21. [Testing: Security Controls](#21-testing-security-controls)
22. [Regression Checklist](#22-regression-checklist)

---

## 1. Prerequisites

### On the FreeBSD host

| Requirement | Version |
|-------------|---------|
| FreeBSD | 14.0-RELEASE or 14.1-RELEASE |
| Python | 3.11+ (`pkg install python311`) |
| pip | bundled with python311 |
| OpenVPN | 2.6+ (`pkg install openvpn`) |
| strongSwan | 5.9+ (`pkg install strongswan`) |
| mpd5 | 5.9+ (`pkg install mpd5`) |
| Suricata | 7.x (`pkg install suricata`) |
| sudo | (`pkg install sudo`) |
| git | (`pkg install git`) — optional |

### Network requirements for VPN tests

- At least **two network interfaces** visible to FreeBSD (physical or VMs with multiple NICs)
- A **test client machine** (Linux, Windows, or another BSD) on the same or routed network
- Internet access from the FreeBSD host (for DDNS / update tests)

---

## 2. Moving Smart Shield to FreeBSD

### 2.1 System Preparation

```sh
# Update package database
pkg update && pkg upgrade -y

# Install all runtime dependencies
pkg install -y python311 py311-pip openvpn strongswan mpd5 suricata sudo git curl

# Create dedicated service user (no shell, no home login)
pw useradd -n smartshield -s /usr/sbin/nologin -d /var/db/smartshield -m -c "Smart Shield Daemon"
```

### 2.2 Transfer the Codebase

**Option A — SCP from dev machine:**

```sh
# On your Windows dev machine (PowerShell):
scp -r "C:\Users\m7med\OneDrive\Desktop\A3OOOOOOOOOOOOOO\NIGGA\Smart-Shield" \
    root@<freebsd-ip>:/usr/local/share/smartshield
```

**Option B — Git clone:**

```sh
git clone https://github.com/your-org/smart-shield.git /usr/local/share/smartshield
```

**Option C — Tarball:**

```sh
# On dev machine — create tarball (PowerShell):
tar -czf smart-shield.tar.gz -C "C:\Users\m7med\OneDrive\Desktop\A3OOOOOOOOOOOOOO\NIGGA" Smart-Shield

# On FreeBSD:
tar -xzf smart-shield.tar.gz -C /usr/local/share/
mv /usr/local/share/Smart-Shield /usr/local/share/smartshield
```

### 2.3 Python Environment

```sh
cd /usr/local/share/smartshield

# Create virtualenv with FreeBSD python311
python3.11 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Verify key packages
python -c "import flask, cryptography, gunicorn; print('OK')"
```

> **Expected output:** `OK`

### 2.4 Directory Layout & Permissions

```sh
# Runtime directories
install -d -o smartshield -g smartshield -m 750 /var/db/smartshield
install -d -o smartshield -g smartshield -m 750 /var/db/smartshield/uploads
install -d -o smartshield -g smartshield -m 750 /var/db/smartshield/uploads/profile_pictures
install -d -o smartshield -g smartshield -m 750 /var/log/smartshield
install -d -o root         -g smartshield -m 750 /usr/local/etc/smartshield

# Application source (read-only for smartshield user)
chown -R root:smartshield /usr/local/share/smartshield
chmod -R 750 /usr/local/share/smartshield
```

### 2.5 Environment & Configuration Files

```sh
# Copy the example env file
cp /usr/local/share/smartshield/.env.example \
   /usr/local/etc/smartshield/smartshield.env

vi /usr/local/etc/smartshield/smartshield.env
```

Set these values:

```ini
SECRET_KEY=<at-least-64-random-chars>
FLASK_DEBUG=0
SMARTSHIELD_DB_PATH=/var/db/smartshield/data.db
SMARTSHIELD_CONFIG_PATH=/usr/local/etc/smartshield/config.json
SMARTSHIELD_UPLOAD_DIR=/var/db/smartshield/uploads/profile_pictures
SMARTSHIELD_AUDIT_LOG_PATH=/var/log/smartshield/audit.log
SMARTSHIELD_ENABLE_NETWORK_APPLY=1
SMARTSHIELD_NETWORK_DRY_RUN=0
BOOTSTRAP_ADMIN_USERNAME=admin
BOOTSTRAP_ADMIN_PASSWORD=<strong-password-change-immediately>
```

```sh
# Copy system config
cp /usr/local/share/smartshield/config.example.json \
   /usr/local/etc/smartshield/config.json

chown root:smartshield /usr/local/etc/smartshield/smartshield.env \
                        /usr/local/etc/smartshield/config.json
chmod 640 /usr/local/etc/smartshield/smartshield.env \
           /usr/local/etc/smartshield/config.json
```

### 2.6 Master Encryption Key

The master key encrypts VPN pre-shared keys and L2TP/PPPoE passwords at rest.

```sh
# Auto-generate on first run (preferred)
# The app writes /usr/local/etc/smartshield/master.key automatically

# OR generate manually and set env var:
python3.11 -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())"
# Add to smartshield.env:
# SMARTSHIELD_MASTER_KEY=<output above>
```

### 2.7 rc.d Service & Auto-start

The project ships with `bsd/smart-shield.rc` (the rc.d script). Install it:

```sh
install -o root -g wheel -m 555 \
    /usr/local/share/smartshield/bsd/smart-shield.rc \
    /usr/local/etc/rc.d/smart_shield

# Add to /etc/rc.conf
echo 'smart_shield_enable="YES"' >> /etc/rc.conf

# Verify rc script syntax
service smart_shield status
```

The rc script should call gunicorn as the `smartshield` user:

```sh
# Manual start for first-time verification:
su -m smartshield -c "cd /usr/local/share/smartshield && \
    .venv/bin/gunicorn \
    --env-file /usr/local/etc/smartshield/smartshield.env \
    --workers 2 \
    --bind 0.0.0.0:443 \
    --certfile /usr/local/etc/smartshield/ssl/server.crt \
    --keyfile  /usr/local/etc/smartshield/ssl/server.key \
    wsgi:app"
```

> For initial HTTP-only testing (no cert yet), use `--bind 0.0.0.0:8080` and leave out `--certfile/--keyfile`.

### 2.8 Sudoers Allowlist

```sh
# Install the sudoers fragment from the bsd/ directory
install -o root -g wheel -m 440 \
    /usr/local/share/smartshield/bsd/sudoers.d/smartshield \
    /usr/local/etc/sudoers.d/smartshield

# Verify it parses cleanly
visudo -c
```

The file grants `smartshield` user privilege to run specific system commands (pfctl, ifconfig, service openvpn, etc.) without a password.

### 2.9 Log Rotation

```sh
install -o root -g wheel -m 644 \
    /usr/local/share/smartshield/bsd/newsyslog.d/smart-shield.conf \
    /usr/local/etc/newsyslog.conf.d/smart-shield.conf

# Test rotation immediately
newsyslog -v /var/log/smartshield/audit.log
```

### 2.10 First Boot Verification

```sh
# Start the service
service smart_shield start

# Tail the application log
tail -f /var/log/smartshield/app.log &

# Verify gunicorn workers are up
ps aux | grep gunicorn

# Check the port is listening
sockstat -4 | grep 8080   # or 443 if SSL

# Hit the login page
curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/login
```

> **Expected:** HTTP 200

---

## 3. Testing: Authentication & Session

### 3.1 Valid Login

1. Open `http://<freebsd-ip>:8080/login` in a browser.
2. Enter username `admin` and the bootstrap password from `.env`.
3. Click **Sign In**.
4. **Expected:** Redirect to `/` (dashboard). Sidebar and top navbar visible.

### 3.2 Invalid Login

1. Submit wrong password.
2. **Expected:** Stays on `/login`, flash message "Invalid username or password".

### 3.3 Session Persistence

1. Login successfully.
2. Open a new tab, visit `/system`.
3. **Expected:** Page loads (session cookie retained).

### 3.4 Logout

1. Click the user icon → **Logout** in the sidebar.
2. **Expected:** Redirect to `/login`.
3. Try navigating to `/system` directly.
4. **Expected:** Redirect back to `/login`.

### 3.5 Superuser vs. Regular User Access

1. Create a regular user (see Section 6).
2. Log in as that user.
3. Try `/system/user-manager`.
4. **Expected:** 403 Forbidden or redirect.
5. **Expected (superuser):** Full access.

---

## 4. Testing: Setup Wizard

> Run this on a fresh DB (`rm /var/db/smartshield/data.db`) or a test instance.

### 4.1 Step 1 — Interface Assignment

> **Match by MAC address, not device name.** The wizard auto-detects
> whatever physical NICs are present, but the labels are
> platform-dependent: VMware names them `em0`, `em1`, …; libvirt/QEMU
> shows `vtnet0`, `vtnet1`; Intel server NICs are `igb0`, `igb1`; Realtek
> appears as `re0`; etc. The dropdown shows each port's MAC next to its
> name — pick the MAC of the cable that runs upstream for WAN and the
> MAC of the cable that runs to your LAN switch for LAN. If you guess by
> name on a non-VMware host you will swap the roles and lock yourself
> out of the GUI.

1. Navigate to `/setup/step1`.
2. From the WAN dropdown, pick the port whose **MAC** matches the
   upstream cable (the example below uses `em0`, but you may see
   `vtnet0` / `igb0` / `re0` depending on the host).
3. From the LAN dropdown, pick the port whose **MAC** matches the
   downstream switch cable (example: `em1`).
4. Click **Next**.
5. **Expected:** Redirect to `/setup/step2`.
6. **DB check:** `SELECT * FROM interface_assignments;` — rows present.

### 4.2 Step 2 — LAN Configuration

1. Set LAN IP to `192.168.1.1`, subnet `24`.
2. Click **Next**.
3. **Expected:** Redirect to `/setup/step3`.
4. **DB check:** `SELECT * FROM lan_config;` — `ipv4_address` column populated.

### 4.3 Step 3 — Admin Password

1. Enter new admin password (min 8 chars).
2. Confirm password.
3. Click **Next**.
4. **Expected:** Redirect to `/setup/step4`.
5. **Verify:** Old bootstrap password no longer works on next login.

### 4.4 Step 4 — Apply & Finish

1. Review summary on step 4 page.
2. Click **Apply**.
3. **Expected:** `service_state` table has `setup_complete = true`.
4. **Expected:** Redirect to dashboard.

---

## 5. Testing: Dashboard & System

### 5.1 Dashboard Loads

1. Login as admin. Visit `/`.
2. **Expected:** KPI cards visible (CPU, Memory, Disk, Swap), service status tiles, no JS errors in console.

### 5.2 System Settings

1. Navigate to `/system/general-setup`.
2. Change hostname to `test-shield`, click **Save**.
3. **Expected:** Flash success, page reloads with new hostname.
4. **DB check:** `SELECT value_json FROM service_state WHERE key_name='system_config';`

### 5.3 Health Monitoring

1. Navigate to `/status/smart-status` or `/status/summary`.
2. **Expected:** CPU/memory/disk percentages shown, health snapshots rendering.

---

## 6. Testing: User Management

### 6.1 Create User

1. Navigate to `/system/user-manager`.
2. Click **Add User**.
3. Fill in: username `testuser`, password, email, full name.
4. Click **Save**.
5. **Expected:** User appears in the list.
6. **DB check:** `SELECT * FROM users WHERE username='testuser';`

### 6.2 Create Group & Assign Permissions

1. Navigate to `/system/user-manager` → **Groups** tab.
2. Create group `network-admins`.
3. Assign page permissions: check `/interfaces` and `/routing`.
4. Add `testuser` to this group.
5. **Expected:** `testuser` can access `/interfaces` but not `/vpn`.

### 6.3 Edit User (Profile Picture)

1. Edit `testuser` → upload a small PNG as profile picture.
2. **Expected:** Image appears in the user card.
3. **File check:** `ls /var/db/smartshield/uploads/profile_pictures/`

### 6.4 Disable / Delete User

1. Edit `testuser` → set status to **Disabled**.
2. Try logging in as `testuser`.
3. **Expected:** Login rejected.
4. Delete the user from the manager.
5. **Expected:** User removed from list.

---

## 7. Testing: Network Interfaces

### 7.1 WAN Configuration

1. Navigate to `/interfaces/wan`.
2. Set IP type to **Static**, enter WAN IP, gateway, and DNS.
3. Click **Save** then **Apply**.
4. **Expected:** Flash success. On FreeBSD: `ifconfig em0` shows new IP.
5. **DB check:** `SELECT * FROM wan_config;`

### 7.2 LAN Configuration

1. Navigate to `/interfaces/lan`.
2. Change LAN MTU to `1500`, add a description.
3. Click **Save & Apply**.
4. **Expected:** `ifconfig em1` reflects MTU change on FreeBSD.

### 7.3 VLAN

1. Navigate to `/interfaces/vlan` → **Add VLAN**.
2. Parent interface: `em0`, VLAN tag: `10`, description: `MGMT`.
3. Click **Save**.
4. **Expected:** Row appears in VLAN table.
5. **FreeBSD check:** `ifconfig vlan10` exists (after apply).

### 7.4 Interface Assignment

1. Navigate to `/interfaces/assignments`.
2. Add a new assignment mapping `em2` to `OPT1`.
3. **Expected:** Assignment appears in the table.

### 7.5 GRE Tunnel

1. Navigate to `/interfaces/gre` → **Add**.
2. Parent: `em0`, remote address: `10.0.0.2`, local tunnel address: `172.16.0.1/30`.
3. Save and apply.
4. **Expected:** GRE interface appears in assignments.

---

## 8. Testing: Routing

### 8.1 Add Gateway

1. Navigate to `/routing/gateways` → **Add**.
2. Name: `GW_WAN`, interface: `WAN`, gateway IP: `<your WAN gateway>`.
3. Save.
4. **Expected:** Gateway in list, not disabled.

### 8.2 Add Static Route

1. Navigate to `/routing/static-routes` → **Add**.
2. Destination: `10.10.0.0/24`, gateway: `GW_WAN`.
3. Save.
4. **FreeBSD check:** `netstat -rn | grep 10.10.0.0`

### 8.3 Gateway Group

1. Navigate to `/routing/gateway-groups` → **Add**.
2. Name: `FAILOVER`, add two gateways with tier priorities.
3. Save.
4. **Expected:** Group appears, members JSON stored correctly.

---

## 9. Testing: Firewall & NAT

### 9.1 LAN Firewall Rule

1. Navigate to `/firewall/rules` → **LAN** tab → **Add**.
2. Protocol: `TCP`, source: `LAN net`, destination: `any`, destination port: `443`.
3. Save and apply.
4. **Expected:** Rule appears in LAN rules list.
5. **FreeBSD check:** `pfctl -sr | grep 443`

### 9.2 Floating Rule

1. Navigate to `/firewall/rules` → **Floating** tab → **Add**.
2. Interface: `WAN`, direction: `in`, action: `Block`, source: `192.168.100.0/24`.
3. Save.
4. **Expected:** Row in floating rules list with correct order.

### 9.3 Rule Reorder

1. In the LAN rules list, drag rule 2 above rule 1 (or use the move API).
2. **Expected:** `rule_order` values update in DB.

### 9.4 NAT Port Forward

1. Navigate to `/firewall/nat` → **Port Forward** tab → **Add**.
2. External port: `8443`, protocol: `TCP`, destination port: `443`, destination IP: `192.168.1.100`.
3. Save and apply.
4. **FreeBSD check:** `pfctl -sn | grep 8443`

### 9.5 NAT Outbound

1. Add outbound NAT rule: interface `WAN`, source `192.168.1.0/24`, target: WAN address.
2. **FreeBSD check:** `pfctl -sn | grep 192.168.1.0`

### 9.6 Alias

1. Navigate to `/firewall/aliases` → **Add**.
2. Type: `Network`, name: `INTERNAL_NETS`, content: `192.168.0.0/16`.
3. Save.
4. **Expected:** Alias available in rule dropdowns.

---

## 10. Testing: DHCP & DNS

### 10.1 DHCP Server

1. Navigate to `/services/dhcp-server`.
2. Enable DHCP, range: `192.168.1.100`–`192.168.1.200`, DNS: `192.168.1.1`.
3. Save and apply.
4. **FreeBSD check:** `service isc-dhcpd status` (running).
5. Connect a DHCP client on the LAN — verify it gets an address in range.

### 10.2 DHCP Static Mapping

1. Navigate to `/services/dhcp-server` → **Static Mappings** → **Add**.
2. MAC: `aa:bb:cc:dd:ee:ff`, IP: `192.168.1.50`, hostname: `myserver`.
3. Save.
4. **Expected:** Entry in static mappings table.

### 10.3 DHCP Leases

1. Navigate to `/services/dhcp-leases`.
2. **Expected:** Table shows active leases from clients.

### 10.4 DNS Resolver

1. Navigate to `/services/dns-resolver`.
2. Enable resolver, enable DNSSEC.
3. Add a custom host: hostname `nas.local`, IP `192.168.1.10`.
4. Save and apply.
5. **FreeBSD check:** `dig nas.local @192.168.1.1` returns `192.168.1.10`.

### 10.5 DNS Forwarder

1. Navigate to `/services/dns-forwarder`.
2. Enable, set upstream: `1.1.1.1`.
3. Save and apply.
4. **FreeBSD check:** `dig google.com @192.168.1.1` resolves.

---

## 11. Testing: VPN — OpenVPN

### 11.1 Create OpenVPN Server

1. Navigate to `/vpn/openvpn`.
2. Click **Add Server**.
3. Fill in:
   - Description: `Test-VPN`
   - Mode: `Remote Access (SSL/TLS + User Auth)`
   - Protocol: `UDP`
   - Port: `1194`
   - Tunnel network: `10.8.0.0/24`
   - Local network: `192.168.1.0/24`
   - TLS Key: paste or generate
   - CA Certificate: select one from the PKI section
4. Click **Save**.
5. **Expected:** Server row appears in the list with disabled toggle off.

### 11.2 Apply OpenVPN Server

1. Click **Apply** next to the new server entry.
2. **Expected:** Flash success.
3. **FreeBSD checks:**
   ```sh
   service openvpn status
   cat /usr/local/etc/openvpn/server.conf
   ifconfig tun0   # tunnel interface should exist
   ```

### 11.3 Connect a VPN Client

On the test client machine (Linux example):

```sh
# Download client config from /vpn/openvpn/clients → export
openvpn --config client.ovpn --daemon

# Verify connection
ip addr show tun0    # should show 10.8.0.x
ping 192.168.1.1     # gateway through tunnel
```

**Expected:** Client gets `10.8.0.x`, can reach LAN `192.168.1.0/24`.

### 11.4 OpenVPN Client-Specific Overrides (CSO)

1. Navigate to `/vpn/openvpn/cso` → **Add**.
2. Common Name: `testclient`, tunnel network: `10.8.0.10/32`.
3. Save.
4. Reconnect the VPN client — verify it receives the fixed IP `10.8.0.10`.

### 11.5 OpenVPN Client Config

1. Navigate to `/vpn/openvpn/clients` → **Add Client**.
2. Server hostname: `<remote VPN server IP>`, port: `1194`, protocol: `UDP`.
3. Upload CA cert, client cert, and key.
4. Save and apply.
5. **FreeBSD check:** `service openvpn status` (client instance running).

### 11.6 OpenVPN Setup Wizard

1. Navigate to `/vpn/openvpn/wizards`.
2. Step through the 3-step wizard: CA selection → Server config → User config.
3. **Expected:** Wizard completes and creates both a CA certificate and an OpenVPN server entry.

---

## 12. Testing: VPN — IPsec

### 12.1 Create IPsec Phase 1 (IKE)

1. Navigate to `/vpn/ipsec` → **Tunnels** tab → **Add P1**.
2. Fill in:
   - IKE Version: `IKEv2`
   - Interface: `WAN`
   - Remote Gateway: `<peer IP>`
   - My Identifier: `My IP address`
   - Auth method: `Pre-Shared Key`
   - Pre-Shared Key: `SuperSecretPSK123`
   - Encryption: `AES`, Key length: `256`, Hash: `SHA256`, DH Group: `14`
   - Lifetime: `28800`
3. Click **Save**.
4. **Expected:** Phase 1 row in the tunnels list.

### 12.2 Create IPsec Phase 2 (Child SA)

1. Click **Show Phase 2** next to the P1 entry → **Add P2**.
2. Fill in:
   - Local network: `192.168.1.0/24`
   - Remote network: `10.0.0.0/24`
   - Protocol: `ESP`
   - Encryption: `AES`, Hash: `SHA256`, Key length: `256`
   - Lifetime: `3600`
3. Click **Save**.

### 12.3 Apply IPsec

1. Click **Apply** on the IPsec tunnels page.
2. **FreeBSD checks:**
   ```sh
   service strongswan status
   cat /usr/local/etc/ipsec.conf
   cat /usr/local/etc/ipsec.secrets
   swanctl --list-conns
   ```

### 12.4 Establish IPsec Tunnel

On the peer machine (also running strongSwan):

```sh
swanctl --initiate --child <conn-name>
swanctl --list-sas    # verify SA established
```

On FreeBSD host:

```sh
swanctl --list-sas
ping 10.0.0.1   # destination behind peer
```

**Expected:** SA shows `ESTABLISHED`, traffic flows through the tunnel.

### 12.5 IPsec Pre-Shared Keys Manager

1. Navigate to `/vpn/ipsec?tab=psk`.
2. Add a PSK: identifier `peer@example.com`, key `MyPSK456`.
3. Save.
4. **DB check:** `SELECT identifier FROM ipsec_pre_shared_keys;`
5. **Verify encrypted at rest:** value in `pre_shared_key` column starts with `enc:`.

### 12.6 IPsec Mobile Clients

1. Navigate to `/vpn/ipsec?tab=mobile_clients`.
2. Enable IKEv2 EAP, set virtual address pool: `172.16.100.0/24`.
3. Set DNS server: `192.168.1.1`.
4. Save and apply.
5. From a mobile client (iOS/Windows native IKEv2), connect using the FreeBSD host's WAN IP.
6. **Expected:** Client gets an IP from `172.16.100.x`, can browse through the tunnel.

---

## 13. Testing: VPN — L2TP/IPsec

### 13.1 Configure L2TP Server

1. Navigate to `/vpn/l2tp`.
2. Fill in:
   - Server address: `192.168.1.1`
   - Remote address range: `192.168.200.1` (start of pool)
   - Subnet mask: `255.255.255.0`
   - Authentication: `MSCHAPv2`
   - DNS server 1: `192.168.1.1`
3. Click **Save**.
4. **DB check:** `SELECT * FROM l2tp_config;`

### 13.2 Add L2TP Users

1. On the L2TP page → **Users** tab → **Add User**.
2. Username: `vpnuser1`, password: `Pass@1234`.
3. Save.
4. **Verify encrypted at rest:** `SELECT password FROM l2tp_users WHERE username='vpnuser1';` — should start with `enc:`.

### 13.3 Apply L2TP

1. Click **Apply** on the L2TP page.
2. **FreeBSD checks:**
   ```sh
   service mpd5 status
   cat /usr/local/etc/mpd5/mpd.conf
   cat /usr/local/etc/mpd5/mpd.secret
   ```

### 13.4 Connect L2TP Client (Windows)

1. On Windows: **Settings → VPN → Add VPN** → type: `L2TP/IPsec with Pre-shared Key`.
2. Server: `<freebsd-ip>`, PSK from the IPsec PSK manager.
3. Username: `vpnuser1`, password: `Pass@1234`.
4. Connect.
5. **Expected:** VPN shows "Connected", client gets IP from `192.168.200.x`.
6. **FreeBSD check:** `mpd5 -f /usr/local/etc/mpd5/mpd.conf status`

### 13.5 Connect L2TP Client (Linux)

```sh
# Install xl2tpd and strongswan
apt-get install xl2tpd strongswan   # on Debian/Ubuntu client

# Configure /etc/ipsec.conf (PSK mode)
# Configure /etc/xl2tpd/xl2tpd.conf
# Start and connect
ipsec up L2TP
echo "c myvpn" > /var/run/xl2tpd/l2tp-control
```

**Expected:** `ppp0` interface gets `192.168.200.x`, ping to `192.168.1.1` succeeds.

---

## 14. Testing: Certificates & PKI

### 14.1 Create Certificate Authority

1. Navigate to `/system/certificates` → **Certificate Authorities** tab → **Add CA**.
2. Fill in: CN `SmartShield-Root-CA`, validity `3650` days.
3. Click **Create**.
4. **Expected:** CA appears in the list with valid dates.
5. **DB check:** `SELECT common_name, valid_from, valid_to FROM certificate_authorities;`

### 14.2 Create Server Certificate

1. Navigate to **Certificates** tab → **Add Certificate**.
2. Select the CA created above, CN `smart-shield.local`, type `Server`.
3. Click **Create**.
4. **Expected:** Certificate in list, signed by the CA.

### 14.3 Download Certificate (PKCS#12)

1. Click **Export** (or download icon) next to the server certificate.
2. **Expected:** Browser downloads a `.p12` file.
3. Verify on CLI: `openssl pkcs12 -info -in exported.p12` (enter password if set).

### 14.4 Certificate Revocation

1. Click **Revoke** on a certificate.
2. **Expected:** Status changes to "Revoked", `revoked_at` timestamp set in DB.

---

## 15. Testing: IDS/IPS (Suricata)

### 15.1 Enable IDS

1. Navigate to `/ids`.
2. Enable IDS, select interface `WAN`, mode: **IDS** (alert only).
3. Home network: `192.168.1.0/24`.
4. Click **Save & Apply**.
5. **FreeBSD check:**
   ```sh
   service suricata status
   tail -f /var/log/suricata/fast.log
   ```

### 15.2 Switch to IPS Mode

1. Change mode to **IPS** (inline blocking).
2. Apply.
3. **FreeBSD check:** `suricata --list-runmodes` — verify `af-packet` or `netmap`.

### 15.3 Rule Management

1. Navigate to `/ids` → **Rulesets** tab.
2. Enable the `emerging-threats` ruleset.
3. Click **Update Rules**.
4. **Expected:** Rule count updates, `last_update` timestamp changes.

### 15.4 Trigger a Test Alert

```sh
# From a client on the LAN, trigger the EICAR test signature:
curl -s https://secure.eicar.org/eicar.com.txt

# On FreeBSD:
tail -f /var/log/suricata/fast.log | grep EICAR
```

**Expected:** Alert line appears in `fast.log`.

---

## 16. Testing: Content Filtering

### 16.1 DNS Filter

1. Navigate to `/filters/dns`.
2. Add a block rule for category `Gambling` or enter domain `badsite.example.com`.
3. Save.
4. From a LAN client: `nslookup badsite.example.com 192.168.1.1`
5. **Expected:** Returns `NXDOMAIN` or the block page IP.

### 16.2 Web Filter

1. Navigate to `/filters/web`.
2. Enable web filtering, add URL `ads.example.com` to block list.
3. Save.
4. From LAN client, attempt HTTP request to `ads.example.com`.
5. **Expected:** Connection blocked or redirected to block page.

### 16.3 Application Filter

1. Navigate to `/filters/app`.
2. Block application category `BitTorrent`.
3. Save and apply.

---

## 17. Testing: Services

### 17.1 NTP Server

1. Navigate to `/services/ntp`.
2. Enable NTP server, set upstream servers to `pool.ntp.org`.
3. Save and apply.
4. **FreeBSD check:** `service ntpd status`
5. From a LAN client: `ntpdate -q 192.168.1.1` — verify clock sync.

### 17.2 SNMP

1. Navigate to `/services/snmp`.
2. Enable SNMP, community: `public`, contact: `admin@local`.
3. Save.
4. **FreeBSD check:** `service bsnmpd status`
5. From a monitoring host: `snmpwalk -v2c -c public <freebsd-ip>` — verify OID tree.

### 17.3 Dynamic DNS

1. Navigate to `/services/dynamic-dns` → **Add**.
2. Provider: `Cloudflare`, hostname: `home.yourdomain.com`, API key: `<your key>`.
3. Save.
4. **Expected:** Entry in list with "Last Updated" timestamp after first check.

### 17.4 Wake-on-LAN

1. Navigate to `/services/wake-on-lan`.
2. Enter MAC address `aa:bb:cc:dd:ee:ff`, interface `LAN`.
3. Click **Wake**.
4. **Expected:** Success message. The target machine (if WoL-capable) powers on.

### 17.5 UPnP / NAT-PMP

1. Navigate to `/services/upnp`.
2. Enable UPnP, interface `LAN`.
3. Save and apply.
4. From a LAN client with a UPnP-capable app (e.g., VLC), verify port mapping is created.
5. **FreeBSD check:** `service miniupnpd status`

### 17.6 Captive Portal

1. Navigate to `/services/captive-portal`.
2. Enable, interface `LAN`, authentication: **Local user database**.
3. Save.
4. Connect a new client to the LAN without a valid session.
5. **Expected:** Browser redirects to `/portal/login`.
6. Log in with a valid user — **Expected:** Redirect to `/portal/success`.

---

## 18. Testing: Diagnostics

### 18.1 Ping

1. Navigate to `/diagnostics/ping`.
2. Enter hostname `8.8.8.8`, count `4`.
3. Click **Ping**.
4. **Expected:** RTT values returned in the UI.

### 18.2 Traceroute

1. Navigate to `/diagnostics/traceroute`.
2. Target: `google.com`.
3. **Expected:** Hop-by-hop output with IPs and RTTs.

### 18.3 Packet Capture

1. Navigate to `/diagnostics/packet-capture`.
2. Interface: `em0`, filter: `port 80`, count: `10`.
3. Click **Start**.
4. Generate traffic (HTTP request from client).
5. **Expected:** Captured packets displayed or downloadable `.pcap`.

### 18.4 PF Info / PF Top

1. Navigate to `/diagnostics/pfinfo`.
2. **Expected:** PF state table count, rule stats.
3. Navigate to `/diagnostics/pftop`.
4. **Expected:** Live connection listing.

### 18.5 DNS Lookup

1. Navigate to `/diagnostics/dns-lookup`.
2. Query: `example.com`, type: `A`.
3. **Expected:** IP address returned.

---

## 19. Testing: Audit Logs & Status

### 19.1 Audit Log Entries

1. Login, make a config change, apply it.
2. Navigate to `/status/audit-log`.
3. **Expected:** Log entries for login, config save, and apply — each with timestamp, username, action, category.
4. **File check:** `tail -50 /var/log/smartshield/audit.log | python3 -m json.tool`

### 19.2 Application Log

1. Navigate to `/status/app-log`.
2. **Expected:** Recent operational events (service starts, migrations, errors).

### 19.3 Service Status

1. Navigate to `/status/services`.
2. **Expected:** Table showing service name, status (running/stopped), and uptime.

### 19.4 Sensitive Data Redaction in Logs

1. Change a VPN PSK through the UI.
2. Check `audit.log`.
3. **Expected:** PSK value is `[REDACTED]`, not the plaintext secret.

---

## 20. Testing: Config Versioning & Rollback

### 20.1 Config History

1. Navigate to `/status/config-history`.
2. Make two firewall rule changes (save & apply each time).
3. **Expected:** Two new entries in the config history list for the `firewall` service.

### 20.2 Rollback

1. Click **Restore** on a previous firewall config version.
2. **Expected:**
   - Flash success.
   - `pfctl -sr` output matches the older config.
   - New history entry created for the rollback action.

### 20.3 Interface Change Rollback (60-second window)

1. Change the LAN IP to an invalid value and apply.
2. Within 60 seconds, click **Undo** in the UI (or the rollback widget).
3. **Expected:** LAN IP reverts. `ifconfig em1` shows the original address.

---

## 21. Testing: Security Controls

### 21.1 CSRF Protection

```sh
# Attempt a cross-site POST without CSRF token
curl -X POST http://<freebsd-ip>:8080/system/api/save \
     -H "Content-Type: application/json" \
     -d '{"hostname":"evil"}'
```

**Expected:** HTTP 403 Forbidden.

### 21.2 CSRF with Valid Token

```sh
# Get a token from the login page first, then use it:
curl -c cookies.txt -b cookies.txt \
     -X POST http://<freebsd-ip>:8080/system/api/save \
     -H "X-CSRF-Token: <token-from-page-source>" \
     -H "Content-Type: application/json" \
     -d '{"hostname":"test-shield"}'
```

**Expected:** HTTP 200.

### 21.3 Unauthenticated Access

```sh
curl -s -o /dev/null -w "%{http_code}" \
     http://<freebsd-ip>:8080/system
```

**Expected:** HTTP 302 redirect to `/login`.

### 21.4 Secret Encryption at Rest

```sh
# After saving an IPsec PSK via the UI:
sqlite3 /var/db/smartshield/data.db \
    "SELECT pre_shared_key FROM ipsec_phase1 LIMIT 1;"
```

**Expected:** Value starts with `enc:` — never plaintext.

### 21.5 Privilege Separation Verification

```sh
# The gunicorn process should NOT run as root
ps aux | grep gunicorn | head -1
```

**Expected:** User column shows `smartshield`, not `root`.

```sh
# Attempt a forbidden sudo command as smartshield
su -m smartshield -c "sudo rm -rf /etc"
```

**Expected:** `sudo: command not allowed`.

---

## 22. Regression Checklist

Run through this checklist before any production deployment or after major code changes:

| # | Feature | Test | Pass/Fail |
|---|---------|------|-----------|
| 1 | Login with valid credentials | Section 3.1 | |
| 2 | Login with invalid credentials | Section 3.2 | |
| 3 | Logout clears session | Section 3.4 | |
| 4 | Setup wizard completes | Section 4 | |
| 5 | Dashboard loads with no JS errors | Section 5.1 | |
| 6 | Create, edit, delete user | Section 6 | |
| 7 | WAN static IP apply → `ifconfig` reflects change | Section 7.1 | |
| 8 | LAN DHCP range active → client gets address | Section 10.1 | |
| 9 | DNS resolver resolves external domains | Section 10.4 | |
| 10 | Firewall LAN rule appears in `pfctl -sr` | Section 9.1 | |
| 11 | NAT port forward in `pfctl -sn` | Section 9.4 | |
| 12 | OpenVPN server generates valid `server.conf` | Section 11.1 | |
| 13 | OpenVPN client connects and gets tunnel IP | Section 11.3 | |
| 14 | IPsec P1+P2 config generates valid `ipsec.conf` | Section 12.1–12.2 | |
| 15 | IPsec tunnel establishes with peer | Section 12.4 | |
| 16 | L2TP mpd5 starts after apply | Section 13.3 | |
| 17 | L2TP Windows client connects | Section 13.4 | |
| 18 | Certificate CA created, cert signed | Section 14.1–14.2 | |
| 19 | PKCS#12 export opens in openssl | Section 14.3 | |
| 20 | VPN PSK stored encrypted (`enc:` prefix) | Section 21.4 | |
| 21 | CSRF block on token-less POST | Section 21.1 | |
| 22 | Unauthenticated request redirects to login | Section 21.3 | |
| 23 | Audit log entry created per action | Section 19.1 | |
| 24 | Config rollback restores previous state | Section 20.2 | |
| 25 | gunicorn runs as `smartshield` user, not root | Section 21.5 | |

---

## Appendix: Useful Commands on FreeBSD

```sh
# View PF rules
pfctl -sr

# View NAT rules
pfctl -sn

# View active PF states
pfctl -ss | head -30

# Restart PF
pfctl -d && pfctl -e -f /etc/pf.conf

# OpenVPN logs
tail -f /var/log/openvpn.log

# strongSwan/IPsec status
swanctl --list-sas
swanctl --list-conns

# mpd5 / L2TP status
service mpd5 status

# Suricata alerts
tail -f /var/log/suricata/fast.log

# Smart Shield app log
tail -f /var/log/smartshield/app.log

# Smart Shield audit log (pretty-printed NDJSON)
tail -100 /var/log/smartshield/audit.log | while read line; do echo "$line" | python3 -m json.tool; done

# SQLite quick queries
sqlite3 /var/db/smartshield/data.db ".tables"
sqlite3 /var/db/smartshield/data.db "SELECT * FROM users;"
sqlite3 /var/db/smartshield/data.db "SELECT key_name, value_json FROM service_state;"
```

---

## 23. Two-Kali Lab: Captive Portal & Content Policy End-to-End

This section walks through a focused lab with two Kali VMs (one acting as admin, one as a regular user) connected to the BSD Smart Shield router.

### Lab Topology

```
┌──────────────────────────────────────────────────────────┐
│  VMware / VirtualBox Host                                │
│                                                          │
│  ┌─────────────────┐  em0 (NAT/WAN)   ┌──────────────┐  │
│  │  Smart Shield   │─────────────────▶│  Internet    │  │
│  │  (FreeBSD)      │                  └──────────────┘  │
│  │  em1 = LAN      │                                    │
│  │  192.168.1.1    │────────┬──────────────────────────┐ │
│  └─────────────────┘        │  Host-Only Adapter       │ │
│                     ┌───────┴──────┐  ┌───────────────┐ │ │
│                     │  Kali Admin  │  │  Kali User    │ │ │
│                     │ 192.168.1.x  │  │ 192.168.1.y   │ │ │
│                     └──────────────┘  └───────────────┘ │ │
└──────────────────────────────────────────────────────────┘
```

### VM Network Adapters

| VM | Adapter | Type | Network |
|----|---------|------|---------|
| Smart Shield | em0 | NAT | Internet |
| Smart Shield | em1 | Host-Only | 192.168.1.0/24 |
| Kali Admin | eth0 | Host-Only | Same as em1 |
| Kali User | eth0 | Host-Only | Same as em1 |

### 23.1 Baseline: DHCP + Connectivity

```bash
# On each Kali VM (set static or DHCP via BSD DHCP server):
ip route add default via 192.168.1.1
ping 192.168.1.1       # must reply
curl -sI http://example.com  # should work if portal disabled
```

### 23.2 Enable Captive Portal

In GUI: Services → Captive Portal → Settings
- Enable: ON
- LAN Interface: `em1`
- Portal IP: `192.168.1.1`
- Portal Port: `5000`
- Save → Apply & Activate

```bash
# On Kali User VM:
curl -v http://example.com
# Expected: connection lands on portal login page (PF redirect)

# In browser → navigate to http://example.com → portal appears
```

### 23.3 Authenticate as Regular User

1. In portal, log in as `regularuser` (created in User Manager)
2. After login → internet accessible
3. **On BSD:** `pfctl -t authenticated_clients -T show` → Kali User IP listed

### 23.4 Enable Content Policy (Block a Domain)

In GUI: Services → Content Policy (or DNS Filter)
- Add rule: block domain `facebook.com`
- Apply

```bash
# On Kali User VM (already portal-authenticated):
nslookup facebook.com 192.168.1.1
# Expected: resolves to 192.168.1.1 (blocked A record)

# In browser → visit http://facebook.com
# Expected: "Access Blocked" interstitial page appears in same tab
# "Open Login" button opens portal in a new tab
```

### 23.5 Bypass via Portal Login (Whitelisted User)

In GUI: Services → Captive Portal → Settings → Whitelisted Users
- Add `regularuser` to whitelist
- Save Settings

```bash
# Log out of portal first, then log in again as regularuser
# On BSD:
pfctl -t admin_bypass_clients -T show
# Expected: Kali User IP listed (whitelisted = treated as bypass)

# In browser: visit http://facebook.com → loads normally
```

### 23.6 Admin Bypass Test (Kali Admin VM)

1. On **Kali Admin VM**, open browser → visit any blocked domain
2. Interstitial appears → "Open Login" opens portal in new tab
3. Log in as `admin` (superuser)
4. New tab closes, original tab reloads → domain loads (bypassed)

```bash
# On BSD:
pfctl -t admin_bypass_clients -T show
# Expected: Kali Admin IP listed

# On Kali Admin VM:
curl -sI http://facebook.com   # should get 200 response, not interstitial
```

### 23.7 Voucher Test

In GUI: Captive Portal → Vouchers → Generate (60 min)
- Copy the code

```bash
# Log out current session from Kali User VM first
# In browser → visit any URL → portal appears → Voucher tab
# Enter code → Submit → internet access granted for 60 min
```

**Revoke voucher:** Captive Portal → Vouchers → click trash icon → confirms deletion.

### 23.8 MRTG Bandwidth Graphs

In GUI: Status → Traffic History
- Click **Reinitialize MRTG** → wait for success
- Page reloads → daily graphs for `em0` and `em1` appear

```bash
# On BSD:
ls /var/db/smartshield/mrtg/*.png   # should show em0-day.png etc.
crontab -l | grep mrtg               # should show */5 cron entry
```

### 23.9 Quick Diagnostic Reference

```bash
# BSD: check PF tables
pfctl -t authenticated_clients -T show
pfctl -t admin_bypass_clients -T show

# BSD: check Unbound A-record (content policy)
grep "local-data" /usr/local/etc/unbound/unbound.conf | head -10
# Expected: "facebook.com. A 192.168.1.1" — bare IP only, never URL

# BSD: validate Unbound config
unbound-checkconf /usr/local/etc/unbound/unbound.conf

# BSD: reload Unbound after content policy change
service unbound reload

# BSD: Smart Shield logs
tail -f /var/log/smartshield/app.log
```

---

*Generated for Smart Shield — FreeBSD deployment guide.*
