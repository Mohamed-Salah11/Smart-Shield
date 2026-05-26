# Smart Shield on FreeBSD (Move + Appliance Checklist)

This guide is the practical checklist for moving the project to FreeBSD and keeping it stable as an appliance-style deployment.

## 1) Prepare FreeBSD host

1. Install base requirements:
```sh
pkg update
pkg install -y python3 git ca_root_nss
python3 -m ensurepip --upgrade
```
2. Create runtime directories:
```sh
install -d -m 0755 /usr/local/share/smart-shield
install -d -m 0755 /usr/local/etc/smart-shield
install -d -m 0755 /var/db/smart-shield/uploads/profile_pictures
install -d -m 0755 /var/log/smart-shield
```

## 2) Copy project + install Python dependencies

1. Copy or clone project into `/usr/local/share/smart-shield`.
2. Build a venv and install:
```sh
cd /usr/local/share/smart-shield
python3 -m venv .venv
. .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

## 3) Configure environment

Create `/usr/local/etc/smart-shield/smart-shield.env`:

```env
SECRET_KEY=replace-with-long-random-secret
FLASK_DEBUG=0

SMARTSHIELD_DB_PATH=/var/db/smart-shield/data.db
SMARTSHIELD_CONFIG_PATH=/usr/local/etc/smart-shield/config.json
SMARTSHIELD_UPLOAD_DIR=/var/db/smart-shield/uploads/profile_pictures
SMARTSHIELD_AUDIT_LOG_PATH=/var/log/smart-shield/audit.log

# Keep OFF until you are ready to apply live network changes on FreeBSD:
SMARTSHIELD_ENABLE_NETWORK_APPLY=0
SMARTSHIELD_NETWORK_DRY_RUN=0

BOOTSTRAP_ADMIN_USERNAME=admin
BOOTSTRAP_ADMIN_PASSWORD=change-this-now
```

## 4) Install service helpers

1. Install rc.d script:
```sh
install -m 0555 bsd/rc.d/smart_shield /usr/local/etc/rc.d/smart_shield
```
2. Install operator tools:
```sh
install -m 0555 bsd/sbin/smartshieldctl /usr/local/sbin/smartshieldctl
install -m 0555 bsd/sbin/smartshield-cli /usr/local/sbin/smartshield-cli
```
3. Enable + start:
```sh
sysrc smart_shield_enable=YES
service smart_shield start
service smart_shield status
```

Interface mode examples from CLI:
```sh
smartshieldctl iface-show LAN
smartshieldctl iface-set LAN static 192.168.1.1/24
smartshieldctl iface-set WAN dhcp --apply
smartshieldctl iface-set WAN static 203.0.113.2/24 203.0.113.1 --apply
```

## 5) Verify app + audit logs (login and browsing)

1. Login to web UI.
2. Open multiple pages and perform a few API-backed actions.
3. Validate logs:
```sh
smartshieldctl logs 100
smartshieldctl audit 200
```

Expected audit categories:
- `session` for login success/failure/logout.
- `browsing` for authenticated page views.
- `system` for API mutating actions.

In UI you can review them at `Status > System Logs` tabs.

## 6) Verify LAN/WAN host tracking and rule coverage

1. In UI, make sure interface assignments are set (`Interfaces > Assignments`) for LAN and WAN ports.
2. Open `Diagnostics > ARP Table (Host Tracking)` and click `Refresh Hosts`.
3. Confirm each discovered peer has:
- an interface type (`LAN`/`WAN`),
- a policy state (`covered_specific`, `allowed_broad`, `blocked`, etc.),
- a suggestion if rule coverage is weak.
4. API alternative:
```sh
fetch -qo - --header 'X-CSRF-Token: <token>' http://127.0.0.1:5000/api/network/hosts?refresh=1
```

Web-activity sample (best effort) from assigned interfaces:
```sh
fetch -qo - http://127.0.0.1:5000/api/network/web-activity?refresh_hosts=1
```
Notes:
- DNS domains and plain HTTP links can be observed.
- Full HTTPS URLs are encrypted unless you deploy a TLS interception proxy.

## 7) Enable firewall traffic logging (browsing/network traffic visibility)

If you want network traffic logs from PF:

1. Ensure PF + pflog are enabled:
```sh
sysrc pf_enable=YES
sysrc pflog_enable=YES
service pf start
service pflog start
```
2. Add `log` on PF rules you want to track.
3. Read PF logs:
```sh
smartshieldctl filterlog 200
```

## 8) Before turning on live network apply

Only when you are ready:

1. Set in env:
```env
SMARTSHIELD_ENABLE_NETWORK_APPLY=1
```
2. Restart service:
```sh
service smart_shield restart
```
3. Test from console/KVM first to avoid locking yourself out.

## 9) Appliance hardening baseline

1. **TLS reverse proxy (nginx)**
```sh
pkg install nginx
# Create SSL directory and generate or install your certificate:
install -d -m 0700 /usr/local/etc/smart-shield/ssl
# Copy the example config, edit server_name + cert paths, then enable:
cp bsd/etc/nginx.conf.example /usr/local/etc/nginx/smart-shield.conf
# Add  include /usr/local/etc/nginx/smart-shield.conf;  to nginx.conf http block
nginx -t
sysrc nginx_enable=YES
service nginx start
```

2. **Log rotation (newsyslog)**
```sh
cp bsd/etc/newsyslog.d/smartshield.conf /usr/local/etc/newsyslog.d/smartshield.conf
newsyslog -v   # dry-run to verify
```

3. Use a non-default admin password and rotate `SECRET_KEY` periodically.

4. Enable regular snapshots of:
- `/var/db/smart-shield/` (database + uploads)
- `/usr/local/etc/smart-shield/` (config + master key)
- `/var/log/smart-shield/` (audit trail)

5. Restrict management UI access to admin networks (see nginx example `allow`/`deny` block).

## Known scope

Smart Shield currently persists most firewall/service settings to its DB/UI model. Full PF/service rendering and end-to-end OS control is still an active build area.
