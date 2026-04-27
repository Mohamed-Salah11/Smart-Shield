# Smart Shield — Administrator Guide

## Table of Contents

1. [First-Time Setup](#1-first-time-setup)
2. [User Management](#2-user-management)
3. [Backup & Restore](#3-backup--restore)
4. [Log Management](#4-log-management)
5. [Schema Upgrades](#5-schema-upgrades)
6. [Config Version History & Rollback](#6-config-version-history--rollback)
7. [Privilege Separation](#7-privilege-separation)
8. [Service Health Monitoring](#8-service-health-monitoring)
9. [Release Upgrades](#9-release-upgrades)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. First-Time Setup

After running `bsd/install.sh`:

```sh
# Edit the environment file
vi /usr/local/etc/smart-shield/smart-shield.env

# Set a strong admin password (used only for the first DB init)
BOOTSTRAP_ADMIN_USERNAME=admin
BOOTSTRAP_ADMIN_PASSWORD=ChangeMe123!

# Enable network apply when ready (keep 0 during testing)
SMARTSHIELD_ENABLE_NETWORK_APPLY=1

# Start the service
service smart_shield start
service smart_shield status

# Verify at http://<LAN-IP>:5000
```

### Secrets Required

| Variable                   | Purpose                               | Minimum length |
|----------------------------|---------------------------------------|----------------|
| `SECRET_KEY`               | Flask session signing                 | 32 bytes hex   |
| `SMARTSHIELD_MASTER_KEY`   | AES-256-GCM key for encrypted secrets | 32 bytes hex   |

Generate strong keys:

```sh
python3 -c "import secrets; print(secrets.token_hex(32))"
```

---

## 2. User Management

### Create a user via CLI

```sh
smartshieldctl user-add --username ops1 --password 'P@ssw0rd!' --role admin
```

### Reset an admin password (DB direct)

```sh
python3 - <<'PY'
import sys; sys.path.insert(0, '/usr/local/share/smart-shield')
from werkzeug.security import generate_password_hash
from app.database import get_db
conn = get_db()
conn.execute("UPDATE users SET password=? WHERE username='admin'",
             (generate_password_hash('NewPassword!'),))
conn.commit()
print("Password updated.")
PY
```

### API Permissions

Grant a group API-level permissions from **System → Users → Groups → Edit**.
Available permissions:

| Permission           | Controls                                    |
|----------------------|---------------------------------------------|
| `api.firewall.edit`  | Create/edit/delete firewall rules           |
| `api.vpn.edit`       | Edit VPN configs                            |
| `api.vpn.apply`      | Apply VPN configs (write to disk + restart) |
| `api.network.edit`   | Edit interface/routing configs              |
| `api.network.apply`  | Apply interface changes (live network)      |
| `api.ids.edit`       | Edit IDS/IPS configuration                  |

Superusers bypass all permission checks.

---

## 3. Backup & Restore

### Manual backup

```sh
smartshieldctl backup [/path/to/backup.tar.gz]
```

This archives:
- `data.db` — the SQLite database
- `smart-shield.env` — environment / secrets
- Generated config files in `/etc` and `/usr/local/etc`

### Automated nightly backup (cron)

```
# /etc/cron.d/smart-shield-backup
0 2 * * *  root  smartshieldctl backup /var/backups/smart-shield/$(date +\%Y\%m\%d).tar.gz
```

### Restore

```sh
service smart_shield stop
smartshieldctl restore /var/backups/smart-shield/20250101.tar.gz
service smart_shield start
```

### Pre-migration backup (automatic)

Before applying any DB schema migration, Smart Shield automatically creates a
timestamped backup of `data.db`:

```
/var/db/smart-shield/data.db.bak-20250101T120000
```

These are NOT pruned automatically.  Clean them up periodically:

```sh
find /var/db/smart-shield -name 'data.db.bak-*' -mtime +30 -delete
```

---

## 4. Log Management

### Log files

| File                                     | Contents                                |
|------------------------------------------|-----------------------------------------|
| `/var/log/smart-shield/audit.log`        | Security events (logins, config changes)|
| `/var/log/smart-shield/app.log`          | Operational events (apply, errors)      |
| `/var/log/smart-shield/access.log`       | HTTP access log (gunicorn)              |

All logs are NDJSON (one JSON object per line) for easy parsing.

### Log rotation (newsyslog)

Install the provided newsyslog config:

```sh
install -m 644 bsd/etc/newsyslog.conf.d/smart-shield.conf \
    /usr/local/etc/newsyslog.conf.d/smart-shield.conf
```

This rotates logs daily, keeps 14 copies, and compresses them.

### Viewing logs via the web UI

Navigate to **Status → System Logs** to view the audit log with live polling,
category filters, and text search.

For the operational app log:

```
GET /status/api/app-logs?limit=100&level=ERROR
```

### Searching logs from the command line

```sh
# All login failures in the last hour
grep '"action":"login_failed"' /var/log/smart-shield/audit.log | \
    python3 -c "import json,sys; [print(json.dumps(json.loads(l), indent=2)) for l in sys.stdin]"

# Errors from the last day
grep '"level":"ERROR"' /var/log/smart-shield/app.log | tail -50
```

---

## 5. Schema Upgrades

Smart Shield uses a formal migration system.  Migrations are applied
automatically at startup when needed.

### Checking the current schema version

```sh
sqlite3 /var/db/smart-shield/data.db "SELECT MAX(version) FROM schema_version;"
```

### Forcing a migration check

```sh
python3 -c "
import sys; sys.path.insert(0, '/usr/local/share/smart-shield')
from app.database import get_db, init_db
init_db()
print('DB is up to date.')
"
```

### Error: DB is newer than code

If you see `SchemaVersionError: Database schema version N is newer than the
application supports`, you are running an older version of the application
against a newer DB.  **Do not downgrade the DB.**  Instead, upgrade the
application to the latest release.

---

## 6. Config Version History & Rollback

Every time a config is applied (PF, DHCP, DNS, VPN, IDS) a versioned snapshot
is stored in the DB.

### Viewing history via the API

```
GET /status/api/config-history              → services with saved versions
GET /status/api/config-history/pf           → list of pf versions
GET /status/api/config-history/42           → full content of version #42
```

### Rolling back to a previous version

```
POST /status/api/config-history/42/rollback
```

This:
1. Writes the stored config to the original file path.
2. Reloads the service (pfctl, dhcpd restart, etc.).
3. Records the rollback in the audit log.
4. Saves a new config version entry noting it's a rollback.

### Pruning old versions

```
POST /status/api/config-history/pf/prune
Content-Type: application/json

{"keep": 20}
```

---

## 7. Privilege Separation

Smart Shield runs as an unprivileged `smartshield` user.  Privileged
operations (pfctl, service restart, ifconfig) are executed via `sudo` with a
strict allowlist.

### How it works

1. `app/services/priv_helper.py` defines `run_privileged(action, **params)`.
2. The action is looked up in `_ALLOWLIST` — an exact list of permitted commands.
3. All parameters are validated before the command is built.
4. The command is executed via `sudo -n` (non-interactive, no TTY).
5. Every call is logged to the audit log with `category: "privileged"`.

### Allowlist coverage

| Action                | Command(s)                                     |
|-----------------------|------------------------------------------------|
| `pf.reload`           | `pfctl -f <config_path>`                       |
| `pf.anchor_reload`    | `pfctl -a <anchor> -f <config_path>`           |
| `pf.table_add`        | `pfctl -t <table> -T add <ip>`                 |
| `pf.table_delete`     | `pfctl -t <table> -T delete <ip>`              |
| `service.action`      | `service <known_service> <start|stop|restart>` |
| `sysrc.set`           | `sysrc <key>=<value>`                          |
| `ifconfig.inet`       | `ifconfig <iface> inet <ip> netmask <mask>`    |
| `route.add_default`   | `route -n add default <gw>`                    |
| (and others)          | See `app/services/priv_helper.py`              |

### Auditing privileged calls

```sh
grep '"category":"privileged"' /var/log/smart-shield/audit.log | \
    python3 -m json.tool
```

---

## 8. Service Health Monitoring

### On-demand health check

```
GET /status/api/health/full
```

Returns:
- Per-service status (running/stopped/dry-run)
- Config drift (unsaved changes vs applied)
- Disk usage for `/`, `/var`, `/var/db/smart-shield`, `/var/log`
- Memory and CPU load averages

The result is stored in `health_snapshots` for trend display.

### Health history

```
GET /status/api/health/history?limit=24
```

Returns the 24 most-recent stored snapshots.

### Setting up automatic health checks (cron)

```
# /etc/cron.d/smart-shield-health
*/15 * * * *  smartshield  curl -s -b /tmp/ss.cookie \
    http://127.0.0.1:5000/status/api/health/full > /dev/null
```

Or add a periodic background task in your monitoring system that hits the API.

### Disk alert threshold

The health monitor flags `ok: false` when a filesystem is above 90% used.
Adjust by modifying `health_monitor._PATHS_TO_MONITOR`.

---

## 9. Release Upgrades

### Build a release archive (on a developer machine)

```sh
python tools/build_release.py 1.2.0
# Output: dist/smartshield-1.2.0.tar.gz
#          dist/smartshield-1.2.0.sha256
```

The archive is built from a whitelist — `.env`, `data.db`, `audit.log`, and
other sensitive files are **never** included.

### Deploy an upgrade

```sh
# 1. Verify checksum
sha256sum -c dist/smartshield-1.2.0.sha256

# 2. Stop the service
service smart_shield stop

# 3. Back up the DB (in case migration fails)
cp /var/db/smart-shield/data.db /var/db/smart-shield/data.db.pre-upgrade

# 4. Extract over the existing installation
tar -xzf dist/smartshield-1.2.0.tar.gz -C /usr/local/share/ \
    --strip-components=1 smart-shield-1.2.0/

# 5. Upgrade pip dependencies
/usr/local/share/smart-shield/.venv/bin/pip install -r \
    /usr/local/share/smart-shield/requirements.txt -q

# 6. Update sudoers (in case new privileged commands were added)
install -m 0440 /usr/local/share/smart-shield/bsd/etc/sudoers.d/smartshield \
    /usr/local/etc/sudoers.d/smartshield

# 7. Start the service (migrations run automatically)
service smart_shield start
service smart_shield status
```

---

## 10. Troubleshooting

### App won't start — SECRET_KEY not set

```
RuntimeError: SECRET_KEY is not set.
```

Edit `/usr/local/etc/smart-shield/smart-shield.env` and set `SECRET_KEY`.

### App won't start — DB schema too new

```
SchemaVersionError: Database schema version 7 is newer than the application supports (5).
```

You're running an old version of Smart Shield against a newer DB.
Upgrade the application to the latest release.

### PF config validation fails

```sh
pfctl -n -f /etc/pf.conf
```

Look for syntax errors.  The error message includes a line number.

### DHCP clients not getting addresses

1. Check `service isc-dhcpd status`.
2. Check `/var/log/messages` for dhcpd errors.
3. Verify the pool range is inside the LAN subnet.

```sh
smartshieldctl dhcp-leases
```

### DNS not resolving

```sh
unbound-control status
unbound-control reload
drill @127.0.0.1 google.com
```

### Privileged command denied (sudo)

Check `sudo -l -U smartshield` to see what's allowed.  If a new command is
needed, add it to `bsd/etc/sudoers.d/smartshield` and reinstall.

### Log files growing too large

Set up newsyslog rotation (see section 4).  Emergency manual rotation:

```sh
mv /var/log/smart-shield/audit.log /var/log/smart-shield/audit.log.old
pkill -HUP -f gunicorn  # force log reopen
```

### Reset to factory defaults

```sh
service smart_shield stop
rm /var/db/smart-shield/data.db
service smart_shield start  # re-creates DB from scratch
```

**Warning:** This erases all users, firewall rules, VPN configs, and settings.
