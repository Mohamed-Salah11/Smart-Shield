# Smart Shield F24 — Full Live Appliance TODO

This file tracks implementation status for turning Smart Shield F24 into a fully live FreeBSD
firewall appliance. Use actual code, config files, and schemas as the source of truth — not
Markdown documentation.

## Implementation Status Legend
- `[ ]` Not started
- `[~]` Partially implemented
- `[x]` Complete and verified

## Current Status (assessed 2026-05-27)

> **Assessed 2026-05-27** — this file was reconciled against the current source on disk.
> The prior assessment (2026-05-10) reported four "Known Critical Bugs" and several
> PARTIAL/BUG statuses that have since been fixed; those are now marked resolved/`[x]`
> with the implementing source noted. Items still tracked as open audit prompts in
> `docs/audit/CLAUDE_CODE_PROMPTS.md` (Tier 1+) remain `[ ]`.

| Area | Status | Notes |
|------|--------|-------|
| PF generator | MATURE | pfctl -nf syntax check + known_good rollback implemented |
| DHCPv4 writer | MATURE | dhcpd -t syntax check + known-good rollback (`dhcp_writer.py`) |
| DNS/Unbound writer | MATURE | unbound-checkconf + rollback + restart escalation + `recover_dns_service` (`dns_writer.py`) |
| Captive portal | MATURE | Soft portal, PF table, RADIUS, vouchers |
| Network service | MATURE | FreeBSD ifconfig apply, dry-run, rollback snapshot, CARP VIP apply |
| rc_conf_writer | MATURE | Safe managed-block format in /etc/rc.conf.local |
| OpenVPN writer | MATURE | Apply, status, log tailing |
| IPsec writer | MATURE | Multi-Phase 2 emits `conn <name>_child_N` via `also=` (`ipsec_writer.py`) |
| L2TP/mpd5 writer | MATURE | Config, apply, status |
| IDS/Suricata writer | MATURE | IDS+IPS modes, suricata -T validation, `validate_ips_safety` netmap/NIC check |
| DDNS writer | MATURE | Multiple providers, RFC2136, secrets encrypted, force-update endpoint |
| Chatbot service | MATURE | Block-rule path applies via `pf_generator.reload_pf_rules` (Groq-based) |
| SIEM collectors | MATURE | Offsets persisted to `siem_state`, log-rotation reset, flock single-leader |
| DB migrations | MATURE | v46 current; dhcpv6_pools columns fixed by migration v9 |
| Certificate manager | MATURE | CA/cert gen, encrypted key storage |
| Secret store | MATURE | AES-256-GCM encryption |
| install.sh packages | COMPLETE | kea, mpd5, miniupnpd, igmpproxy, ddclient, sudo (optional) + bind-tools (critical) all present |

---

## Phase 0 — Baseline verification and safety

- [x] PF generator: syntax check before reload (`pfctl -nf`)
- [x] PF generator: rollback to known-good config on reload failure
- [x] Dry-run mode (`SMARTSHIELD_NETWORK_DRY_RUN=1`)
- [x] Network apply gated by `SMARTSHIELD_ENABLE_NETWORK_APPLY=1`
- [x] Audit logging via `audit_log.py`
- [x] Config versioning via `config_versions` table
- [x] Create `runtime_mode.py` helper exposing is_freebsd, network_apply_enabled, dry_run_enabled, current_mode()
- [ ] Global UI banner showing current mode (live / dry-run / development / degraded)
- [ ] Every "applied" response must only emit after a real live apply succeeds
- [ ] Dry-run responses must say "dry run" and include generated config diff
- [~] Config-change transaction IDs — config_versions table exists but not all writers use it

**Detailed fixes:**

- [ ] Add central `app/services/runtime_mode.py` exposing:
  - `is_freebsd()` — `sys.platform.startswith("freebsd")`
  - `network_apply_enabled()` — `SMARTSHIELD_ENABLE_NETWORK_APPLY == "1"`
  - `dry_run_enabled()` — `SMARTSHIELD_NETWORK_DRY_RUN == "1"`
  - `current_mode()` → "live" | "dry-run" | "development" | "degraded"
  - `missing_dependencies()` — list from freebsd_setup.preflight_check()
  - `feature_availability(feature_name)` — per-feature check
- [ ] Add `/api/system/mode` endpoint returning current mode JSON
- [ ] Add mode banner partial template included in base layout

---

## Phase 1 — Fix current failing tests

- [x] Fix Abuse.ch API key validation failures (resolved 2026-05-29: `tests/test_abusech_client.py` 19/19 pass)
- [x] Fix DHCP writer test failures (resolved 2026-05-29: `tests/test_dhcp_writer.py` pass; covers pool range/subnet/routers/DNS, missing-router, invalid-range, overlap, disabled-pool, static-lease conflict)
- [x] Fix PF generator captive portal anchor expectation mismatches (resolved 2026-05-29: anchors emitted unconditionally in `app/services/pf_generator.py:1121,1126`; `tests/test_pf_generator.py:283-287` pin the order)
- [x] Fix captive portal / content policy redirect test failures (resolved 2026-05-29: `tests/test_portal_content_policy.py` + `tests/test_content_policy.py` + `tests/test_route_filters.py` 59/59 pass)
- [x] Re-run tests until all intended tests pass (full suite 1274 passed; only flake is the Windows in-mem shared-cache `TestL2tpSaveConfig` cross-test issue, not a Phase 1 regression)
- [x] Add regression tests for each fix (the four test files above ARE the regression tests; no skip/xfail markers anywhere — verified by `pytest -rsxX`: every skip is the architectural FreeBSD/sudo gate in `test_freebsd_integration.py`)

**Detailed fixes:**

### Abuse.ch
- [x] Decide: strict failure or dry-run/no-op when `ABUSECH_AUTH_KEY` missing (decision: strict `RuntimeError` for live calls, opt-in dry-run via `ABUSECH_DRY_RUN` env; `app/services/abusech_client.py:51,54-78`)
- [x] Make code, UI, and tests match that decision (every API in `abusech_client.py` checks `is_dry_run()` first; `tests/test_abusech_client.py::test_dry_run_*` × 7 pin the dry-run short-circuit)
- [ ] Add feed-status endpoint: key configured, dry-run, last update, last error, indicator count

### DHCP writer tests
- [x] Ensure generated config includes valid subnet/range/router/DNS when a pool exists (`tests/test_dhcp_writer.py:64-82` cover `range`, `subnet … netmask`, `option routers`, `domain-name-servers`)
- [ ] Add/seed default LAN DHCP pool after first setup
- [x] Add tests: valid LAN pool, missing router, invalid range, overlap detection, disabled pool ignored, static lease conflict (`tests/test_dhcp_writer.py:188,196,252`)

### PF / captive portal tests
- [x] Decide: captive portal PF anchors always present (empty) or only when enabled (decision: always present)
- [x] Prefer always-present empty managed anchors (prevents syntax errors) (`pf_generator.py:1119-1127` emits `rdr-anchor "captive_portal_rdr"` and `anchor "captive_portal_filter"` independent of `_cp_enabled`)
- [x] Update PF generator and tests accordingly (`tests/test_pf_generator.py:283-287`)

### Content policy redirect tests
- [ ] Document soft vs strict portal behavior
- [x] Make redirect/session behavior explicit in tests (`tests/test_portal_content_policy.py`, `tests/test_content_policy.py`, `tests/test_route_filters.py`)

---

## Phase 2 — Installer, packages, and FreeBSD dependencies

- [~] `python3` — installed
- [~] `git` — installed
- [~] `sqlite3` — installed
- [~] `ca_root_nss` — installed
- [~] `unbound` — installed
- [~] `isc-dhcp44-server` — installed
- [x] `kea` / Kea DHCPv6 — in `OPTIONAL_PKGS` (bsd/install.sh)
- [~] `openvpn` — installed
- [~] `strongswan` — installed
- [x] `mpd5` — in `OPTIONAL_PKGS` (bsd/install.sh)
- [~] `suricata` — installed
- [~] `suricata-update` — installed
- [~] `nginx` — installed
- [~] `mrtg` — installed
- [x] `ddclient` — in `OPTIONAL_PKGS` (bsd/install.sh)
- [x] `miniupnpd` — in `OPTIONAL_PKGS` (bsd/install.sh)
- [x] `igmpproxy` — in `OPTIONAL_PKGS` (bsd/install.sh)
- [x] `bind-tools` (nsupdate for RFC2136) — in `CRITICAL_PKGS` (bsd/install.sh)
- [~] `bsnmpd` — in FreeBSD base, rc.conf enable needed
- [~] `tcpdump` — in FreeBSD base
- [ ] Add post-install binary verification loop
- [ ] Add installer idempotency checks
- [ ] Make installer detect LAN/WAN interfaces or defer to wizard (do not assume em0/em1)

---

## Phase 3 — Preflight checks and feature availability

- [~] OS is FreeBSD check in live mode
- [~] PF available — checked via pfctl
- [~] Basic tool availability — `check_tools()` in freebsd_setup.py
- [ ] Per-feature availability `FeatureStatus` structure
- [ ] `/api/system/preflight` endpoint
- [ ] Admin dashboard warnings for unavailable features
- [ ] Block apply for features with missing required dependencies
- [ ] Disk space check (warn < 500 MB on /var)
- [ ] FreeBSD version check (warn < 13.x)
- [ ] Check all daemon binaries for each enabled feature
- [ ] Check pfctl is usable (`pfctl -s info`)
- [ ] Check sudo rules allow priv_helper operations

---

## Phase 4 — rc.d, environment, and service startup

- [x] rc.d service script at `bsd/rc.d/smart_shield`
- [x] Environment file loading from smart-shield.env
- [~] Required env vars exported — some missing (SMARTSHIELD_APP_LOG_PATH)
- [ ] Validate env file permissions (must not be world-readable)
- [ ] Refuse startup if mandatory production secrets are default/empty
- [ ] Add `service smart_shield configtest` if feasible
- [ ] Ensure rc.d status reflects Gunicorn process state accurately
- [ ] Prevent duplicate background collectors across Gunicorn workers

**Required env vars to export:**
- [x] FLASK_DEBUG
- [x] SECRET_KEY
- [x] SMARTSHIELD_DB_PATH
- [x] SMARTSHIELD_CONFIG_PATH
- [x] SMARTSHIELD_UPLOAD_DIR
- [x] SMARTSHIELD_AUDIT_LOG_PATH
- [ ] SMARTSHIELD_APP_LOG_PATH
- [x] SMARTSHIELD_ENABLE_NETWORK_APPLY
- [x] SMARTSHIELD_NETWORK_DRY_RUN
- [x] SMARTSHIELD_MASTER_KEY
- [ ] APP_ENV
- [ ] GROQ_API_KEY (chatbot is Groq-based; documented in `.env.example`)
- [x] ABUSECH_AUTH_KEY
- [x] ABUSECH_DRY_RUN

---

## Phase 5 — Privilege model and privileged helper

- [~] sudoers allowlist at `bsd/etc/sudoers.d/smartshield`
- [~] `priv_helper.py` wraps privileged operations
- [~] List-form subprocess calls in most places
- [x] Secrets redacted from logs via `_redact_secret` in network_service.py
- [ ] Choose one privilege model and make entire project consistent (currently root with sudo fallback)
- [ ] Replace any remaining ad-hoc `subprocess.run` shell=True calls
- [ ] Verify sudoers entries match exactly what priv_helper requests

---

## Phase 6 — Database schema and migrations

- [x] Migration framework with version tracking
- [x] Backup before migration (FreeBSD)
- [x] Transactions per migration
- [x] Schema version at startup (`CURRENT_SCHEMA_VERSION = 46`)
- [x] ~~**BUG:** `dhcpv6_pools` fresh schema missing 4 columns vs migration~~ — RESOLVED:
  `_migration_v9` adds `interface_type`, `enabled`, `pd_prefix`, `pd_prefix_len`
- [x] Add migration v9 to add missing dhcpv6_pools columns with safe defaults
- [ ] Add migration path tests from each historical version
- [ ] Validate required indexes and constraints at startup
- [ ] Seed default LAN data only during first setup, not on every startup

---

## Phase 7 — Appliance build and first-boot flow

- [~] First-boot setup wizard (routes/setup.py)
- [~] Default admin creation via BOOTSTRAP_ADMIN_* vars
- [ ] Build ISO/VM image or documented image process
- [ ] First-boot filesystem resize
- [ ] First-boot hostname + timezone setup
- [ ] Safe WAN/LAN interface selection (do not assume em0/em1)
- [ ] Console menu for interface assignment, LAN IP, admin reset, factory reset, logs, shell
- [ ] Safe upgrade mechanism with rollback
- [ ] Disable setup wizard after first successful setup completion

---

## Phase 8 — Interface management

- [x] LAN static IPv4 apply via ifconfig
- [x] WAN DHCP IPv4
- [x] WAN static IPv4
- [~] VLAN — rc_conf_writer generates config, live apply needs verification
- [~] Bridge — rc_conf_writer generates config
- [~] LAGG — rc_conf_writer generates config
- [~] GRE/GIF — rc_conf_writer generates config
- [ ] PPPoE WAN — pppoe_writer.py exists, verify live apply
- [ ] IPv6 static/DHCPv6/track interface live apply
- [ ] MTU/MSS controls
- [ ] Prevent overlapping subnets on multiple interfaces
- [x] Rollback snapshot via `pending_interface_changes` table
- [x] Rollback confirmation endpoint

---

## Phase 9 — Routing, gateways, and multi-WAN

- [~] Gateway add/edit/delete (DB schema exists, routes exist)
- [x] Gateway health monitoring — 30s background pinger (`gateway_monitor.py`); exposed via `routes/routing.py::/api/gateway-health`
- [~] Static routes (DB schema exists)
- [ ] Multi-WAN failover
- [x] Policy-based routing in PF — `pf_generator._build_policy_routes()` emits `route-to` from `policy_routes` (migration v14)
- [ ] Gateway groups
- [ ] UI warnings when gateways are down

---

## Phase 10 — PF firewall core

- [x] PF config generation from DB rules
- [x] Alias tables
- [x] NAT outbound
- [~] Port forwards — dst_type=wan_address now renders `to (iface)`; was silently using `to any`
- [x] 1:1 NAT
- [~] IPv6 firewall rules — icmpv6 now normalizes to icmp6 in _proto_line(); was invalid PF syntax
- [x] Captive portal anchors
- [x] Traffic shaper/limiter anchors
- [x] Application filter rules
- [x] Syntax check before reload
- [x] Atomic write + rollback
- [x] Bogon blocking table — implemented in _build_hardening_rules()
- [x] Anti-spoof rules — antispoof quick for WAN and LAN in _build_hardening_rules()
- [~] NAT reflection/hairpin NAT — global only; per-port-forward reflection not yet supported
- [ ] Kill states on rule change (option)
- [ ] pfsync/CARP integration for HA
- [x] Fix: _proto_line() normalize tcp+udp → proto { tcp udp } and icmpv6 → proto icmp6
- [x] Fix: _port_line() normalize comma-lists and dash-ranges to PF syntax
- [x] Fix: Remove echoreq from hardening pass in (no quick) — user block-ping rules now work
- [x] Fix: NAT port-forward dst_type=wan_address renders to (iface) not to any

---

## Phase 11 — Firewall schedules

- [~] Schedule DB schema + UI (firewall_schedules, firewall_schedule_ranges)
- [x] Actual schedule enforcement — `schedule_enforcer.py` 60s background thread reloads PF on any schedule transition
- [x] Background scheduler (single process, safe under Gunicorn multi-worker via `worker_lock.py`)
- [ ] UI indicator of currently active/inactive schedule
- [ ] Tests for active/inactive schedule logic

---

## Phase 12 — NAT, VIPs, CARP, and HA

- [x] Outbound NAT
- [x] Port forwards
- [x] 1:1 NAT
- [~] VIP DB schema exists
- [x] VIP live apply (IP alias, CARP) — `network_service.py` applies vhid/advskew/advbase/pass via `ifconfig`; `_migration_v15` adds CARP columns
- [ ] HA settings — if not fully implemented, mark UI as unavailable
- [ ] pfsync setup

---

## Phase 13 — DHCPv4

- [x] Pool validation (semantic)
- [x] Static lease validation
- [x] dhcpd.conf generation
- [x] Service restart
- [x] `dhcpd -t -cf <tempfile>` syntax check before apply — `_validate_dhcpd_conf_syntax()`
- [x] Rollback to known-good config on restart failure — `_save_known_good_dhcpd()` / `_rollback_dhcpd()`
- [x] Structured apply result `{ok, applied, rolled_back, error}`
- [~] Lease viewer (route exists)
- [~] DHCP logs in UI
- [x] dhcpd_ifaces boot persistence via sysrc

---

## Phase 14 — DNS resolver / Unbound

- [x] unbound.conf generation
- [x] `unbound-checkconf` validation
- [x] Host/domain overrides
- [x] DHCP lease registration into DNS
- [x] Service reload
- [x] Rollback to known-good config on reload failure — `_save_known_good_unbound()` / `_rollback_unbound()` / `_restart_unbound()` escalation; `recover_dns_service()` / `unbound_serving_lan()` watchdog
- [x] Structured apply result

---

## Phase 15 — DNS filtering

- [x] Block/allow/redirect rules
- [x] Unbound local-zone/local-data generation
- [x] Reload Unbound after filter update
- [ ] Per-interface policy (if exposed)
- [ ] Feed updates + scheduled updates
- [ ] DoH/DoT bypass controls

---

## Phase 16 — Web filtering

- [~] Domain filtering via DNS blocking (dns_filter.py)
- [ ] Clarify scope: DNS-level domain blocking, NOT URL path filtering
- [ ] Update UI labels to avoid overclaiming

---

## Phase 17 — Application filtering

- [~] app_filter.py generates PF/DNS rules for known apps
- [ ] Add UI status showing limitation level (domain/port-based, not DPI)
- [ ] Signature updates

---

## Phase 18 — Captive portal

- [x] Soft portal (HTTP redirect)
- [x] PF anchor + authenticated_clients table
- [x] Session expiry management
- [x] Voucher redemption
- [x] RADIUS authentication
- [x] HTTPS redirect server (self-signed cert)
- [ ] Strict portal mode (block ALL unauthenticated traffic except DHCP/DNS/portal)
- [ ] Session cleanup worker safe under Gunicorn
- [ ] Captive Network Assistant support
- [ ] Tests: unauthenticated blocked, authenticated allowed, expired denied, voucher consumed

---

## Phase 19 — OpenVPN

- [x] Server/client config generation
- [x] Validation (protocol, port, network)
- [x] Config write + service restart
- [x] Connected clients list (status file parsing)
- [x] Log tailing
- [ ] Complete CA/cert lifecycle (generate CA → server cert → client cert)
- [ ] Client export package
- [ ] Firewall rules for listen ports (auto-generated)
- [ ] Certificate expiry warnings
- [ ] Rollback

---

## Phase 20 — IPsec / strongSwan

- [x] Phase 1 config generation
- [x] Secrets file generation (PSK encrypted)
- [x] Phase 2 DB schema supports multiple child SAs
- **BUG:** Config generation only uses `phase2s[0]` — all other Phase 2 entries silently dropped
- [ ] Fix: loop all enabled Phase 2 entries (use `also=` for multiple child SAs)
- [x] `ipsec statusall` status parsing
- [ ] Multiple Phase 2 connect/disconnect per tunnel
- [ ] VTI/route-based IPsec (if exposed)
- [ ] Rollback

---

## Phase 21 — L2TP VPN

- [x] mpd.conf + mpd.secret generation
- [x] Service restart
- [x] Status via pgrep + sockstat
- [ ] Companion IPsec config for L2TP/IPsec
- [ ] Firewall rules for L2TP/IPsec ports
- [ ] Rollback

---

## Phase 22 — IDS/IPS / Suricata

- [x] IDS pcap mode config
- [x] IPS netmap inline mode config
- [x] `suricata -T` YAML validation
- [x] Rule source management
- [x] EVE JSON alert parsing
- [x] Status check
- [x] Netmap/NIC compatibility check before IPS enable — `validate_ips_safety()` (netmap auto-load, NIC-driver prefix check, rules-ready check)
- [ ] Safe fallback from IPS to IDS on failure
- [ ] Block-on-alert PF table integration
- [ ] Threat table expiration
- [ ] Rollback

---

## Phase 23 — Threat intelligence / Abuse.ch

- [x] Abuse.ch API client (`abusech_client.py`)
- [x] Encrypted key storage in DB (`ids_threat_feeds` table)
- [x] Dry-run flag (`abusech_dry_run`)
- [ ] Fix test failures when key is missing (dry-run/no-op vs strict failure)
- [ ] Feed-status API endpoint
- [ ] Scheduled/manual update trigger
- [ ] PF table integration for fetched indicators
- [ ] Tests with mocked API responses

---

## Phase 24 — SIEM / log collection

- [x] IDS collector (tails eve.json)
- [x] DHCP collector (parses dhcpd.leases)
- [x] DNS collector (tails unbound query.log)
- [x] PF collector (pfctl -s states)
- [x] Anomaly detector (brute-force + IDS flood)
- [x] Persist file offsets to DB (`siem_state` table) — `_load_offset()` / `_save_offset()`
- [x] Prevent duplicate collector workers across Gunicorn multi-worker — `worker_lock.py` flock-based single-leader
- [x] Log rotation detection — `_tail_file()` resets offset to 0 when `size < offset`

---

## Phase 25 — DDNS

- [x] ddclient.conf generation for multiple providers
- [x] RFC2136 nsupdate support
- [x] Secrets encrypted
- [x] Service restart
- [ ] Status: last update time, last error, current IP (status route exists; rich last-success/last-error fields still TODO — see CLAUDE_CODE_PROMPTS Tier 1.5)
- [x] Manual force-update endpoint — `routes/services/network.py::/api/ddns/force-update` → `ddns_writer.force_ddns_update()`
- [ ] Rollback

---

## Phase 26 — DHCPv6 and IPv6 prefix delegation

- [x] ~~**BUG:** Migration v4 created `dhcpv6_pools` without `interface_type`, `enabled`, `pd_prefix`, `pd_prefix_len`~~ — RESOLVED by `_migration_v9` (schema v46)
- [x] Add migration v9 to add missing columns — `_migration_v9` adds all four with safe defaults
- [~] Kea DHCPv6 JSON config generation (dhcpv6_writer.py)
- [x] Install kea package — in `OPTIONAL_PKGS` (bsd/install.sh)
- [ ] Validate Kea config before restart
- [ ] Lease viewer
- [ ] Rollback

---

## Phase 27 — Router advertisements / rtadvd

- [x] rtadvd config generation (`rtadvd_writer.py`)
- [x] RA settings table (`ra_settings`)
- [ ] Validate rtadvd config before restart
- [ ] Coordinate RA with DHCPv6 and prefix delegation
- [ ] Rollback

---

## Phase 28 — UPnP

- [x] miniupnpd config generation (`upnp_writer.py`)
- [ ] Install miniupnpd (not in install.sh)
- [ ] ACL validation
- [ ] Current mappings display
- [ ] Rollback

---

## Phase 29 — IGMP proxy

- [x] igmpproxy config generation (`igmp_writer.py`)
- [ ] Install igmpproxy (not in install.sh)
- [ ] Multicast firewall rules
- [ ] Rollback

---

## Phase 30 — SNMP

- [x] bsnmpd config generation (`snmp_writer.py`)
- [ ] Do not expose insecure default community publicly
- [ ] SNMPv3 if exposed
- [ ] Firewall rule helper
- [ ] Rollback

---

## Phase 31 — NTP

- [x] NTP config generation (`ntp_writer.py`)
- [ ] Service status check
- [ ] Firewall rules if serving LAN clients
- [ ] Rollback

---

## Phase 32 — MRTG and traffic graphs

- [~] MRTG config generation (`mrtg_writer.py`)
- [ ] Remove hardcoded em0/em1 assumptions
- [ ] Dynamic interface discovery
- [ ] SNMP dependency check before enabling
- [ ] Disk usage control + log rotation

---

## Phase 33 — Diagnostics

- [~] Ping, traceroute, DNS lookup, packet capture, routes, ARP, sockets
- [ ] Filter validation for packet capture (no unsafe shell injection)
- [x] Reboot/halt require admin role + reauthentication — `@superuser_required` + `@reauth_required` + password confirm (`routes/diagnostics/tools.py`)
- [x] Factory reset requires admin + reauthentication + CSRF + confirmation token — `factory_defaults_reset()` carries `@superuser_required` + `@reauth_required`
- [ ] Destructive actions audited at high severity

---

## Phase 34 — Package manager and appliance updates

- [ ] Real installed package list (pkg info)
- [ ] Available updates (pkg version)
- [ ] Application update mechanism
- [ ] Do not show fake package management

---

## Phase 35 — Backup and restore

- [~] Backup/restore routes exist
- [ ] Backup must include: DB, generated configs, certs/keys, OpenVPN keys, IPsec secrets, custom Suricata rules, uploads, version metadata
- [ ] Encrypted backup support
- [ ] Validate backup integrity before restore
- [ ] Pre-restore backup
- [ ] Restart affected services after restore
- [ ] Audit restore action

---

## Phase 36 — Certificates and secrets

- [x] Certificate generation/import (cert_manager.py)
- [x] Encrypted private key storage
- [x] CA/server/client cert support
- [ ] Certificate expiry dashboard
- [ ] CRL support
- [ ] Web UI TLS cert management
- [ ] Captive portal HTTPS cert management
- [ ] All service writers consume cert store entries (not missing file paths)

---

## Phase 37 — Admin security hardening

- [x] RBAC (groups, page_permissions)
- [x] Login audit logging
- [x] CSRF protection
- [x] Session management
- [ ] Account lockout / rate limiting (login_failures table exists, enforcement?)
- [ ] 2FA/TOTP if exposed
- [ ] Secure cookie settings in production (verify)
- [ ] Security headers
- [ ] TLS by default in production (Nginx handles this)
- [~] Reauthentication enforced for factory reset, restore backup, shutdown/reboot, password change; still missing on interface apply + firewall apply (see CLAUDE_CODE_PROMPTS Tier 1.7)
- [x] Disable setup wizard after first successful setup — `routes/setup.py` `setup_complete` flag in `service_state` blocks re-entry (also: admin-exists→login, LAN/loopback only, console claim token)

---

## Phase 38 — UI/API consistency

- [ ] Audit every form field maps to DB → validation → writer → apply → status, or is disabled
- [ ] Add disabled/unavailable state for incomplete features
- [ ] Add health badges per feature
- [ ] Add pending-changes / saved-but-not-applied / applied / apply-failed / dry-run states
- [ ] Add missing-package state for features needing uninstalled daemons

---

## Phase 39 — Config history, transactions, and rollback

- [x] Config versions table (`config_versions`)
- [x] PF rollback (known_good mechanism)
- [ ] Rollback for: DHCPv4, DNS/Unbound, DHCPv6/Kea, OpenVPN, IPsec, L2TP, Suricata, DDNS, UPnP, IGMP, SNMP, NTP, MRTG, rc.conf/network
- [ ] Common `ConfigApplyResult` object
- [ ] Common atomic file writer helper
- [ ] Common backup/rollback helper shared by all writers
- [ ] Automatic rollback after connectivity loss for network changes (rollback timer)

---

## Phase 40 — Health monitoring

- [x] Health snapshots (`health_snapshots` table)
- [x] Service health checks (`health_monitor.py`)
- [ ] Expand checks: dhcpd, unbound, openvpn, strongswan, mpd5, suricata, ddclient, miniupnpd, igmpproxy, kea-dhcp6, rtadvd, bsnmpd, ntpd, nginx, MRTG
- [ ] Gateway reachability checks
- [ ] DNS resolution verification
- [ ] Disk usage, memory, CPU checks
- [ ] Interface link status
- [ ] Pending updates
- [ ] Config drift detection

---

## Phase 41 — AI/chatbot integration

- [x] ~~**BUG:** `chatbot_service.py` imports non-existent `firewall_writer.write_pf_rules`~~ — RESOLVED
- [x] Fix: `execute_approved_action()` uses `from app.services.pf_generator import reload_pf_rules` and calls it (`chatbot_service.py:1771`)
- [x] Groq API integration (tool use, agentic loop)
- [x] Read-only tools: system health, audit logs, firewall rules, network config, DHCP leases, IDS alerts
- [x] Write tools: block_domain, unblock_domain, add_firewall_block_rule (with approval gate)
- [x] Connect AI firewall action to real PF preview/apply/rollback — block rule persists then applies via `reload_pf_rules`
- [ ] Dry-run preview for AI-generated changes
- [ ] AI-suggested changes audited to audit log
- [x] Fix .env.example: chatbot is Groq-based — `.env.example` documents `GROQ_API_KEY`

---

## Phase 42 — Live FreeBSD integration tests

- [ ] Clean FreeBSD install runs installer
- [ ] App starts under rc.d
- [ ] Setup wizard creates admin and interfaces
- [ ] LAN IP applies
- [ ] PF syntax test passes
- [ ] PF reload works
- [ ] LAN client gets DHCP lease
- [ ] LAN client resolves DNS through firewall
- [ ] LAN client reaches WAN through NAT
- [ ] WAN inbound blocked by default
- [ ] Port forward works
- [ ] Backup/restore roundtrip works
- [ ] Role permissions enforced

---

## Phase 43 — Final production-readiness gate

The project is not production-ready until ALL of the following are true:

- [ ] All unit tests pass
- [ ] All integration tests pass on FreeBSD
- [ ] Installer installs every dependency for enabled features
- [ ] Preflight reports all missing dependencies accurately
- [ ] Live/dry-run/dev mode visible in UI
- [ ] No UI feature falsely claims to work
- [ ] Every enabled feature: validation, preview, apply, status, logs, audit, rollback
- [ ] PF reload is syntax-checked and rollback-safe
- [ ] DHCP works on LAN
- [ ] DNS works on LAN
- [ ] NAT works from LAN to WAN
- [ ] WAN inbound blocked by default
- [ ] Interface changes have rollback protection
- [ ] DB migrations work from old versions
- [ ] Secrets are encrypted/redacted
- [ ] Destructive routes require strong authorization and reauthentication
- [ ] Backup/restore works
- [ ] rc.d startup works after reboot
- [ ] Health dashboard reflects true service state

---

## Known Critical Bugs — all RESOLVED (2026-05-27)

The four bugs reported in the 2026-05-10 assessment are fixed in the current source:

1. ~~**chatbot_service.py:** imports non-existent `firewall_writer.write_pf_rules`~~ —
   **RESOLVED.** `execute_approved_action()` now uses
   `from app.services.pf_generator import reload_pf_rules` and calls it
   (`app/services/chatbot_service.py:1771`).
2. ~~**migrations.py v4 + dhcpv6_writer.py:** `dhcpv6_pools` missing four columns~~ —
   **RESOLVED.** `_migration_v9` adds `interface_type`, `enabled`, `pd_prefix`,
   `pd_prefix_len` (`app/migrations.py:221-233`); schema is now v46. Covered by
   `tests/integration/test_schema_equivalence.py::test_dhcpv6_pools_has_required_columns`.
3. ~~**ipsec_writer.py:** only `phase2s[0]` used; other Phase 2 entries dropped~~ —
   **RESOLVED.** Multi-Phase 2 emits one `conn <name>_child_N` block per entry via
   `also=<name>`, and the base conn rewrites `auto=start` → `auto=add`
   (`app/services/ipsec_writer.py:248-274`). Covered by
   `tests/test_ipsec_writer.py::{test_two_phase2_creates_child_conns,test_three_phase2_all_child_conns}`.
4. ~~**.env.example:** lists `ANTHROPIC_API_KEY`~~ — **RESOLVED.** The chatbot is Groq-based;
   `.env.example` documents `GROQ_API_KEY` (`.env.example:81`).

---

## Implementation Order

1. ~~Create this file~~ ✓
2. ~~Fix 4 critical bugs above~~ ✓ (all RESOLVED — see Known Critical Bugs section)
3. ~~Run `python -m pytest -q` — capture and fix test failures~~ ✓
4. ~~Add missing packages to `bsd/install.sh`~~ ✓
5. ~~Add `dhcpd -t` syntax check + rollback to `dhcp_writer.py`~~ ✓
6. ~~Add rollback to `dns_writer.py`~~ ✓
7. ~~Add SIEM offset persistence (`siem_state` table + DB reads/writes in collectors)~~ ✓
8. ~~Create `app/services/runtime_mode.py`~~ ✓ + UI mode banner (`templates/partials/mode_banner.html`)
9. Expand `freebsd_setup.py` preflight checks + `/api/system/preflight` endpoint
10. Continue remaining open items — see `docs/audit/CLAUDE_CODE_PROMPTS.md` Tier 1+ for the current backlog
