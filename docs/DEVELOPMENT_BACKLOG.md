# Smart Shield — Development Backlog

> Each section is **one self-contained task**. Tasks are **independent** and **idempotent** —
> re-doing them is safe. Order is loosely by impact, but they can be tackled in any order. Every
> task ends with the verification commands a developer should run before declaring it complete.
>
> All findings below were re-verified against the current source on **2026-05-27**.
> Items already fixed since `ROADMAP.md` (dated 2026-05-10) are intentionally
> not repeated here. This list contains only **real, currently-open** issues.

---

## Tier 0 — Stale-doc / scoreboard drift (do this first; cheap)

### Task 0.1 — Rewrite `ROADMAP.md` to match current source

```
Target: the Smart Shield repo on FreeBSD 14.x.

Rewrite `ROADMAP.md` so it matches the current source on disk.
The file is dated "assessed 2026-05-10" and is wrong about all four "Known Critical Bugs" plus
many phase statuses. Use the source as ground truth, not the doc.

Verify each of these is FIXED before re-marking — read the file and confirm:

1. `app/services/chatbot_service.py` — `execute_approved_action()` imports
   `from app.services.pf_generator import reload_pf_rules` (NOT the nonexistent
   `firewall_writer.write_pf_rules`). Mark "Phase 41 / chatbot_service.py" as DONE.

2. `app/migrations.py` — `CURRENT_SCHEMA_VERSION = 46`; migration v9 adds
   `interface_type`, `enabled`, `pd_prefix`, `pd_prefix_len` to `dhcpv6_pools`.
   `tests/integration/test_schema_equivalence.py::test_dhcpv6_pools_has_required_columns`
   exercises it. Mark "Phase 26 / dhcpv6_pools" as DONE.

3. `app/services/ipsec_writer.py` — multi-Phase 2 generates `conn <name>_child_N`
   blocks with `also=<name>`, and the base conn rewrites `auto=start` → `auto=add`.
   Tests `test_two_phase2_creates_child_conns`, `test_three_phase2_all_child_conns`
   in `tests/test_ipsec_writer.py` cover it. Mark "IPsec writer / BUG" as DONE.

4. `.env.example` — documents `GROQ_API_KEY` (chatbot is Groq-based, not Gemini).
   Mark "Phase 41 / .env.example" as DONE.

5. `bsd/install.sh` — `OPTIONAL_PKGS` includes `kea mpd5 miniupnpd igmpproxy ddclient sudo`;
   `CRITICAL_PKGS` includes `bind-tools`. Mark every "NOT in install.sh" line in Phase 2
   as DONE.

Also mark DONE:
  - Phase 13: `dhcp_writer.py` has `_validate_dhcpd_conf_syntax()` (dhcpd -t),
    `_save_known_good_dhcpd()`, `_rollback_dhcpd()`.
  - Phase 14: `dns_writer.py` has `_save_known_good_unbound()`, `_rollback_unbound()`,
    `_restart_unbound()` (escalation), `unbound_serving_lan()`, `recover_dns_service()`.
  - Phase 24 / SIEM offsets: `siem_collector._load_offset` / `_save_offset` exist and
    are used; `app/services/worker_lock.py` implements flock-based single-leader.
  - Phase 24 / log rotation: `_tail_file()` resets offset to 0 when `size < offset`.
  - Phase 25 / DDNS: `routes/services/network.py` exposes `/api/ddns/status` and
    `/api/ddns/force-update`; `ddns_writer.force_ddns_update()` exists.
  - Phase 9: `app/services/gateway_monitor.py` runs a 30s background pinger;
    `routes/routing.py::/api/gateway-health` exposes it.
  - Phase 9: `pf_generator._build_policy_routes()` emits `route-to` rules from
    the `policy_routes` table (migration v14).
  - Phase 12: `network_service.py` applies CARP VIPs (vhid/advskew/advbase/pass)
    via `ifconfig`; `migrations._migration_v15` adds CARP columns.
  - Phase 11: `app/services/schedule_enforcer.py` is a 60s background thread that
    reloads PF when any schedule transitions.
  - Phase 33: `factory_defaults_reset()`, `change_password()`, etc. carry both
    `@superuser_required` and `@reauth_required(...)`. The shutdown/halt route
    requires password confirm.
  - Phase 37 / setup wizard: `routes/setup.py` enforces (a) admin-exists → login required,
    (b) LAN/loopback only, (c) console claim token, (d) `setup_complete` flag in
    `service_state` blocks unauthenticated re-entry.
  - Phase 22 IDS: `validate_ips_safety()` performs netmap auto-load, NIC-driver
    prefix check, and rules-ready check.

Update the top-of-file "Current Status" table — replace BUG/PARTIAL/MATURE with
current reality.

Keep the remaining open items (listed in this file's Tier 1+) as `[ ]` and add a
new "Assessed 2026-05-27" line at the top.

Verify:
  git diff --stat ROADMAP.md
  pytest tests/ -q -k 'ipsec or dhcpv6 or chatbot or migrations'
```

### Task 0.2 — Reconcile path naming (`smart-shield` vs `smartshield`)

```
The repo has inconsistent path naming. The installer (`bsd/install.sh`) deploys to
`/usr/local/share/smartshield/` and the env file is `/usr/local/etc/smartshield/smartshield.env`,
but several docs still say `/usr/local/share/smart-shield/` and `smart-shield.env`.

Run:
  grep -rn 'smart-shield' README.md Manual.md Testing.md docs/ 2>/dev/null
  grep -rn '/smart-shield/' README.md Manual.md Testing.md docs/ 2>/dev/null

Replace `/usr/local/share/smart-shield` → `/usr/local/share/smartshield`,
`/usr/local/etc/smart-shield` → `/usr/local/etc/smartshield`,
`/var/db/smart-shield` → `/var/db/smartshield`,
`/var/log/smart-shield` → `/var/log/smartshield`,
`/var/run/smart-shield` → `/var/run/smartshield`,
`smart-shield.env` → `smartshield.env`
**in user-facing docs only** (README.md, Manual.md, Testing.md, docs/*.md).

Do NOT change:
  - Display strings ("Smart Shield" is the product name).
  - Source code in `app/config.py::_ss_dir()` which already supports both via
    the LEGACY path fallback.
  - bsd/rc.d/smart_shield — the rc.d service name is intentionally hyphen-free
    and stable.

Verify:
  grep -rn '/usr/local/share/smart-shield\|/var/db/smart-shield\|smart-shield.env' \
       README.md Manual.md Testing.md docs/ 2>/dev/null | wc -l   # must print 0
  pytest tests/ -q
```

---

## Tier 1 — Truly open functional gaps

### Task 1.1 — Add IPS → IDS safe fallback on apply failure

```
Goal: when an operator enables IPS mode and the `suricata -T` test fails OR the
`service suricata restart` returns non-zero AND netmap is unavailable, the writer
must automatically fall back to IDS mode and surface the demotion clearly instead
of leaving Suricata in a not-running state with `mode=ips` persisted.

Files to edit:
  - app/services/ids_writer.py
  - tests/test_ids_writer.py

Implementation:
  1. In `apply_ids(conn)` (the function that orchestrates write + restart), after
     a failed restart in IPS mode, check `_netmap_available()`. If netmap is not
     present, set `ids_config.mode='ids'` (best-effort UPDATE), set
     `ids_config.ips_fallback_reason='netmap_unavailable'` (add column via a new
     migration), regenerate suricata.yaml, retry the restart. Append to the
     returned `message`: "IPS unavailable — fell back to IDS." Emit a high-severity
     audit event `ids_ips_fallback`.
  2. Add column `ips_fallback_reason TEXT DEFAULT ''` to `ids_config` via a new
     migration (bump `CURRENT_SCHEMA_VERSION` and add `_migration_v47`).
  3. Surface the fallback reason in `get_ids_status()` so the UI can render it.

Tests to add:
  - `test_apply_ips_falls_back_when_netmap_missing`
  - `test_fallback_event_logged_at_high_severity`
  - `test_no_fallback_when_netmap_present_and_restart_ok`

Verify:
  pytest tests/test_ids_writer.py -q
  python tools/release_check.py
```

### Task 1.2 — Add block-on-alert PF table integration for IDS

```
Goal: persist IDS alert source IPs into a PF table (`ss_ids_blocked`) so the
firewall can dynamically drop traffic from attackers, with an expiration policy.

Files:
  - NEW: app/services/ids_blocker.py
  - app/services/pf_generator.py (emit `table <ss_ids_blocked> persist`)
  - app/services/siem_collector.py (call `ids_blocker.maybe_block(alert)` in
    `_handle_alert_event`)
  - app/migrations.py (NEW _migration_v48: table `ids_blocked_ips`
    columns: id, ip, source_alert_id, signature, severity, added_at, expires_at)

Behavior:
  - Only block alerts with severity in {"high","critical"} OR sid in an admin-set
    `auto_block_sids` list.
  - Default TTL: 1 hour. Configurable via a new `ids_config.auto_block_ttl_seconds`
    column (default 3600).
  - Honor a per-process rate limit: ≤60 block actions / 5 min so a noisy ruleset
    can't blow the PF table.
  - Background thread `ids_blocker_expirer` (registered via `app/background.py`)
    expires rows every 60s with `pfctl -t ss_ids_blocked -T expire <secs>` and
    deletes DB rows whose `expires_at < now()`.
  - Add `pf_generator._build_ids_block_rules()` that emits at the top of the
    hardening section:
        block in quick on $wan_iface from <ss_ids_blocked>
        block out quick on $wan_iface to <ss_ids_blocked>
  - Add `routes/ids.py` endpoints: `/ids/api/blocked` (list, unblock).

Tests:
  - Mock `_log` and `pfctl` calls; verify a HIGH alert adds the IP and a low-sev
    alert does not.
  - Verify expiry deletes a row whose `expires_at` is in the past.
  - Verify the PF rule appears in `generate_pf_conf()` output when the table has
    members.

Verify:
  pytest tests/ -q -k 'ids_blocker or pf_generator'
  python tools/release_check.py
```

### Task 1.3 — Add MTU/MSS apply and overlapping-subnet validation for interfaces

```
The interfaces UI exposes MTU and MSS fields (templates/interfaces_lan.html and
interfaces_wan.html) but `network_service.apply_interface_with_rollback()` never
calls `ifconfig <iface> mtu <N>`, and there is no check that two interfaces don't
share an overlapping subnet.

Files:
  - app/services/network_service.py — extend `apply_interface_with_rollback`
    to set MTU when provided (`ifconfig em1 mtu 1492`), and to update `rc.conf`
    via `rc_conf_writer.set_iface_mtu(iface, mtu)`.
  - app/services/rc_conf_writer.py — add `set_iface_mtu` that appends
    `ifconfig_em1=" ... mtu 1500"` to the managed block.
  - app/validators.py — add `validate_no_overlap(conn, iface_to_skip, new_cidr)`
    that walks `lan_config`, `wan_config`, `vlans`, `bridges` and raises
    ValueError if `new_cidr` overlaps any existing interface CIDR.
  - routes/interfaces.py — call `validate_no_overlap` in `save_lan_config`
    and `save_wan_config` before persisting. Reject with HTTP 400 on overlap.
  - MSS clamping: PF already supports `scrub on $iface max-mss N`. Update
    `pf_generator._build_scrub_rules()` (add it if absent) to emit
    `scrub on $iface ... max-mss <mss>` when lan/wan_config.mss is set.

Tests:
  - `tests/test_network_service.py::test_apply_interface_sets_mtu`
  - `tests/test_validators.py::test_overlap_rejects_lan_when_wan_already_covers`
  - `tests/test_pf_generator.py::test_scrub_max_mss_emitted_when_set`

Verify:
  pytest tests/ -q
  python tools/release_check.py
```

### Task 1.4 — Add Kea, rtadvd, UPnP, IGMP, SNMP, NTP, MRTG writer rollback

```
PF, DNS, DHCPv4 already do validate → backup → atomic write → reload → rollback
via `app/services/config_file_utils.apply_with_rollback`. Some writers still
do plain atomic_write without rollback.

For each of these writers, refactor `apply_<service>(conn)` to use
`apply_with_rollback(path, content, restart_fn, validate_fn=...)`:

  - app/services/dhcpv6_writer.py     (validate: `kea-dhcp6 -t -c <tmp>`)
  - app/services/rtadvd_writer.py     (validate: best-effort syntax via
                                       Python preflight only; no rtadvd -t)
  - app/services/upnp_writer.py       (no validator — accept ok=True from atomic_write)
  - app/services/igmp_writer.py       (no validator)
  - app/services/snmp_writer.py       (`bsnmpd -t` if installed)
  - app/services/ntp_writer.py        (`ntpd -d -n -q` is too heavy; instead run
                                       a Python regex sanity check on the conf)
  - app/services/mrtg_writer.py       (validate via mrtg-internal `--check`)

Each writer must:
  1. Generate config into a string.
  2. Wrap the disk write + service restart in `apply_with_rollback`.
  3. Return a dict shaped like the existing pf/dns writers:
     `{"ok": bool, "message": str, "conf": str, "rolled_back": bool}`.
  4. Record the apply through `app.services.apply_state.record_apply_start` /
     `record_apply_result` so the UI badge stays accurate.

Tests:
  - For each writer add `test_apply_<svc>_rolls_back_on_restart_failure` using
    monkeypatch to make the restart fn return ok=False, and assert the
    `.known_good` backup is restored.

Verify:
  pytest tests/ -q -k 'writer'
  python tools/release_check.py
```

### Task 1.5 — Make DDNS surface last-update timestamp and last error

```
`ddns_writer.get_ddns_status()` currently only returns running/state/message
from the pidfile. There is no "last successful update at" or "last error" — the
UI shows the daemon as up even when ddclient is failing every cycle.

Files:
  - app/services/ddns_writer.py
  - app/migrations.py (NEW _migration_v49: table `ddns_status`)
  - routes/services/network.py — extend `/api/ddns/status` to include the new
    fields.

Implementation:
  1. Add a table `ddns_status` with columns:
       provider TEXT PRIMARY KEY,
       last_attempt_at REAL,
       last_success_at REAL,
       last_ip TEXT,
       last_error TEXT,
       updated_at REAL
  2. Add a background thread `ddns_status_poller` that:
       - reads `/var/log/ddclient.log` and `/var/cache/ddclient/ddclient.cache`
       - parses successful update lines + failure lines
       - upserts `ddns_status` rows
       - polls every 60s; registered in app/background.py with `_try_start`
  3. Extend `get_ddns_status()` to return:
       {"running": bool, "state": str, "message": str,
        "providers": [{"name": ..., "last_success_at": ts, "last_ip": ...,
                       "last_error": ...}]}

Tests:
  - Feed the parser a fixture ddclient.log with mixed success/failure lines and
    verify the right rows land in `ddns_status`.

Verify:
  pytest tests/ -q -k 'ddns'
  python tools/release_check.py
```

### Task 1.6 — Persist DHCP collector offset across restarts

```
`app/services/siem_collector._run_dhcp_collector` uses a process-local
`state["dhcp_seen"]` set instead of byte offsets. After a restart it re-parses
the full `dhcpd.leases` and re-emits every active lease as a "new" event.

Other collectors (IDS, DNS, syslog, system) already persist offsets via
`_save_offset` / `_load_offset`. The DHCP collector should also persist a
per-mac-last-seen-at watermark to `siem_state`:

Files:
  - app/services/siem_collector.py
  - tests/test_siem_collector.py

Implementation:
  - Replace the in-memory `dhcp_seen` with a watermark of "last reported
    bind/release timestamp" per mac, persisted as JSON in `siem_state` under
    key `dhcp_last_seen`.
  - On startup, `_load_offset("dhcp_last_seen", default="{}")` and parse JSON.
  - On every tick, after emitting events, `_save_offset("dhcp_last_seen",
    json.dumps(state["dhcp_seen"]))`.
  - Cap dict size at 5000 entries; LRU-evict by timestamp.

Tests:
  - Test that a restart with a populated watermark does NOT re-emit a lease
    whose bind time is older than the watermark.

Verify:
  pytest tests/ -q -k 'siem'
```

### Task 1.7 — Reauthenticate on firewall and interface apply

```
`@reauth_required` is enforced on factory reset, halt/reboot, password change,
and backup/restore. It is NOT enforced on these destructive paths:

  - POST /firewall/api/apply/all                  (firewall_bp / routes/firewall/apply.py)
  - POST /firewall/api/rules/*/reorder            (firewall_bp / routes/firewall/apply.py)
  - POST /interfaces/save-lan-config              (interfaces_bp / routes/interfaces.py)
  - POST /interfaces/save-wan-config              (interfaces_bp / routes/interfaces.py)
  - POST /interfaces/api/apply-pending/<itype>    (interfaces_bp / routes/interfaces.py)
  - POST /system/api/certificates/<id>/revoke    (system_bp)
  - POST /system/api/packages/install             (system_bp / routes/system/tools.py)

Add `@reauth_required(reason="<thing>")` (or `reauth_required_form` if the
caller is a browser form) to each of these routes. JSON callers already handle
the 403 `{"reauth_required": true}` response — the existing front-end
`SS.openReauthModal()` flow covers them.

Tests:
  - tests/integration/test_security_hardening.py — add cases that the routes
    above return 403 with `reauth_required:true` when no recent reauth is set,
    and 200 when reauth is fresh.

Verify:
  python tools/security_lint_routes.py
  pytest tests/integration/test_security_hardening.py -q
```

### Task 1.8 — Add config drift dashboard tile

```
`health_monitor.check_config_drift(conn)` already computes whether the generator
output matches the latest `config_versions.content_hash` per service. Surface
this in the UI:

Files:
  - routes/status.py — add `/status/api/config-drift` returning
    `{"ok": True, "drift": {"pf": {...}, "dhcpd": {...}, "unbound": {...}}}`
  - templates/dashboard.html — add a "Config Drift" KPI card listing each
    drifted service with a red dot.
  - templates/preflight.html — link from the preflight page.

Behavior:
  - When drift > 0, the dashboard tile turns red and links to `/system/preflight`.
  - When all services are in sync, tile is green "All configs match DB".

Tests:
  - tests/test_route_status.py::test_config_drift_endpoint_returns_per_service_state

Verify:
  pytest tests/ -q -k 'config_drift or drift'
  python tools/release_check.py
```

### Task 1.9 — Verify PPPoE WAN live-apply path end to end

```
`pppoe_writer.py` generates `/etc/ppp/ppp.conf` and the `mpd.conf` fragment, but
the live apply path is untested. Confirm or fix:

Steps:
  1. Read `app/services/pppoe_writer.py` and `routes/interfaces.py` end to end.
     Identify whether `wan_config.ipv4_config_type='pppoe'` actually invokes
     `apply_pppoe(conn)` from the save endpoint, or only writes DB rows.
  2. If the call site is missing, add it to `routes/interfaces.py::save_wan_config`
     so that switching the WAN type to 'pppoe' triggers a config write AND a
     `service ppp restart`.
  3. Add `validate_pppoe()` checks:
       - username + (encrypted) password present
       - assigned_port is one of the physical NICs from `list_physical_nics()`
       - service name is alphanumeric
  4. Make sure rollback is wired: a failed PPPoE bring-up rolls the WAN back
     to its previous config-type via `pending_interface_changes`.
  5. Add a fixture test that exercises a PPPoE save against a mocked
     `run_privileged` and confirms `service.action(name="ppp", action="restart")`
     is called.

Tests:
  - tests/test_pppoe_writer.py::test_save_pppoe_invokes_apply
  - tests/test_pppoe_writer.py::test_invalid_pppoe_credentials_rejected

Verify:
  pytest tests/ -q -k 'pppoe'
```

---

## Tier 2 — Hardening, observability, ergonomics

### Task 2.1 — Reject setup wizard re-entry after `setup_complete` even for superusers without reauth

```
`routes/setup.py::_wizard_guard` lets any authenticated superuser re-enter the
wizard after `setup_complete=true`. That's a big destructive surface — reassigning
WAN/LAN can knock the appliance off the network — and should require a fresh
reauth.

Wrap the four step endpoints (`api_step1_save`, `api_step2_save`,
`api_step3_save`, `api_step4_apply`) with `@reauth_required(reason="re-run setup")`
when `_is_setup_complete()` is true AND the caller is an authenticated superuser
(i.e. NOT during the legitimate first-boot path).

Implementation pattern:
  def _conditional_reauth(view):
      @wraps(view)
      def wrapped(*a, **k):
          if _is_setup_complete() and _is_authenticated_superuser():
              if not reauth_is_fresh():
                  return jsonify({"ok": False, "reauth_required": True,
                                  "message": "Please re-authenticate to re-run setup."}), 403
          return view(*a, **k)
      return wrapped

Apply on each `/setup/api/step*/save` and `/setup/api/step4/apply`.

Tests:
  - tests/test_setup_wizard_reliability.py — add cases for the reauth gate.

Verify:
  pytest tests/test_setup_wizard_reliability.py -q
  python tools/security_lint_routes.py
```

### Task 2.2 — Per-source mail-alert cooldown + alert digest

```
`app/services/mail_alerts.py::notify_event` currently rate-limits globally
(an hourly cap). Add per-source-IP and per-rule cooldowns so a single noisy
attacker can't burn the hourly budget and starve other alerts.

Files:
  - app/services/mail_alerts.py
  - tests/test_mail_alerts.py (create if absent)

Implementation:
  - Add columns to `mail_alert_settings`:
       per_source_cooldown_minutes INTEGER DEFAULT 10,
       digest_window_minutes INTEGER DEFAULT 60
    (new migration v50).
  - When a high/critical event arrives, look up the most recent mail for the
    same `details.src_ip` (or `details.signature`). Suppress if within
    `per_source_cooldown_minutes`.
  - Add an optional "digest mode": instead of one mail per event, accumulate
    matching events for `digest_window_minutes`, then emit a single mail
    listing each event. The mail sender thread already exists — add a 60s
    flush tick.

Tests:
  - test_per_source_cooldown_suppresses_duplicate_within_window
  - test_digest_aggregates_and_sends_after_window

Verify:
  pytest tests/ -q -k 'mail'
```

### Task 2.3 — Add `/api/system/mode` endpoint

```
The UI banner consumes `runtime_mode_badge` from the template context, but
there is no JSON endpoint for programmatic callers (the AI chatbot, the
operator CLI, external monitoring).

Files:
  - routes/status.py

Add:
  @status_bp.route("/api/mode")
  @login_required
  def api_mode():
      from app.services.runtime_mode import current_mode, mode_badge, production_ready
      ok, issues = production_ready()
      return jsonify({
          "ok": True,
          "mode": current_mode(),
          "badge": mode_badge(),
          "production_ready": ok,
          "issues": issues,
      })

Tests:
  - tests/test_route_status.py::test_api_mode_returns_badge

Verify:
  pytest tests/ -q -k 'mode or runtime'
```

### Task 2.4 — Reject world-readable env files at startup (fatal)

```
`runtime_mode.startup_warnings()` warns about a world-readable smartshield.env
but only logs `critical` and continues. On FreeBSD in `live` mode this should
abort startup — the env file holds SECRET_KEY and SMARTSHIELD_MASTER_KEY.

Files:
  - app/services/runtime_mode.py
  - tests/test_runtime_mode.py

Add `production_ready()` to refuse boot when `env_file_perms` is critical AND
`current_mode() == "live"`. Plumb the refusal through `app/__init__.py`:
if `production_ready()[0] is False` and live mode is set, log a CRITICAL line
and `raise SystemExit(78)` (EX_CONFIG).

Make sure dev mode (`SMARTSHIELD_NETWORK_DRY_RUN=1` or non-FreeBSD) keeps
booting with a warning only — never fatal.

Tests:
  - monkeypatch os.stat to return a world-readable mode and verify SystemExit.

Verify:
  pytest tests/ -q -k 'runtime_mode or env_file'
```

### Task 2.5 — Surface SIEM collector restart count in `/status/collector-health`

```
`collector_health.heartbeat()` accepts a `restart=True` argument but the
collector loops never pass it. Each collector should call `heartbeat(restart=True)`
when its outer `while True: try: ... except: time.sleep(N)` catches an
exception, so operators can see "DNS collector has restarted 12 times in the
last hour" in `/status/collector-health`.

Files:
  - app/services/siem_collector.py — every `_run_*_collector` function
  - tests/test_collector_health.py

Pattern:
  def _run_ids_collector(state):
      while True:
          try:
              _collect_ids_alerts(state)
          except Exception as exc:
              from app.services.collector_health import heartbeat
              heartbeat("siem-ids", restart=True, last_error=str(exc)[:200])
          time.sleep(10)

Verify:
  pytest tests/ -q -k 'collector_health'
```

### Task 2.6 — Replace process-pgrep daemon checks with `service status` where reliable

```
`health_monitor.check_daemon_processes` uses `pgrep -x <name>` for every daemon.
This produces false negatives for daemons that run under a wrapper (e.g.
strongSwan / charon is launched by `/usr/local/sbin/ipsec start` and pgrep -x
`charon` may not match the executable name on FreeBSD pkg builds).

Cross-check `pgrep` AND `service <name> status`. Treat the daemon as running
if either reports OK. Update each row to also include `rc_state` so the UI
can show "running per rc.d but not per pgrep" anomalies.

Files:
  - app/services/health_monitor.py
  - tests/test_health_monitor.py

Verify:
  pytest tests/ -q -k 'health_monitor or daemon'
```

### Task 2.7 — `python_runtime.json` drift check against `requirements.txt`

```
The installer reads `app/manifests/python_runtime.json` to do post-install
import checks. If `requirements.txt` adds a package and the manifest forgets
it, the import check passes anyway. Conversely, a removed dep stays in the
manifest as an orphan.

Add a CI/release check:
  tools/check_manifest.py
  - Parse requirements.txt → dist names → import names (reuse
    `PACKAGE_IMPORT_MAP` from `tools/release_check.py`).
  - Compare against `app/manifests/python_runtime.json::imports`.
  - Fail with diff if they don't match.

Hook into `bsd/install.sh §4b` after `release_check.py`:
  if ! ( cd "${APP_ROOT}" && "${PYBIN}" tools/check_manifest.py ); then
      fatal "python_runtime.json out of sync with requirements.txt"
  fi

Verify:
  python tools/check_manifest.py
  python tools/release_check.py
```

### Task 2.8 — Pin SOC-portal templates against stored XSS via `details` field

```
SOC-portal `templates/soc_portal/saved_searches.html`, `cases.html` etc. render
event/case fields with `escapeHtml()` only sometimes — there's a JS helper
`SOC.esc(value)` defined in `templates/soc_portal/base.html` that not every
inline render uses. A SIEM event whose `details.signature` contains
`<img src=x onerror=...>` could land in an analyst's browser unescaped.

Steps:
  1. Audit `templates/soc_portal/*.html`. Grep for `innerHTML` / template
     literal interpolation. Confirm every dynamic field is passed through
     `SOC.esc()`.
  2. For each unescaped interpolation, wrap it in `SOC.esc(...)`.
  3. Add a CI lint to `scripts/migrate_handlers.py --check` (or a new
     `scripts/soc_template_lint.py`) that scans for ``${...}`` or
     ``${event.<field>}`` patterns NOT wrapped in `SOC.esc(`. Fail on any
     direct interpolation of a `details.*`, `signature`, `action`, or
     `username` field.

Verify:
  python scripts/soc_template_lint.py
  pytest tests/ -q
```

---

## Tier 3 — Test-suite hygiene

### Task 3.1 — Re-enable the "Phase 1" formerly-failing tests in the TODO

```
`ROADMAP.md::Phase 1` lists four classes of failing tests. The
underlying bugs have all been fixed since (verify by reading the relevant
modules), but the tests themselves may be `pytest.skip`-marked or `xfail`.

Run:
  pytest tests/ -q --collect-only 2>&1 | grep -E 'SKIPPED|XFAIL|XPASS'

For each match:
  - Confirm the underlying bug is genuinely fixed in the current code.
  - Remove the skip/xfail decoration.
  - If the test now fails, write a focused fix in the relevant module
    (NOT in the test).

Targets to verify:
  - abuse.ch tests when ABUSECH_AUTH_KEY is missing (must work in dry-run)
  - dhcp_writer tests asserting generated subnet/range/router/DNS
  - pf_generator captive portal anchor expectations
  - content-policy redirect tests

Verify:
  pytest tests/ -q
  pytest tests/ -q --collect-only 2>&1 | grep -c SKIPPED   # should not increase
```

### Task 3.2 — Add a regression test for the "chatbot writes block rule then applies PF" flow

```
The chatbot block-rule path (`chatbot_service.execute_approved_action` →
`firewall_rules_floating` insert → `pf_generator.reload_pf_rules`) is the
exact place that was broken in ROADMAP.md. There is no
regression test for it.

Add `tests/test_chatbot_pf_integration.py`:
  - Set up an in-memory DB.
  - Mock `pf_generator.reload_pf_rules` to return `{"ok": True, "message": "ok"}`.
  - Call `execute_approved_action(conn, {"tool": "add_firewall_block_rule",
        "args": {"description": "test", "source": "1.2.3.4"}}, "tester")`.
  - Assert (a) a row appeared in `firewall_rules_floating` with action='block',
    (b) `reload_pf_rules` was called once, (c) a `config_apply_jobs` row was
    written via `apply_state.record_apply_start` / `record_apply_result`.
  - Add a second test where `reload_pf_rules` returns ok=False; assert the
    rule is still persisted but the job state is `failed`.

Verify:
  pytest tests/test_chatbot_pf_integration.py -q
```

### Task 3.3 — Add a smoke test that proves `runtime_preflight.py` survives a `live` env

```
`tools/runtime_preflight.py` already overrides
`SMARTSHIELD_ENABLE_NETWORK_APPLY=0` and `SMARTSHIELD_NETWORK_DRY_RUN=1` before
import. Prove this regression-tests:

  tests/test_runtime_preflight.py
  - Set `os.environ["SMARTSHIELD_ENABLE_NETWORK_APPLY"] = "1"` and
    `os.environ["SMARTSHIELD_NETWORK_DRY_RUN"] = "0"` BEFORE invoking
    `runtime_preflight.run(json_output=True)`.
  - Capture stdout; parse the JSON; assert `ok=True`.
  - The point is to prove that even if a misconfigured smartshield.env claims
    live mode, the preflight does not actually trigger PF/network mutation.
    Monkeypatch `app.services.network_service.run_command` to raise — if the
    preflight tries to run it, the test fails.

Verify:
  pytest tests/test_runtime_preflight.py -q
```

### Task 3.4 — Add a fast PF static-validator regression test

```
`app/services/pf_static_validator.py` already implements the captive-portal-
anchor-after-broad-LAN-pass and DNS-intercept-after-broad-LAN-pass checks.
Add a regression test that catches each rule-order violation with a synthetic
pf.conf string.

  tests/test_pf_static_validator.py
  - test_captive_portal_anchor_after_broad_lan_pass_raises
  - test_dns_intercept_after_broad_lan_pass_raises
  - test_clean_ruleset_passes

Verify:
  pytest tests/test_pf_static_validator.py -q
```

---

## Tier 4 — Documentation polish

### Task 4.1 — Add a "Schema Migration Map" to `Manual.md`

```
The repo is at schema v46. Operators upgrading from an older release have no
single document explaining which migrations touch what. Add a section to
`Manual.md`:

  ## 12. Schema Migration Map
  Table of: migration number, what it adds/changes, when shipped, whether it
  is safe to apply in-place (most are; v6 backed up the DB file first; v15
  added CARP columns; v9 fixed dhcpv6_pools …).

Source the data by reading `app/migrations.py` — every `_migration_vN`
function has a docstring; lift those into a markdown table.

Verify:
  grep -c '^| v' Manual.md   # row count matches CURRENT_SCHEMA_VERSION
```

### Task 4.2 — Document `SMARTSHIELD_DISABLE_BACKGROUND=1` in env reference

```
The variable is used by `tools/runtime_preflight.py` and the CI fixtures but
not documented anywhere. Add it to `Manual.md §7. Environment Variables
Reference` and `.env.example`:

  SMARTSHIELD_DISABLE_BACKGROUND     0 by default. Set to 1 in CI / preflight
                                     to skip starting daemon threads
                                     (SIEM, threat intel, mail, gateway monitor,
                                     schedule enforcer, …) while still
                                     building a full Flask app.

Verify:
  grep -q SMARTSHIELD_DISABLE_BACKGROUND Manual.md .env.example
```

### Task 4.3 — Note ports vs interfaces in setup wizard step 1 docs

```
`Testing.md §4.1` and `templates/setup/step1_interfaces.html` both say
"em0, em1" as if these names are stable. In VMware, FreeBSD names them
based on adapter order; in libvirt they become `vtnet0`, `vtnet1`; on
some HW boxes they are `igb*`, `re*`, etc.

Add a paragraph at the top of `Testing.md §4.1` explaining that the wizard
auto-detects whatever physical NICs are present, and that the operator
should match the **MAC address** (shown in the dropdown label) to the
expected upstream/downstream cable, NOT the device name. Update the
screenshot caption if one exists.

Verify:
  grep -A 3 'Interface Assignment' Testing.md | grep -q MAC
```

---

## How to work through this list

```sh
# Suggested order:
#   Tier 0 first (cheap & high-signal — fixes the scoreboard).
#   Tier 1 next (real functional gaps).
#   Tier 2 + 3 in parallel.
#   Tier 4 last (docs).

# After every change, re-run the gate:
. .venv/bin/activate
python tools/release_check.py
python tools/check_routes.py
python tools/check_tab_render.py
python tools/security_lint_routes.py
python tools/runtime_preflight.py
pytest tests/ -q
```

## What I deliberately did NOT include

The following items appear in `ROADMAP.md` but are **already
done** in the current source — re-opening them as tasks would create
busywork or, worse, regress working code:

- chatbot_service `firewall_writer` import bug (fixed; uses `pf_generator.reload_pf_rules`)
- ipsec_writer multi-Phase 2 silent drop (fixed; `_child_N` blocks)
- dhcpv6_pools missing columns (fixed by migration v9; schema is v46)
- `.env.example` ANTHROPIC_API_KEY (fixed; uses GROQ_API_KEY)
- install.sh missing kea/mpd5/miniupnpd/igmpproxy/ddclient/bind-tools (all present)
- dhcpd -t syntax check + rollback (present in `dhcp_writer.py`)
- unbound-checkconf + rollback + restart-escalation (present in `dns_writer.py`)
- SIEM offset persistence (present for IDS, DNS, syslog, system, strongswan, mpd5)
- Multi-worker single-leader (`app/services/worker_lock.py`)
- Gateway health monitor (`app/services/gateway_monitor.py`)
- Schedule enforcer thread (`app/services/schedule_enforcer.py`)
- PF route-to / policy_routes (in `pf_generator._build_policy_routes`)
- CARP VIP live apply (in `network_service.apply_virtual_ips`)
- runtime_mode badge + banner partial (`templates/partials/mode_banner.html`)
- Backup/restore encryption + integrity (`routes/diagnostics/_common.py`)
- API token scopes + machine auth (`app/api_tokens.py`, `app/api_auth.py`)
- CSP nonce strict mode (`app/security_headers.py`)
- Terminal nonce cross-worker safety (DB-backed `terminal_ticket_nonces` table)
- Packet-capture input validation against shell injection (`routes/diagnostics/tools.py`)
- Factory-reset and password-change reauth (`routes/diagnostics/tools.py`, `routes/users.py`)
- DDNS force-update endpoint (`routes/services/network.py::api_ddns_force_update`)

If you want any of these re-audited, ask explicitly — but as written, they're done.
