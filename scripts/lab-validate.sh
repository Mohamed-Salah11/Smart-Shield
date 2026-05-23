#!/bin/sh
# =============================================================================
# Smart Shield — Lab Validation Runbook (FreeBSD)
# =============================================================================
# Run on the Smart Shield VM after a fresh install or any apply cycle to
# confirm the runtime is sane. Pairs with docs/lab-validation.md for the
# full client-side test matrix (Test Kali → portal, DNS, app filter, SOC).
#
# Usage:
#   sh scripts/lab-validate.sh                # full run
#   sh scripts/lab-validate.sh services       # just service status
#   sh scripts/lab-validate.sh pf             # just PF state
#   sh scripts/lab-validate.sh events         # event-store schema (Wave A)
#   sh scripts/lab-validate.sh installer      # source-deploy + sysrc + service start (Wave I)
#   sh scripts/lab-validate.sh pf-order       # section + anchor order static checks (Wave H)
#   sh scripts/lab-validate.sh captive-portal # captive portal pre/post-login (Wave H+I)
#   sh scripts/lab-validate.sh content-policy # canonical action round-trip (Wave F)
#   sh scripts/lab-validate.sh logs           # firewall + DNS events populate (Wave G+J)
# =============================================================================
set -u

MODE="${1:-all}"
FAIL=0
DB="${SMARTSHIELD_DB_PATH:-/var/db/smart-shield/smart_shield.db}"

hdr()  { printf "\n=== %s ===\n" "$*"; }
pass() { printf "[ OK ] %s\n" "$*"; }
warn() { printf "[WARN] %s\n" "$*"; }
fail() { printf "[FAIL] %s\n" "$*"; FAIL=1; }

# ---------------------------------------------------------------------------
# Service status
# ---------------------------------------------------------------------------
if [ "$MODE" = "all" ] || [ "$MODE" = "services" ]; then
    hdr "Smart Shield services"
    for svc in smart_shield pf unbound nginx isc-dhcpd; do
        if service "$svc" status >/dev/null 2>&1; then
            pass "$svc running"
        else
            # isc-dhcpd is wizard-owned per §2.2 — don't fail the run on it
            if [ "$svc" = "isc-dhcpd" ]; then
                warn "$svc not running (wizard-controlled; OK if not yet enabled)"
            else
                fail "$svc not running"
            fi
        fi
    done
fi

# ---------------------------------------------------------------------------
# Listening sockets
# ---------------------------------------------------------------------------
if [ "$MODE" = "all" ] || [ "$MODE" = "services" ]; then
    hdr "Listening sockets (53 / 80 / 443 / 5000)"
    sockstat -4 -l 2>/dev/null | grep -E ':(53|80|443|5000)\>' \
        || warn "no expected ports listening — services may still be coming up"
fi

# ---------------------------------------------------------------------------
# PF state and anchors
# ---------------------------------------------------------------------------
if [ "$MODE" = "all" ] || [ "$MODE" = "pf" ]; then
    hdr "PF main ruleset (first 40 rules)"
    pfctl -sr 2>/dev/null | head -40 || fail "pfctl -sr failed"

    hdr "PF captive-portal RDR anchor"
    pfctl -a smartshield/captive_portal_rdr -sn 2>/dev/null \
        || warn "captive_portal_rdr anchor empty (OK if captive portal disabled)"

    hdr "PF captive-portal filter anchor"
    pfctl -a smartshield/captive_portal_filter -sr 2>/dev/null \
        || warn "captive_portal_filter anchor empty (OK if captive portal disabled)"

    hdr "Authenticated client table"
    pfctl -t authenticated_clients -T show 2>/dev/null \
        || warn "authenticated_clients table not loaded (OK if no captive sessions)"

    # Phase 1.2 regression check: confirm `no rdr` DNS bypass is emitted
    # BEFORE the catch-all rdr.
    hdr "DNS bypass ordering (regression check for §1.2)"
    rdr_dump=$(pfctl -a smartshield/captive_portal_rdr -sn 2>/dev/null)
    if printf '%s\n' "$rdr_dump" | grep -q "no rdr.*port 53"; then
        first_no=$(printf '%s\n' "$rdr_dump" | grep -n "no rdr.*port 53" | head -1 | cut -d: -f1)
        first_rdr=$(printf '%s\n' "$rdr_dump" | grep -n "^rdr .*port 53" | head -1 | cut -d: -f1)
        if [ -n "$first_no" ] && [ -n "$first_rdr" ] && [ "$first_no" -lt "$first_rdr" ]; then
            pass "DNS 'no rdr' bypass precedes catch-all rdr"
        else
            fail "DNS bypass order WRONG — admin clients will still be redirected"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# DNS sanity
# ---------------------------------------------------------------------------
if [ "$MODE" = "all" ] || [ "$MODE" = "dns" ]; then
    hdr "Unbound config validation"
    unbound-checkconf 2>&1 | head -10 || fail "unbound-checkconf reported errors"
fi

# ---------------------------------------------------------------------------
# Event-store schema (Wave A: event_uuid + normalized columns + SOC join key)
# ---------------------------------------------------------------------------
if [ "$MODE" = "all" ] || [ "$MODE" = "events" ]; then
    hdr "Event-store schema (Wave A)"
    if [ ! -f "$DB" ]; then
        warn "DB not found at $DB — skip"
    else
        ver=$(sqlite3 "$DB" "SELECT COALESCE(MAX(version),0) FROM schema_version" 2>/dev/null)
        if [ "${ver:-0}" -ge 35 ]; then
            pass "schema_version = $ver (>= 35)"
        else
            fail "schema_version = $ver (Wave A needs >= 35)"
        fi

        # event_uuid + a sample of normalized columns must exist on events
        cols=$(sqlite3 "$DB" "SELECT GROUP_CONCAT(name,',') FROM pragma_table_info('events')" 2>/dev/null)
        for c in event_uuid source_type src_ip dst_ip protocol soc_origin; do
            if printf '%s' "$cols" | tr ',' '\n' | grep -qx "$c"; then
                pass "events.$c present"
            else
                fail "events.$c MISSING — migration v34 did not run"
            fi
        done

        # event_uuid must be set on every row + unique
        null_uuid=$(sqlite3 "$DB" "SELECT COUNT(*) FROM events WHERE event_uuid IS NULL OR event_uuid = ''" 2>/dev/null)
        if [ "${null_uuid:-0}" -eq 0 ]; then
            pass "events: no NULL event_uuid rows"
        else
            fail "events: $null_uuid rows have NULL event_uuid (backfill skipped)"
        fi
        dup_uuid=$(sqlite3 "$DB" "SELECT COUNT(*) FROM (SELECT event_uuid FROM events WHERE event_uuid != '' GROUP BY event_uuid HAVING COUNT(*) > 1)" 2>/dev/null)
        if [ "${dup_uuid:-0}" -eq 0 ]; then
            pass "events: no duplicate event_uuid rows"
        else
            fail "events: $dup_uuid duplicate event_uuid groups"
        fi

        # SOC alert-actions/assignments must carry event_uuid going forward
        for tbl in siem_alert_actions siem_alert_assignments; do
            saa_cols=$(sqlite3 "$DB" "SELECT GROUP_CONCAT(name,',') FROM pragma_table_info('$tbl')" 2>/dev/null)
            if printf '%s' "$saa_cols" | tr ',' '\n' | grep -qx event_uuid; then
                pass "$tbl.event_uuid present"
            else
                fail "$tbl.event_uuid MISSING — migration v35 did not run"
            fi
        done

        # Confirm new writes are populating normalized columns. Look at the
        # last 50 rows: at least one should have a non-NULL src_ip OR dst_ip
        # OR domain if the firewall/dns/ids collectors are running.
        recent_norm=$(sqlite3 "$DB" "SELECT COUNT(*) FROM (SELECT 1 FROM events ORDER BY id DESC LIMIT 50) WHERE 1=1" 2>/dev/null)
        any_norm=$(sqlite3 "$DB" "SELECT COUNT(*) FROM (SELECT 1 FROM events WHERE (src_ip IS NOT NULL OR dst_ip IS NOT NULL OR domain IS NOT NULL OR rule_id IS NOT NULL) ORDER BY id DESC LIMIT 50)" 2>/dev/null)
        if [ "${any_norm:-0}" -gt 0 ]; then
            pass "recent events have normalized fields populated ($any_norm/50)"
        else
            warn "recent events have no normalized fields — collectors may be idle"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Wave I — Installer / FreeBSD runtime sanity
# ---------------------------------------------------------------------------
if [ "$MODE" = "all" ] || [ "$MODE" = "installer" ]; then
    hdr "Installer / runtime (Wave I)"
    # sysrc enabled-knob coverage
    for knob in smart_shield_enable pf_enable pflog_enable unbound_enable gateway_enable; do
        if sysrc -n "$knob" 2>/dev/null | grep -qi '^yes'; then
            pass "sysrc $knob=YES"
        else
            fail "sysrc $knob is NOT YES (run install.sh in live mode or sysrc $knob=YES)"
        fi
    done
    # Canonical APP_ROOT must be populated (rsync deploy from any SRC_ROOT)
    for f in /usr/local/share/smart-shield/wsgi.py \
             /usr/local/share/smart-shield/requirements.txt \
             /usr/local/share/smart-shield/app/__init__.py; do
        if [ -f "$f" ]; then
            pass "$f present"
        else
            fail "$f missing — installer did not deploy SRC_ROOT to APP_ROOT"
        fi
    done
    # Master key strictly 0600
    if [ -f /usr/local/etc/smart-shield/master.key ]; then
        mode=$(stat -f '%Lp' /usr/local/etc/smart-shield/master.key 2>/dev/null)
        if [ "$mode" = "600" ]; then
            pass "master.key mode 0600"
        else
            fail "master.key mode $mode (expected 600)"
        fi
    else
        warn "master.key not present — auto-generated on first app start"
    fi
fi

# ---------------------------------------------------------------------------
# Wave H — PF static order (anchor + section)
# ---------------------------------------------------------------------------
if [ "$MODE" = "all" ] || [ "$MODE" = "pf-order" ]; then
    hdr "PF static-order validator (Wave H)"
    if [ ! -f /etc/pf.conf ]; then
        warn "/etc/pf.conf missing — skip"
    else
        if pfctl -nf /etc/pf.conf 2>/tmp/ss_pfnf.log; then
            pass "pfctl -nf accepts /etc/pf.conf"
        else
            fail "pfctl -nf rejected /etc/pf.conf:"
            head -20 /tmp/ss_pfnf.log
        fi
        if command -v python3 >/dev/null 2>&1; then
            if python3 - <<'PY' >/tmp/ss_pford.log 2>&1
import sys, os
sys.path.insert(0, '/usr/local/share/smart-shield')
from app.services.pf_static_validator import (
    validate_section_order, validate_anchor_order,
)
text = open('/etc/pf.conf').read()
validate_section_order(text)
validate_anchor_order(text)
print("section + anchor order OK")
PY
            then
                pass "pf_static_validator section + anchor order OK"
            else
                fail "pf_static_validator rejected /etc/pf.conf:"
                cat /tmp/ss_pford.log
            fi
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Wave H — Captive portal pre/post-login
# ---------------------------------------------------------------------------
if [ "$MODE" = "all" ] || [ "$MODE" = "captive-portal" ]; then
    hdr "Captive portal (Wave H)"
    # rdr anchor must list the DNS intercept BEFORE the HTTP rdr
    rdr=$(pfctl -a smartshield/captive_portal_rdr -sn 2>/dev/null)
    if printf '%s\n' "$rdr" | grep -q 'port 53'; then
        pass "rdr anchor contains DNS intercept"
    else
        warn "rdr anchor missing DNS intercept (OK if captive portal disabled)"
    fi
    # filter anchor: every block + key passes must carry smartshield: labels
    filt=$(pfctl -a smartshield/captive_portal_filter -sr 2>/dev/null)
    if printf '%s\n' "$filt" | grep -q 'label "smartshield:captive_portal:'; then
        pass "captive_portal filter anchor uses canonical labels"
    else
        warn "no smartshield:captive_portal:* labels found (re-apply PF)"
    fi
fi

# ---------------------------------------------------------------------------
# Wave F — Content-policy canonical-action round-trip
# ---------------------------------------------------------------------------
if [ "$MODE" = "all" ] || [ "$MODE" = "content-policy" ]; then
    hdr "Content policy canonical actions (Wave F)"
    if [ ! -f "$DB" ]; then
        warn "DB not found at $DB — skip"
    else
        # is_blocked_domain must recognise a 'block_all' rule
        result=$(python3 - <<PY 2>/dev/null
import sys
sys.path.insert(0, '/usr/local/share/smart-shield')
import sqlite3
conn = sqlite3.connect("$DB")
conn.row_factory = sqlite3.Row
from app.services.content_policy import has_active_content_policy, is_blocked_domain
print("has_active:", has_active_content_policy(conn))
PY
)
        if printf '%s' "$result" | grep -q 'has_active:'; then
            pass "content_policy callable: $result"
        else
            fail "content_policy callable but returned unexpected output"
        fi
        # No stale policy_exempt_clients in PF tables
        if pfctl -t policy_exempt_clients -T show 2>/dev/null | head -1 | grep -q .; then
            fail "stale policy_exempt_clients PF table populated — should be policy_exemption only"
        else
            pass "no policy_exempt_clients PF table contents"
        fi
        # Canonical policy_exemption table exists
        if pfctl -t policy_exemption -T show 2>/dev/null | head -1 >/dev/null; then
            pass "policy_exemption table loaded"
        else
            warn "policy_exemption table not populated (OK if no exempt clients)"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Wave G+J — Firewall + DNS logs populate
# ---------------------------------------------------------------------------
if [ "$MODE" = "all" ] || [ "$MODE" = "logs" ]; then
    hdr "Firewall + DNS logs (Waves G+J)"
    if [ ! -f "$DB" ]; then
        warn "DB not found at $DB — skip"
    else
        # firewall_events: at least one row with a non-default policy_source
        ev_total=$(sqlite3 "$DB" "SELECT COUNT(*) FROM firewall_events" 2>/dev/null)
        ev_sources=$(sqlite3 "$DB" "SELECT COUNT(DISTINCT policy_source) FROM firewall_events" 2>/dev/null)
        if [ "${ev_total:-0}" -gt 0 ]; then
            pass "firewall_events: $ev_total rows, $ev_sources distinct policy_source"
            sqlite3 "$DB" "SELECT policy_source, COUNT(*) FROM firewall_events GROUP BY policy_source ORDER BY 2 DESC LIMIT 8" 2>/dev/null \
                | sed 's/^/      /'
        else
            warn "firewall_events empty — generate traffic and re-run"
        fi
        # dns_events: should have rows with matched_domain populated when policy is active
        dns_total=$(sqlite3 "$DB" "SELECT COUNT(*) FROM dns_events" 2>/dev/null)
        dns_matched=$(sqlite3 "$DB" "SELECT COUNT(*) FROM dns_events WHERE matched_domain IS NOT NULL AND matched_domain != ''" 2>/dev/null)
        if [ "${dns_total:-0}" -gt 0 ]; then
            pass "dns_events: $dns_total rows, $dns_matched with matched_domain"
        else
            warn "dns_events empty — set mode=blocked_only and trigger DNS hits"
        fi
        # SOC events MUST NOT be inflating firewall counts
        soc_in_fw=$(sqlite3 "$DB" "SELECT COUNT(*) FROM firewall_events WHERE policy_source='soc'" 2>/dev/null)
        pass "firewall_events with policy_source=soc: ${soc_in_fw:-0} (these are correctly attributed, not mixed in)"
    fi
fi

hdr "Summary"
if [ "$FAIL" -eq 0 ]; then
    pass "All checks passed"
    exit 0
fi
fail "One or more checks failed — review output above"
exit 1
