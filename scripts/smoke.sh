#!/bin/sh
# =============================================================================
# Smart Shield — pre-push smoke check
# =============================================================================
# Cheap static gates that catch the regressions called out in the Fv4 review:
#   * Python files compile
#   * Flask app imports
#   * Every mutating route under routes/ carries @api_permission_required
#   * No pfSense wording survived
# Run from the repo root: sh scripts/smoke.sh
# =============================================================================
set -u
FAIL=0
hdr()  { printf "\n=== %s ===\n" "$*"; }
pass() { printf "[ OK ] %s\n" "$*"; }
fail() { printf "[FAIL] %s\n" "$*"; FAIL=1; }

PY=${PYTHON:-python}

hdr "Compile-all (app, routes, wsgi)"
if $PY -m compileall -q app routes wsgi.py >/tmp/ss_compileall.log 2>&1; then
    pass "compileall clean"
else
    fail "compileall failed"
    cat /tmp/ss_compileall.log
fi

hdr "Flask app importable"
if $PY - <<'PY' >/tmp/ss_import.log 2>&1
import os
os.environ.setdefault("APP_ENV", "development")
import wsgi
assert wsgi.app
print("import OK")
PY
then
    pass "wsgi.app imports"
else
    fail "wsgi.app failed to import"
    cat /tmp/ss_import.log
fi

hdr "RBAC gate (filter / firewall / network-services routes)"
# Files in this list MUST have @api_permission_required on every mutating
# route. Files outside (auth.py, portal.py, setup.py, *_portal.py, etc.)
# include intentionally-unauthenticated endpoints — see route docstrings.
$PY - <<'PY' || FAIL=$?
import re, sys, pathlib
GATED = [
    "routes/filters.py",
    "routes/services/dns_dhcp.py",
    "routes/services/captive.py",
    "routes/firewall/aliases.py",
    "routes/firewall/apply.py",
    "routes/firewall/nat.py",
    "routes/firewall/rules.py",
    "routes/firewall/schedules.py",
    "routes/firewall/shaper.py",
    "routes/network_api/interfaces.py",
    "routes/network_api/vips.py",
]
problems = []
for rel in GATED:
    path = pathlib.Path(rel)
    if not path.exists():
        continue
    src = path.read_text(encoding="utf-8", errors="ignore")
    routes = list(re.finditer(
        r"@\w+_bp\.route\([^)]*methods=\[[^\]]*?(POST|PUT|DELETE)[^\]]*\]",
        src,
    ))
    if not routes:
        continue
    decorators = src.count('@api_permission_required')
    if decorators < len(routes):
        problems.append(f"{rel}: {len(routes)} mutating routes, "
                        f"{decorators} api_permission_required decorators")
if problems:
    print("FAIL — gated routes missing RBAC decorator:")
    for p in problems:
        print(" ", p)
    sys.exit(1)
print("OK — all gated files fully covered")
PY
if [ "$FAIL" -ne 0 ]; then
    fail "RBAC gate failed"
else
    pass "RBAC gate passed"
fi

hdr "Wave F: bypass_policy uses canonical policy_exemption table"
if grep -RnE 'policy_exempt_clients' app routes bsd scripts 2>/dev/null \
        | grep -v 'scripts/smoke.sh'; then
    fail "stale policy_exempt_clients reference"
else
    pass "no stale policy_exempt_clients references"
fi

hdr "Wave G: pf_generator emits smartshield:* labels"
if grep -q 'smartshield:user_rule:' app/services/pf_generator.py \
        && grep -q 'smartshield:captive_portal:' app/services/captive_portal.py \
        && grep -q 'smartshield:hardening:' app/services/pf_generator.py; then
    pass "canonical labels present in pf_generator + captive_portal"
else
    fail "expected smartshield:<source>:<detail> labels missing"
fi

hdr "Wave G: tcpdump invocation captures rule labels (-v flag)"
if grep -q '"-v"' app/services/siem_collector.py; then
    pass "tcpdump -v present (rule labels surface)"
else
    fail "tcpdump invocation missing -v — rule_label will always be None"
fi

hdr "Wave J: dns mode GET gated by api.logs.read"
if grep -A2 'def api_mode_get' routes/dns_logs.py | grep -q 'api.logs.read'; then
    pass "dns_logs api_mode_get carries api.logs.read"
else
    fail "dns_logs api_mode_get missing api.logs.read decorator"
fi

hdr "Wave K: alert_observations helper exported"
if grep -q 'list_alert_observations' app/services/alert_service.py; then
    pass "alert_service.list_alert_observations present"
else
    fail "alert_service.list_alert_observations missing"
fi

hdr "Wave N: schema migrations apply cleanly to fresh DB"
if $PY - <<'PY' >/tmp/ss_mig.log 2>&1
import sqlite3, tempfile, os, sys, uuid
sys.path.insert(0, os.getcwd())
from app import migrations
dbpath = os.path.join(tempfile.gettempdir(), f"ss_smoke_{uuid.uuid4().hex[:8]}.db")
conn = sqlite3.connect(dbpath)
conn.row_factory = sqlite3.Row
conn.executescript("CREATE TABLE IF NOT EXISTS schema_version "
                   "(version INTEGER PRIMARY KEY, applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);")
applied = migrations.run_migrations(conn)
ver = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
assert ver == migrations.CURRENT_SCHEMA_VERSION, f"applied to {ver}, expected {migrations.CURRENT_SCHEMA_VERSION}"
# v40 dns_events.policy_source
cols = {r["name"] for r in conn.execute("PRAGMA table_info(dns_events)").fetchall()}
assert "policy_source" in cols, "v40 missing"
# v41 alert_observations
tables = {r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
assert "alert_observations" in tables, "v41 missing"
# v42 firewall_events richer cols
fwl_cols = {r["name"] for r in conn.execute("PRAGMA table_info(firewall_events)").fetchall()}
for c in ("policy_id","policy_name","zone_in","zone_out","nat_translated_src","nat_translated_dst"):
    assert c in fwl_cols, f"v42 missing column {c}"
print(f"migrations OK: {len(applied)} applied, final v{ver}")
conn.close()
PY
then
    cat /tmp/ss_mig.log
    pass "migrations apply cleanly to v$(grep -oE 'final v[0-9]+' /tmp/ss_mig.log | head -1 | tr -d 'fnalv ')"
else
    fail "migration smoke failed"
    cat /tmp/ss_mig.log
fi

hdr "pfSense wording purge"
# Use grep here since Skills' Grep tool isn't available in shell context.
# Exclude compiled bytecode — those mirror the .py files which the gate
# already covers.
if grep -RniE --exclude-dir=__pycache__ --exclude='*.pyc' \
        'pfsense' app bsd static templates routes 2>/dev/null; then
    fail "pfSense wording found above"
else
    pass "no pfSense wording"
fi

hdr "Summary"
if [ "$FAIL" -eq 0 ]; then
    pass "smoke OK"
    exit 0
fi
fail "smoke failed — see output above"
exit 1
