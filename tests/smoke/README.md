# tests/smoke/

Fast, low-coverage tests that exercise one critical user flow each. The goal is
**regression detection**, not feature verification — if any of these fail in
CI, a load-bearing path is broken and the build should not ship.

Each file targets one subsystem:

| File              | Flow                                                           |
| ----------------- | -------------------------------------------------------------- |
| `test_auth.py`    | Login + logout via `/login` and `/system/logout`               |
| `test_firewall.py`| Firewall rules page loads + NAT rules JSON endpoint responds   |
| `test_services.py`| DHCP, DNS, and IDS settings pages load for a logged-in user    |
| `test_vpn.py`     | OpenVPN, IPsec, and L2TP setup pages load                      |
| `test_portal.py`  | Captive portal landing page is reachable without auth          |

Pattern:
* Use the `client`, `superuser`, and other fixtures from `tests/conftest.py`.
* Assert on HTTP status (not page content) so cosmetic changes don't break.
* Keep each test under ~10 lines — these are smoke, not behavior tests.

Run just this suite locally:

```
pytest tests/smoke -q
```
