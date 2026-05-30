# Contributing to Smart-Shield

Thanks for your interest in improving Smart-Shield. This document explains how to set up a
development environment, run the tests, and submit changes.

## Development environment

Smart-Shield runs in a reduced "development mode" on any OS (Linux, macOS, Windows) — no FreeBSD
host is required to work on most of the codebase. Live OS operations (PF, interface config,
service control) are gated behind FreeBSD plus explicit environment flags, so the full UI and all
configuration generators are exercisable off-appliance.

```sh
git clone https://github.com/Mohamed-Salah11/Smart-Shield.git
cd Smart-Shield
python3 -m venv .venv
. .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
APP_ENV=development FLASK_DEBUG=1 python wsgi.py
```

## Running the tests

The test suite uses an in-memory SQLite database and mocks system commands, so it runs fully
offline on any platform:

```sh
pytest -q
```

All pull requests must pass `pytest`. Validate configuration-generator output using dry-run mode
(`SMARTSHIELD_NETWORK_DRY_RUN=1`) where a FreeBSD host is not available.

## Submitting changes

1. Fork the repository and create a feature branch.
2. Make your change with a focused commit history and clear messages.
3. Add or update tests for any behavior you change.
4. Run `pytest -q` and ensure it is green.
5. Open a pull request describing the change and its purpose.

Please do not introduce new runtime dependencies without justification. If you add a package to
`requirements.txt`, also update `app/manifests/python_runtime.json` (the release gate checks them
against each other).

## Reporting issues

Open a GitHub issue with steps to reproduce, expected vs. actual behavior, your OS/FreeBSD
version, and relevant log excerpts from `/var/log/smartshield/`. For **security vulnerabilities**,
do not open a public issue — see `SECURITY.md`.

## Getting support

For questions and usage help, open a GitHub issue with the `question` label or start a discussion.
Consult `Manual.md` and `Testing.md` first for installation and operational guidance.

## Code of Conduct

By participating you agree to abide by our `CODE_OF_CONDUCT.md`.
