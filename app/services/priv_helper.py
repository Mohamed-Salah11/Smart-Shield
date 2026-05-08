"""
priv_helper.py
--------------
Least-privilege privileged command executor.

Architecture
------------
The Smart Shield web process runs as root (or as the unprivileged
``smartshield`` user in non-root deployments).
Operations that require root (pfctl, service, ifconfig, etc.) are gated
through this module, which:

  1. Validates all inputs against a per-action allowlist.
  2. Constructs the exact command from a template (no user-supplied strings
     injected raw into the command vector).
  3. Executes the command directly when running as root; falls back to
     ``sudo`` (see bsd/etc/sudoers.d/smartshield) for non-root deployments.
  4. Logs every privileged action to the audit log.
  5. Rejects any action not in the allowlist with a clear error.

Non-FreeBSD / dry-run
---------------------
When ``SMARTSHIELD_NETWORK_DRY_RUN=1`` or not running on FreeBSD, every
call returns a no-op result without executing anything.  Unit tests always
operate in this mode.

Public API
----------
run_privileged(action, **params)  -> CommandResult
list_allowed_actions()             -> list[str]
is_privileged_available()          -> bool
"""

import os
import re
import sys
from typing import Any, Callable, Dict, List, Optional

from app.services.network_service import (
    CommandResult,
    FreeBSDNetworkError,
    _network_dry_run_enabled,
    run_command,
)


def _maybe_sudo(cmd: List[str]) -> List[str]:
    """Return cmd unchanged when root (uid 0); otherwise prepend sudo -n."""
    if os.getuid() == 0:
        return cmd
    return ["/usr/local/bin/sudo", "-n"] + cmd


# ---------------------------------------------------------------------------
# Input validators — each raises ValueError on bad input
# ---------------------------------------------------------------------------

_SAFE_PATH_RE = re.compile(r"^/[A-Za-z0-9_./-]{1,255}$")
_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_SAFE_IP_RE   = re.compile(
    r"^(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?$|^[0-9a-fA-F:]{2,39}(?:/\d{1,3})?$"
)
_KNOWN_CONFIG_DIRS = {
    "/etc",
    "/usr/local/etc",
    "/usr/local/etc/openvpn",
    "/usr/local/etc/suricata",
    "/usr/local/etc/unbound",
    "/usr/local/etc/kea",
    "/usr/local/etc/miniupnpd",
    "/usr/local/etc/ddclient.conf",
    "/var/db/smart-shield",
}


def _val_config_path(v: str) -> str:
    v = str(v).strip()
    if not _SAFE_PATH_RE.match(v):
        raise ValueError(f"Unsafe config path: {v!r}")
    # Must start with a known config directory
    if not any(v.startswith(d) for d in _KNOWN_CONFIG_DIRS):
        raise ValueError(f"Config path not in allowed dirs: {v!r}")
    return v


def _val_anchor_name(v: str) -> str:
    v = str(v).strip()
    if not _SAFE_NAME_RE.match(v):
        raise ValueError(f"Invalid anchor name: {v!r}")
    return v


def _val_table_name(v: str) -> str:
    v = str(v).strip()
    if not _SAFE_NAME_RE.match(v):
        raise ValueError(f"Invalid PF table name: {v!r}")
    return v


def _val_ip(v: str) -> str:
    import ipaddress
    v = str(v).strip()
    try:
        # Accept IP or CIDR
        if "/" in v:
            ipaddress.ip_network(v, strict=False)
        else:
            ipaddress.ip_address(v)
    except ValueError:
        raise ValueError(f"Invalid IP/CIDR: {v!r}")
    return v


def _val_service_name(v: str) -> str:
    """Only allow known FreeBSD service names managed by Smart Shield."""
    _KNOWN_SERVICES = {
        "isc-dhcpd", "unbound", "openvpn", "strongswan",
        "suricata", "ntpd", "miniupnpd", "igmpproxy", "mpd5",
        "ddclient", "kea-dhcp6", "rtadvd", "bsnmpd",
        "smart_shield", "nginx", "pf", "pflog",
    }
    v = str(v).strip()
    if v not in _KNOWN_SERVICES:
        raise ValueError(f"Unknown service name: {v!r}")
    return v


def _val_service_action(v: str) -> str:
    _ALLOWED = {"start", "stop", "restart", "reload", "status", "onerestart"}
    v = str(v).strip().lower()
    if v not in _ALLOWED:
        raise ValueError(f"Unknown service action: {v!r}")
    return v


def _val_iface_name(v: str) -> str:
    v = str(v).strip()
    if not re.match(r"^[A-Za-z][A-Za-z0-9_]{0,15}$", v):
        raise ValueError(f"Invalid interface name: {v!r}")
    return v


def _val_cidr(v: str) -> str:
    import ipaddress
    v = str(v).strip()
    try:
        iface = ipaddress.ip_interface(v)
        return str(iface)
    except ValueError:
        raise ValueError(f"Invalid CIDR: {v!r}")


def _val_gateway(v: str) -> str:
    return _val_ip(v)


def _val_sysrc_key(v: str) -> str:
    v = str(v).strip()
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$", v):
        raise ValueError(f"Invalid sysrc key: {v!r}")
    return v


def _val_sysrc_value(v: str) -> str:
    v = str(v).strip()
    # Restrict to safe values (YES/NO, paths, simple strings)
    if len(v) > 256:
        raise ValueError("sysrc value too long")
    if any(c in v for c in (";", "&", "|", "`", "$", "!")):
        raise ValueError(f"Unsafe characters in sysrc value: {v!r}")
    return v


# ---------------------------------------------------------------------------
# Action allowlist
# ---------------------------------------------------------------------------
# Each entry describes one privileged action.
# "cmd" is a list of tokens; use {param_name} placeholders.
# "params" maps param_name -> validator function.
# ---------------------------------------------------------------------------

_ALLOWLIST: Dict[str, Dict[str, Any]] = {
    # PF rules
    "pf.reload": {
        "description": "Reload PF rules from a config file.",
        "cmd": ["/sbin/pfctl", "-f", "{config_path}"],
        "params": {"config_path": _val_config_path},
    },
    "pf.enable": {
        "description": "Enable PF.",
        "cmd": ["/sbin/pfctl", "-e"],
        "params": {},
    },
    "pf.disable": {
        "description": "Disable PF.",
        "cmd": ["/sbin/pfctl", "-d"],
        "params": {},
    },
    "pf.flush_rules": {
        "description": "Flush all PF rules.",
        "cmd": ["/sbin/pfctl", "-F", "rules"],
        "params": {},
    },
    # PF anchors
    "pf.anchor_reload": {
        "description": "Reload a named PF anchor from a config file.",
        "cmd": ["/sbin/pfctl", "-a", "{anchor_name}", "-f", "{config_path}"],
        "params": {"anchor_name": _val_anchor_name, "config_path": _val_config_path},
    },
    # PF tables
    "pf.table_add": {
        "description": "Add an IP to a PF table.",
        "cmd": ["/sbin/pfctl", "-t", "{table}", "-T", "add", "{ip}"],
        "params": {"table": _val_table_name, "ip": _val_ip},
    },
    "pf.table_delete": {
        "description": "Remove an IP from a PF table.",
        "cmd": ["/sbin/pfctl", "-t", "{table}", "-T", "delete", "{ip}"],
        "params": {"table": _val_table_name, "ip": _val_ip},
    },
    "pf.table_flush": {
        "description": "Flush all IPs from a PF table.",
        "cmd": ["/sbin/pfctl", "-t", "{table}", "-T", "flush"],
        "params": {"table": _val_table_name},
    },
    "pf.table_show": {
        "description": "Show all IPs in a PF table.",
        "cmd": ["/sbin/pfctl", "-t", "{table}", "-T", "show"],
        "params": {"table": _val_table_name},
    },
    # Services
    "service.action": {
        "description": "Run a service action (start/stop/restart/reload).",
        "cmd": ["/usr/sbin/service", "{service_name}", "{action}"],
        "params": {"service_name": _val_service_name, "action": _val_service_action},
    },
    "sysrc.get": {
    "description": "Read an rc.conf variable.",
    "cmd": ["/usr/sbin/sysrc", "-n", "{key}"],
    "params": {"key": _val_sysrc_key},
    },
    # sysrc
    "sysrc.set": {
        "description": "Persistently set an rc.conf variable.",
        "cmd": ["/usr/sbin/sysrc", "{key}={value}"],
        "params": {"key": _val_sysrc_key, "value": _val_sysrc_value},
        "custom_builder": "_build_sysrc_set",
    },
    # Interface
    "ifconfig.inet": {
        "description": "Assign an IPv4 address to an interface.",
        "cmd": ["/sbin/ifconfig", "{iface}", "inet", "{ip}", "netmask", "{netmask}"],
        "params": {"iface": _val_iface_name, "ip": _val_ip, "netmask": _val_ip},
    },
    "ifconfig.up": {
        "description": "Bring an interface up.",
        "cmd": ["/sbin/ifconfig", "{iface}", "up"],
        "params": {"iface": _val_iface_name},
    },
    "ifconfig.down": {
        "description": "Bring an interface down.",
        "cmd": ["/sbin/ifconfig", "{iface}", "down"],
        "params": {"iface": _val_iface_name},
    },
    # Routing
    "route.add_default": {
        "description": "Add a default route.",
        "cmd": ["/sbin/route", "-n", "add", "default", "{gateway}"],
        "params": {"gateway": _val_gateway},
    },
    "route.delete_default": {
        "description": "Delete the default route.",
        "cmd": ["/sbin/route", "-n", "delete", "default"],
        "params": {},
    },
    # Config file reload helpers
    "unbound.reload": {
        "description": "Reload unbound-control.",
        "cmd": ["/usr/local/sbin/unbound-control", "reload"],
        "params": {},
    },
    "ipsec.reload": {
        "description": "Hot-reload strongSwan IKE daemon configuration.",
        "cmd": ["/usr/local/sbin/ipsec", "reload"],
        "params": {},
    },
    "ipsec.statusall": {
        "description": "Show all active IPsec tunnels and SAs.",
        "cmd": ["/usr/local/sbin/ipsec", "statusall"],
        "params": {},
    },
    "pfctl.check": {
        "description": "Validate a PF config file without applying it.",
        "cmd": ["/sbin/pfctl", "-n", "-f", "{config_path}"],
        "params": {"config_path": _val_config_path},
    },
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def list_allowed_actions() -> List[str]:
    """Return all allowed privileged action names."""
    return sorted(_ALLOWLIST.keys())


def is_privileged_available() -> bool:
    """True if privileged commands can be executed (root or sudo on FreeBSD, non-dry-run)."""
    if not sys.platform.startswith("freebsd"):
        return False
    if _network_dry_run_enabled():
        return False
    if os.getuid() == 0:
        return True
    try:
        r = run_command(["/usr/local/bin/sudo", "-n", "-l"], check=False, timeout_seconds=3)
        return r.returncode == 0
    except Exception:
        return False


class PrivilegedActionError(RuntimeError):
    pass


def run_privileged(priv_action: str, audit_username: str = "system", **params) -> CommandResult:
    """
    Execute a pre-approved privileged action via sudo.

    Parameters
    ----------
    priv_action    : Key into the _ALLOWLIST, e.g. "pf.reload".
    audit_username : Username to record in the audit log.
    **params       : Named parameters required by the action; all are
                     validated before the command is constructed.
                     NOTE: use ``priv_action`` (not ``action``) for the
                     action name so that params named ``action`` (e.g.
                     for ``service.action``) do not clash.

    Returns
    -------
    CommandResult — same object as run_command().

    Raises
    ------
    PrivilegedActionError — if action is unknown or a param fails validation.
    FreeBSDNetworkError   — if the command itself fails.
    """
    action = priv_action
    if action not in _ALLOWLIST:
        raise PrivilegedActionError(
            f"Action {action!r} is not in the privileged allowlist. "
            f"Allowed: {sorted(_ALLOWLIST.keys())}"
        )

    entry    = _ALLOWLIST[action]
    p_schema = entry.get("params", {})

    # Validate every supplied parameter
    validated: Dict[str, str] = {}
    for key, validator in p_schema.items():
        if key not in params:
            raise PrivilegedActionError(f"Missing required param {key!r} for action {action!r}.")
        try:
            validated[key] = validator(params[key])
        except ValueError as exc:
            raise PrivilegedActionError(f"Invalid param {key!r} for {action!r}: {exc}") from exc

    # Reject any extra params not in the schema (defense in depth)
    extra = set(params) - set(p_schema)
    if extra:
        raise PrivilegedActionError(f"Unexpected params for {action!r}: {extra}")

    # Build command from template
    cmd_template = entry["cmd"]
    cmd: List[str] = []
    for token in cmd_template:
        # Replace {param_name} placeholders
        for k, v in validated.items():
            token = token.replace(f"{{{k}}}", v)
        cmd.append(token)

    # Special case: sysrc.set — key=value must be a single token
    if action == "sysrc.set":
        cmd = ["/usr/sbin/sysrc", f"{validated['key']}={validated['value']}"]

    # Prepend sudo on FreeBSD non-root deployments (no-op when running as root)
    if sys.platform.startswith("freebsd") and not _network_dry_run_enabled():
        cmd = _maybe_sudo(cmd)

    # Audit every privileged call
    try:
        from app.audit_log import log_event
        log_event(
            category="privileged",
            action=action,
            username=audit_username,
            remote_addr="",
            details={"params": {k: v for k, v in validated.items()}, "cmd": cmd},
        )
    except Exception:
        pass

    return run_command(cmd, check=False, timeout_seconds=30)
