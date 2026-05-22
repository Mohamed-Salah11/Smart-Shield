"""
app/services/parsers/pf_parser.py
---------------------------------
Pure parser for ``tcpdump -l -n -e -i pflog0`` output.

PF rules emitted by :mod:`app.services.pf_generator` copy matched packets to
the pflog0 pseudo-interface.  The SIEM collector tails that interface via
tcpdump and feeds each line into :func:`parse_pflog_line` to obtain a
normalised dict ready to be stored in the ``firewall_events`` SQLite table.

The parser is deliberately tolerant: a malformed line returns ``None``
instead of raising, so a single garbled packet cannot kill the collector
thread.  Unknown protocols / IP versions are recorded verbatim — the goal is
to surface *every* PF decision, not to drop the awkward ones.

Supported shapes (all observed on FreeBSD 13/14):

  IPv4 TCP::
      rule 12/0(match): block in on em0: 1.2.3.4.5678 > 10.0.0.5.22:
          Flags [S], seq 0, win 1024, length 0

  IPv4 UDP::
      rule 34/0(match): pass out on em1: 10.0.0.5.53251 > 8.8.8.8.53:
          12345+ A? example.com. (29)

  IPv4 ICMP::
      rule 5/0(match): block in on em0: 1.2.3.4 > 10.0.0.5: ICMP echo request,
          id 1, seq 1, length 64

  IPv6 TCP::
      rule 44/0(match): block in on em0: 2001:db8::1.5678 > 2001:db8::2.22:
          Flags [S], length 0

  IPv6 ICMP6::
      rule 7/0(match): pass out on em1: IP6 2001:db8::1 > 2001:db8::2:
          ICMP6, echo request, length 8

The leading tcpdump timestamp (``HH:MM:SS.uuuuuu``) is **not** consumed
here — the caller already has its own wall-clock when the line arrived and
should prefer that to the kernel's clock-stamp.
"""

from __future__ import annotations

import re
from typing import Optional

# ---------------------------------------------------------------------------
# Regexes
# ---------------------------------------------------------------------------

# rule N(/M)(match|...) [optional label "..."]: pass|block|match in|out on iface
#                       [optional label "..."]:
#
# tcpdump prints the PF rule label when invoked with -v on FreeBSD. Position
# varies by tcpdump version:
#   * Most common: ``rule 5/0(match) [label "..."]: block in on em0: ...``
#   * Some builds: ``rule 5/0(match): block in on em0 [label "..."]: ...``
# Both forms are accepted; the older/non-verbose form omits the bracket and
# leaves ``rule_label`` as ``None``.
_HDR_RE = re.compile(
    r'rule\s+(?P<rule_id>\d+)(?:[./]\d+)*\([^)]*\)'
    r'(?:\s+\[label\s+"(?P<rule_label_head>[^"]*)"\])?:\s+'
    r'(?P<action>pass|block|match)\s+(?P<direction>in|out)\s+on\s+'
    r'(?P<iface>[A-Za-z0-9_.:-]+)'
    r'(?:\s+\[label\s+"(?P<rule_label_tail>[^"]*)"\])?:'
)

# Standalone fallback: some tcpdump variants drop the label in unexpected
# positions (for example after the verbose IP options block). Anything that
# looks like a smart-shield label anywhere in the first 240 chars of the line
# still gets attributed correctly via this scanner.
_LABEL_FALLBACK_RE = re.compile(r'\[label\s+"([^"]*)"\]')

# IPv4 endpoint: dotted-quad, optional .port. tcpdump prints port AFTER a
# dot rather than colon for IPv4. Examples:
#   192.168.50.20.443    (TCP/UDP)
#   192.168.50.20        (ICMP — no port)
_IPV4 = r'(?P<{0}>\d{{1,3}}(?:\.\d{{1,3}}){{3}})(?:\.(?P<{0}_port>\d+))?'

# IPv6 endpoint: tcpdump prints port AFTER a literal dot here too (not a
# colon), to keep the format parseable. Examples:
#   2001:db8::1.443
#   fe80::1
_IPV6 = r'(?P<{0}>[0-9A-Fa-f:]+(?:%[A-Za-z0-9._-]+)?)(?:\.(?P<{0}_port>\d+))?'

_IPV4_PAIR_RE = re.compile(
    _IPV4.format("src") + r'\s+>\s+' + _IPV4.format("dst") + r'\s*:'
)
_IPV6_PAIR_RE = re.compile(
    r'IP6\s+' + _IPV6.format("src") + r'\s+>\s+' + _IPV6.format("dst") + r'\s*:'
)

# tcpdump TCP flag groups: "Flags [S]", "Flags [S.]", "Flags [P.U]" etc.
_FLAGS_RE = re.compile(r'Flags\s+\[([^\]]*)\]')

# "length N" — packet payload length when tcpdump prints it.
_LEN_RE = re.compile(r'\blength\s+(\d+)\b')

# ICMP / ICMP6 hint patterns; we only capture the immediate type token.
_ICMP_RE  = re.compile(r'\bICMP\b[\s,]+([A-Za-z][A-Za-z0-9 -]*?)(?:,|$)')
_ICMP6_RE = re.compile(r'\bICMP6\b[\s,]+([A-Za-z][A-Za-z0-9 -]*?)(?:,|$)')

# Map tcpdump TCP-flag short letters to a canonical comma-joined string the
# UI can render. tcpdump prints the flag set in alphabetical-ish order.
_TCP_FLAG_NAMES = {
    "S": "SYN", "F": "FIN", "R": "RST", "P": "PSH",
    "U": "URG", "E": "ECE", "W": "CWR", ".": "ACK",
}


def _expand_tcp_flags(token: str) -> str:
    out = []
    for ch in token:
        name = _TCP_FLAG_NAMES.get(ch)
        if name and name not in out:
            out.append(name)
    return ",".join(out)


def _int(value: Optional[str]) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _guess_protocol(line: str, has_tcp_flags: bool,
                    icmp4: bool, icmp6: bool) -> str:
    """Best-effort protocol classification from tcpdump verbiage."""
    if has_tcp_flags:
        return "tcp"
    if icmp6:
        return "icmp6"
    if icmp4:
        return "icmp"
    low = line.lower()
    # Order matters: ESP / GRE / IGMP / SCTP all appear by name in tcpdump.
    for proto in ("udp", "esp", "gre", "igmp", "sctp", "ipv6-icmp"):
        if f" {proto} " in low or f", {proto}," in low or low.endswith(f" {proto}"):
            return proto
    # tcpdump shows UDP as `12345+ A? example.com.` — the `+` after the
    # query id is a strong tell. So is the bare " A? " or " AAAA? ".
    if re.search(r'\b\d+\+', line):
        return "udp"
    return ""


def parse_pflog_line(line: str) -> Optional[dict]:
    """Parse one tcpdump pflog line into a structured dict.

    Returns ``None`` when the line lacks a recognisable ``rule N(...): ...``
    header (this catches blank lines, tcpdump preamble, kernel messages, and
    truncated buffers).  All other parse failures surface as ``None`` fields
    inside an otherwise populated dict so the row can still be stored — the
    raw line is always preserved in the ``raw_line`` field.
    """
    if not line:
        return None
    line = line.rstrip()
    if not line:
        return None

    hdr = _HDR_RE.search(line)
    if not hdr:
        return None

    rule_label = (
        hdr.groupdict().get("rule_label_head")
        or hdr.groupdict().get("rule_label_tail")
    )
    if not rule_label:
        # Fallback: scan the first 240 chars for a stray `[label "..."]`.
        m = _LABEL_FALLBACK_RE.search(line[:240])
        rule_label = m.group(1) if m else None

    out: dict = {
        "raw_line":   line,
        "rule_id":    hdr.group("rule_id"),
        "rule_label": rule_label,
        "action":     hdr.group("action"),
        "direction":  hdr.group("direction"),
        "interface":  hdr.group("iface"),
        "ip_version": None,
        "protocol":   "",
        "src_ip":     None,
        "src_port":   None,
        "dst_ip":     None,
        "dst_port":   None,
        "tcp_flags":  None,
        "icmp_type":  None,
        "icmp_code":  None,
        "packet_length": None,
    }

    # Normalise the action — pf 'match' rules just observe; treat as 'pass'
    # for downstream rendering since the packet was not blocked.
    if out["action"] == "match":
        out["action"] = "pass"

    # IPv6 line — try it first because IPv4 regex would match the leading
    # "IP6" prefix as a hostname otherwise.
    v6 = _IPV6_PAIR_RE.search(line)
    if v6:
        out["ip_version"] = 6
        out["src_ip"]     = v6.group("src")
        out["src_port"]   = _int(v6.group("src_port"))
        out["dst_ip"]     = v6.group("dst")
        out["dst_port"]   = _int(v6.group("dst_port"))
    else:
        v4 = _IPV4_PAIR_RE.search(line)
        if v4:
            out["ip_version"] = 4
            out["src_ip"]     = v4.group("src")
            out["src_port"]   = _int(v4.group("src_port"))
            out["dst_ip"]     = v4.group("dst")
            out["dst_port"]   = _int(v4.group("dst_port"))

    flags = _FLAGS_RE.search(line)
    if flags:
        out["tcp_flags"] = _expand_tcp_flags(flags.group(1))

    icmp4 = _ICMP_RE.search(line) if " ICMP " in line or " ICMP," in line else None
    if icmp4:
        out["icmp_type"] = icmp4.group(1).strip()
    icmp6 = _ICMP6_RE.search(line)
    if icmp6:
        out["icmp_type"] = icmp6.group(1).strip()

    out["protocol"] = _guess_protocol(
        line,
        has_tcp_flags=out["tcp_flags"] is not None,
        icmp4=bool(icmp4),
        icmp6=bool(icmp6),
    )

    length = _LEN_RE.search(line)
    if length:
        out["packet_length"] = _int(length.group(1))

    return out


__all__ = ["parse_pflog_line"]
