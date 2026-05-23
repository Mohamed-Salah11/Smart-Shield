"""Lightweight per-source log parsers used by the SIEM collectors.

Each module exposes one pure ``parse_*`` function that turns a single log
line into a normalised dict. No I/O, no side effects, no global state — so
they are trivial to unit-test and to swap out at runtime.
"""
