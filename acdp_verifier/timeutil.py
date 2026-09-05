"""RFC 3339 timestamp handling per RFC-ACDP-0001 §5.3."""

from __future__ import annotations

import re
from datetime import UTC, datetime

__all__ = [
    "CANONICAL_MS_RE",
    "RFC3339_RE",
    "is_canonical_ms",
    "is_rfc3339_utc",
    "parse_rfc3339",
]

# Canonical millisecond emission form: exactly three fractional digits, Z suffix.
CANONICAL_MS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")

# Any-precision RFC 3339 UTC form accepted on input (schema regex).
RFC3339_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")


def is_canonical_ms(value: str) -> bool:
    """True when *value* is canonical millisecond-precision RFC 3339 UTC and a real instant."""
    if not CANONICAL_MS_RE.match(value):
        return False
    try:
        parse_rfc3339(value)
    except ValueError:
        return False
    return True


def is_rfc3339_utc(value: str) -> bool:
    """True when *value* matches the accept-profile RFC 3339 UTC regex and parses."""
    if not RFC3339_RE.match(value):
        return False
    try:
        parse_rfc3339(value)
    except ValueError:
        return False
    return True


def parse_rfc3339(value: str) -> datetime:
    """Parse an RFC 3339 UTC ``Z`` timestamp of any fractional precision.

    Fractional digits beyond microseconds are truncated (comparisons in ACDP
    are at millisecond granularity by construction).
    """
    match = RFC3339_RE.match(value)
    if match is None:
        raise ValueError(f"not an RFC 3339 UTC timestamp: {value!r}")
    base, frac = value[:19], value[19:-1]
    micro = 0
    if frac:
        digits = frac[1:]  # strip leading '.'
        micro = int(digits[:6].ljust(6, "0"))
    # base is sliced from a value that RFC3339_RE already required to end in a
    # literal "Z" (the RFC 3339 UTC-only profile), so it never carries an offset;
    # the naive result is immediately given tzinfo=UTC below and can't escape.
    parsed = datetime.strptime(base, "%Y-%m-%dT%H:%M:%S")  # noqa: DTZ007
    return parsed.replace(microsecond=micro, tzinfo=UTC)
