"""RFC 8785 (JSON Canonicalization Scheme) canonicalizer.

Implemented independently from the RFC text (not ported from any other ACDP
implementation). Number serialization follows the ECMA-262 ``Number::toString``
algorithm that RFC 8785 §3.2.2.3 normatively references, including:

- the exponential-notation boundaries (magnitude >= 1e21 -> ``e+``,
  magnitude <= 1e-7 -> ``e-``), with the plain-decimal band between them;
- integer exactness through 2**53;
- negative-zero normalization to ``0``;
- shortest-round-trip digit selection with the ECMA round-half-even tie rule
  (RFC 8785 Appendix B: bits 0x43143ff3c1cb0959 -> ``1424953923781206.2``).

CPython's ``repr(float)`` produces the shortest decimal digit string that
round-trips to the same IEEE 754 double with correct rounding — the same digit
sequence ECMA-262 mandates — so this module reuses those digits and applies
the ECMA formatting rules on top.

Object member names are sorted by their UTF-16 code units (RFC 8785 §3.2.3),
which differs from code-point order for supplementary-plane characters.
"""

from __future__ import annotations

import json
import math
from typing import Any, Union

JsonValue = Union[None, bool, int, float, str, list["JsonValue"], dict[str, "JsonValue"]]

__all__ = ["JcsError", "canonicalize", "dumps", "format_number", "loads"]


class JcsError(ValueError):
    """Input cannot be canonicalized (or parsed) under RFC 8785 rules."""


# --- parsing -----------------------------------------------------------------


def _reject_duplicate_keys(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
    obj: dict[str, JsonValue] = {}
    for key, value in pairs:
        if key in obj:
            raise JcsError(f"duplicate object member name: {key!r}")
        obj[key] = value
    return obj


def loads(data: Union[str, bytes]) -> JsonValue:
    """Parse JSON text strictly: valid UTF-8, no duplicate member names, no NaN/Infinity."""
    if isinstance(data, bytes):
        try:
            data = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise JcsError(f"input is not valid UTF-8: {exc}") from exc
    try:
        value: JsonValue = json.loads(
            data,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except json.JSONDecodeError as exc:
        raise JcsError(f"invalid JSON: {exc}") from exc
    return value


def _reject_constant(name: str) -> JsonValue:
    raise JcsError(f"non-finite JSON constant not allowed: {name}")


# --- number serialization (ECMA-262 Number::toString, base 10) ---------------

_MAX_SAFE_INTEGER = 2**53


def format_number(value: Union[int, float]) -> str:
    """Serialize a JSON number per RFC 8785 §3.2.2.3 / ECMA-262 7.1.12.1."""
    if isinstance(value, bool):  # bool is an int subclass; guard explicitly
        raise JcsError("bool is not a number")
    if isinstance(value, int):
        try:
            as_float = float(value)
        except OverflowError as exc:
            raise JcsError(f"integer magnitude exceeds IEEE 754 double range: {value}") from exc
        # JCS numbers are IEEE 754 doubles: integers above 2**53 reflect the
        # rounded double (can-011 implementer note), which float() performs.
        value = as_float
    if math.isnan(value) or math.isinf(value):
        raise JcsError("NaN and Infinity are not valid JSON numbers")
    if value == 0.0:
        return "0"  # covers -0.0 -> "0"

    negative = value < 0.0
    magnitude = -value if negative else value

    digits, n = _shortest_digits(magnitude)
    k = len(digits)

    # ECMA-262 7.1.12.1 (ToString of Number), steps for base 10:
    # value = int(digits) * 10 ** (n - k)
    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + digits
    else:
        exponent = n - 1
        exp_str = f"e+{exponent}" if exponent >= 0 else f"e-{-exponent}"
        if k == 1:
            body = digits + exp_str
        else:
            body = digits[0] + "." + digits[1:] + exp_str
    return "-" + body if negative else body


def _shortest_digits(magnitude: float) -> tuple[str, int]:
    """Return (digits, n) such that magnitude == 0.<digits> * 10**n exactly.

    ``digits`` carries no leading or trailing zeros. Uses CPython repr(), which
    emits the shortest correctly-rounded digit string for the double.
    """
    text = repr(magnitude)
    if "e" in text or "E" in text:
        mantissa, _, exp_part = text.lower().partition("e")
        exp = int(exp_part)
    else:
        mantissa, exp = text, 0
    if "." in mantissa:
        int_part, _, frac_part = mantissa.partition(".")
    else:
        int_part, frac_part = mantissa, ""
    digits = int_part + frac_part
    # n: exponent such that value = 0.<digits> * 10 ** n (before zero-stripping)
    n = len(int_part) + exp
    stripped = digits.lstrip("0")
    n -= len(digits) - len(stripped)
    digits = stripped.rstrip("0")
    if not digits:  # pragma: no cover - zero handled by caller
        raise JcsError("internal: zero reached digit extraction")
    return digits, n


# --- string serialization -----------------------------------------------------

_NAMED_ESCAPES = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}


def _format_string(value: str) -> str:
    out: list[str] = ['"']
    for ch in value:
        code = ord(ch)
        named = _NAMED_ESCAPES.get(code)
        if named is not None:
            out.append(named)
        elif code < 0x20:
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


# --- serialization ------------------------------------------------------------


def _utf16_sort_key(name: str) -> bytes:
    """Sort key implementing RFC 8785 §3.2.3 (UTF-16 code unit order)."""
    return name.encode("utf-16-be")


def _serialize(value: JsonValue, out: list[str]) -> None:
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, str):
        out.append(_format_string(value))
    elif isinstance(value, (int, float)):
        out.append(format_number(value))
    elif isinstance(value, list):
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _serialize(item, out)
        out.append("]")
    elif isinstance(value, dict):
        out.append("{")
        first = True
        for key in sorted(value.keys(), key=_utf16_sort_key):
            if not isinstance(key, str):
                raise JcsError(f"object member name is not a string: {key!r}")
            if not first:
                out.append(",")
            first = False
            out.append(_format_string(key))
            out.append(":")
            _serialize(value[key], out)
        out.append("}")
    else:
        raise JcsError(f"value is not JSON-serializable: {type(value).__name__}")


def dumps(value: JsonValue) -> str:
    """Return the JCS canonical form of *value* as a string."""
    out: list[str] = []
    _serialize(value, out)
    return "".join(out)


def canonicalize(value: JsonValue) -> bytes:
    """Return the JCS canonical form of *value* as UTF-8 bytes."""
    return dumps(value).encode("utf-8")


def canonicalize_any(value: Any) -> bytes:
    """Canonicalize a value typed as ``Any`` (parsed JSON). Raises JcsError on bad shapes."""
    checked: JsonValue = value  # runtime-checked during serialization
    return canonicalize(checked)
