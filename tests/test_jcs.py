"""JCS canonicalizer tests: numeric bands, tie values, sorting, escaping."""

from __future__ import annotations

import math
import struct

import pytest

from acdp_verifier import jcs


def bits(hex64: str) -> float:
    value = struct.unpack(">d", bytes.fromhex(hex64))[0]
    assert isinstance(value, float)
    return value


class TestNumberFormatting:
    def test_appendix_b_tie_round_half_even(self) -> None:
        # RFC 8785 Appendix B: the ES6 round-half-even canary value.
        assert jcs.format_number(bits("43143ff3c1cb0959")) == "1424953923781206.2"

    @pytest.mark.parametrize(
        ("hex64", "expected"),
        [
            ("0000000000000000", "0"),
            ("8000000000000000", "0"),  # negative zero normalizes
            ("0000000000000001", "5e-324"),  # smallest subnormal
            ("7fefffffffffffff", "1.7976931348623157e+308"),  # largest finite
            ("4340000000000000", "9007199254740992"),  # 2**53
            ("444b1ae4d6e2ef50", "1e+21"),  # exponential boundary (high)
            ("3eb0c6f7a0b5ed8d", "0.000001"),  # decimal band floor
            ("3e7ad7f29abcaf48", "1e-7"),  # exponential boundary (low)
            ("bfe0000000000000", "-0.5"),
            ("4024000000000000", "10"),
        ],
    )
    def test_rfc8785_appendix_b_vectors(self, hex64: str, expected: str) -> None:
        assert jcs.format_number(bits(hex64)) == expected

    def test_high_band_edges(self) -> None:
        assert jcs.format_number(1e20) == "100000000000000000000"
        assert jcs.format_number(1e21) == "1e+21"
        assert jcs.format_number(-1e21) == "-1e+21"
        assert jcs.format_number(1.23e25) == "1.23e+25"

    def test_low_band_edges(self) -> None:
        assert jcs.format_number(1e-6) == "0.000001"
        assert jcs.format_number(1e-7) == "1e-7"
        assert jcs.format_number(5e-9) == "5e-9"
        assert jcs.format_number(-1e-10) == "-1e-10"

    def test_trailing_zero_normalization(self) -> None:
        assert jcs.format_number(1.10) == "1.1"
        assert jcs.format_number(1.50) == "1.5"
        assert jcs.format_number(100.0) == "100"

    def test_integers_within_2_53(self) -> None:
        assert jcs.format_number(42) == "42"
        assert jcs.format_number(-7) == "-7"
        assert jcs.format_number(2**53) == "9007199254740992"

    def test_integer_beyond_2_53_reflects_rounded_double(self) -> None:
        # 2**53 + 1 is not representable; the rounded double is 2**53.
        assert jcs.format_number(2**53 + 1) == "9007199254740992"

    def test_nan_and_infinity_rejected(self) -> None:
        with pytest.raises(jcs.JcsError):
            jcs.format_number(math.nan)
        with pytest.raises(jcs.JcsError):
            jcs.format_number(math.inf)
        with pytest.raises(jcs.JcsError):
            jcs.format_number(-math.inf)

    def test_oversized_int_rejected(self) -> None:
        with pytest.raises(jcs.JcsError):
            jcs.format_number(10**400)


class TestSerialization:
    def test_key_sorting_utf16_code_units(self) -> None:
        # A supplementary-plane char (first UTF-16 unit 0xD834) sorts BEFORE
        # U+FF01 in UTF-16 code-unit order, although its code point is larger.
        supplementary = "\U0001d306"
        fullwidth = "\uff01"
        text = jcs.dumps({fullwidth: 1, supplementary: 2})
        assert text.index(supplementary) < text.index(fullwidth)

    def test_rfc8785_sorting_example(self) -> None:
        # From RFC 8785 3.2.3: expected key order is
        # \r, "1", U+0080, U+00F6, U+20AC, U+1F602 (surrogates), U+FB33.
        obj: jcs.JsonValue = {
            "\u20ac": "Euro Sign",
            "\r": "Carriage Return",
            "\ufb33": "Hebrew Letter Dalet With Dagesh",
            "1": "One",
            "\U0001f602": "Smiley",
            "\u0080": "Control",
            "\u00f6": "Latin Small Letter O With Diaeresis",
        }
        want = (
            '{"\\r":"Carriage Return","1":"One","\u0080":"Control",'
            '"\u00f6":"Latin Small Letter O With Diaeresis",'
            '"\u20ac":"Euro Sign","\U0001f602":"Smiley",'
            '"\ufb33":"Hebrew Letter Dalet With Dagesh"}'
        )
        assert jcs.dumps(obj) == want

    def test_string_escapes(self) -> None:
        assert jcs.dumps("a\"b\\c\b\t\n\f\r\x1f") == '"a\\"b\\\\c\\b\\t\\n\\f\\r\\u001f"'

    def test_non_ascii_literal(self) -> None:
        assert jcs.canonicalize({"t": "café — test"}) == '{"t":"café — test"}'.encode()

    def test_null_vs_absent_distinct(self) -> None:
        assert jcs.dumps({"a": None}) != jcs.dumps({})
        assert jcs.dumps({"a": None, "b": [], "c": {}}) == '{"a":null,"b":[],"c":{}}'

    def test_array_order_preserved(self) -> None:
        assert jcs.dumps({"tags": ["zebra", "apple"]}) == '{"tags":["zebra","apple"]}'

    def test_booleans_and_null(self) -> None:
        assert jcs.dumps([True, False, None]) == "[true,false,null]"


class TestLoads:
    def test_duplicate_keys_rejected(self) -> None:
        with pytest.raises(jcs.JcsError):
            jcs.loads('{"a":1,"a":2}')

    def test_non_finite_constants_rejected(self) -> None:
        with pytest.raises(jcs.JcsError):
            jcs.loads('{"a": NaN}')

    def test_invalid_utf8_rejected(self) -> None:
        with pytest.raises(jcs.JcsError):
            jcs.loads(b'{"a": "\xff"}')

    def test_roundtrip(self) -> None:
        assert jcs.loads('{"b":2,"a":1}') == {"a": 1, "b": 2}
