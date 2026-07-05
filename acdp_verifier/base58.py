"""Base58-btc encoding (the multibase ``z`` alphabet)."""

from __future__ import annotations

__all__ = ["ALPHABET", "b58decode", "b58encode"]

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_INDEX = {ch: i for i, ch in enumerate(ALPHABET)}


def b58encode(data: bytes) -> str:
    num = int.from_bytes(data, "big")
    out: list[str] = []
    while num > 0:
        num, rem = divmod(num, 58)
        out.append(ALPHABET[rem])
    # Preserve leading zero bytes as '1' characters.
    for byte in data:
        if byte == 0:
            out.append(ALPHABET[0])
        else:
            break
    return "".join(reversed(out))


def b58decode(text: str) -> bytes:
    num = 0
    for ch in text:
        idx = _INDEX.get(ch)
        if idx is None:
            raise ValueError(f"character {ch!r} is not in the base58-btc alphabet")
        num = num * 58 + idx
    body = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    leading = 0
    for ch in text:
        if ch == ALPHABET[0]:
            leading += 1
        else:
            break
    return b"\x00" * leading + body
