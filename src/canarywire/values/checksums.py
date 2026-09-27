"""Check-digit algorithms: Luhn (cards), mod-97 (IBAN), ISO 7064 MOD 11,10 (German tax ID)."""

from __future__ import annotations

import string
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

LUHN_MIN_LENGTH = 2
DOUBLE_OVERFLOW = 9
IBAN_MIN_LENGTH = 5
MOD11_LENGTH = 11
MOD11_TEN = 10


def luhn_valid(value: str) -> bool:
    """True if `value` (digits, spaces allowed) passes the Luhn check."""
    digits = _ascii_digits(value)
    if digits is None or len(digits) < LUHN_MIN_LENGTH:
        return False
    return _luhn_sum(digits) % 10 == 0


def luhn_check_digit(payload: str) -> str:
    """The digit that makes `payload + digit` pass Luhn."""
    return str((10 - _luhn_sum(payload + "0") % 10) % 10)


def mod97_valid(value: str) -> bool:
    """True if `value` is an IBAN (spaces allowed) with valid mod-97 check digits."""
    compact = value.replace(" ", "").upper()
    if len(compact) < IBAN_MIN_LENGTH or not compact.isascii() or not compact.isalnum():
        return False
    return _mod97(compact[4:] + compact[:4]) == 1


def iban_check_digits(country: str, bban: str) -> str:
    """The two check digits for `country` + `bban`."""
    return f"{98 - _mod97(bban + country + '00'):02d}"


def mod11_valid(value: str) -> bool:
    """True if `value` is 11 digits (spaces allowed) passing ISO 7064 MOD 11,10."""
    digits = _ascii_digits(value)
    if digits is None or len(digits) != MOD11_LENGTH:
        return False
    return mod11_check_digit(digits[:10]) == digits[10]


def mod11_check_digit(body: str) -> str:
    """ISO 7064 MOD 11,10 check digit for a digit string (used by the German tax ID)."""
    product = MOD11_TEN
    for char in body:
        total = (int(char) + product) % MOD11_TEN
        if total == 0:
            total = MOD11_TEN
        product = (total * 2) % 11
    check = 11 - product
    return "0" if check == MOD11_TEN else str(check)


CHECKSUMS: dict[str, Callable[[str], bool]] = {
    "luhn": luhn_valid,
    "mod97": mod97_valid,
    "mod11": mod11_valid,
}


def _ascii_digits(value: str) -> str | None:
    stripped = value.replace(" ", "")
    if not stripped or any(c not in string.digits for c in stripped):
        return None
    return stripped


def _luhn_sum(digits: str) -> int:
    total = 0
    for index, char in enumerate(reversed(digits)):
        digit = int(char)
        if index % 2 == 1:
            digit *= 2
            if digit > DOUBLE_OVERFLOW:
                digit -= DOUBLE_OVERFLOW
        total += digit
    return total


def _mod97(text: str) -> int:
    return int("".join(str(int(char, 36)) for char in text)) % 97
