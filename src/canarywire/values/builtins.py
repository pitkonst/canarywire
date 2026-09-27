"""Built-in canary types: parameterised generators for common formats (synthetic values)."""

from __future__ import annotations

import re
import string
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from canarywire.values.checksums import iban_check_digits, luhn_check_digit, mod11_check_digit
from canarywire.values.errors import CanaryTypeError

if TYPE_CHECKING:
    import random
    from collections.abc import Callable, Mapping

WORDS = (
    "amber",
    "birch",
    "cedar",
    "delta",
    "ember",
    "fjord",
    "garnet",
    "harbor",
    "indigo",
    "juniper",
    "kestrel",
    "lumen",
    "maple",
    "nectar",
    "onyx",
    "pine",
)
LABEL = r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
HOSTNAME = re.compile(rf"{LABEL}(\.{LABEL})+")
IBAN_BBAN = {
    "de": (("n", 18),),
    "fr": (("n", 23),),
    "gb": (("a", 4), ("n", 14)),
    "nl": (("a", 4), ("n", 10)),
    "es": (("n", 20),),
}
CARDS = {
    "visa": ("400000", 16, (4, 4, 4, 4)),
    "mastercard": ("555555", 16, (4, 4, 4, 4)),
    "amex": ("378282", 15, (4, 6, 5)),
}
NINO_FIRST = "".join(c for c in string.ascii_uppercase if c not in "DFIQUV")
NINO_SECOND = "".join(c for c in string.ascii_uppercase if c not in "DFIOQUV")
NINO_EXCLUDED = frozenset({"BG", "GB", "KN", "NK", "NT", "TN", "ZZ"})
SSN_AREA_MAX = 899
SSN_RESERVED_AREA = 666


@dataclass(frozen=True)
class Builtin:
    """A built-in type: enumerated params (first value = default), free params, a generator."""

    name: str
    make: Callable[[random.Random, Mapping[str, str]], str]
    choices: dict[str, tuple[str, ...]] = field(default_factory=dict)
    free: dict[str, str] = field(default_factory=dict)

    def resolve(self, params: Mapping[str, Any]) -> dict[str, str]:
        """Validate `params` and fill in defaults; raise CanaryTypeError naming the parameter."""
        resolved = {key: options[0] for key, options in self.choices.items()} | dict(self.free)
        for key, value in params.items():
            if key not in resolved:
                raise CanaryTypeError(f"{key}: unknown parameter for type {self.name}")
            if not isinstance(value, str):
                raise CanaryTypeError(f"{key}: expected a string")
            if key in self.choices and value not in self.choices[key]:
                raise CanaryTypeError(f"{key}: expected one of {', '.join(self.choices[key])}")
            resolved[key] = value
        if "domain" in resolved and not HOSTNAME.fullmatch(resolved["domain"]):
            raise CanaryTypeError("domain: expected a hostname like example.org")
        return resolved


def _digits(rng: random.Random, count: int) -> str:
    return "".join(rng.choice(string.digits) for _ in range(count))


def _grouped(text: str, sizes: tuple[int, ...]) -> str:
    parts: list[str] = []
    position = 0
    for size in sizes:
        parts.append(text[position : position + size])
        position += size
    if position < len(text):
        parts.append(text[position:])
    return " ".join(parts)


def _email(rng: random.Random, params: Mapping[str, str]) -> str:
    return f"{rng.choice(WORDS)}.{rng.choice(WORDS)}{_digits(rng, 4)}@{params['domain']}"


def _phone(rng: random.Random, params: Mapping[str, str]) -> str:
    """US 555-01xx and UK 07700 900xxx are fiction ranges; DE and FR numbers are synthetic only."""
    region, e164 = params["region"], params["format"] == "e164"
    if region == "us":
        tail = f"01{_digits(rng, 2)}"
        return f"+1202555{tail}" if e164 else f"(202) 555-{tail}"
    if region == "uk":
        tail = _digits(rng, 3)
        return f"+447700900{tail}" if e164 else f"07700 900{tail}"
    if region == "de":
        tail = _digits(rng, 5)
        return f"+49301234{tail}" if e164 else f"030 1234{tail}"
    pairs = [_digits(rng, 2) for _ in range(3)]
    return "+33199" + "".join(pairs) if e164 else "01 99 " + " ".join(pairs)


def _iban(rng: random.Random, params: Mapping[str, str]) -> str:
    country = params["country"].upper()
    bban = "".join(
        "".join(rng.choice(string.ascii_uppercase) for _ in range(count))
        if kind == "a"
        else _digits(rng, count)
        for kind, count in IBAN_BBAN[params["country"]]
    )
    iban = country + iban_check_digits(country, bban) + bban
    if params["format"] == "compact":
        return iban
    return " ".join(iban[i : i + 4] for i in range(0, len(iban), 4))


def _card(rng: random.Random, params: Mapping[str, str]) -> str:
    prefix, length, groups = CARDS[params["brand"]]
    payload = prefix + _digits(rng, length - len(prefix) - 1)
    number = payload + luhn_check_digit(payload)
    return number if params["format"] == "compact" else _grouped(number, groups)


def _tax_id_body(rng: random.Random) -> str:
    """The 10-digit body of a German tax ID (Steuer-ID), satisfying its structural rule.

    Exactly one digit appears two or three times (if three, not all three in a row), every
    other digit at most once, so some digits are absent; the first digit is not 0.
    """
    repeats = rng.choice((2, 3))
    repeated, *others = rng.sample(string.digits, 11 - repeats)
    digits = [repeated] * repeats + others
    while True:
        rng.shuffle(digits)
        body = "".join(digits)
        if body[0] != "0" and repeated * 3 not in body:
            return body


def _national_id(rng: random.Random, params: Mapping[str, str]) -> str:
    """US SSN, UK NINO or DE tax ID.

    SSNs avoid never-issued areas (000, 666, 900+) and zero groups/serials, so they are
    synthetic but may coincide with real issued numbers; reports store them as-is.
    """
    country, standard = params["country"], params["format"] == "standard"
    if country == "us":
        area = rng.choice([a for a in range(1, SSN_AREA_MAX + 1) if a != SSN_RESERVED_AREA])
        group, serial = rng.randint(1, 99), rng.randint(1, 9999)
        if standard:
            return f"{area:03d}-{group:02d}-{serial:04d}"
        return f"{area:03d}{group:02d}{serial:04d}"
    if country == "uk":
        while True:
            prefix = rng.choice(NINO_FIRST) + rng.choice(NINO_SECOND)
            if prefix not in NINO_EXCLUDED:
                break
        digits, suffix = _digits(rng, 6), rng.choice("ABCD")
        if standard:
            return f"{prefix} {digits[0:2]} {digits[2:4]} {digits[4:6]} {suffix}"
        return f"{prefix}{digits}{suffix}"
    body = _tax_id_body(rng)
    number = body + mod11_check_digit(body)
    return _grouped(number, (2, 3, 3, 3)) if standard else number


BUILTINS: dict[str, Builtin] = {
    "email": Builtin("email", _email, free={"domain": "example.org"}),
    "phone": Builtin(
        "phone",
        _phone,
        choices={"region": ("us", "uk", "de", "fr"), "format": ("e164", "national")},
    ),
    "iban": Builtin(
        "iban",
        _iban,
        choices={"country": ("de", "fr", "gb", "nl", "es"), "format": ("compact", "grouped")},
    ),
    "card": Builtin(
        "card",
        _card,
        choices={"brand": ("visa", "mastercard", "amex"), "format": ("compact", "grouped")},
    ),
    "national_id": Builtin(
        "national_id",
        _national_id,
        choices={"country": ("us", "uk", "de"), "format": ("standard", "compact")},
    ),
}
