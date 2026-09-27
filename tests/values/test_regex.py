# ruff: noqa: S311 - seeded random.Random is test data, not cryptographic use
import random
import re

import pytest

from canarywire.values.regex import PatternError, PatternGenerator

SUPPORTED = [
    r"^K-20[0-9]{2}-[0-9]{5}/[A-Z]{2}$",
    r"^4[0-9]{15}$",
    r"^(ab|cd)e$",
    r"^(?:x|yz){2}$",
    r"^\d{3}-\d{2}-\d{4}$",
    r"^[^a-z]{3}$",
    r"^.{2}$",
    r"^a?b*c+$",
    r"^x{2,}$",
    r"^x{2,4}?$",
    r"^\.[\w-]{5}\s\S$",
    r"^[\d_]{3}\D\W$",
    r"^\x41\u0042[\-\]]$",
    r"^a{b$",
    "^CUST-[0-9]{8}$",
    r"no-anchors-\d",
]


@pytest.mark.parametrize("pattern", SUPPORTED)
def test_generated_values_match(pattern: str) -> None:
    generator = PatternGenerator(pattern)
    for seed in range(200):
        value = generator(random.Random(seed))
        assert re.fullmatch(pattern, value, re.ASCII), (pattern, value)


def test_deterministic_per_seed() -> None:
    generator = PatternGenerator(r"^[A-Z]{4}\d{6}$")
    assert generator(random.Random(7)) == generator(random.Random(7))


def test_open_ended_repeats_are_capped() -> None:
    generator = PatternGenerator(r"^a*$")
    assert max(len(generator(random.Random(s))) for s in range(300)) <= 8


def test_negated_class_stays_printable_ascii() -> None:
    generator = PatternGenerator(r"^[^A-Za-z0-9]{50}$")
    value = generator(random.Random(1))
    assert all(0x20 <= ord(c) < 0x7F for c in value)


@pytest.mark.parametrize(
    ("pattern", "message"),
    [
        (r"^(?=a)a$", "lookahead is not supported"),
        (r"^(?!a)b$", "lookahead is not supported"),
        (r"^(?<=a)b$", "lookbehind is not supported"),
        (r"^(?<!a)b$", "lookbehind is not supported"),
        (r"^(?<n>a)$", "named group is not supported"),
        (r"^(?P<n>a)$", "named group is not supported"),
        (r"^(?i)a$", "inline flags is not supported"),
        (r"^(a)\1$", "backreferences are not supported"),
        (r"^\bword$", "word boundary is not supported"),
        (r"^\p{L}$", "Unicode property escape is not supported"),
        (r"^\q$", "escape \\q is not supported"),
        (r"^a^b$", "anchors are only supported at the start and end"),
        (r"^[]$", "empty character class"),
        (r"^(a$", "unbalanced parenthesis"),
        (r"^*a$", "nothing to repeat"),
        (r"^[z-a]$", "invalid character range"),
        (r"^[\d-z]$", "invalid character range"),
        (r"^a{3,1}$", "quantifier range is out of order"),
        (r"^\u00e9$", "only ASCII characters are supported"),
        (r"^[^\x20-\x7e]$", "character class matches nothing"),
    ],
)
def test_unsupported_constructs(pattern: str, message: str) -> None:
    with pytest.raises(PatternError, match=re.escape(message)):
        PatternGenerator(pattern)
