"""Generator entry points used by the custom-type tests (synthetic values only)."""

import random
from collections.abc import Mapping
from typing import Any


def loyalty(rng: random.Random, params: Mapping[str, Any]) -> str:
    tier = params.get("tier", "std").upper()
    return f"LOY-{tier}-{rng.randrange(10**6):06d}"


def unseeded(rng: random.Random, params: Mapping[str, Any]) -> str:
    return f"X{random.random()}"  # noqa: S311 - deliberately ignores rng


def not_a_string(rng: random.Random, params: Mapping[str, Any]) -> object:
    return 42


def broken(rng: random.Random, params: Mapping[str, Any]) -> str:
    raise RuntimeError("boom")


def is_even_length(value: str) -> bool:
    return len(value) % 2 == 0


def raising_check(value: str) -> bool:
    raise RuntimeError("checksum boom")


NOT_CALLABLE = "nope"
