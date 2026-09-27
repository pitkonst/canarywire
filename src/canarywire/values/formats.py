"""Generators for the supported JSON Schema `format` values."""

from __future__ import annotations

import datetime
import uuid
from typing import TYPE_CHECKING

from canarywire.values.builtins import WORDS

if TYPE_CHECKING:
    import random

FORMATS = ("email", "uuid", "date", "date-time", "ipv4", "ipv6")
FIRST_DAY = datetime.date(2000, 1, 1).toordinal()
LAST_DAY = datetime.date(2030, 12, 31).toordinal()


def generate_format(name: str, rng: random.Random) -> str:
    """A synthetic value for a JSON Schema format (documentation address ranges for IPs)."""
    if name == "email":
        return f"{rng.choice(WORDS)}.{rng.choice(WORDS)}{rng.randrange(10_000):04d}@example.org"
    if name == "uuid":
        return str(uuid.UUID(int=rng.getrandbits(128), version=4))
    day = datetime.date.fromordinal(rng.randint(FIRST_DAY, LAST_DAY))
    if name == "date":
        return day.isoformat()
    if name == "date-time":
        seconds = rng.randrange(86_400)
        hours, minutes, secs = seconds // 3600, seconds // 60 % 60, seconds % 60
        return f"{day.isoformat()}T{hours:02d}:{minutes:02d}:{secs:02d}Z"
    if name == "ipv4":
        return f"198.51.100.{rng.randint(1, 254)}"  # RFC 5737 TEST-NET-2
    return f"2001:db8:{rng.randrange(0x10000):x}::{rng.randrange(1, 0x10000):x}"  # RFC 3849
