"""Where to cut a streamed text: pure, seeded cut positions for each fragmentation case."""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass
from itertools import pairwise
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

    from canarywire.config import FragmentationSettings

SEED_BYTES = 8


@dataclass(frozen=True)
class Case:
    """One fragmentation case: its report name and how it cuts."""

    name: str
    kind: str
    size: int = 0
    phase: int = 0


def expand_cases(settings: FragmentationSettings) -> list[Case]:
    """Every case the settings describe, in configuration order."""
    cases: list[Case] = []
    for kind in settings.cases:
        if kind == "baseline":
            cases.append(Case("baseline", "baseline"))
        elif kind == "chunks":
            for size in settings.chunks.sizes:
                phases = range(size) if settings.chunks.phases == "all" else range(1)
                cases.extend(
                    Case(f"chunks:{size}@{phase}", "chunks", size=size, phase=phase)
                    for phase in phases
                )
        elif kind == "random-chunks":
            samples = settings.random_chunks.samples
            cases.extend(Case(f"random-chunks#{i}", kind) for i in range(1, samples + 1))
        elif kind == "random-cuts":
            samples = settings.random_cuts.samples
            cases.extend(Case(f"random-cuts#{i}", kind) for i in range(1, samples + 1))
    return cases


def ordered_cases(settings: FragmentationSettings, seed: int) -> list[Case]:
    """Baseline first (the split cases' refusal rule depends on it), the rest in seeded order."""
    cases = expand_cases(settings)
    head = [case for case in cases if case.kind == "baseline"]
    rest = [case for case in cases if case.kind != "baseline"]
    case_rng(seed, "order").shuffle(rest)
    return head + rest


def case_rng(seed: int, name: str) -> random.Random:
    """A generator that depends only on the run seed and the case name."""
    digest = hashlib.sha256(f"{seed}:{name}".encode()).digest()
    return random.Random(  # noqa: S311 - seeded cut/delay choice, not security-relevant
        int.from_bytes(digest[:SEED_BYTES], "big")
    )


def cuts(length: int, case: Case, settings: FragmentationSettings, rng: random.Random) -> list[int]:
    """Sorted, unique cut positions strictly inside a text of `length` characters."""
    positions: list[int] = []
    if case.kind == "chunks":
        positions = list(range(case.phase, length, case.size))
    elif case.kind == "random-chunks":
        position = 0
        while True:
            position += rng.randint(
                settings.random_chunks.min_size, settings.random_chunks.max_size
            )
            if position >= length:
                break
            positions.append(position)
    elif case.kind == "random-cuts" and length > 1:
        count = rng.randint(1, min(settings.random_cuts.max_cuts, length - 1))
        positions = rng.sample(range(1, length), count)
    return sorted({p for p in positions if 0 < p < length})


def pieces(text: str, positions: Sequence[int]) -> list[str]:
    """Split `text` at `positions`."""
    bounds = [0, *positions, len(text)]
    return [text[start:end] for start, end in pairwise(bounds)]


def delays(count: int, settings: FragmentationSettings, rng: random.Random) -> list[int]:
    """Seeded delays in milliseconds, one per content event."""
    return [rng.randint(settings.delay.min_ms, settings.delay.max_ms) for _ in range(count)]
