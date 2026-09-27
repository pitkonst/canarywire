# ruff: noqa: S311 - seeded random.Random is test data, not cryptographic use
import random
from collections import Counter

from canarywire.config import (
    ChunksSettings,
    DelaySettings,
    FragmentationSettings,
    RandomChunksSettings,
    RandomCutsSettings,
)
from canarywire.runner.splits import (
    Case,
    case_rng,
    cuts,
    delays,
    expand_cases,
    ordered_cases,
    pieces,
)

SETTINGS = FragmentationSettings()


def chunk_case(size: int, phase: int) -> Case:
    return Case(f"chunks:{size}@{phase}", "chunks", size=size, phase=phase)


def test_default_cases() -> None:
    assert [case.name for case in expand_cases(SETTINGS)] == [
        "baseline",
        "chunks:1@0",
        "chunks:2@0",
        "chunks:2@1",
        "chunks:4@0",
        "chunks:4@1",
        "chunks:4@2",
        "chunks:4@3",
        "random-chunks#1",
        "random-chunks#2",
        "random-chunks#3",
        "random-chunks#4",
        "random-cuts#1",
        "random-cuts#2",
        "random-cuts#3",
        "random-cuts#4",
    ]


def test_first_phase_only() -> None:
    settings = FragmentationSettings(
        cases=("baseline", "chunks"), chunks=ChunksSettings(sizes=(1, 2, 4), phases="first")
    )
    assert [c.name for c in expand_cases(settings)] == [
        "baseline",
        "chunks:1@0",
        "chunks:2@0",
        "chunks:4@0",
    ]


def test_ordered_cases_baseline_first_and_deterministic() -> None:
    first = ordered_cases(SETTINGS, seed=7)
    assert first[0].name == "baseline"
    assert first == ordered_cases(SETTINGS, seed=7)
    assert sorted(c.name for c in first) == sorted(c.name for c in expand_cases(SETTINGS))


def test_baseline_has_no_cuts() -> None:
    assert cuts(10, Case("baseline", "baseline"), SETTINGS, random.Random(0)) == []


def test_every_inner_offset_is_cut_exactly_once_across_phases() -> None:
    for size in range(2, 7):
        seen: Counter[int] = Counter()
        for phase in range(size):
            seen.update(cuts(20, chunk_case(size, phase), SETTINGS, random.Random(0)))
        assert seen == Counter(range(1, 20)), size


def test_size_one_is_one_character_per_piece() -> None:
    positions = cuts(5, chunk_case(1, 0), SETTINGS, random.Random(0))
    assert pieces("abcde", positions) == ["a", "b", "c", "d", "e"]


def test_phase_shortens_first_chunk() -> None:
    assert pieces("abcdefg", cuts(7, chunk_case(3, 1), SETTINGS, random.Random(0))) == [
        "a",
        "bcd",
        "efg",
    ]


def test_random_chunks_respect_bounds() -> None:
    settings = FragmentationSettings(
        random_chunks=RandomChunksSettings(samples=1, min_size=2, max_size=3)
    )
    for seed in range(50):
        parts = pieces(
            "x" * 40,
            cuts(40, Case("random-chunks#1", "random-chunks"), settings, random.Random(seed)),
        )
        assert "".join(parts) == "x" * 40
        assert all(2 <= len(part) <= 3 for part in parts[:-1])
        assert 1 <= len(parts[-1]) <= 3


def test_random_cuts_respect_bounds() -> None:
    settings = FragmentationSettings(random_cuts=RandomCutsSettings(samples=1, max_cuts=3))
    for seed in range(50):
        positions = cuts(10, Case("random-cuts#1", "random-cuts"), settings, random.Random(seed))
        assert 1 <= len(positions) <= 3
        assert positions == sorted(set(positions))
        assert all(0 < p < 10 for p in positions)


def test_short_text_never_crashes() -> None:
    for case in expand_cases(SETTINGS):
        assert cuts(1, case, SETTINGS, random.Random(0)) == []


def test_case_rng_is_per_seed_and_name() -> None:
    assert case_rng(1, "a").random() == case_rng(1, "a").random()
    assert case_rng(1, "a").random() != case_rng(1, "b").random()


def test_delays_within_bounds() -> None:
    settings = FragmentationSettings(delay=DelaySettings(min_ms=2, max_ms=4))
    values = delays(100, settings, random.Random(0))
    assert len(values) == 100
    assert all(2 <= v <= 4 for v in values)
