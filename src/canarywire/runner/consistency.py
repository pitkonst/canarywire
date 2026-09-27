"""Placeholder consistency: one instance, one placeholder; two instances, two placeholders."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

    from canarywire.runner.catalog import Occurrence
    from canarywire.runner.prepare import BoundTemplate


@dataclass(frozen=True)
class Seen:
    """Where an instance was seen upstream and the placeholder it had there."""

    path: str
    placeholder: str


@dataclass(frozen=True)
class Inconsistent:
    """An instance the gateway masked to more than one placeholder."""

    template: str
    instance: str
    type: str
    occurrences: tuple[Seen, ...]


def inconsistencies(occurrences: Sequence[Occurrence], bound: BoundTemplate) -> list[Inconsistent]:
    """Instances with more than one distinct placeholder, unless the template says `ignore`."""
    if bound.template.consistency == "ignore":
        return []
    types = {canary.name: canary.type for canary in bound.canaries}
    by_instance: dict[str, list[Occurrence]] = {}
    for occurrence in occurrences:
        by_instance.setdefault(occurrence.instance, []).append(occurrence)
    return [
        Inconsistent(
            bound.name,
            name,
            types[name],  # occurrences only name request-used, hence bound, instances
            tuple(Seen(o.location, o.placeholder) for o in seen),
        )
        for name, seen in by_instance.items()
        if len({o.placeholder for o in seen}) > 1
    ]


def collision_notes(occurrences: Sequence[Occurrence]) -> dict[str, str]:
    """A note for every instance that shared a placeholder with another instance."""
    by_placeholder: dict[str, set[str]] = {}
    for occurrence in occurrences:
        by_placeholder.setdefault(occurrence.placeholder, set()).add(occurrence.instance)
    notes: dict[str, str] = {}
    for placeholder, names in by_placeholder.items():
        if len(names) < 2:  # noqa: PLR2004 - a collision needs two instances
            continue
        text = (
            f"instances {', '.join(sorted(names))} were masked to the same placeholder "
            f"{placeholder}"
        )
        for name in sorted(names):
            notes[name] = add_note(notes.get(name), text) or text
    return notes


def add_note(existing: str | None, new: str | None) -> str | None:
    """Join two optional notes with `"; "`."""
    if existing and new:
        return f"{existing}; {new}"
    return existing or new
