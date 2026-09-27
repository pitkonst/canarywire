"""Report evidence: excerpts, grouped findings and grouped trust problems."""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Sequence

CONTEXT = 40
CUT = "…"
_ONE_LINE = {"\n": "⏎", "\t": "⇥"}


@dataclass(frozen=True)
class Excerpt:
    """The text around a leaked value: `match` is the value as found."""

    before: str
    match: str
    after: str


def one_line(text: str) -> str:
    """Replace newlines, tabs and other control characters so the text stays on one line."""
    return "".join(
        _ONE_LINE.get(ch, "�" if unicodedata.category(ch) == "Cc" else ch) for ch in text
    )


def leak_excerpt(text: str, value: str) -> Excerpt:
    """Up to CONTEXT characters on each side of the first occurrence of `value` in `text`."""
    index = text.index(value)
    start = max(0, index - CONTEXT)
    end = min(len(text), index + len(value) + CONTEXT)
    before = (CUT if start > 0 else "") + text[start:index]
    after = text[index + len(value) : end] + (CUT if end < len(text) else "")
    return Excerpt(one_line(before), one_line(value), one_line(after))


def diff_excerpt(expected: str | None, actual: str | None) -> dict[str, str] | None:
    """The first differing character and up to CONTEXT characters on each side of it."""
    if expected is None or actual is None:
        return None
    index = next(
        (i for i, (a, b) in enumerate(zip(expected, actual, strict=False)) if a != b),
        min(len(expected), len(actual)),
    )
    start = max(0, index - CONTEXT)

    def cut(text: str) -> str:
        end = min(len(text), index + 1 + CONTEXT)
        return one_line(
            (CUT if start > 0 else "") + text[start:end] + (CUT if end < len(text) else "")
        )

    return {"expected": cut(expected), "actual": cut(actual)}


KIND_ORDER = {"leak": 0, "mangled": 1, "unrestored": 2, "altered": 2, "inconsistent": 3}


def route_of(attack: str) -> str | None:
    """The route of an attack name: the first `/` segment with `@`, after the `@`."""
    for segment in attack.split("/"):
        if "@" in segment:
            return segment.split("@", 1)[1]
    return None


def group_findings(
    leaks: list[dict[str, Any]],
    unrestored: list[dict[str, Any]],
    inconsistent: list[dict[str, Any]],
    duty: str,
    mangled: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Group leaks, unrestored/altered, inconsistent and mangled items by kind/template/location.

    A mangled item has no `canary`/`type` (the value never reached its slot), so it contributes
    only to `attacks`, never to `instances`/`types`.
    """
    unrestored_kind = "altered" if duty == "mask-only" else "unrestored"
    items = [
        *(("leak", item, item["canary"], item["location"]) for item in leaks),
        *((unrestored_kind, item, item["canary"], item["location"]) for item in unrestored),
        *(
            ("inconsistent", item, item["instance"], item["occurrences"][0]["path"])
            for item in inconsistent
        ),
        *(("mangled", item, None, item["location"]) for item in mangled),
    ]
    groups: dict[tuple[str, str, str | None, str], dict[str, Any]] = {}
    for kind, item, instance, where in items:
        key = (kind, item["template"], route_of(item["attack"]), where)
        group = groups.get(key)
        if group is None:
            group = groups[key] = {
                "kind": kind,
                "template": item["template"],
                "route": key[2],
                "location": where,
                "instances": [],
                "types": [],
                "attacks": [],
                "occurrences": 0,
                "leak_excerpt": item["excerpt"] if kind == "leak" else None,
                "diff_excerpt": item["excerpt"] if kind in (unrestored_kind, "mangled") else None,
                "placeholders": (
                    [
                        {"placeholder": o["placeholder"], "path": o["path"]}
                        for o in item["occurrences"]
                    ]
                    if kind == "inconsistent"
                    else []
                ),
            }
        if kind == "mangled":
            if item["attack"] not in group["attacks"]:
                group["attacks"].append(item["attack"])
        else:
            for name, value in (
                ("instances", instance),
                ("types", item["type"]),
                ("attacks", item["attack"]),
            ):
                if value not in group[name]:
                    group[name].append(value)
        group["occurrences"] += 1
    return sorted(groups.values(), key=lambda g: (KIND_ORDER[g["kind"]], -len(g["attacks"])))


def group_problems(entries: Sequence[tuple[str, bool, str | None]]) -> list[dict[str, Any]]:
    """Group trust problems by (reason, run_level); first-seen order."""
    groups: dict[tuple[str, bool], dict[str, Any]] = {}
    for reason, run_level, attack in entries:
        group = groups.setdefault(
            (reason, run_level),
            {"reason": reason, "run_level": run_level, "attacks": [], "count": 0},
        )
        if attack is not None:
            group["attacks"].append(attack)
        group["count"] += 1
    return list(groups.values())
