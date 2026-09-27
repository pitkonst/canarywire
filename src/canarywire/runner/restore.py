"""Restore check: compare the client response with the expected one, slot by slot.

Strings outside `$json` nodes compare exactly. A `$json` node's string is parsed: its slots
compare after parsing (key order and whitespace do not matter), and a difference outside the
slots, or a string that does not parse, fails every slot of that node at the node's path.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from canarywire.runner.catalog import json_nodes, slotted_strings
from canarywire.runner.jsonpath import JSON_NODE, decode_json, get_path, json_equal, location

if TYPE_CHECKING:
    from collections.abc import Collection

    from canarywire.runner.jsonpath import JsonPath


@dataclass(frozen=True)
class Mismatch:
    """One failed check: the instances it covers, where, and what was expected and seen."""

    names: tuple[str, ...]
    location: str
    expected: str | None
    actual: str | None
    note: str | None = None


@dataclass(frozen=True)
class Comparison:
    """How many instance checks passed, and the ones that did not."""

    restored: int
    mismatches: list[Mismatch]


def compare_response(template_response: Any, expected_doc: Any, actual_doc: Any) -> Comparison:
    """Compare every slotted string of the response template; see the module docstring."""
    slots = slotted_strings(template_response)
    nodes = json_nodes(template_response)
    slot_paths = {path for path, _ in slots}
    failed: dict[JsonPath, str | None] = {}  # node path -> note, for nodes that fail whole
    for node in nodes:
        if any(_inside(node, outer) for outer in failed):
            continue
        ok, parsed = decode_json(get_path(actual_doc, node))
        if not ok or not isinstance(get_path(actual_doc, node), str):
            failed[node] = None
            continue
        if any(_inside(node, other) for other in nodes if other != node):
            continue  # nested nodes are checked as part of their outermost node
        difference = _first_difference(
            get_path(expected_doc, (*node, JSON_NODE)),
            parsed,
            (*node, JSON_NODE),
            slot_paths,
            set(nodes),
        )
        if difference is not None:
            owner = max((n for n in nodes if _inside(difference, n) or difference == n), key=len)
            failed[owner] = f"JSON differs outside slots at {location('body', difference)}"
    restored = 0
    mismatches: list[Mismatch] = []
    for node, note in failed.items():
        covered = tuple(dict.fromkeys(n for path, ns in slots if _inside(path, node) for n in ns))
        mismatches.append(
            Mismatch(
                covered,
                location("body", node),
                _text(get_path(expected_doc, node)),
                _text(get_path(actual_doc, node)),
                note,
            )
        )
    for path, names in slots:
        if any(_inside(path, node) for node in failed):
            continue
        expected, got = get_path(expected_doc, path), get_path(actual_doc, path)
        if got == expected:
            restored += len(names)
        else:
            mismatches.append(Mismatch(tuple(names), location("body", path), expected, _text(got)))
    return Comparison(restored, mismatches)


def _inside(path: JsonPath, node: JsonPath) -> bool:
    """Whether `path` lies inside the `$json` node at `node`."""
    return len(path) > len(node) and path[: len(node)] == node and path[len(node)] == JSON_NODE


def _first_difference(  # noqa: PLR0911 - one rule per JSON kind
    expected: Any,
    actual: Any,
    path: JsonPath,
    ignore: Collection[JsonPath],
    nodes: Collection[JsonPath],
) -> JsonPath | None:
    if path in ignore:
        return None
    if path in nodes:
        ok, parsed = decode_json(actual) if isinstance(actual, str) else (False, None)
        if not ok:
            return path
        return _first_difference(
            decode_json(expected)[1], parsed, (*path, JSON_NODE), ignore, nodes
        )
    if isinstance(expected, dict):
        if not isinstance(actual, dict) or expected.keys() != actual.keys():
            return path
        for key, value in expected.items():
            found = _first_difference(value, actual[key], (*path, key), ignore, nodes)
            if found is not None:
                return found
        return None
    if isinstance(expected, list):
        if not isinstance(actual, list) or len(expected) != len(actual):
            return path
        for index, (e, a) in enumerate(zip(expected, actual, strict=True)):
            found = _first_difference(e, a, (*path, index), ignore, nodes)
            if found is not None:
                return found
        return None
    return None if json_equal(expected, actual) else path


def _text(value: Any) -> str | None:
    if value is None or isinstance(value, str):
        return value
    return json.dumps(value)
