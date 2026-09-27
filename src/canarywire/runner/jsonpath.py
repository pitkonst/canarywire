"""JSON path helpers: iterate strings, read values, format locations for reports."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterator

JsonPath = tuple[str | int, ...]
JSON_NODE = "$json"


def format_path(path: JsonPath) -> str:
    """Render a JSON path as `messages[0].content`; a `$json` step renders as `$`."""
    text = ""
    for part in path:
        if part == JSON_NODE:
            text += "$"
        elif isinstance(part, int):
            text += f"[{part}]"
        else:
            text += f".{part}" if text else part
    return text


def location(prefix: str, path: JsonPath) -> str:
    """Prefix a JSON path for reports: `body.messages[0].content`, or `body` for the root."""
    rendered = format_path(path)
    if not rendered:
        return prefix
    return f"{prefix}{rendered}" if rendered.startswith("[") else f"{prefix}.{rendered}"


def iter_strings(doc: Any, path: JsonPath = ()) -> Iterator[tuple[JsonPath, str]]:
    """Yield every string value in document order (depth-first, keys in insertion order)."""
    if isinstance(doc, str):
        yield path, doc
    elif isinstance(doc, list):
        for index, item in enumerate(doc):
            yield from iter_strings(item, (*path, index))
    elif isinstance(doc, dict):
        for key, value in doc.items():
            yield from iter_strings(value, (*path, key))


def get_path(doc: Any, path: JsonPath) -> Any:
    """Return the value at path, or None if any step is missing.

    A `$json` step decodes a JSON string (or enters a template's `$json` node).
    """
    current = doc
    for part in path:
        if part == JSON_NODE:
            ok, current = decode_json(current)
            if not ok:
                return None
        elif isinstance(part, int):
            if not isinstance(current, list) or part >= len(current):
                return None
            current = current[part]
        elif not isinstance(current, dict) or part not in current:
            return None
        else:
            current = current[part]
    return current


def is_json_node(value: Any) -> bool:
    """A template's `{$json: …}` node: a mapping whose only key is `$json`."""
    return isinstance(value, dict) and len(value) == 1 and JSON_NODE in value


def decode_json(value: Any) -> tuple[bool, Any]:
    """`(True, parsed)` for a JSON string or a template node's value, else `(False, None)`."""
    if is_json_node(value):
        return True, value[JSON_NODE]
    if isinstance(value, str):
        try:
            return True, json.loads(value)
        except (ValueError, RecursionError):
            return False, None
    return False, None


def json_equal(a: Any, b: Any) -> bool:
    """Equality of parsed JSON: numbers by value; booleans and null only equal themselves."""
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b) and a == b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(json_equal(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(json_equal(x, y) for x, y in zip(a, b, strict=True))
    return type(a) is type(b) and a == b
