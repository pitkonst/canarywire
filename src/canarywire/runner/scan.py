"""Find canary values in upstream requests."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import unquote_plus

from canarywire.report.findings import Excerpt, leak_excerpt
from canarywire.runner.jsonpath import JSON_NODE, iter_strings, location

if TYPE_CHECKING:
    from collections.abc import Sequence

    from canarywire.canaries import Canary
    from canarywire.runner.jsonpath import JsonPath
    from canarywire.runner.messages import UpstreamRequest


@dataclass(frozen=True)
class Hit:
    """A canary value found in an upstream request."""

    canary: str
    value: str
    location: str
    template: str = ""
    type: str = ""
    excerpt: Excerpt | None = None


def scan(canaries: Sequence[Canary], request: UpstreamRequest) -> list[Hit]:
    r"""Find every canary in the URL, header values and body of an upstream request.

    JSON bodies are reported per string path; a canary in a JSON key (at any depth) is
    reported at the containing object's location plus `{key}`. A value present in the raw
    body but in no string value and no key is reported at `body`. Strings that hold a JSON
    object or array are decoded too, so a value escaped inside them (`Jürgen`) is still
    found, at a `$` path, whether in a string value or a key; a value already visible in
    the encoded string is reported there only.
    """
    url = request.path + (f"?{request.query}" if request.query else "")
    strings = [] if request.json is None else _strings(request.json)
    keys = [] if request.json is None else _keys(request.json)
    hits: list[Hit] = []
    for canary in canaries:
        value = canary.value
        if value in url or value in unquote_plus(url):
            source = url if value in url else unquote_plus(url)
            hits.append(
                Hit(
                    canary.name,
                    value,
                    "url",
                    canary.template,
                    canary.type,
                    leak_excerpt(source, value),
                )
            )
        hits.extend(
            Hit(
                canary.name,
                value,
                f"headers.{name}",
                canary.template,
                canary.type,
                leak_excerpt(header, value),
            )
            for name, header in request.headers
            if value in header
        )
        body_hits = [
            Hit(
                canary.name,
                value,
                location("body", _sanitize(path, value)),
                canary.template,
                canary.type,
                leak_excerpt(text, value),
            )
            for path, text, encoded in strings
            if value in text and (encoded is None or value not in encoded)
        ]
        key_hits: list[Hit] = []
        seen_locations: set[str] = set()
        for path, key, encoded in keys:
            if value not in key or (encoded is not None and value in encoded):
                continue
            key_location = location("body", _sanitize(path, value)) + "{key}"
            if key_location in seen_locations:  # two keys of one object both leak: one hit
                continue
            seen_locations.add(key_location)
            key_hits.append(
                Hit(
                    canary.name,
                    value,
                    key_location,
                    canary.template,
                    canary.type,
                    leak_excerpt(key, value),
                )
            )
        if not body_hits and not key_hits and value in request.body:
            body_hits = [
                Hit(
                    canary.name,
                    value,
                    "body",
                    canary.template,
                    canary.type,
                    leak_excerpt(request.body, value),
                )
            ]
        hits.extend(body_hits)
        hits.extend(key_hits)
    return hits


def _sanitize(path: JsonPath, value: str) -> JsonPath:
    """Blank out any path segment (an ancestor object's own key) that itself holds `value`.

    Otherwise a key that is itself a canary (or holds one) would leak the value into the
    *location* of a hit found underneath it, e.g. a child key or a nested string value.
    """
    return tuple(
        "{key}" if isinstance(part, str) and part != JSON_NODE and value in part else part
        for part in path
    )


def _strings(
    doc: Any, path: JsonPath = (), encoded: str | None = None
) -> list[tuple[JsonPath, str, str | None]]:
    """Every string with its path, plus the strings inside JSON-holding strings.

    Each decoded string carries the encoded string it came from, so a value visible there
    is not reported twice.
    """
    found: list[tuple[JsonPath, str, str | None]] = []
    for inner, text in iter_strings(doc, path):
        found.append((inner, text, encoded))
        if text.lstrip()[:1] in ("{", "["):
            try:
                decoded = json.loads(text)
            except (ValueError, RecursionError):
                continue
            if isinstance(decoded, (dict, list)):
                found += _strings(decoded, (*inner, JSON_NODE), text)
    return found


def _keys(
    doc: Any, path: JsonPath = (), encoded: str | None = None
) -> list[tuple[JsonPath, str, str | None]]:
    """Every dict key with the path to its containing object, at every depth.

    Includes keys of objects nested inside JSON-holding strings, decoded the same way
    `_strings` does; each decoded key carries the encoded string it came from, so a key
    whose value is already visible there is not reported twice.
    """
    found: list[tuple[JsonPath, str, str | None]] = []

    def walk(node: Any, at: JsonPath) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                found.append((at, key, encoded))
                walk(value, (*at, key))
        elif isinstance(node, list):
            for index, item in enumerate(node):
                walk(item, (*at, index))
        elif isinstance(node, str) and node.lstrip()[:1] in ("{", "["):
            try:
                decoded = json.loads(node)
            except (ValueError, RecursionError):
                return
            if isinstance(decoded, (dict, list)):
                found.extend(_keys(decoded, (*at, JSON_NODE), node))

    walk(doc, path)
    return found
