"""`docs/guide/canarywire.yaml` stays in sync with the config parser.

Three things are checked:
- Loading the reference file (as shipped, `#>` examples still commented out) yields exactly the
  built-in defaults.
- With every `#>` example uncommented, the file still parses.
- Every key the parser accepts appears somewhere in the file (as a live default or a `#>`
  example), and the file names no key the parser doesn't accept — in both directions.

See the reference file's header comment for the `#>` marker convention.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
import yaml

from canarywire import config
from canarywire.values import types as canary_types

if TYPE_CHECKING:
    from collections.abc import Iterable

REFERENCE = Path(__file__).parents[1] / "docs" / "guide" / "canarywire.yaml"

# Sentinels for the two config.py sections whose fixed key set isn't (fully) checked here:
# `canary_types` entries are checked against canarywire.values.types's own constants instead
# (below), and `templates` content is a template, not a config.py `_mapping` key set.
_CANARY_TYPES = object()
_OPAQUE = object()


def _leaf_map(keys: Iterable[str]) -> dict[str, object]:
    return dict.fromkeys(keys)


_ROUTE = _leaf_map(config.ROUTE_KEYS)
_TARGET = {**_leaf_map(config.TARGET_KEYS - {"routes"}), "routes": [_ROUTE]}
_CHUNKS = _leaf_map(config.CHUNKS_KEYS)
_RANDOM_CHUNKS = _leaf_map(config.RANDOM_CHUNKS_KEYS)
_RANDOM_CUTS = _leaf_map(config.RANDOM_CUTS_KEYS)
_DELAY_MS = _leaf_map(config.DELAY_KEYS)
_FRAGMENTATION = {
    **_leaf_map(config.FRAGMENTATION_KEYS - {"chunks", "random_chunks", "random_cuts", "delay_ms"}),
    "chunks": _CHUNKS,
    "random_chunks": _RANDOM_CHUNKS,
    "random_cuts": _RANDOM_CUTS,
    "delay_ms": _DELAY_MS,
}
_GENERATORS = {
    "baseline": _leaf_map(config.BASELINE_KEYS),
    "fragmentation": _FRAGMENTATION,
    "fault": _leaf_map(config.FAULT_SETTINGS_KEYS),
}
_FAULT = _leaf_map(config.FAULT_KEYS)
_OUTPUT = _leaf_map(config.OUTPUT_KEYS)
_REPORT = {**_leaf_map(config.REPORT_KEYS - {"outputs"}), "outputs": [_OUTPUT]}

ROOT_SCHEMA: dict[str, object] = {
    "seed": None,
    "capture": _leaf_map(config.CAPTURE_KEYS),
    "target": _TARGET,
    "timeouts": _leaf_map(config.TIMEOUT_KEYS),
    "generators": _GENERATORS,
    "canary_types": _CANARY_TYPES,
    "templates": _OPAQUE,
    "faults": [_FAULT],
    "report": _REPORT,
}

# Keeps the schema above honest: every branch is derived from a config.py constant, but the
# *set of top-level/generators keys itself* is asserted against the same constants here so a
# new key added to one but not the other fails loudly.
assert set(ROOT_SCHEMA) == config.DOC_KEYS
assert set(_GENERATORS) == config.GENERATORS_KEYS


def _uncomment(text: str) -> str:
    """Strip the leading `#>` marker from every commented-out example line."""
    return "\n".join(line[2:] if line.startswith("#>") else line for line in text.splitlines())


def _walk(schema: object, data: object, path: str) -> None:
    if schema is None:
        return
    if schema is _OPAQUE:
        assert isinstance(data, dict), f"{path}: expected a mapping"
        return
    if schema is _CANARY_TYPES:
        _walk_canary_types(data, path)
        return
    if isinstance(schema, list):
        _walk_list(schema[0], data, path)
        return
    assert isinstance(schema, dict), f"{path}: schema bug: {schema!r}"
    assert isinstance(data, dict), f"{path}: expected a mapping, got {data!r}"
    missing = set(schema) - set(data)
    extra = set(data) - set(schema)
    assert not missing, f"{path}: reference file is missing key(s) {sorted(missing)}"
    assert not extra, f"{path}: key(s) the parser doesn't accept: {sorted(extra)}"
    for key, subschema in schema.items():
        _walk(subschema, data[key], f"{path}.{key}" if path else key)


def _walk_list(item_schema: object, data: object, path: str) -> None:
    """Check a list of items against a flat item schema, aggregating coverage across items.

    Not every item needs every optional key (a route's `name`, a fault's `settle_ms`, an
    output's `escape`) — coverage only needs the *union* of the example items to reach every
    key the item schema allows.
    """
    assert isinstance(data, list), f"{path}: expected a list"
    assert data, f"{path}: expected a non-empty example list"
    assert isinstance(item_schema, dict), f"{path}: schema bug: {item_schema!r}"
    seen: set[str] = set()
    for index, item in enumerate(data):
        assert isinstance(item, dict), f"{path}[{index}]: expected a mapping"
        extra = set(item) - set(item_schema)
        assert not extra, f"{path}[{index}]: key(s) the parser doesn't accept: {sorted(extra)}"
        seen |= set(item)
        for key in item:
            _walk(item_schema[key], item[key], f"{path}[{index}].{key}")
    missing = set(item_schema) - seen
    assert not missing, f"{path}[]: examples together don't cover {sorted(missing)}"


def _walk_canary_types(data: object, path: str) -> None:
    assert isinstance(data, dict), f"{path}: expected a mapping"
    assert data, f"{path}: expected at least one example entry"
    seen_type_keys: set[str] = set()
    seen_schema_keys: set[str] = set()
    for name, spec in data.items():
        where = f"{path}.{name}"
        assert isinstance(spec, dict), f"{where}: expected a mapping"
        seen_type_keys |= set(spec)
        extra = set(spec) - canary_types.CUSTOM_TYPE_KEYS
        assert not extra, f"{where}: key(s) the parser doesn't accept: {sorted(extra)}"
        if "schema" in spec:
            sub = spec["schema"]
            assert isinstance(sub, dict), f"{where}.schema: expected a mapping"
            seen_schema_keys |= set(sub)
            extra_schema = set(sub) - canary_types.SCHEMA_KEYS
            assert not extra_schema, f"{where}.schema: key(s) not accepted: {sorted(extra_schema)}"
    missing_types = canary_types.CUSTOM_TYPE_KEYS - seen_type_keys
    assert not missing_types, f"{path}: examples don't cover {sorted(missing_types)}"
    missing_schema = canary_types.SCHEMA_KEYS - seen_schema_keys
    assert not missing_schema, f"{path}.schema: examples don't cover {sorted(missing_schema)}"


@pytest.mark.real_delays
def test_reference_file_matches_built_in_defaults() -> None:
    """Loading the shipped file (examples still commented out) is exactly `Config()`."""
    loaded = config.load(REFERENCE)
    assert replace(loaded, config_dir=None, config_sha256=None) == config.Config()


def test_reference_file_with_examples_uncommented_parses() -> None:
    uncommented = yaml.safe_load(_uncomment(REFERENCE.read_text()))
    config.parse(uncommented)  # must not raise


def test_reference_file_covers_every_accepted_key() -> None:
    uncommented = yaml.safe_load(_uncomment(REFERENCE.read_text()))
    _walk(ROOT_SCHEMA, uncommented, "")
