"""Canary types — built-in or custom — resolved to a value source for one template instance."""

from __future__ import annotations

import copy
import importlib
import random
import re
import types
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from canarywire.values.builtins import BUILTINS
from canarywire.values.checksums import CHECKSUMS
from canarywire.values.errors import CanaryTypeError
from canarywire.values.formats import FORMATS, generate_format
from canarywire.values.regex import PatternError, PatternGenerator

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

MAX_ATTEMPTS = 1000
KINDS = ("values", "schema", "generator")
NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")
CHECKSUM_HINT = "expected one of luhn, mod97, mod11 or package.module:function"

# Accepted keys under one canary_types.<name> entry and its `schema` sub-mapping, exposed as
# constants so tests can check coverage against them without duplicating the literals.
CUSTOM_TYPE_KEYS = frozenset({*KINDS, "checksum"})
SCHEMA_KEYS = frozenset({"type", "pattern", "format"})


@dataclass(frozen=True)
class CustomType:
    """A custom canary type from `canary_types` in the config."""

    name: str
    values: tuple[str, ...] | None = None
    pattern: str | None = None
    value_format: str | None = None
    generator: str | None = None
    checksum: str | None = None


@dataclass(frozen=True)
class Source:
    """How one instance gets its value: a pool to draw from, or a seeded draw."""

    type_name: str
    pool: tuple[str, ...] | None = None
    draw: Callable[[random.Random], str] | None = None


def parse_custom_types(raw: object, path: str = "canary_types") -> dict[str, CustomType]:
    """Validate the `canary_types` mapping; errors start with the key path."""
    if not isinstance(raw, dict):
        raise CanaryTypeError(f"{path}: expected a mapping")
    types: dict[str, CustomType] = {}
    for name, spec in raw.items():
        where = f"{path}.{name}"
        if not isinstance(name, str) or not NAME.fullmatch(name):
            raise CanaryTypeError(f"{where}: expected a name like customer_id")
        if name in BUILTINS:
            raise CanaryTypeError(f"{where}: is a built-in type name")
        types[name] = _parse_custom(name, spec, where)
    return types


def _parse_custom(name: str, spec: object, where: str) -> CustomType:
    if not isinstance(spec, dict):
        raise CanaryTypeError(f"{where}: expected a mapping")
    for key in spec:
        if key not in CUSTOM_TYPE_KEYS:
            raise CanaryTypeError(f"{where}.{key}: unknown key")
    kinds = [kind for kind in KINDS if kind in spec]
    if len(kinds) != 1:
        raise CanaryTypeError(f"{where}: expected exactly one of values, schema, generator")
    checksum: str | None = None
    if "checksum" in spec:
        checksum = spec["checksum"]
        if not isinstance(checksum, str) or (
            checksum not in CHECKSUMS and not _is_entry_point(checksum)
        ):
            raise CanaryTypeError(f"{where}.checksum: {CHECKSUM_HINT}, got {checksum!r}")
    kind = kinds[0]
    if kind == "values":
        values = spec["values"]
        if (
            not isinstance(values, list)
            or not values
            or not all(isinstance(v, str) and v for v in values)
        ):
            raise CanaryTypeError(f"{where}.values: expected a non-empty list of non-empty strings")
        if len(set(values)) != len(values):
            raise CanaryTypeError(f"{where}.values: duplicate values")
        if checksum in CHECKSUMS:  # entry-point checksums are checked in make_source
            _check_pool(tuple(values), CHECKSUMS[checksum], checksum, where)
        return CustomType(name, values=tuple(values), checksum=checksum)
    if kind == "schema":
        return _parse_schema(name, spec["schema"], f"{where}.schema", checksum)
    generator = spec["generator"]
    if not isinstance(generator, str) or not _is_entry_point(generator):
        raise CanaryTypeError(
            f"{where}.generator: expected package.module:function, got {generator!r}"
        )
    return CustomType(name, generator=generator, checksum=checksum)


def _parse_schema(name: str, schema: object, where: str, checksum: str | None) -> CustomType:
    if not isinstance(schema, dict):
        raise CanaryTypeError(f"{where}: expected a mapping")
    for key in schema:
        if key not in SCHEMA_KEYS:
            raise CanaryTypeError(f"{where}.{key}: unknown key")
    if schema.get("type") != "string":
        raise CanaryTypeError(f"{where}.type: expected string")
    if ("pattern" in schema) == ("format" in schema):
        raise CanaryTypeError(f"{where}: expected exactly one of pattern, format")
    if "pattern" in schema:
        pattern = schema["pattern"]
        if not isinstance(pattern, str):
            raise CanaryTypeError(f"{where}.pattern: expected a string")
        try:
            PatternGenerator(pattern)
        except PatternError as exc:
            raise CanaryTypeError(f"{where}.pattern: {exc}") from exc
        return CustomType(name, pattern=pattern, checksum=checksum)
    value_format = schema["format"]
    if value_format not in FORMATS:
        raise CanaryTypeError(f"{where}.format: expected one of {', '.join(FORMATS)}")
    return CustomType(name, value_format=value_format, checksum=checksum)


def _is_entry_point(ref: str) -> bool:
    module_name, separator, attribute = ref.partition(":")
    return bool(separator and module_name and attribute)


def _check_pool(
    values: tuple[str, ...], check: Callable[[str], bool], checksum: str, where: str
) -> None:
    try:
        failing = [v for v in values if not check(v)]
    except CanaryTypeError as exc:
        raise CanaryTypeError(f"{where}.checksum: {exc}") from exc
    if failing:
        raise CanaryTypeError(f"{where}.values: entries failing {checksum}: {', '.join(failing)}")


def load_entry_point(ref: str) -> Callable[..., Any]:
    """Import `package.module:function`; raise CanaryTypeError if it is not a callable."""
    module_name, separator, attribute = ref.partition(":")
    if not separator or not module_name or not attribute:
        raise CanaryTypeError(f"expected package.module:function, got {ref!r}")
    try:
        target = getattr(importlib.import_module(module_name), attribute)
    except Exception as exc:
        raise CanaryTypeError(f"cannot load {ref}: {exc!r}") from exc
    if not callable(target):
        raise CanaryTypeError(f"{ref} is not callable")
    return target  # type: ignore[no-any-return]


def make_source(
    type_name: str, params: Mapping[str, Any], custom: Mapping[str, CustomType]
) -> Source:
    """Resolve a type and its parameters to a value source; raise CanaryTypeError if invalid.

    This is where user entry points (generator, checksum) are imported and the generator's
    determinism is probed — only when a run prepares its values, never when a config is parsed.
    """
    if type_name in BUILTINS:
        builtin = BUILTINS[type_name]
        resolved = builtin.resolve(params)

        def builtin_draw(rng: random.Random) -> str:
            return builtin.make(rng, resolved)

        return Source(type_name, draw=builtin_draw)
    spec = custom.get(type_name)
    if spec is None:
        raise CanaryTypeError(f"unknown type {type_name!r}")
    if params and spec.generator is None:
        raise CanaryTypeError(f"type {type_name} takes no parameters")
    where = f"canary_types.{type_name}"
    if spec.values is not None:
        if spec.checksum is not None and spec.checksum not in CHECKSUMS:
            _check_pool(spec.values, _loaded_checksum(spec.checksum, where), spec.checksum, where)
        return Source(type_name, pool=spec.values)
    draw: Callable[[random.Random], str]
    if spec.pattern is not None:
        draw = PatternGenerator(spec.pattern)
    elif spec.value_format is not None:
        value_format = spec.value_format

        def format_draw(rng: random.Random) -> str:
            return generate_format(value_format, rng)

        draw = format_draw
    else:
        draw = _generator_draw(spec, params, where)
    if spec.checksum is not None:
        draw = _with_checksum(draw, _loaded_checksum(spec.checksum, where), spec)
    return Source(type_name, draw=draw)


def _loaded_checksum(ref: str, where: str) -> Callable[[str], bool]:
    try:
        return _checksum(ref)
    except CanaryTypeError as exc:
        raise CanaryTypeError(f"{where}.checksum: {exc}") from exc


def _checksum(ref: str) -> Callable[[str], bool]:
    if ref in CHECKSUMS:
        return CHECKSUMS[ref]
    if _is_entry_point(ref):
        target = load_entry_point(ref)

        def check(value: str) -> bool:
            try:
                return bool(target(value))
            except Exception as exc:
                raise CanaryTypeError(f"checksum {ref} failed: {exc!r}") from exc

        return check
    raise CanaryTypeError(f"{CHECKSUM_HINT}, got {ref!r}")


def _generator_draw(
    spec: CustomType, params: Mapping[str, Any], where: str
) -> Callable[[random.Random], str]:
    ref = spec.generator or ""
    try:
        target = load_entry_point(ref)
    except CanaryTypeError as exc:
        raise CanaryTypeError(f"{where}.generator: {exc}") from exc
    frozen = types.MappingProxyType(copy.deepcopy(dict(params)))

    def draw(rng: random.Random) -> str:
        try:
            value = target(rng, frozen)
        except Exception as exc:
            raise CanaryTypeError(f"generator {ref} failed: {exc!r}") from exc
        if not isinstance(value, str) or not value:
            raise CanaryTypeError(f"generator {ref} must return a non-empty string, got {value!r}")
        return value

    probe_seed = 0
    first = draw(random.Random(probe_seed))  # noqa: S311 - determinism probe, not security
    second = draw(random.Random(probe_seed))  # noqa: S311 - determinism probe, not security
    if first != second:
        raise CanaryTypeError(f"generator {ref} is not deterministic for a seed")
    return draw


def _with_checksum(
    draw: Callable[[random.Random], str], check: Callable[[str], bool], spec: CustomType
) -> Callable[[random.Random], str]:
    def checked(rng: random.Random) -> str:
        for _ in range(MAX_ATTEMPTS):
            value = draw(rng)
            if check(value):
                return value
        raise CanaryTypeError(
            f"cannot generate a value for {spec.name} that passes {spec.checksum}"
        )

    return checked
