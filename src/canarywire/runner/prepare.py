"""Validate templates and types, then assign one value per (template, instance) — before traffic."""

from __future__ import annotations

import dataclasses
import hashlib
import random
from dataclasses import dataclass
from typing import TYPE_CHECKING

from canarywire.canaries import Canary
from canarywire.config import ConfigError, fault_generator_runs
from canarywire.runner import protocols
from canarywire.runner.catalog import (
    TemplateError,
    build_catalog,
    check_streamed_content,
    for_protocol,
)
from canarywire.values.errors import CanaryTypeError
from canarywire.values.types import MAX_ATTEMPTS, make_source

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from types import ModuleType

    from canarywire.config import Config, Route
    from canarywire.runner.catalog import Template
    from canarywire.values.types import CustomType, Source

SEED_BYTES = 8


@dataclass(frozen=True)
class BoundTemplate:
    """A template bound to one route, with the values assigned to its request-used instances.

    `template` holds the documents translated for the route's protocol. Every route of one
    template shares the same `canaries`.
    """

    template: Template
    canaries: tuple[Canary, ...]
    route: Route

    @property
    def name(self) -> str:
        """The template's name (reports use it for `template` fields)."""
        return self.template.name

    @property
    def label(self) -> str:
        """`<template>@<route>`, as attack names use it."""
        return f"{self.template.name}@{self.route.name}"

    @property
    def module(self) -> ModuleType:
        """The protocol module of the route."""
        return protocols.module(self.route.protocol)

    def raw(self) -> dict[str, str]:
        """Instance name → value."""
        return {canary.name: canary.value for canary in self.canaries}


@dataclass(frozen=True)
class Prepared:
    """Every (template, route) pair the enabled generators use, bound to its values."""

    templates: dict[str, BoundTemplate]

    def bound(self, name: str) -> list[BoundTemplate]:
        """The bindings of template `name`, in route order."""
        return [bound for bound in self.templates.values() if bound.name == name]

    def all_canaries(self) -> list[Canary]:
        """Every value of the run, template by template, once per template."""
        seen: set[str] = set()
        canaries: list[Canary] = []
        for bound in self.templates.values():
            if bound.name not in seen:
                seen.add(bound.name)
                canaries.extend(bound.canaries)
        return canaries


def instance_rng(seed: int, template: str, instance: str) -> random.Random:
    """A generator depending only on the run seed, template name and instance name."""
    digest = hashlib.sha256(f"{seed}:{template}:{instance}".encode()).digest()
    return random.Random(int.from_bytes(digest[:SEED_BYTES], "big"))  # noqa: S311 - seeded canary values, not security


def prepare(config: Config, seed: int) -> Prepared:
    """Validate everything and assign values; raise ConfigError with a key path."""
    try:
        catalog = build_catalog(config.templates)
    except TemplateError as exc:
        raise ConfigError(str(exc)) from exc
    names = _referenced(config, catalog)
    _check_served(config, catalog)
    translated = _translate(config, catalog, names)
    sources = _validate_all_instances(catalog, config.canary_types)
    for name in names:
        if not catalog[name].used_in_request():
            raise ConfigError(f"templates.{name}: no canary instance is used in the request")
    if config.generators.fragmentation.enabled:
        for name in config.generators.fragmentation.templates:
            for route, template in translated[name]:
                try:
                    check_streamed_content(
                        dataclasses.replace(template, name=f"{name}@{route.name}")
                    )
                except TemplateError as exc:
                    raise ConfigError(str(exc)) from exc
    _check_pool_containment(names, catalog, sources)
    run_values: list[str] = []
    assigned: dict[str, tuple[Canary, ...]] = {}
    for name in sorted(names):
        template = catalog[name]
        canaries: list[Canary] = []
        for instance in template.used_in_request():
            declared = template.instances[instance]
            where = f"templates.{name}.canaries.{instance}"
            source, rng = sources[(name, instance)], instance_rng(seed, name, instance)
            try:
                if source.pool is not None:
                    value = _assign_from_pool(source, rng, [c.value for c in canaries], run_values)
                else:
                    value = _assign_drawn(source, rng, run_values)
            except CanaryTypeError as exc:
                raise ConfigError(f"{where}: {exc}") from exc
            canaries.append(Canary(instance, value, declared.type_name, name))
            run_values.append(value)
        assigned[name] = tuple(canaries)
    bindings = (
        BoundTemplate(template, assigned[name], route)
        for name in names
        for route, template in translated[name]
    )
    return Prepared({bound.label: bound for bound in bindings})


def _serves(route: Route, template: Template) -> bool:
    """A neutral template runs on every route; a raw one only on routes of its protocol."""
    return template.protocol is None or template.protocol == route.protocol


def _check_served(config: Config, catalog: Mapping[str, Template]) -> None:
    """Every raw template an enabled generator lists needs a route of its protocol."""
    for generator, enabled, templates in _generator_lists(config):
        for name in templates if enabled else ():
            template = catalog[name]
            if not any(_serves(route, template) for route in config.routes):
                raise ConfigError(
                    f"generators.{generator}.templates: template {name} has protocol "
                    f"{template.protocol} but no route serves it"
                )


def _translate(
    config: Config, catalog: Mapping[str, Template], names: Sequence[str]
) -> dict[str, list[tuple[Route, Template]]]:
    """Each referenced template's documents for each route that serves it, in route order."""
    translated: dict[str, list[tuple[Route, Template]]] = {}
    for name in names:
        pairs: list[tuple[Route, Template]] = []
        for route in config.routes:
            if not _serves(route, catalog[name]):
                continue
            try:
                pairs.append((route, for_protocol(catalog[name], route.protocol)))
            except TemplateError as exc:
                raise ConfigError(str(exc)) from exc
        translated[name] = pairs
    return translated


def _validate_all_instances(
    catalog: Mapping[str, Template], canary_types: Mapping[str, CustomType]
) -> dict[tuple[str, str], Source]:
    """Resolve every declared instance of every catalog template to its Source, once each."""
    sources: dict[tuple[str, str], Source] = {}
    for name in sorted(catalog):
        template = catalog[name]
        for instance_name, declared in template.instances.items():
            where = f"templates.{name}.canaries.{instance_name}"
            try:
                sources[(name, instance_name)] = make_source(
                    declared.type_name, declared.params, canary_types
                )
            except CanaryTypeError as exc:
                raise ConfigError(f"{where}: {exc}") from exc
    return sources


def _generator_lists(config: Config) -> list[tuple[str, bool, tuple[str, ...]]]:
    """(generator, whether it runs, its template names), in generator order."""
    generators = config.generators
    return [
        ("baseline", generators.baseline.enabled, generators.baseline.templates),
        ("fragmentation", generators.fragmentation.enabled, generators.fragmentation.templates),
        ("fault", fault_generator_runs(config), generators.fault.templates),
    ]


def _referenced(config: Config, catalog: dict[str, Template]) -> list[str]:
    """Templates the enabled generators use; names under disabled generators are checked too."""
    names: list[str] = []
    for generator, enabled, templates in _generator_lists(config):
        for name in templates:
            if name not in catalog:
                raise ConfigError(f"generators.{generator}.templates: unknown template {name!r}")
            if enabled and name not in names:
                names.append(name)
    return names


def _check_pool_containment(
    names: Sequence[str],
    catalog: Mapping[str, Template],
    sources: Mapping[tuple[str, str], Source],
) -> None:
    """Reject `values` pools (used in this run) where one entry contains another.

    Checked once, independent of the seed, so a config either always prepares or never does.
    """
    pools: dict[str, tuple[str, ...]] = {}
    for name in names:
        for instance in catalog[name].used_in_request():
            source = sources[(name, instance)]
            if source.pool is not None:
                pools[source.type_name] = source.pool
    entries = sorted({(value, type_name) for type_name, pool in pools.items() for value in pool})
    for inner, inner_type in entries:
        for outer, outer_type in entries:
            if inner != outer and inner in outer:
                raise ConfigError(
                    f"canary_types.{inner_type}.values: {inner!r} is contained in {outer!r} "
                    f"(canary_types.{outer_type}.values); canary values must not contain each other"
                )


def _overlap(value: str, others: Sequence[str]) -> str | None:
    return next((other for other in others if value in other or other in value), None)


def _assign_drawn(source: Source, rng: random.Random, run_values: Sequence[str]) -> str:
    """Draw until the value is non-empty and overlaps no run value (this template's included)."""
    if source.draw is None:
        raise CanaryTypeError(f"type {source.type_name} has no values")
    clash: str | None = None
    candidate = ""
    for _ in range(MAX_ATTEMPTS):
        drawn = source.draw(rng)
        if not drawn:
            continue  # an empty value would match everywhere: treat it as a clash
        candidate = drawn
        clash = _overlap(candidate, run_values)
        if clash is None:
            return candidate
    if not candidate:
        raise CanaryTypeError("cannot generate a non-empty value")
    raise CanaryTypeError(
        f"cannot generate a value for {source.type_name}: {candidate!r} overlaps with {clash!r}"
    )


def _assign_from_pool(
    source: Source,
    rng: random.Random,
    template_values: Sequence[str],
    run_values: Sequence[str],
) -> str:
    order = list(source.pool or ())
    rng.shuffle(order)
    candidates = [v for v in order if v not in template_values]
    if not candidates:
        raise CanaryTypeError(
            f"type {source.type_name} has fewer values than instances in this template"
        )
    for candidate in candidates:
        if _overlap(candidate, run_values) is None:
            return candidate
    raise CanaryTypeError("no value left that is unused and does not overlap other run values")
