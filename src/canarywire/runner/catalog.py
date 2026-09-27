"""Templates: request/response pairs with canary instances, `{{ x.raw }}`/`{{ x.masked }}` slots."""

from __future__ import annotations

import dataclasses
import json
import re
from dataclasses import dataclass
from importlib import resources
from itertools import pairwise
from typing import TYPE_CHECKING, Any

import yaml

from canarywire.runner import protocols
from canarywire.runner.jsonpath import (
    JSON_NODE,
    decode_json,
    format_path,
    get_path,
    is_json_node,
    iter_strings,
    json_equal,
    location,
)
from canarywire.runner.neutral import TemplateError as TemplateError  # noqa: PLC0414 - re-export
from canarywire.runner.neutral import check_neutral
from canarywire.runner.protocols import PROTOCOLS

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from canarywire.runner.jsonpath import JsonPath

SLOT = re.compile(r"\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\.(raw|masked)\s*\}\}")
BRACES = re.compile(r"\{\{.*?\}\}", re.DOTALL)
INSTANCE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
TEMPLATE_KEYS = frozenset({"protocol", "canaries", "request", "response", "consistency"})
CONSISTENCY = ("required", "ignore")


class MaskedValueNotFoundError(Exception):
    """The upstream request does not have the shape the request template predicts."""

    def __init__(self, location: str, message: str | None = None) -> None:
        """Record the body location that did not match."""
        super().__init__(message or f"masked value not found at {location}")
        self.location = location


class RequestMangledError(MaskedValueNotFoundError):
    """The upstream string is the template's text, changed around a canary."""

    def __init__(self, location: str, expected: str, actual: str) -> None:
        """Record where, the template text (slots shown by instance) and what arrived."""
        super().__init__(location, f"request text changed around a canary at {location}")
        self.expected = expected
        self.actual = actual


def _recognisable(text: str, slots: list[re.Match[str]], actual: object) -> bool:
    """Whether `actual` is recognisably `text` (spec: leading, else trailing, literal)."""
    if not isinstance(actual, str) or not actual:
        return False
    leading = text[: slots[0].start()]
    if leading:
        shorter_prefix = len(actual) < len(leading) and leading.startswith(actual)
        return actual.startswith(leading) or shorter_prefix
    trailing = text[slots[-1].end() :]
    return bool(trailing) and actual.endswith(trailing)


def _shown(text: str) -> str:
    """The template string with each slot shown as `{{<instance>}}`."""
    return SLOT.sub(lambda m: "{{" + m.group(1) + "}}", text)


@dataclass(frozen=True)
class Instance:
    """A canary instance declared by a template: its type and type parameters."""

    name: str
    type_name: str
    params: dict[str, Any]


@dataclass(frozen=True)
class Template:
    """A validated request/response pair.

    `protocol` is None for a neutral template; `for_protocol` translates it into a raw one.
    """

    name: str
    protocol: str | None
    instances: dict[str, Instance]
    request: Any
    response: Any
    consistency: str = "required"

    def used_in_request(self) -> list[str]:
        """Instances with at least one `.raw` slot in the request, in declaration order."""
        used = {m.group(1) for _, text in iter_strings(self.request) for m in SLOT.finditer(text)}
        return [name for name in self.instances if name in used]


def parse_template(name: str, raw: object) -> Template:
    """Validate one template; raise TemplateError with a `templates.<name>…` path."""
    where = f"templates.{name}"
    if not isinstance(raw, dict):
        raise TemplateError(f"{where}: expected a mapping")
    for key in raw:
        if key not in TEMPLATE_KEYS:
            raise TemplateError(f"{where}.{key}: unknown key")
    protocol = raw.get("protocol")
    if protocol is not None and protocol not in PROTOCOLS:
        raise TemplateError(f"{where}.protocol: expected one of {', '.join(PROTOCOLS)}")
    instances = _instances(raw.get("canaries"), f"{where}.canaries")
    consistency = raw.get("consistency", "required")
    if consistency not in CONSISTENCY:
        raise TemplateError(f"{where}.consistency: expected one of {', '.join(CONSISTENCY)}")
    request, response = raw.get("request"), raw.get("response")
    if protocol is None:
        check_neutral(request, response, where)
    _check_documents(request, response, instances, where)
    return Template(name, protocol, instances, request, response, consistency)


def for_protocol(template: Template, protocol: str) -> Template:
    """The template as `protocol` documents: a neutral one translated, a raw one as it is.

    The translated documents get the raw template checks, under `templates.<name>@<protocol>`.
    """
    if template.protocol is not None:
        if template.protocol != protocol:
            raise TemplateError(
                f"templates.{template.name}: protocol {template.protocol} cannot run on {protocol}"
            )
        return template
    request, response = protocols.module(protocol).translate(template.request, template.response)
    _check_documents(request, response, template.instances, f"templates.{template.name}@{protocol}")
    return dataclasses.replace(template, protocol=protocol, request=request, response=response)


def _check_documents(
    request: Any, response: Any, instances: Mapping[str, Instance], where: str
) -> None:
    _check_json_nodes(request, f"{where}.request")
    _check_json_nodes(response, f"{where}.response")
    _check_slots(request, f"{where}.request", instances, used=None)
    used = {m.group(1) for _, text in iter_strings(request) for m in SLOT.finditer(text)}
    _check_slots(response, f"{where}.response", instances, used=used)


def builtin_templates() -> dict[str, Template]:
    """Templates shipped in `canarywire/templates/*.yaml` (file stem = template name)."""
    templates: dict[str, Template] = {}
    for entry in sorted(resources.files("canarywire.templates").iterdir(), key=lambda e: e.name):
        if entry.name.endswith(".yaml"):
            name = entry.name.removesuffix(".yaml")
            templates[name] = parse_template(
                name, yaml.safe_load(entry.read_text(encoding="utf-8"))
            )
    return templates


def build_catalog(inline: Mapping[str, Any]) -> dict[str, Template]:
    """Built-in templates, overridden and extended by the config's inline templates."""
    catalog = builtin_templates()
    for name, raw in inline.items():
        catalog[name] = parse_template(name, raw)
    return catalog


def render(doc: Any, raw: Mapping[str, str], masked: Mapping[str, str]) -> Any:
    """A copy of `doc` with every slot replaced by the instance's raw or masked value."""
    if is_json_node(doc):
        value = render(doc[JSON_NODE], raw, masked)
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    if isinstance(doc, str):
        return SLOT.sub(lambda m: (raw if m.group(2) == "raw" else masked)[m.group(1)], doc)
    if isinstance(doc, list):
        return [render(item, raw, masked) for item in doc]
    if isinstance(doc, dict):
        return {key: render(value, raw, masked) for key, value in doc.items()}
    return doc


def slotted_strings(doc: Any) -> list[tuple[JsonPath, list[str]]]:
    """Paths of strings containing slots, with the instances each refers to."""
    result: list[tuple[JsonPath, list[str]]] = []
    for path, text in iter_strings(doc):
        names = [m.group(1) for m in SLOT.finditer(text)]
        if names:
            result.append((path, list(dict.fromkeys(names))))
    return result


@dataclass(frozen=True)
class Occurrence:
    """One request slot and the placeholder the gateway put there."""

    instance: str
    location: str
    placeholder: str


def extract_occurrences(request_doc: Any, upstream_json: Any) -> list[Occurrence]:
    """Every request slot's placeholder, in template document order.

    `$json` strings are decoded and must have the template's shape exactly (same keys, same
    list lengths, strings where the template has strings, other leaves equal as JSON).
    """
    for path in _outermost(json_nodes(request_doc)):
        if not _same_shape(get_path(request_doc, path), get_path(upstream_json, path)):
            raise MaskedValueNotFoundError(location("body", path))
    occurrences: list[Occurrence] = []
    for path, text in iter_strings(request_doc):
        slots = list(SLOT.finditer(text))
        if not slots:
            continue
        actual = get_path(upstream_json, path)
        match = _pattern(text, slots).fullmatch(actual) if isinstance(actual, str) else None
        if match is None:
            where = location("body", path)
            if isinstance(actual, str) and _pattern(text, slots, greedy=False).fullmatch(actual):
                # The slot(s) were redacted to nothing: the value is missing, not mangled.
                raise MaskedValueNotFoundError(where)
            if _recognisable(text, slots, actual):
                assert isinstance(actual, str)  # noqa: S101 - _recognisable narrows this
                raise RequestMangledError(where, _shown(text), actual)
            raise MaskedValueNotFoundError(where)
        occurrences += [
            Occurrence(slot.group(1), location("body", path), value)
            for slot, value in zip(slots, match.groups(), strict=True)
        ]
    return occurrences


def first_placeholders(occurrences: Sequence[Occurrence]) -> dict[str, str]:
    """The first placeholder of each instance."""
    masked: dict[str, str] = {}
    for occurrence in occurrences:
        masked.setdefault(occurrence.instance, occurrence.placeholder)
    return masked


def extract_masked(request_doc: Any, upstream_json: Any) -> dict[str, str]:
    """What the gateway put in place of each request slot, by instance (first occurrence wins)."""
    return first_placeholders(extract_occurrences(request_doc, upstream_json))


def json_nodes(doc: Any, path: JsonPath = ()) -> list[JsonPath]:
    """Paths of every `$json` node in a template, outermost first, in document order."""
    if is_json_node(doc):
        return [path, *json_nodes(doc[JSON_NODE], (*path, JSON_NODE))]
    if isinstance(doc, list):
        return [p for index, item in enumerate(doc) for p in json_nodes(item, (*path, index))]
    if isinstance(doc, dict):
        return [p for key, value in doc.items() for p in json_nodes(value, (*path, key))]
    return []


def _outermost(paths: Sequence[JsonPath]) -> list[JsonPath]:
    return [p for p in paths if JSON_NODE not in p]


def _same_shape(template: Any, actual: Any) -> bool:
    if is_json_node(template):
        ok, parsed = decode_json(actual) if isinstance(actual, str) else (False, None)
        return ok and _same_shape(template[JSON_NODE], parsed)
    if isinstance(template, dict):
        return (
            isinstance(actual, dict)
            and template.keys() == actual.keys()
            and all(_same_shape(value, actual[key]) for key, value in template.items())
        )
    if isinstance(template, list):
        return (
            isinstance(actual, list)
            and len(template) == len(actual)
            and all(_same_shape(t, a) for t, a in zip(template, actual, strict=True))
        )
    if isinstance(template, str):
        return isinstance(actual, str)
    return json_equal(template, actual)


def _check_json_nodes(doc: Any, where: str, *, inside: bool = False) -> None:
    if isinstance(doc, list):
        for index, item in enumerate(doc):
            _check_json_nodes(item, f"{where}[{index}]", inside=inside)
    elif isinstance(doc, dict):
        if JSON_NODE in doc:
            if len(doc) != 1:
                raise TemplateError(f"{where}: a $json mapping has no other keys")
            value = doc[JSON_NODE]
            if not isinstance(value, (dict, list)):
                raise TemplateError(f"{where}.$json: expected a mapping or a list")
            _check_json_nodes(value, f"{where}$", inside=True)
            return
        for key, value in doc.items():
            _check_json_nodes(value, f"{where}.{key}", inside=inside)
    elif inside and not (doc is None or isinstance(doc, (str, int, float, bool))):
        raise TemplateError(f"{where}: unsupported value in $json")


def check_streamed_content(template: Template) -> None:
    """Fragmentation needs a slot of a request-used instance in the streamed content.

    The template must be raw (as `for_protocol` returns): the path depends on the protocol.
    """
    where = f"templates.{template.name}"
    if template.protocol is None:
        raise TemplateError(f"{where}: the streamed content check needs a translated template")
    content_path = protocols.module(template.protocol).CONTENT_PATH
    used = set(template.used_in_request())
    content = get_path(template.response, content_path)
    names = {m.group(1) for m in SLOT.finditer(content)} if isinstance(content, str) else set()
    if not names & used:
        raise TemplateError(
            f"{where}: the streamed content ({format_path(content_path)}) "
            "has no slot of an instance used in the request"
        )


def _instances(raw: object, where: str) -> dict[str, Instance]:
    if not isinstance(raw, dict):
        raise TemplateError(f"{where}: expected a mapping")
    instances: dict[str, Instance] = {}
    for name, spec in raw.items():
        if not isinstance(name, str) or not INSTANCE_NAME.fullmatch(name):
            raise TemplateError(f"{where}.{name}: expected an instance name like customer")
        if isinstance(spec, str):
            instances[name] = Instance(name, spec, {})
        elif isinstance(spec, dict):
            type_name = spec.get("type")
            if not isinstance(type_name, str):
                raise TemplateError(f"{where}.{name}.type: expected a type name")
            params = {key: value for key, value in spec.items() if key != "type"}
            instances[name] = Instance(name, type_name, params)
        else:
            raise TemplateError(f"{where}.{name}: expected a type name or a mapping with type")
    return instances


def _check_slots(
    doc: Any, where: str, instances: Mapping[str, Instance], *, used: set[str] | None
) -> None:
    for path, text in iter_strings(doc):
        at = f"{where}.{format_path(path)}" if path else where
        for braces in BRACES.finditer(text):
            if not SLOT.fullmatch(braces.group()):
                raise TemplateError(f"{at}: malformed slot {braces.group()!r}")
        slots = list(SLOT.finditer(text))
        for slot in slots:
            instance, kind = slot.group(1), slot.group(2)
            if instance not in instances:
                raise TemplateError(f"{at}: slot {instance}.{kind} names an undeclared instance")
            if used is None and kind == "masked":
                raise TemplateError(f"{at}: .masked is only allowed in the response")
            if used is not None and instance not in used:
                raise TemplateError(
                    f"{at}: slot {instance}.{kind} names an instance not used in the request"
                )
        if used is None:
            for left, right in pairwise(slots):
                if left.end() == right.start():
                    raise TemplateError(f"{at}: adjacent slots make extraction ambiguous")


def _pattern(text: str, slots: list[re.Match[str]], *, greedy: bool = True) -> re.Pattern[str]:
    """The template text as a regex, one capture group per slot.

    `greedy=False` uses `(.*?)` instead of `(.+?)`, so a slot redacted to the empty string still
    fullmatches: used to tell "value removed" apart from "text around it changed".
    """
    quantifier = "(.+?)" if greedy else "(.*?)"
    parts: list[str] = []
    position = 0
    for slot in slots:
        parts += [re.escape(text[position : slot.start()]), quantifier]
        position = slot.end()
    parts.append(re.escape(text[position:]))
    return re.compile("".join(parts), re.DOTALL)
