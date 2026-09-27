"""Configuration: an optional YAML file merged with CLI flags into frozen dataclasses."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, fields, replace
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any

import yaml

from canarywire.values.errors import CanaryTypeError
from canarywire.values.types import parse_custom_types

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from canarywire.values.types import CustomType

DEFAULT_CAPTURE_URL = "http://127.0.0.1:8765"
DEFAULT_LISTEN = "127.0.0.1:8765"
MAX_PORT = 65535
TEMPLATE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")
BUILTIN_TEMPLATES = ("builtin:markdown", "builtin:junit")

PROTOCOL_IDS = ("openai-chat", "anthropic-messages")
DUTIES = ("restore", "mask-only")
ROUTE_NAME = re.compile(r"[A-Za-z0-9_-]+")


class ConfigError(ValueError):
    """Invalid configuration; the message starts with the offending key path."""


@dataclass(frozen=True)
class Timeouts:
    """Timeouts in seconds."""

    capture_connect: float = 5.0
    client_request: float = 30.0
    upstream_response: float = 30.0
    serve_ready: float = 10.0
    stop_grace: float = 10.0
    upstream_done: float = 2.0
    fault_command: float = 60.0


GENERATOR_NAMES = ("baseline", "fragmentation", "fault")
GENERATORS_KEYS = frozenset(GENERATOR_NAMES)
FAULT_NAME = re.compile(r"[A-Za-z0-9_-]+")
CONTROL = "control"  # control attacks are `fault/control/<template>`: no fault may use the name
FAULT_KEYS = frozenset({"name", "before", "after", "expect", "settle_ms"})
FRAGMENTATION_CASES = ("baseline", "chunks", "random-chunks", "random-cuts")
PHASES = ("all", "first")

# Accepted keys at each level of the config file, exposed as constants so tests can check
# coverage against them without duplicating the literals (see tests/test_config_reference.py).
DOC_KEYS = frozenset(
    {
        "seed",
        "capture",
        "target",
        "timeouts",
        "generators",
        "canary_types",
        "templates",
        "faults",
        "report",
    }
)
CAPTURE_KEYS = frozenset({"url"})
TARGET_KEYS = frozenset({"base_url", "routes", "duty"})
ROUTE_KEYS = frozenset({"protocol", "path", "name"})
BASELINE_KEYS = frozenset({"enabled", "templates"})
FAULT_SETTINGS_KEYS = frozenset({"enabled", "templates"})
FRAGMENTATION_KEYS = frozenset(
    {"enabled", "templates", "cases", "chunks", "random_chunks", "random_cuts", "delay_ms"}
)
CHUNKS_KEYS = frozenset({"sizes", "phases"})
RANDOM_CHUNKS_KEYS = frozenset({"samples", "min", "max"})
RANDOM_CUTS_KEYS = frozenset({"samples", "max_cuts"})
DELAY_KEYS = frozenset({"min", "max"})
REPORT_KEYS = frozenset({"dir", "outputs"})
OUTPUT_KEYS = frozenset({"template", "path", "escape"})


@dataclass(frozen=True)
class ChunksSettings:
    """Fixed chunk sizes; `phases` is `all` (every phase of each size) or `first`."""

    sizes: tuple[int, ...] = (1, 2, 4)
    phases: str = "all"


@dataclass(frozen=True)
class RandomChunksSettings:
    """`samples` cases of random chunk sizes in `min_size..max_size`."""

    samples: int = 4
    min_size: int = 1
    max_size: int = 8


@dataclass(frozen=True)
class RandomCutsSettings:
    """`samples` cases of `1..max_cuts` cuts at random positions."""

    samples: int = 4
    max_cuts: int = 6


@dataclass(frozen=True)
class DelaySettings:
    """Seeded delay before each content event, in milliseconds."""

    min_ms: int = 0
    max_ms: int = 5


@dataclass(frozen=True)
class BaselineSettings:
    """The non-streaming baseline generator."""

    enabled: bool = True
    templates: tuple[str, ...] = ("default", "tool-calls", "multi-turn")


@dataclass(frozen=True)
class FragmentationSettings:
    """The fragmentation generator's cases and parameters."""

    enabled: bool = True
    templates: tuple[str, ...] = ("default", "multi-turn")
    cases: tuple[str, ...] = FRAGMENTATION_CASES
    chunks: ChunksSettings = field(default_factory=ChunksSettings)
    random_chunks: RandomChunksSettings = field(default_factory=RandomChunksSettings)
    random_cuts: RandomCutsSettings = field(default_factory=RandomCutsSettings)
    delay: DelaySettings = field(default_factory=DelaySettings)


@dataclass(frozen=True)
class FaultSettings:
    """The fault generator: which templates each fault sends."""

    enabled: bool = True
    templates: tuple[str, ...] = ("default",)


@dataclass(frozen=True)
class Route:
    """One route: a name, the protocol it speaks, and the path it is served on."""

    name: str
    protocol: str
    path: str


DEFAULT_ROUTES = (Route("openai-chat", "openai-chat", "/v1/chat/completions"),)


def ok_word(duty: str) -> str:
    """The word `expect` uses for "the answer is as the duty requires"."""
    return "restore" if duty == "restore" else "deliver"


@dataclass(frozen=True)
class FaultSpec:
    """One fault: shell commands that break and repair the environment, and what is acceptable."""

    name: str
    before: str
    after: str
    expect: tuple[str, ...] = ("refuse",)
    settle_ms: int = 0


@dataclass(frozen=True)
class Generators:
    """Which generators run, with their settings."""

    baseline: BaselineSettings = field(default_factory=BaselineSettings)
    fragmentation: FragmentationSettings = field(default_factory=FragmentationSettings)
    fault: FaultSettings = field(default_factory=FaultSettings)


@dataclass(frozen=True)
class OutputSpec:
    """One configured report output: a template and where to write it."""

    template: str
    path: str
    escape: str | None = None


DEFAULT_OUTPUTS = (OutputSpec("builtin:markdown", "report.md"),)


@dataclass(frozen=True)
class ReportSettings:
    """The `report` config section: where reports go and what gets written."""

    dir: Path | None = None
    outputs: tuple[OutputSpec, ...] = DEFAULT_OUTPUTS


@dataclass(frozen=True)
class Config:
    """Effective settings after merging defaults, the config file and CLI flags."""

    seed: int | None = None
    capture_url: str = DEFAULT_CAPTURE_URL
    target_url: str | None = None
    routes: tuple[Route, ...] = DEFAULT_ROUTES
    duty: str = "restore"
    timeouts: Timeouts = field(default_factory=Timeouts)
    generators: Generators = field(default_factory=Generators)
    canary_types: dict[str, CustomType] = field(default_factory=dict)
    templates: dict[str, Any] = field(default_factory=dict)
    faults: tuple[FaultSpec, ...] = ()
    report: ReportSettings = field(default_factory=ReportSettings)
    config_dir: Path | None = None
    config_sha256: str | None = None


def fault_generator_runs(config: Config) -> bool:
    """Whether the fault generator will run: enabled and at least one fault configured."""
    return config.generators.fault.enabled and bool(config.faults)


TIMEOUT_KEYS = frozenset(f.name for f in fields(Timeouts))


def load(path: Path | None) -> Config:
    """Load a YAML config file; None means defaults only."""
    if path is None:
        return Config()
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ConfigError(f"{path}: cannot read: {exc.strerror}") from exc
    try:
        raw = yaml.safe_load(data)
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: invalid YAML: {exc}") from exc
    config = parse({} if raw is None else raw)
    sha256 = hashlib.sha256(data).hexdigest()
    return replace(config, config_dir=path.parent, config_sha256=sha256)


def parse(raw: object) -> Config:
    """Validate a parsed YAML document into a Config."""
    doc = _mapping(raw, "", DOC_KEYS)
    capture = _mapping(doc.get("capture", {}), "capture", CAPTURE_KEYS)
    target = _mapping(doc.get("target", {}), "target", TARGET_KEYS)
    duty = target.get("duty", "restore")
    if duty not in DUTIES:
        raise ConfigError(f"target.duty: expected one of {', '.join(DUTIES)}")
    timeouts = _mapping(doc.get("timeouts", {}), "timeouts", TIMEOUT_KEYS)
    try:
        canary_types = parse_custom_types(doc.get("canary_types", {}))
    except CanaryTypeError as exc:
        raise ConfigError(str(exc)) from exc
    return Config(
        seed=_seed(doc.get("seed")),
        capture_url=_string(capture.get("url", DEFAULT_CAPTURE_URL), "capture.url"),
        target_url=_string(target["base_url"], "target.base_url") if "base_url" in target else None,
        routes=_routes(target["routes"]) if "routes" in target else DEFAULT_ROUTES,
        duty=duty,
        timeouts=Timeouts(
            **{key: _positive(value, f"timeouts.{key}") for key, value in timeouts.items()}
        ),
        generators=_generators(doc.get("generators", {})),
        canary_types=canary_types,
        templates=_templates(doc.get("templates", {})),
        faults=_faults(doc.get("faults", []), duty),
        report=_report(doc.get("report", {})),
    )


def override(
    config: Config,
    *,
    seed: int | None = None,
    capture_url: str | None = None,
    target_url: str | None = None,
    timeouts: Mapping[str, float | None] | None = None,
    generators: Sequence[str] | None = None,
) -> Config:
    """Apply CLI flags over a loaded config; None means the flag was not given."""
    given = {key: value for key, value in (timeouts or {}).items() if value is not None}
    generators_ = config.generators
    if generators is not None:
        generators_ = replace(
            generators_,
            baseline=replace(generators_.baseline, enabled="baseline" in generators),
            fragmentation=replace(generators_.fragmentation, enabled="fragmentation" in generators),
            fault=replace(generators_.fault, enabled="fault" in generators),
        )
    return replace(
        config,
        seed=config.seed if seed is None else seed,
        capture_url=config.capture_url if capture_url is None else capture_url,
        target_url=config.target_url if target_url is None else target_url,
        timeouts=replace(config.timeouts, **given),
        generators=generators_,
    )


def parse_listen(value: str) -> tuple[str, int]:
    """Split HOST:PORT; raise ConfigError if malformed."""
    host, _, port = value.rpartition(":")
    if not host or not port.isdigit() or not 0 < int(port) <= MAX_PORT:
        raise ConfigError(f"listen: expected HOST:PORT, got {value!r}")
    return host, int(port)


def parse_generator_names(text: str) -> tuple[str, ...]:
    """Parse `--generators`: comma-separated, known names, no duplicates."""
    return _names([name.strip() for name in text.split(",")], "--generators", GENERATOR_NAMES)


def _generators(raw: object) -> Generators:
    doc = _mapping(raw, "generators", GENERATORS_KEYS)
    baseline = _mapping(doc.get("baseline", {}), "generators.baseline", BASELINE_KEYS)
    return Generators(
        baseline=BaselineSettings(
            enabled=_bool(baseline.get("enabled", True), "generators.baseline.enabled"),
            templates=_template_list(
                baseline.get("templates", list(BaselineSettings.templates)),
                "generators.baseline.templates",
            ),
        ),
        fragmentation=_fragmentation(doc.get("fragmentation", {})),
        fault=_fault_settings(doc.get("fault", {})),
    )


def _fault_settings(raw: object) -> FaultSettings:
    doc = _mapping(raw, "generators.fault", FAULT_SETTINGS_KEYS)
    return FaultSettings(
        enabled=_bool(doc.get("enabled", True), "generators.fault.enabled"),
        templates=_template_list(
            doc.get("templates", list(FaultSettings.templates)), "generators.fault.templates"
        ),
    )


def _routes(raw: object) -> tuple[Route, ...]:
    if not isinstance(raw, list) or not raw:
        raise ConfigError("target.routes: expected a non-empty list")
    routes: list[Route] = []
    for index, item in enumerate(raw):
        where = f"target.routes[{index}]"
        entry = _mapping(item, where, ROUTE_KEYS)
        protocol = entry.get("protocol")
        if protocol not in PROTOCOL_IDS:
            raise ConfigError(f"{where}.protocol: expected one of {', '.join(PROTOCOL_IDS)}")
        path = entry.get("path")
        if not isinstance(path, str) or not path.startswith("/"):
            raise ConfigError(f"{where}.path: expected a path starting with /")
        name_defaulted = "name" not in entry
        name = entry.get("name", protocol)
        if not isinstance(name, str) or not ROUTE_NAME.fullmatch(name):
            raise ConfigError(f"{where}.name: expected a name like claude")
        if any(route.name == name for route in routes):
            if name_defaulted:
                raise ConfigError(
                    f"{where}.name: duplicate name {name!r} "
                    "(a route's name defaults to its protocol; set name)"
                )
            raise ConfigError(f"{where}.name: duplicate name {name!r}")
        if any(route.protocol == protocol and route.path == path for route in routes):
            raise ConfigError(f"{where}: duplicate route {protocol} {path}")
        routes.append(Route(name, protocol, path))
    return tuple(routes)


def _faults(raw: object, duty: str) -> tuple[FaultSpec, ...]:
    if not isinstance(raw, list):
        raise ConfigError("faults: expected a list")
    specs: list[FaultSpec] = []
    for index, item in enumerate(raw):
        where = f"faults[{index}]"
        entry = _mapping(item, where, FAULT_KEYS)
        if "name" not in entry:
            raise ConfigError(f"{where}.name: required")
        name = entry["name"]
        if not isinstance(name, str) or not FAULT_NAME.fullmatch(name):
            raise ConfigError(f"{where}.name: expected a name like analyzer-down")
        if name == CONTROL:
            raise ConfigError(f"{where}.name: {CONTROL!r} is reserved for the control requests")
        if any(spec.name == name for spec in specs):
            raise ConfigError(f"{where}.name: duplicate name {name!r}")
        commands: dict[str, str] = {}
        for hook in ("before", "after"):
            command = entry.get(hook)
            if not isinstance(command, str) or not command.strip():
                raise ConfigError(f"{where}.{hook}: expected a non-empty command")
            commands[hook] = command
        specs.append(
            FaultSpec(
                name,
                commands["before"],
                commands["after"],
                _expect(entry.get("expect", "refuse"), f"{where}.expect", duty),
                _int(entry.get("settle_ms", 0), f"{where}.settle_ms", minimum=0),
            )
        )
    return tuple(specs)


def _expect(value: object, path: str, duty: str) -> tuple[str, ...]:
    word = ok_word(duty)
    items = [value] if isinstance(value, str) else value
    if isinstance(items, list) and all(isinstance(item, str) for item in items):
        if sorted(items) == ["refuse"]:
            return ("refuse",)
        if sorted(items) == sorted(["refuse", word]):
            return ("refuse", word)
    raise ConfigError(f"{path}: expected refuse or [refuse, {word}] under duty {duty}")


def _fragmentation(raw: object) -> FragmentationSettings:
    p = "generators.fragmentation"
    doc = _mapping(raw, p, FRAGMENTATION_KEYS)
    cases = _names(doc.get("cases", list(FRAGMENTATION_CASES)), f"{p}.cases", FRAGMENTATION_CASES)
    if "baseline" not in cases:
        raise ConfigError(f"{p}.cases: must include baseline when split cases are listed")
    chunks = _mapping(doc.get("chunks", {}), f"{p}.chunks", CHUNKS_KEYS)
    phases = chunks.get("phases", "all")
    if phases not in PHASES:
        raise ConfigError(f"{p}.chunks.phases: expected one of all, first")
    rc = _mapping(doc.get("random_chunks", {}), f"{p}.random_chunks", RANDOM_CHUNKS_KEYS)
    rc_min = _int(rc.get("min", 1), f"{p}.random_chunks.min", minimum=1)
    rc_max = _int(rc.get("max", 8), f"{p}.random_chunks.max", minimum=1)
    if rc_min > rc_max:
        raise ConfigError(f"{p}.random_chunks: min must not exceed max")
    cuts = _mapping(doc.get("random_cuts", {}), f"{p}.random_cuts", RANDOM_CUTS_KEYS)
    delay = _mapping(doc.get("delay_ms", {}), f"{p}.delay_ms", DELAY_KEYS)
    d_min = _int(delay.get("min", 0), f"{p}.delay_ms.min", minimum=0)
    d_max = _int(delay.get("max", 5), f"{p}.delay_ms.max", minimum=0)
    if d_min > d_max:
        raise ConfigError(f"{p}.delay_ms: min must not exceed max")
    return FragmentationSettings(
        enabled=_bool(doc.get("enabled", True), f"{p}.enabled"),
        templates=_template_list(
            doc.get("templates", list(FragmentationSettings.templates)), f"{p}.templates"
        ),
        cases=cases,
        chunks=ChunksSettings(
            sizes=_int_list(chunks.get("sizes", [1, 2, 4]), f"{p}.chunks.sizes", minimum=1),
            phases=phases,
        ),
        random_chunks=RandomChunksSettings(
            samples=_int(rc.get("samples", 4), f"{p}.random_chunks.samples", minimum=1),
            min_size=rc_min,
            max_size=rc_max,
        ),
        random_cuts=RandomCutsSettings(
            samples=_int(cuts.get("samples", 4), f"{p}.random_cuts.samples", minimum=1),
            max_cuts=_int(cuts.get("max_cuts", 6), f"{p}.random_cuts.max_cuts", minimum=1),
        ),
        delay=DelaySettings(min_ms=d_min, max_ms=d_max),
    )


def _report(raw: object) -> ReportSettings:
    doc = _mapping(raw, "report", REPORT_KEYS)
    outputs = _outputs(doc["outputs"]) if "outputs" in doc else DEFAULT_OUTPUTS
    dir_ = Path(_string(doc["dir"], "report.dir")) if "dir" in doc else None
    return ReportSettings(dir=dir_, outputs=outputs)


def _report_template(value: object, where: str) -> str:
    template = _string(value, f"{where}.template")
    if template.startswith("builtin:") and template not in BUILTIN_TEMPLATES:
        raise ConfigError(f'{where}.template: unknown builtin "{template}"')
    return template


def _outputs(raw: object) -> tuple[OutputSpec, ...]:
    if not isinstance(raw, list) or not raw:
        raise ConfigError("report.outputs: expected a non-empty list")
    specs: list[OutputSpec] = []
    seen: list[PurePosixPath] = []
    for index, item in enumerate(raw):
        where = f"report.outputs[{index}]"
        entry = _mapping(item, where, OUTPUT_KEYS)
        template = _report_template(entry.get("template"), where)
        if entry.get("path") == "":
            raise ConfigError(f"{where}.path: must name a file")
        path = _string(entry.get("path"), f"{where}.path")
        pure = PurePosixPath(path)
        if pure == PurePosixPath("."):
            raise ConfigError(f"{where}.path: must name a file")
        if pure.is_absolute():
            raise ConfigError(f"{where}.path: must be relative")
        if ".." in pure.parts:
            raise ConfigError(f"{where}.path: must not contain ..")
        if pure == PurePosixPath("report.json"):
            raise ConfigError(f"{where}.path: report.json is reserved")
        if pure in seen:
            raise ConfigError(f"{where}.path: duplicate path {path}")
        seen.append(pure)
        escape: str | None = None
        if "escape" in entry:
            escape = entry["escape"]
            if escape not in ("xml", "none"):
                raise ConfigError(f"{where}.escape: expected xml or none")
        specs.append(OutputSpec(template, path, escape))
    return tuple(specs)


def _templates(raw: object) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ConfigError("templates: expected a mapping")
    for name, value in raw.items():
        if not isinstance(name, str) or not TEMPLATE_NAME.fullmatch(name):
            raise ConfigError(f"templates.{name}: expected a name like invoice")
        if not isinstance(value, dict):
            raise ConfigError(f"templates.{name}: expected a mapping")
    return dict(raw)


def _template_list(value: object, path: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"{path}: expected a non-empty list of names")
    if len(set(value)) != len(value):
        raise ConfigError(f"{path}: duplicate names")
    return tuple(value)


def _bool(value: object, path: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{path}: expected true or false")
    return value


def _int(value: object, path: str, *, minimum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ConfigError(f"{path}: expected an integer >= {minimum}")
    return value


def _int_list(value: object, path: str, *, minimum: int) -> tuple[int, ...]:
    if not isinstance(value, list) or not value:
        raise ConfigError(f"{path}: expected a non-empty list")
    items = tuple(_int(item, path, minimum=minimum) for item in value)
    if len(set(items)) != len(items):
        raise ConfigError(f"{path}: duplicate values")
    return items


def _names(value: object, path: str, allowed: tuple[str, ...]) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ConfigError(f"{path}: expected a non-empty list")
    for item in value:
        if item not in allowed:
            raise ConfigError(f"{path}: unknown name {item!r}")
    if len(set(value)) != len(value):
        raise ConfigError(f"{path}: duplicate names")
    return tuple(value)


def _mapping(value: object, path: str, allowed: set[str] | frozenset[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"{path or '<root>'}: expected a mapping")
    for key in value:
        if key not in allowed:
            raise ConfigError(f"{f'{path}.{key}' if path else key}: unknown key")
    return value


def _seed(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError("seed: expected an integer")
    return value


def _string(value: object, path: str) -> str:
    if not isinstance(value, str) or not value:
        raise ConfigError(f"{path}: expected a non-empty string")
    return value


def _positive(value: object, path: str) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float) or value <= 0:
        raise ConfigError(f"{path}: expected a positive number")
    return float(value)
