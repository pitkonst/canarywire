"""Resolve, statically check and write the outputs configured under `report.outputs`."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from canarywire.config import ConfigError, ReportSettings
from canarywire.report import BUILTINS, Report, builtin_source
from canarywire.report.mustache import Template, TemplateError, parse
from canarywire.report.samples import sample_shape
from canarywire.report.view import view

if TYPE_CHECKING:
    from collections.abc import Sequence


@dataclass(frozen=True)
class ResolvedOutput:
    """One output after resolving its path against the report directory (or the cwd)."""

    source: str
    template_name: str
    path: Path
    escape: str


def resolve_outputs(
    settings: ReportSettings, out_dir: Path, junit: Path | None
) -> list[ResolvedOutput]:
    """Resolve configured outputs and `--junit` to absolute paths; check for collisions."""
    base = out_dir.resolve()
    resolved: list[ResolvedOutput] = []
    for index, spec in enumerate(settings.outputs):
        resolved.append(
            ResolvedOutput(
                f"report.outputs[{index}]",
                spec.template,
                (base / spec.path).resolve(),
                spec.escape or _default_escape(spec.path),
            )
        )
    if junit is not None:
        resolved.append(ResolvedOutput("--junit", "builtin:junit", junit.resolve(), "xml"))
    _check_collisions(resolved, base)
    return resolved


def load_outputs(
    resolved: list[ResolvedOutput], config_dir: Path | None
) -> list[tuple[ResolvedOutput, Template]]:
    """Read and statically check every output's template. Raises ConfigError."""
    loaded: list[tuple[ResolvedOutput, Template]] = []
    for output in resolved:
        text = _read_template(output, config_dir)
        try:
            template = parse(text, output.template_name)
            template.check(sample_shape())
        except TemplateError as exc:
            raise ConfigError(f"{output.source}.template: {exc}") from exc
        loaded.append((output, template))
    return loaded


def write_outputs(
    viewed: dict[str, Any], loaded: Sequence[tuple[ResolvedOutput, Template]]
) -> list[str]:
    """Render each output from the view; return error lines, empty on success."""
    errors: list[str] = []
    for output, template in loaded:
        try:
            output.path.parent.mkdir(parents=True, exist_ok=True)
            output.path.write_text(template.render(viewed, output.escape))
        except (OSError, TemplateError) as exc:
            errors.append(f"canarywire: cannot write {output.path}: {exc}")
    return errors


def write(
    report: Report, out_dir: Path, loaded: Sequence[tuple[ResolvedOutput, Template]]
) -> tuple[Path, list[str]]:
    """Write report.json into out_dir, then every configured output; return path and errors."""
    out_dir.mkdir(parents=True, exist_ok=True)
    data = report.to_dict()
    json_path = out_dir / "report.json"
    json_path.write_text(json.dumps(data, indent=2) + "\n")
    errors = write_outputs(view(data), loaded)
    return json_path, errors


def _default_escape(path: str) -> str:
    suffix = Path(path).suffix.lower()
    return "xml" if suffix in (".xml", ".html") else "none"


def _label(output: ResolvedOutput) -> str:
    return output.source if output.source == "--junit" else f"{output.source}.path"


def _check_collisions(resolved: list[ResolvedOutput], base: Path) -> None:
    report_json = base / "report.json"
    for output in resolved:
        if output.path == report_json:
            raise ConfigError(f"{_label(output)}: would overwrite report.json")
    for index, later in enumerate(resolved):
        for earlier in resolved[:index]:
            if later.path == earlier.path:
                raise ConfigError(f"{_label(later)}: same path as {_label(earlier)}")


def _read_template(output: ResolvedOutput, config_dir: Path | None) -> str:
    if output.template_name in BUILTINS:
        return builtin_source(output.template_name)
    base = config_dir or Path.cwd()
    try:
        return (base / output.template_name).read_text()
    except OSError as exc:
        raise ConfigError(
            f"{output.source}.template: cannot read {output.template_name}: {exc.strerror}"
        ) from exc
