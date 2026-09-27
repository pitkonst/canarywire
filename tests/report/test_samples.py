import json
from typing import Any

import pytest

from canarywire.report import BUILTINS, Report, builtin_source
from canarywire.report.mustache import parse
from canarywire.report.samples import (
    AFTER_COMMAND,
    BEFORE_COMMAND,
    passing_report,
    sample_reports,
    sample_shape,
)
from canarywire.report.view import view


def leaves(value: Any, path: str = "") -> list[tuple[str, Any]]:
    if isinstance(value, dict):
        return [leaf for k, v in value.items() for leaf in leaves(v, f"{path}.{k}")]
    if isinstance(value, list):
        if not value:
            return [(path, [])]
        return [leaf for item in value for leaf in leaves(item, f"{path}[]")]
    return [(path, value)]


def test_leaves_reports_empty_lists() -> None:
    assert leaves({"a": {"b": []}, "c": [1]}) == [(".a.b", []), (".c[]", 1)]


def test_sample_run_has_faults_but_never_their_commands() -> None:
    for report in [*sample_reports(), passing_report()]:
        assert [f["name"] for f in report.run["faults"]] == ["down", "slow"]
        dumped = json.dumps(report.to_dict())
        assert BEFORE_COMMAND not in dumped
        assert AFTER_COMMAND not in dumped
        for builtin in BUILTINS:
            rendered = parse(builtin_source(builtin), builtin).render(view(report.to_dict()))
            assert BEFORE_COMMAND not in rendered
            assert AFTER_COMMAND not in rendered


def test_sample_shape_has_no_null_and_no_empty_list() -> None:
    shape = sample_shape()
    assert [p for p, v in leaves(shape) if v is None] == []
    assert [p for p, v in leaves(shape) if v == []] == []
    assert shape["run_failures"] != []


def same_keys(value: Any, shape: Any, path: str = "") -> list[str]:
    """Paths where a view object's keys differ from the shape's."""
    if isinstance(value, dict):
        if set(value) != set(shape):
            return [f"{path}: {sorted(set(value) ^ set(shape))}"]
        return [
            p
            for k in value
            for p in same_keys(value[k], shape[k], f"{path}.{k}")
            if value[k] is not None
        ]
    if isinstance(value, list):
        return [p for item in value for p in same_keys(item, shape[0], f"{path}[]")]
    return []


def test_every_real_view_object_has_the_shape_keys() -> None:
    shape = sample_shape()
    for report in [*sample_reports(), passing_report()]:
        assert same_keys(view(report.to_dict()), shape) == []


NULL_SAFE_DOTTED = [
    "{{#findings}}{{leak_excerpt.match}}{{/findings}}",
    "{{run.config.path}}",
    "{{#faults}}{{before.exit}}{{after.exit}}{{/faults}}",
]


def _null_heavy_report() -> Report:
    """No config file, a fault whose after-hook never ran, a leak without an excerpt."""
    report = sample_reports()[0]
    report.run = {**report.run, "config": None}
    report.faults[0].after = None
    return report


@pytest.mark.parametrize("source", NULL_SAFE_DOTTED)
def test_dotted_names_through_null_objects(source: str) -> None:
    template = parse(source, "t")
    template.check(sample_shape())
    for report in [*sample_reports(), passing_report(), _null_heavy_report()]:
        template.render(view(report.to_dict()))
