from pathlib import Path

import pytest

from canarywire.config import ConfigError, OutputSpec, ReportSettings
from canarywire.report.outputs import load_outputs, resolve_outputs, write_outputs
from canarywire.report.samples import sample_reports
from canarywire.report.view import view


def settings(*outputs: OutputSpec) -> ReportSettings:
    return ReportSettings(outputs=outputs)


def test_escape_defaults_by_extension(tmp_path: Path) -> None:
    resolved = resolve_outputs(
        settings(
            OutputSpec("builtin:junit", "j.xml"),
            OutputSpec("builtin:markdown", "r.md"),
            OutputSpec("builtin:markdown", "r.html"),
        ),
        tmp_path,
        None,
    )
    assert [r.escape for r in resolved] == ["xml", "none", "xml"]
    assert resolved[0].path == (tmp_path / "j.xml").resolve()


def test_junit_flag_is_cwd_relative_and_checked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    out = tmp_path / "out"
    resolved = resolve_outputs(
        settings(OutputSpec("builtin:markdown", "report.md")), out, Path("junit.xml")
    )
    assert resolved[-1].source == "--junit"
    assert resolved[-1].path == (tmp_path / "junit.xml").resolve()
    with pytest.raises(ConfigError, match=r"--junit: would overwrite report.json"):
        resolve_outputs(settings(), out, Path("out/report.json"))
    with pytest.raises(ConfigError, match=r"--junit: same path as report.outputs\[0\].path"):
        resolve_outputs(settings(OutputSpec("builtin:markdown", "j.xml")), out, Path("out/j.xml"))


def test_missing_template_file_and_static_check(tmp_path: Path) -> None:
    (tmp_path / "bad.mustache").write_text("{{^findings}}{{typo}}{{/findings}}")
    for template, message in [
        ("missing.mustache", r"report.outputs\[0\].template: cannot read"),
        ("bad.mustache", r'report.outputs\[0\].template: bad.mustache:1: unknown name "typo"'),
    ]:
        resolved = resolve_outputs(settings(OutputSpec(template, "x.md")), tmp_path / "out", None)
        with pytest.raises(ConfigError, match=message):
            load_outputs(resolved, tmp_path)


def test_write_continues_after_a_failure(tmp_path: Path) -> None:
    (tmp_path / "out").mkdir()
    (tmp_path / "out" / "blocked").mkdir()  # a directory where a file should go
    resolved = resolve_outputs(
        settings(
            OutputSpec("builtin:markdown", "blocked"), OutputSpec("builtin:junit", "sub/j.xml")
        ),
        tmp_path / "out",
        None,
    )
    errors = write_outputs(view(sample_reports()[0].to_dict()), load_outputs(resolved, tmp_path))
    assert len(errors) == 1
    assert errors[0].startswith(f"canarywire: cannot write {resolved[0].path}: ")
    assert (tmp_path / "out" / "sub" / "j.xml").read_text().startswith("<?xml")


def test_escape_default_ignores_extension_case(tmp_path: Path) -> None:
    resolved = resolve_outputs(
        settings(
            OutputSpec("builtin:junit", "J.XML"),
            OutputSpec("builtin:markdown", "r.HTML"),
            OutputSpec("builtin:markdown", "r.MD"),
        ),
        tmp_path,
        None,
    )
    assert [r.escape for r in resolved] == ["xml", "xml", "none"]
