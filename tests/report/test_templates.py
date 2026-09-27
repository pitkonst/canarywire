import os
import xml.etree.ElementTree as ET
from dataclasses import replace
from pathlib import Path

import pytest

from canarywire.config import BUILTIN_TEMPLATES
from canarywire.report import BUILTINS, builtin_source
from canarywire.report.mustache import parse
from canarywire.report.samples import passing_report, sample_reports, sample_shape
from canarywire.report.view import view

GOLDEN = Path(__file__).parent / "golden"
REPORTS = {
    "failing": lambda: sample_reports()[0],
    "untrusted": lambda: sample_reports()[1],
    "passing": passing_report,
}
CASES = [("builtin:markdown", n, "md", "none") for n in REPORTS] + [
    ("builtin:junit", n, "xml", "xml") for n in ("failing", "passing")
]


def test_builtins_match_config_builtin_templates() -> None:
    assert set(BUILTINS) == set(BUILTIN_TEMPLATES)


@pytest.mark.parametrize("builtin", sorted(BUILTINS))
def test_builtins_pass_the_static_check(builtin: str) -> None:
    parse(builtin_source(builtin), builtin).check(sample_shape())


@pytest.mark.parametrize(("builtin", "report", "ext", "escape"), CASES)
def test_golden(builtin: str, report: str, ext: str, escape: str) -> None:
    template = parse(builtin_source(builtin), builtin)
    rendered = template.render(view(REPORTS[report]().to_dict()), escape)
    path = GOLDEN / f"{report}.{ext}"
    if os.environ.get("CANARYWIRE_UPDATE_GOLDEN") == "1":
        path.write_text(rendered)
    assert rendered == path.read_text()
    if ext == "xml":
        ET.fromstring(rendered.encode())  # noqa: S314 - our own rendered output, not untrusted


def test_junit_counts_match_element_counts() -> None:
    rendered = parse(builtin_source("builtin:junit"), "builtin:junit").render(
        view(sample_reports()[0].to_dict()), "xml"
    )
    root = ET.fromstring(rendered.encode())  # noqa: S314 - our own rendered output, not untrusted
    assert root.get("failures") == str(len(root.findall(".//failure")))
    assert root.get("errors") == str(len(root.findall(".//error")))
    assert root.get("tests") == str(len(root.findall(".//testcase")))


def test_junit_with_control_characters_parses() -> None:
    report = sample_reports()[0]
    [attack] = [a for a in report.attacks if a.inconsistent]
    first = attack.inconsistent[0]
    occurrences = (replace(first.occurrences[0], placeholder="<E\x01>"), *first.occurrences[1:])
    attack.inconsistent[0] = replace(first, occurrences=occurrences)
    rendered = parse(builtin_source("builtin:junit"), "builtin:junit").render(
        view(report.to_dict()), "xml"
    )
    assert "\x01" not in rendered
    root = ET.fromstring(rendered.encode())  # noqa: S314 - our own rendered output, not untrusted
    assert "<E\ufffd>" in "".join(root.itertext())
