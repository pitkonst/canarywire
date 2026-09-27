"""Reports end to end: findings, excerpts, JUnit and the templated Markdown."""

import xml.etree.ElementTree as ET

import pytest
from harness import E2E, Capture, free_port, refgw_spec

pytestmark = [pytest.mark.e2e, pytest.mark.anyio]


async def test_leak_shows_as_finding_junit_failure_and_markdown(e2e: E2E, capture: Capture) -> None:
    gw = refgw_spec(upstream=capture.url, port=free_port(), bug="passthrough")
    await e2e.start_gateway(gw)
    proc = await e2e.canarywire(
        "run",
        "--target",
        gw.url,
        "--capture",
        capture.url,
        "--generators",
        "baseline",
        "--junit",
        "junit.xml",
    )
    assert proc.returncode == 1, e2e.diagnostics()
    report = e2e.report()
    assert report["version"] == 4, e2e.diagnostics()
    leaks = [f for f in report["findings"] if f["kind"] == "leak"]
    assert leaks, e2e.diagnostics()
    leak = leaks[0]
    assert leak["route"] == "openai-chat", e2e.diagnostics()
    values = {c["value"] for c in report["canaries"]}
    assert leak["leak_excerpt"]["match"] in values, e2e.diagnostics()
    assert report["run"]["generators"]["fragmentation"]["enabled"] is False, e2e.diagnostics()
    root = ET.parse(e2e.workdir / "junit.xml").getroot()  # noqa: S314 - our own rendered output
    failed = {tc.get("name") for tc in root.iter("testcase") if tc.find("failure") is not None}
    assert "baseline/default@openai-chat" in failed, e2e.diagnostics()
    markdown = (e2e.workdir / "out" / "report.md").read_text()
    assert markdown.startswith("# canarywire: FAIL"), e2e.diagnostics()
    assert "### 1. Leak: " in markdown, e2e.diagnostics()
