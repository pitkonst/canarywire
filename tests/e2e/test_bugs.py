"""Growth rule: every reference-gateway bug is caught with its expected exit code on both routes."""

import ast
import importlib.util
import sys
from collections.abc import Callable
from typing import Any

import httpx
import pytest
from harness import E2E, REFGW, Capture, free_port, refgw_spec

pytestmark = [pytest.mark.e2e, pytest.mark.anyio]


def _load_refgw() -> Any:
    """Load refgw.py straight from its file path (never imported as a package)."""
    spec = importlib.util.spec_from_file_location("_refgw_under_test", REFGW)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_refgw = _load_refgw()
mangle: Callable[[Any], Any] = _refgw.mangle
build_outbound_content = _refgw.build_outbound_content

EXPECTED_EXIT = {
    "passthrough": 1,
    "blackhole": 2,
    "split-sse": 1,
    "tool-args": 1,
    "inconsistent": 1,
    "collision": 1,
    "fail-open": 1,
    "mangle": 1,
    "key-leak": 1,
}
# Bugs that only show under a fault: the run gets this config (the fault stops the analyzer).
FAULT_CONFIG = (
    "faults:\n"
    "  - {name: analyzer-down, before: 'touch analyzer.down', after: 'rm -f analyzer.down'}\n"
)
NEEDS_FAULT = {"fail-open"}
ROUTES = ("openai-chat", "anthropic-messages")
# Config selecting only one route: the run's traffic all carries that route's `@<route>` suffix.
ROUTE_PATH = {"openai-chat": "/v1/chat/completions", "anthropic-messages": "/v1/messages"}
ROUTE_CONFIG = {
    route: f"target:\n  routes:\n    - {{protocol: {route}, path: {path}}}\n"
    for route, path in ROUTE_PATH.items()
}


def declared_bugs() -> set[str]:
    for node in ast.walk(ast.parse(REFGW.read_text())):
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "BUGS" for t in node.targets
        ):
            return set(ast.literal_eval(node.value))
    raise AssertionError("refgw.py declares no BUGS")


def test_every_bug_has_an_expectation() -> None:
    assert declared_bugs() == set(EXPECTED_EXIT)


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("bug", sorted(EXPECTED_EXIT))
async def test_every_bug_is_caught(e2e: E2E, capture: Capture, bug: str, route: str) -> None:
    gw = refgw_spec(
        upstream=capture.url,
        port=free_port(),
        bug=bug,
        analyzer_down_file=e2e.workdir / "analyzer.down",
    )
    await e2e.start_gateway(gw)
    config = ROUTE_CONFIG[route] + (FAULT_CONFIG if bug in NEEDS_FAULT else "")
    (e2e.workdir / "canarywire.yaml").write_text(config)

    run = await e2e.canarywire(
        "run", "--target", gw.url, "--capture", capture.url, "--config", "canarywire.yaml"
    )

    assert run.returncode == EXPECTED_EXIT[bug], e2e.diagnostics()
    report = e2e.report()
    assert report["outcome"] != "pass"
    if bug == "split-sse" and route == "anthropic-messages":
        assert any(
            a["name"].startswith("fragmentation/") and f"@{route}/" in a["name"]
            for a in report["attacks"]
            if a["status"] == "unrestored"
        ), report["attacks"]


def test_mangle_helper_cuts_after_the_last_space() -> None:
    doc = {
        "a": "Please update <EMAIL_1>, thanks.",
        "b": "no placeholder here",
        "c": "<EMAIL_1>",
        "d": '{"card": "<CARD_1>" }',
    }

    result = mangle(doc)

    assert result["a"] == "Please update <EMAIL_1>,"
    assert result["b"] == "no placeholder here"
    assert result["c"] == "<EMAIL_1>"
    assert result["d"] == '{"card": "<CARD_1>" }'


def test_build_outbound_content_matches_httpx_json_serialization() -> None:
    """Non-key-leak bugs must send the exact bytes httpx's `json=` would have sent."""
    doc = {"a": "café", "b": [1, 2], "c": None}
    content, content_type = build_outbound_content(doc, doc, None)
    assert content == httpx.Request("POST", "http://example", json=doc).content
    assert content_type == "application/json"


def test_key_leak_bug_skips_the_splice_for_a_non_dict_body() -> None:
    original = {"messages": [{"content": "mail ann@example.org"}]}
    outbound = [{"role": "user", "content": "mail <EMAIL_1>"}]
    content, _ = build_outbound_content(outbound, original, "key-leak")
    assert b"metadata" not in content


async def test_mangle_bug_reports_mangled(e2e: E2E, capture: Capture) -> None:
    gw = refgw_spec(upstream=capture.url, port=free_port(), bug="mangle")
    await e2e.start_gateway(gw)
    run = await e2e.canarywire(
        "run", "--target", gw.url, "--capture", capture.url, "--generators", "baseline"
    )
    assert run.returncode == 1, e2e.diagnostics()
    report = e2e.report()
    statuses = {a["name"]: a["status"] for a in report["attacks"]}
    assert statuses["baseline/default@openai-chat"] == "mangled", e2e.diagnostics()
    assert statuses["baseline/tool-calls@openai-chat"] == "mangled", e2e.diagnostics()
    assert any(f["kind"] == "mangled" for f in report["findings"]), e2e.diagnostics()
    assert any("{{email}}" in e["expected"] for e in report["mangled"]), e2e.diagnostics()
    assert not any(e["actual"].endswith("Thanks.") for e in report["mangled"]), e2e.diagnostics()


async def test_key_leak_bug_reports_a_key_hit(e2e: E2E, capture: Capture) -> None:
    gw = refgw_spec(upstream=capture.url, port=free_port(), bug="key-leak")
    await e2e.start_gateway(gw)
    run = await e2e.canarywire(
        "run", "--target", gw.url, "--capture", capture.url, "--generators", "baseline"
    )
    assert run.returncode == 1, e2e.diagnostics()
    report = e2e.report()
    assert report["outcome"] != "pass", e2e.diagnostics()
    assert any(
        f["kind"] == "leak" and f["location"].endswith("{key}") for f in report["findings"]
    ), e2e.diagnostics()
