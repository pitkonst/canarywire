"""E2E: both routes, raw Anthropic templates, mask-only duty, and Anthropic faults."""

from typing import Any

import pytest
from harness import E2E, Capture, free_port, refgw_spec

pytestmark = [pytest.mark.e2e, pytest.mark.anyio]

BOTH_ROUTES = (
    "target:\n"
    "  routes:\n"
    "    - {protocol: openai-chat, path: /v1/chat/completions}\n"
    "    - {protocol: anthropic-messages, path: /v1/messages}\n"
)

RAW_ANTHROPIC_TEMPLATE = (
    "templates:\n"
    "  claude-only:\n"
    "    protocol: anthropic-messages\n"
    "    canaries: {email: email}\n"
    "    request:\n"
    "      model: canarywire-test\n"
    "      max_tokens: 1024\n"
    "      messages:\n"
    "        - role: user\n"
    "          content: 'Mail {{ email.raw }} please.'\n"
    "    response:\n"
    "      content:\n"
    "        - {type: text, text: 'Sent to {{ email.masked }}.'}\n"
)


def attack(report: dict[str, Any], name: str) -> dict[str, Any]:
    found: dict[str, Any] = next(a for a in report["attacks"] if a["name"] == name)
    return found


def template_segment(name: str) -> str:
    """The `<template>@<route>` part of an attack name, dropping any generator prefix/suffix."""
    if name.startswith("baseline/"):
        return name[len("baseline/") :]
    if name.startswith("fragmentation/"):
        return name[len("fragmentation/") :].rsplit("/", 1)[0]
    if name.startswith("fault/control/"):
        return name[len("fault/control/") :]
    if name.startswith("fault/"):
        return name[len("fault/") :].split("/", 1)[1]
    raise AssertionError(f"unrecognized attack name: {name}")


async def test_both_routes_correct_gateway_passes(e2e: E2E, capture: Capture) -> None:
    (e2e.workdir / "canarywire.yaml").write_text(BOTH_ROUTES)
    gw = refgw_spec(upstream=capture.url, port=free_port())
    await e2e.start_gateway(gw)

    run = await e2e.canarywire(
        "run", "--target", gw.url, "--capture", capture.url, "--config", "canarywire.yaml"
    )

    assert run.returncode == 0, e2e.diagnostics()
    report = e2e.report()
    assert report["version"] == 4
    assert report["duty"] == "restore"
    names = [a["name"] for a in report["attacks"]]
    assert names
    for name in names:
        segment = template_segment(name)
        assert segment.endswith("@openai-chat") or segment.endswith("@anthropic-messages"), name
    assert any(segment_ends(name, "@openai-chat") for name in names)
    assert any(segment_ends(name, "@anthropic-messages") for name in names)


def segment_ends(name: str, suffix: str) -> bool:
    return template_segment(name).endswith(suffix)


async def test_raw_anthropic_template_runs_only_on_its_route(e2e: E2E, capture: Capture) -> None:
    config = (
        BOTH_ROUTES + RAW_ANTHROPIC_TEMPLATE + "generators:\n"
        "  baseline: {templates: [default, claude-only]}\n"
        "  fragmentation: {enabled: false}\n"
        "  fault: {enabled: false}\n"
    )
    (e2e.workdir / "canarywire.yaml").write_text(config)
    gw = refgw_spec(upstream=capture.url, port=free_port())
    await e2e.start_gateway(gw)

    run = await e2e.canarywire(
        "run", "--target", gw.url, "--capture", capture.url, "--config", "canarywire.yaml"
    )

    assert run.returncode == 0, e2e.diagnostics()
    names = {a["name"] for a in e2e.report()["attacks"]}
    assert "baseline/claude-only@anthropic-messages" in names
    assert "baseline/claude-only@openai-chat" not in names
    assert "baseline/default@openai-chat" in names
    assert "baseline/default@anthropic-messages" in names


MASK_ONLY_CONFIG = BOTH_ROUTES + "  duty: mask-only\n"


async def test_mask_only_gateway_and_config_pass_delivered(e2e: E2E, capture: Capture) -> None:
    (e2e.workdir / "canarywire.yaml").write_text(MASK_ONLY_CONFIG)
    gw = refgw_spec(upstream=capture.url, port=free_port(), duty="mask-only")
    await e2e.start_gateway(gw)

    run = await e2e.canarywire(
        "run", "--target", gw.url, "--capture", capture.url, "--config", "canarywire.yaml"
    )

    assert run.returncode == 0, e2e.diagnostics()
    report = e2e.report()
    assert report["duty"] == "mask-only"
    statuses = {a["status"] for a in report["attacks"]}
    assert statuses == {"delivered"}
    assert report["unrestored"] == []


async def test_restoring_gateway_with_mask_only_config_fails_altered(
    e2e: E2E, capture: Capture
) -> None:
    (e2e.workdir / "canarywire.yaml").write_text(MASK_ONLY_CONFIG)
    gw = refgw_spec(upstream=capture.url, port=free_port())  # default duty: restore
    await e2e.start_gateway(gw)

    run = await e2e.canarywire(
        "run", "--target", gw.url, "--capture", capture.url, "--config", "canarywire.yaml"
    )

    assert run.returncode == 1, e2e.diagnostics()
    report = e2e.report()
    assert any(a["status"] == "altered" for a in report["attacks"])
    assert report["unrestored"]
    assert all(item["note"] == "altered under duty mask-only" for item in report["unrestored"])


async def test_mask_only_gateway_with_restore_config_fails(e2e: E2E, capture: Capture) -> None:
    (e2e.workdir / "canarywire.yaml").write_text(BOTH_ROUTES)  # duty defaults to restore
    gw = refgw_spec(upstream=capture.url, port=free_port(), duty="mask-only")
    await e2e.start_gateway(gw)

    run = await e2e.canarywire(
        "run", "--target", gw.url, "--capture", capture.url, "--config", "canarywire.yaml"
    )

    assert run.returncode == 1, e2e.diagnostics()


async def test_route_path_not_served_is_untrusted(e2e: E2E, capture: Capture) -> None:
    config = "target:\n  routes:\n    - {protocol: anthropic-messages, path: /v1/nope}\n"
    (e2e.workdir / "canarywire.yaml").write_text(config)
    gw = refgw_spec(upstream=capture.url, port=free_port())
    await e2e.start_gateway(gw)

    run = await e2e.canarywire(
        "run", "--target", gw.url, "--capture", capture.url, "--config", "canarywire.yaml"
    )

    assert run.returncode == 2, e2e.diagnostics()
    assert e2e.report()["outcome"] == "untrusted"


ANTHROPIC_ONLY_FAULT_CONFIG = (
    "target:\n"
    "  duty: mask-only\n"
    "  routes:\n"
    "    - {protocol: anthropic-messages, path: /v1/messages}\n"
    "generators:\n"
    "  baseline: {templates: [default]}\n"
    "  fragmentation: {enabled: false}\n"
    "faults:\n"
    "  - {name: analyzer-down, before: 'touch analyzer.down', after: 'rm -f analyzer.down',"
    " expect: [refuse, deliver]}\n"
)


async def test_anthropic_only_fault_under_mask_only_is_refused(e2e: E2E, capture: Capture) -> None:
    (e2e.workdir / "canarywire.yaml").write_text(ANTHROPIC_ONLY_FAULT_CONFIG)
    gw = refgw_spec(
        upstream=capture.url,
        port=free_port(),
        duty="mask-only",
        analyzer_down_file=e2e.workdir / "analyzer.down",
    )
    await e2e.start_gateway(gw)

    run = await e2e.canarywire(
        "run", "--target", gw.url, "--capture", capture.url, "--config", "canarywire.yaml"
    )

    assert run.returncode == 0, e2e.diagnostics()
    report = e2e.report()
    assert attack(report, "fault/analyzer-down/default@anthropic-messages")["status"] == "refused"
