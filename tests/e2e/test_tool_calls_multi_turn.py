"""Tool-call and multi-turn templates against the reference gateway."""

from pathlib import Path
from typing import Any

import pytest
import yaml
from harness import E2E, Capture, free_port, refgw_spec

pytestmark = [pytest.mark.e2e, pytest.mark.anyio]

TEMPLATES = Path(__file__).parents[2] / "src" / "canarywire" / "templates"
ARGS = "body.choices[0].message.tool_calls[0].function.arguments"
FRAG_MT = "fragmentation/multi-turn@openai-chat/"


def statuses(report: dict[str, Any]) -> dict[str, str]:
    return {attack["name"]: attack["status"] for attack in report["attacks"]}


async def run(
    e2e: E2E, capture: Capture, bug: str | None, *extra: str
) -> tuple[int | None, dict[str, Any]]:
    gw = refgw_spec(upstream=capture.url, port=free_port(), bug=bug)
    await e2e.start_gateway(gw)
    proc = await e2e.canarywire("run", "--target", gw.url, "--capture", capture.url, *extra)
    return proc.returncode, e2e.report()


async def test_correct_gateway_passes_new_templates(e2e: E2E, capture: Capture) -> None:
    code, report = await run(e2e, capture, None)
    assert code == 0, e2e.diagnostics()
    seen = statuses(report)
    assert seen["baseline/tool-calls@openai-chat"] == "restored"
    assert seen["baseline/multi-turn@openai-chat"] == "restored"
    assert any(name.startswith("fragmentation/multi-turn@openai-chat/") for name in seen)
    assert report["inconsistent"] == []


async def test_tool_args_bug(e2e: E2E, capture: Capture) -> None:
    code, report = await run(e2e, capture, "tool-args")
    assert code == 1, e2e.diagnostics()
    seen = statuses(report)
    assert seen["baseline/tool-calls@openai-chat"] == "unrestored"
    assert seen["baseline/multi-turn@openai-chat"] == "restored"
    unrestored = [
        u for u in report["unrestored"] if u["attack"] == "baseline/tool-calls@openai-chat"
    ]
    locations = {u["location"] for u in unrestored}
    assert locations == {f"{ARGS}$.card", f"{ARGS}$.iban", f"{ARGS}$.email"}, e2e.diagnostics()


async def test_inconsistent_bug(e2e: E2E, capture: Capture) -> None:
    code, report = await run(e2e, capture, "inconsistent")
    assert code == 1, e2e.diagnostics()
    seen = statuses(report)
    assert seen["baseline/multi-turn@openai-chat"] == "inconsistent"
    assert seen["baseline/tool-calls@openai-chat"] == "inconsistent"
    assert seen["baseline/default@openai-chat"] == "restored"
    streamed = {name: status for name, status in seen.items() if name.startswith(FRAG_MT)}
    assert streamed, e2e.diagnostics()
    assert set(streamed.values()) == {"inconsistent"}, e2e.diagnostics()
    flagged = {x["attack"] for x in report["inconsistent"]}
    assert set(streamed) <= flagged, e2e.diagnostics()
    entry = next(
        x
        for x in report["inconsistent"]
        if x["attack"] == "baseline/multi-turn@openai-chat" and x["instance"] == "email"
    )
    assert len({o["placeholder"] for o in entry["occurrences"]}) == 3, e2e.diagnostics()


async def test_consistency_ignore_opts_out(e2e: E2E, capture: Capture) -> None:
    template = yaml.safe_load((TEMPLATES / "multi-turn.yaml").read_text())
    template["consistency"] = "ignore"
    config = {
        "templates": {"multi-turn": template},
        "generators": {
            "baseline": {"templates": ["multi-turn"]},
            "fragmentation": {"enabled": False},
        },
    }
    (e2e.workdir / "canarywire.yaml").write_text(yaml.safe_dump(config))
    code, report = await run(e2e, capture, "inconsistent", "--config", "canarywire.yaml")
    assert code == 0, e2e.diagnostics()
    assert statuses(report) == {"baseline/multi-turn@openai-chat": "restored"}


async def test_collision_bug(e2e: E2E, capture: Capture) -> None:
    code, report = await run(e2e, capture, "collision")
    assert code == 1, e2e.diagnostics()
    seen = statuses(report)
    assert seen["baseline/multi-turn@openai-chat"] == "unrestored"
    assert seen["baseline/tool-calls@openai-chat"] == "restored"
    assert report["inconsistent"] == []
    note = "instances colleague, email were masked to the same placeholder <EMAIL_1>"
    notes = [
        u["note"] for u in report["unrestored"] if u["attack"] == "baseline/multi-turn@openai-chat"
    ]
    assert note in notes, e2e.diagnostics()
    streamed = [name for name in seen if name.startswith(FRAG_MT)]
    assert streamed, e2e.diagnostics()
    assert {seen[name] for name in streamed} == {"unrestored"}, e2e.diagnostics()
    streamed_notes = {u["note"] for u in report["unrestored"] if u["attack"] in streamed}
    assert note in streamed_notes, e2e.diagnostics()
