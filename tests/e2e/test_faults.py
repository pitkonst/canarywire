"""Faults: the gateway must fail closed while its environment is broken."""

import os
import signal
from typing import Any

import anyio
import pytest
import yaml
from harness import E2E, Capture, free_port, refgw_spec

pytestmark = [pytest.mark.e2e, pytest.mark.anyio]

DOWN = "analyzer.down"
ONLY_BASELINE_DEFAULT = {
    "baseline": {"templates": ["default"]},
    "fragmentation": {"enabled": False},
}


def fault(**entry: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "name": "analyzer-down",
        "before": f"touch {DOWN}",
        "after": f"rm -f {DOWN}",
    }
    base.update(entry)
    return base


def attack(report: dict[str, Any], name: str) -> dict[str, Any]:
    found: dict[str, Any] = next(a for a in report["attacks"] if a["name"] == name)
    return found


async def start(e2e: E2E, capture: Capture, bug: str | None, config: dict[str, Any]) -> str:
    gw = refgw_spec(
        upstream=capture.url, port=free_port(), bug=bug, analyzer_down_file=e2e.workdir / DOWN
    )
    await e2e.start_gateway(gw)
    (e2e.workdir / "canarywire.yaml").write_text(yaml.safe_dump(config))
    return gw.url


async def run(
    e2e: E2E, capture: Capture, faults: list[dict[str, Any]], bug: str | None = None
) -> tuple[int | None, dict[str, Any]]:
    url = await start(e2e, capture, bug, {"faults": faults, "generators": ONLY_BASELINE_DEFAULT})
    proc = await e2e.canarywire(
        "run", "--target", url, "--capture", capture.url, "--config", "canarywire.yaml"
    )
    return proc.returncode, e2e.report()


async def test_correct_gateway_refuses_while_faulted(e2e: E2E, capture: Capture) -> None:
    code, report = await run(e2e, capture, [fault()])
    assert code == 0, e2e.diagnostics()
    assert attack(report, "fault/analyzer-down/default@openai-chat")["status"] == "refused"
    assert attack(report, "baseline/default@openai-chat")["status"] == "restored"
    assert attack(report, "fault/control/default@openai-chat")["status"] == "restored"
    names = [a["name"] for a in report["attacks"]]
    assert names.index("fault/control/default@openai-chat") < names.index(
        "fault/analyzer-down/default@openai-chat"
    )
    assert not (e2e.workdir / DOWN).exists()
    [entry] = report["faults"]
    assert (entry["before"]["exit"], entry["after"]["exit"]) == (0, 0)
    assert (e2e.workdir / "out" / entry["before"]["log"]).is_file()


async def test_fail_open_leaks(e2e: E2E, capture: Capture) -> None:
    code, report = await run(e2e, capture, [fault()], bug="fail-open")
    assert code == 1, e2e.diagnostics()
    assert {leak["attack"] for leak in report["leaks"]} == {
        "fault/analyzer-down/default@openai-chat"
    }


async def test_fault_without_effect(e2e: E2E, capture: Capture) -> None:
    code, report = await run(e2e, capture, [fault(before="true", after="true")])
    assert code == 2, e2e.diagnostics()
    assert attack(report, "fault/analyzer-down/default@openai-chat")["reason"] == (
        "fault had no effect: the answer was restored"
    )


async def test_gateway_down_before_the_run_fails_the_control(e2e: E2E, capture: Capture) -> None:
    (e2e.workdir / DOWN).touch()  # already broken: refusing proves nothing
    code, report = await run(e2e, capture, [fault(before="true", after="true")])
    assert code == 2, e2e.diagnostics()
    assert attack(report, "fault/control/default@openai-chat")["status"] == "untrusted"
    assert attack(report, "fault/analyzer-down/default@openai-chat")["reason"] == (
        "fault control not restored: the gateway must work before it is faulted"
    )
    assert report["faults"][0]["before"] is None


async def test_fault_without_effect_allowed(e2e: E2E, capture: Capture) -> None:
    faults = [fault(before="true", after="true", expect=["refuse", "restore"])]
    code, report = await run(e2e, capture, faults)
    assert code == 0, e2e.diagnostics()
    assert attack(report, "fault/analyzer-down/default@openai-chat")["status"] == "restored"


async def test_failed_before_still_runs_after(e2e: E2E, capture: Capture) -> None:
    code, report = await run(e2e, capture, [fault(before="exit 3", after="touch after.ran")])
    assert code == 2, e2e.diagnostics()
    assert (e2e.workdir / "after.ran").exists()
    assert (
        attack(report, "fault/analyzer-down/default@openai-chat")["reason"]
        == "before-hook failed: exit 3"
    )


async def test_failed_after_skips_later_faults(e2e: E2E, capture: Capture) -> None:
    faults = [
        fault(name="first", after=f"rm -f {DOWN}; exit 1"),
        fault(name="second", before="touch second.ran"),
    ]
    code, report = await run(e2e, capture, faults)
    assert code == 2, e2e.diagnostics()
    assert attack(report, "fault/second/default@openai-chat")["reason"] == (
        "skipped: an earlier fault's after-hook failed"
    )
    assert not (e2e.workdir / "second.ran").exists()
    assert report["faults"][1] == {
        "name": "second",
        "expect": ["refuse"],
        "before": None,
        "after": None,
    }


async def test_sigterm_during_fault_runs_after(e2e: E2E, capture: Capture) -> None:
    config = {
        "faults": [fault(settle_ms=10000)],
        "generators": {"baseline": {"enabled": False}, "fragmentation": {"enabled": False}},
    }
    url = await start(e2e, capture, None, config)
    proc = await e2e.start_canarywire(
        "run", "--target", url, "--capture", capture.url, "--config", "canarywire.yaml"
    )
    with anyio.fail_after(20):
        while not (e2e.workdir / DOWN).exists():
            await anyio.sleep(0.05)
    os.kill(proc.pid, signal.SIGTERM)
    code = await proc.wait(20)
    assert code == 128 + signal.SIGTERM, e2e.diagnostics()
    assert not (e2e.workdir / DOWN).exists()
    assert (e2e.workdir / "out" / "faults" / "analyzer-down.after.log").is_file()
    assert not (e2e.workdir / "out" / "report.json").exists()
