from pathlib import Path

import pytest
from live import dead_proxy, free_port, live_server
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from canarywire.capture.app import create_app
from canarywire.capture.recorder import Recorder
from canarywire.config import (
    DEFAULT_ROUTES,
    BaselineSettings,
    FaultSettings,
    FaultSpec,
    FragmentationSettings,
    Generators,
    Timeouts,
)
from canarywire.config import Route as TargetRoute
from canarywire.runner import fault as fault_module
from canarywire.runner import runner as runner_module
from canarywire.runner.hooks import HookResult
from canarywire.runner.runner import RunSettings, execute

pytestmark = pytest.mark.anyio

FAST = Timeouts(capture_connect=2, client_request=5, upstream_response=5)
BASELINE_ONLY = Generators(fragmentation=FragmentationSettings(enabled=False))


async def test_unreachable_capture_is_untrusted() -> None:
    dead = f"http://127.0.0.1:{free_port()}"
    report = await execute(RunSettings(dead, dead, 3, FAST))
    assert report.outcome() == "untrusted"
    assert report.problems()[0].startswith("cannot connect to capture")
    assert report.canaries == []  # nothing was tested
    assert report.finished_at is not None


async def test_target_is_the_capture_itself_so_everything_leaks(tmp_path: Path) -> None:
    """With no gateway in between, the canary reaches the upstream verbatim: a leak."""
    async with live_server(create_app(Recorder(tmp_path / "c.jsonl"))) as url:
        report = await execute(RunSettings(url, url, 3, FAST))
    assert report.negative_control_caught
    assert report.outcome() == "fail"
    assert report.leaks()[0]["location"] == "body.messages[0].content"


async def test_loopback_traffic_ignores_proxy_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A CI proxy in the environment must not swallow traffic to a local gateway or capture."""
    async with live_server(create_app(Recorder(tmp_path / "c.jsonl"))) as url:
        dead_proxy(monkeypatch)
        report = await execute(RunSettings(url, url, 3, FAST, BASELINE_ONLY))
    assert report.trust_problems == []
    assert report.negative_control_caught
    assert report.outcome() == "fail"  # the capture as its own target: everything leaks


async def test_crash_during_an_attack_is_never_a_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A crash inside an attack must be reported untrusted, never a fail-open pass."""

    async def boom(*args: object, **kwargs: object) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(runner_module, "baseline", boom)
    async with live_server(create_app(Recorder(tmp_path / "c.jsonl"))) as url:
        report = await execute(RunSettings(url, url, 3, FAST))
    assert report.outcome() == "untrusted"
    assert any(p.startswith("internal error") for p in report.problems())


# "Lost connection to capture" (session.closed becoming True mid-run) is exercised at the
# capture-socket level by test_runner_lost_mid_request_is_503 in tests/capture/test_app.py.
# Reaching it from the runner side deterministically would mean forcing the capture's
# WebSocket to close mid-attack without a race against the in-flight upstream.request call,
# which needs machinery (a controllable fake capture) beyond what's cheap here; skipped.


async def test_blackhole_target_is_untrusted(tmp_path: Path) -> None:
    async def answer_itself(_: Request) -> Response:
        return JSONResponse({"choices": [{"message": {"content": "hi"}}]})

    blackhole = Starlette(routes=[Route("/v1/chat/completions", answer_itself, methods=["POST"])])
    async with (
        live_server(create_app(Recorder(tmp_path / "c.jsonl"))) as capture,
        live_server(blackhole) as target,
    ):
        report = await execute(RunSettings(target, capture, 3, FAST, BASELINE_ONLY))
    assert report.outcome() == "untrusted"
    assert report.problems() == [
        "baseline/default@openai-chat: no upstream traffic",
        "baseline/tool-calls@openai-chat: no upstream traffic",
        "baseline/multi-turn@openai-chat: no upstream traffic",
    ]


async def test_no_template_is_untrusted_without_a_negative_control_line(tmp_path: Path) -> None:
    nothing = Generators(
        baseline=BaselineSettings(enabled=False), fragmentation=FragmentationSettings(enabled=False)
    )
    async with live_server(create_app(Recorder(tmp_path / "c.jsonl"))) as url:
        report = await execute(RunSettings(url, url, 3, FAST, nothing))
    assert report.outcome() == "untrusted"
    assert report.problems() == ["negative control did not run", "no attack ran"]


async def test_fragmentation_runs_by_default(tmp_path: Path) -> None:
    async with live_server(create_app(Recorder(tmp_path / "c.jsonl"))) as url:
        report = await execute(RunSettings(url, url, 3, FAST))
    names = [a.name for a in report.attacks]
    assert names[:3] == [
        "baseline/default@openai-chat",
        "baseline/tool-calls@openai-chat",
        "baseline/multi-turn@openai-chat",
    ]
    assert names[3] == "fragmentation/default@openai-chat/baseline"
    assert names[19] == "fragmentation/multi-turn@openai-chat/baseline"
    assert len(names) == 35
    assert report.outcome() == "fail"  # target is the capture itself: everything leaks


async def test_generators_can_be_switched_off(tmp_path: Path) -> None:
    only_fragmentation = Generators(baseline=BaselineSettings(enabled=False))
    async with live_server(create_app(Recorder(tmp_path / "c.jsonl"))) as url:
        report = await execute(RunSettings(url, url, 3, FAST, only_fragmentation))
    assert report.attacks[0].name == "fragmentation/default@openai-chat/baseline"


async def test_report_lists_every_default_canary(tmp_path: Path) -> None:
    async with live_server(create_app(Recorder(tmp_path / "c.jsonl"))) as url:
        report = await execute(RunSettings(url, url, 3, FAST))
    assert [(c.template, c.name, c.type) for c in report.canaries] == [
        ("default", "email", "email"),
        ("default", "phone", "phone"),
        ("default", "iban", "iban"),
        ("default", "card", "card"),
        ("default", "national_id", "national_id"),
        ("tool-calls", "card", "card"),
        ("tool-calls", "iban", "iban"),
        ("tool-calls", "email", "email"),
        ("multi-turn", "email", "email"),
        ("multi-turn", "colleague", "email"),
        ("multi-turn", "phone", "phone"),
        ("multi-turn", "card", "card"),
    ]
    assert {leak["type"] for leak in report.leaks()} == {
        "email",
        "phone",
        "iban",
        "card",
        "national_id",
    }
    assert report.to_dict()["negative_control"]["templates"] == [
        {"template": f"{name}@openai-chat", "caught": True, "missed": []}
        for name in ("default", "tool-calls", "multi-turn")
    ]


async def test_faults_listed_even_when_the_capture_is_unreachable() -> None:
    faults = (FaultSpec("down", "true", "true"),)
    unreachable = f"http://127.0.0.1:{free_port()}"
    report = await execute(RunSettings(unreachable, unreachable, 3, FAST, faults=faults))
    assert [(r.name, r.before, r.after) for r in report.faults] == [("down", None, None)]


async def test_no_fault_records_when_the_fault_generator_is_off() -> None:
    faults = (FaultSpec("down", "true", "true"),)
    off = Generators(fault=FaultSettings(enabled=False))
    unreachable = f"http://127.0.0.1:{free_port()}"
    report = await execute(RunSettings(unreachable, unreachable, 3, FAST, off, faults=faults))
    assert report.faults == []


async def test_fault_phase_runs_after_the_other_generators(tmp_path: Path) -> None:
    faults = (FaultSpec("noop", "true", "true", ("refuse", "restore")),)
    async with live_server(create_app(Recorder(tmp_path / "c.jsonl"))) as url:
        settings = RunSettings(
            url,
            url,
            3,
            FAST,
            Generators(
                baseline=BaselineSettings(templates=("default",)),
                fragmentation=FragmentationSettings(enabled=False),
            ),
            faults=faults,
            out_dir=tmp_path,
        )
        report = await execute(settings)
    assert [(a.name, a.status) for a in report.attacks] == [
        ("baseline/default@openai-chat", "restored"),
        ("fault/control/default@openai-chat", "restored"),
        ("fault/noop/default@openai-chat", "restored"),
    ]
    after = report.faults[0].after
    assert after is not None
    assert after.exit == 0
    assert (tmp_path / "faults" / "noop.before.log").exists()
    assert report.interrupted is None


async def test_fault_phase_keeps_earlier_results_when_a_later_hook_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`run_faults(sink=report.attacks)` is wired through `execute`: a raise doesn't lose it."""

    async def flaky_hook(
        command: str, *, fault: str, hook: str, out_dir: Path, timeout: float
    ) -> HookResult:
        if (fault, hook) == ("b", "before"):
            raise OSError("cannot run before")
        return HookResult(0, False, 1, f"faults/{fault}.{hook}.log")

    kwdefaults = fault_module.run_faults.__kwdefaults__
    assert kwdefaults is not None
    monkeypatch.setattr(
        fault_module.run_faults, "__kwdefaults__", {**kwdefaults, "hooks": flaky_hook}
    )
    faults = (
        FaultSpec("a", "true", "true", ("refuse", "restore")),
        FaultSpec("b", "true", "true", ("refuse", "restore")),
    )
    async with live_server(create_app(Recorder(tmp_path / "c.jsonl"))) as url:
        settings = RunSettings(
            url,
            url,
            3,
            FAST,
            Generators(
                baseline=BaselineSettings(templates=("default",)),
                fragmentation=FragmentationSettings(enabled=False),
            ),
            faults=faults,
            out_dir=tmp_path,
        )
        report = await execute(settings)
    fault_attacks = [a for a in report.attacks if a.name.startswith("fault/")]
    assert [a.name for a in fault_attacks] == [
        "fault/control/default@openai-chat",
        "fault/a/default@openai-chat",
        "fault/b/default@openai-chat",
    ]
    assert fault_attacks[1].status == "restored"  # fault "a" ran to completion
    assert (fault_attacks[2].status, fault_attacks[2].reason) == (
        "untrusted",
        "not run: fault phase aborted",
    )
    assert any(p.startswith("internal error") for p in report.trust_problems)


async def test_mask_only_against_the_capture_itself_is_delivered(tmp_path: Path) -> None:
    """No gateway: the answer canarywire sent comes back as is, so every case is delivered."""
    faults = (FaultSpec("noop", "true", "true", ("refuse", "deliver")),)
    async with live_server(create_app(Recorder(tmp_path / "c.jsonl"))) as url:
        report = await execute(
            RunSettings(url, url, 3, FAST, faults=faults, out_dir=tmp_path, duty="mask-only")
        )
    assert report.duty == "mask-only"
    assert report.attacks
    assert {a.status for a in report.attacks} == {"delivered"}, [
        (a.name, a.reason) for a in report.attacks if a.status != "delivered"
    ]
    assert report.to_dict()["verified"] > 0


CLAUDE = TargetRoute("claude", "anthropic-messages", "/v1/messages")
TWO_ROUTES = (DEFAULT_ROUTES[0], CLAUDE)


async def test_two_routes_against_the_capture_itself(tmp_path: Path) -> None:
    """Every generator runs each template on both routes; values and canaries are shared."""
    faults = (FaultSpec("noop", "true", "true", ("refuse", "restore")),)
    async with live_server(create_app(Recorder(tmp_path / "c.jsonl"))) as url:
        report = await execute(
            RunSettings(url, url, 3, FAST, faults=faults, out_dir=tmp_path, routes=TWO_ROUTES)
        )
    labels = [
        f"{t}@{r}"
        for t in ("default", "tool-calls", "multi-turn")
        for r in ("openai-chat", "claude")
    ]
    names = [a.name for a in report.attacks]
    assert names[:6] == [f"baseline/{label}" for label in labels]
    fragmentation = [n for n in names if n.startswith("fragmentation/")]
    assert len(fragmentation) == 4 * 16
    assert [n for n in fragmentation if n.endswith("/baseline")] == [
        f"fragmentation/{t}@{r}/baseline"
        for t in ("default", "multi-turn")
        for r in ("openai-chat", "claude")
    ]
    assert names[-4:] == [
        "fault/control/default@openai-chat",
        "fault/control/default@claude",
        "fault/noop/default@openai-chat",
        "fault/noop/default@claude",
    ]
    assert len(names) == 6 + 64 + 4
    assert {a.status for a in report.attacks} == {"restored"}, [
        (a.name, a.reason) for a in report.attacks if a.status != "restored"
    ]
    assert report.to_dict()["negative_control"]["templates"] == [
        {"template": label, "caught": True, "missed": []} for label in labels
    ]
    assert [(c.template, c.name) for c in report.canaries][:5] == [
        ("default", "email"),
        ("default", "phone"),
        ("default", "iban"),
        ("default", "card"),
        ("default", "national_id"),
    ]
    assert len(report.canaries) == 12
    assert report.outcome() == "fail"  # target is the capture itself: everything leaks
