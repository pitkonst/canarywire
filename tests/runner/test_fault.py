import json
import os
import signal
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import anyio
import pytest

from canarywire.canaries import Canary
from canarywire.config import DEFAULT_ROUTES, FaultSpec, Route
from canarywire.report import Report
from canarywire.runner.attacks import AttackResult, Exchange, Mangled
from canarywire.runner.catalog import Occurrence, parse_template
from canarywire.runner.fault import FaultRecord, judge_fault, run_faults
from canarywire.runner.hooks import HookResult
from canarywire.runner.prepare import BoundTemplate
from canarywire.runner.scan import Hit

TEMPLATE = parse_template(
    "t",
    {
        "protocol": "openai-chat",
        "canaries": {"email": "email"},
        "request": {"messages": [{"role": "user", "content": "mail {{ email.raw }} now"}]},
        "response": {"choices": [{"message": {"content": "To {{ email.masked }}."}}]},
    },
)
CANARY = Canary("email", "ann.lee1234@example.org", "email", "t")
BOUND = BoundTemplate(TEMPLATE, (CANARY,), DEFAULT_ROUTES[0])
GOOD = json.dumps({"choices": [{"message": {"content": f"To {CANARY.value}."}}]})
BAD = json.dumps({"choices": [{"message": {"content": "To <E1>."}}]})


def judged(outcome: Exchange, expect: tuple[str, ...] = ("refuse",)) -> AttackResult:
    result = AttackResult("fault/f/t")
    judge_fault(result, expect=expect, outcome=outcome, bound=BOUND)
    return result


def test_masked_problem_is_untrusted_even_if_refused() -> None:
    result = judged(Exchange(503, "no", "masked value not found at body.x", []))
    assert (result.status, result.reason) == ("untrusted", "masked value not found at body.x")


@pytest.mark.parametrize("expect", [("refuse",), ("refuse", "restore")])
def test_mangled_wins_even_with_a_500_client_status(expect: tuple[str, ...]) -> None:
    result = AttackResult("fault/f/t")
    result.mangled = [Mangled("body.m", "e", "a")]
    judge_fault(result, expect=expect, outcome=Exchange(500, "no", None, []), bound=BOUND)
    assert (result.status, result.reason) == (
        "mangled",
        "request text changed around a canary at body.m",
    )


def test_non_2xx_is_refused() -> None:
    result = judged(Exchange(503, "no", None, []))
    assert (result.status, result.reason) == ("refused", "refused with HTTP 503")


def test_restored_under_refuse_is_untrusted() -> None:
    result = judged(Exchange(200, GOOD, None, []))
    assert (result.status, result.reason) == (
        "untrusted",
        "fault had no effect: the answer was restored",
    )


def test_restored_allowed_by_expect() -> None:
    assert judged(Exchange(200, GOOD, None, []), ("refuse", "restore")).status == "restored"


def test_unrestored_fails_whatever_expect() -> None:
    assert judged(Exchange(200, BAD, None, [])).status == "unrestored"
    assert judged(Exchange(200, BAD, None, []), ("refuse", "restore")).status == "unrestored"


def test_no_upstream_traffic_is_not_a_rule() -> None:
    result = judged(Exchange(200, BAD, None, []))
    assert result.upstream_requests == 0
    assert result.status == "unrestored"


MASKED = json.dumps({"choices": [{"message": {"content": "To <E1>."}}]})
E1 = [Occurrence("email", "body.messages[0].content", "<E1>")]


def judged_mask_only(outcome: Exchange, expect: tuple[str, ...]) -> AttackResult:
    result = AttackResult("fault/f/t")
    judge_fault(result, expect=expect, outcome=outcome, bound=BOUND, duty="mask-only")
    return result


def test_delivered_allowed_by_expect_under_mask_only() -> None:
    result = judged_mask_only(Exchange(200, MASKED, None, E1, E1), ("refuse", "deliver"))
    assert result.status == "delivered"


def test_delivered_under_refuse_is_untrusted() -> None:
    result = judged_mask_only(Exchange(200, MASKED, None, E1, E1), ("refuse",))
    assert (result.status, result.reason) == (
        "untrusted",
        "fault had no effect: the answer was delivered",
    )


def test_altered_fails_whatever_expect_under_mask_only() -> None:
    assert judged_mask_only(Exchange(200, GOOD, None, E1, E1), ("refuse",)).status == "altered"
    result = judged_mask_only(Exchange(200, GOOD, None, E1, E1), ("refuse", "deliver"))
    assert result.status == "altered"


# --- loop ---------------------------------------------------------------


class Hooks:
    def __init__(
        self,
        exits: dict[tuple[str, str], int | None] | None = None,
        *,
        delays: dict[tuple[str, str], float] | None = None,
        actions: dict[tuple[str, str], Callable[[], None]] | None = None,
        raising: set[tuple[str, str]] | None = None,
    ) -> None:
        self.exits = exits or {}
        self.delays = delays or {}
        self.actions = actions or {}
        self.raising = raising or set()
        self.calls: list[tuple[str, str]] = []
        self.finished: list[tuple[str, str]] = []

    async def __call__(
        self, command: str, *, fault: str, hook: str, out_dir: Path, timeout: float
    ) -> HookResult:
        key = (fault, hook)
        self.calls.append(key)
        if key in self.actions:
            self.actions[key]()
        if key in self.delays:
            await anyio.sleep(self.delays[key])
        if key in self.raising:
            raise OSError(f"cannot run {hook}")
        self.finished.append(key)
        code = self.exits.get(key, 0)
        return HookResult(code, code is None, 1, f"faults/{fault}.{hook}.log")


async def refusing(bound: BoundTemplate, result: AttackResult) -> Exchange | None:
    return Exchange(503, "no", None, [])


async def loop(
    faults: list[FaultSpec],
    hooks: Hooks,
    send: Any = refusing,
    control: Callable[[BoundTemplate], Awaitable[AttackResult]] | None = None,
) -> tuple[list[AttackResult], list[FaultRecord], list[str]]:
    records = [FaultRecord(f.name, f.expect) for f in faults]
    problems: list[str] = []
    results: list[AttackResult] = []
    interrupted = await run_faults(
        faults,
        records,
        [BOUND],
        sender=send,
        hooks=hooks,
        out_dir=Path("out"),
        timeout=5,
        trust_problems=problems,
        sink=results,
        control=control,
    )
    assert interrupted is None
    return results, records, problems


A = FaultSpec("a", "x", "y")
B = FaultSpec("b", "x", "y")


@pytest.mark.anyio
async def test_refused_fault() -> None:
    hooks = Hooks()
    results, records, problems = await loop([A], hooks)
    assert [(r.name, r.status) for r in results] == [("fault/a/t@openai-chat", "refused")]
    assert hooks.calls == [("a", "before"), ("a", "after")]
    assert records[0].before is not None
    assert records[0].after is not None
    assert problems == []


@pytest.mark.anyio
async def test_before_failure_skips_requests_but_runs_after() -> None:
    hooks = Hooks({("a", "before"): 3})
    sent: list[str] = []

    async def send(bound: BoundTemplate, result: AttackResult) -> Exchange | None:
        sent.append(bound.name)
        return Exchange(503, "", None, [])

    results, _, _ = await loop([A], hooks, send)
    assert (results[0].status, results[0].reason) == ("untrusted", "before-hook failed: exit 3")
    assert sent == []
    assert hooks.calls == [("a", "before"), ("a", "after")]


@pytest.mark.anyio
async def test_before_timeout_reason() -> None:
    results, _, _ = await loop([A], Hooks({("a", "before"): None}))
    assert results[0].reason == "before-hook timed out after 5 s"


@pytest.mark.anyio
async def test_after_failure_skips_later_faults() -> None:
    hooks = Hooks({("a", "after"): 1})
    results, records, problems = await loop([A, B], hooks)
    assert problems == ["fault a: after-hook failed (exit 1); environment may still be faulted"]
    assert (results[1].name, results[1].status, results[1].reason) == (
        "fault/b/t@openai-chat",
        "untrusted",
        "skipped: an earlier fault's after-hook failed",
    )
    assert ("b", "before") not in hooks.calls
    assert (records[1].before, records[1].after) == (None, None)


@pytest.mark.anyio
async def test_after_timeout_problem() -> None:
    _, _, problems = await loop([A], Hooks({("a", "after"): None}))
    assert problems == ["fault a: after-hook timed out after 5 s; environment may still be faulted"]


@pytest.mark.anyio
async def test_after_runs_when_sending_raises() -> None:
    hooks = Hooks()

    async def boom(bound: BoundTemplate, result: AttackResult) -> Exchange | None:
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError, match="boom"):
        await loop([A], hooks, boom)
    assert hooks.calls == [("a", "before"), ("a", "after")]


@pytest.mark.anyio
async def test_after_runs_when_cancelled() -> None:
    hooks = Hooks()

    async def hang(bound: BoundTemplate, result: AttackResult) -> Exchange | None:
        await anyio.sleep(30)
        return None

    with anyio.move_on_after(0.2):
        await loop([A], hooks, hang)
    assert hooks.calls == [("a", "before"), ("a", "after")]


@pytest.mark.anyio
async def test_settle_waits() -> None:
    sent_at: list[float] = []

    async def send(bound: BoundTemplate, result: AttackResult) -> Exchange | None:
        sent_at.append(anyio.current_time())
        return Exchange(503, "", None, [])

    start = anyio.current_time()
    await loop([FaultSpec("a", "x", "y", settle_ms=200)], Hooks(), send)
    assert anyio.current_time() - start >= 0.2
    assert len(sent_at) == 1
    assert sent_at[0] - start >= 0.2


@pytest.mark.anyio
async def test_after_runs_when_cancelled_during_before() -> None:
    hooks = Hooks(delays={("a", "before"): 30})
    with anyio.move_on_after(0.2):
        await loop([A], hooks)
    assert hooks.calls == [("a", "before"), ("a", "after")]
    assert hooks.finished == [("a", "after")]


@pytest.mark.anyio
async def test_after_hook_raising_is_a_trust_problem_and_skips_later_faults() -> None:
    hooks = Hooks(raising={("a", "after")})
    results, records, problems = await loop([A, B], hooks)
    assert records[0].after is None
    assert problems == [
        "fault a: after-hook could not run (OSError('cannot run after')); "
        "environment may still be faulted"
    ]
    assert results[0].status == "refused"
    assert results[1].reason == "skipped: an earlier fault's after-hook failed"
    assert ("b", "before") not in hooks.calls


@pytest.mark.anyio
async def test_after_hook_raising_keeps_the_send_error() -> None:
    hooks = Hooks(raising={("a", "after")})

    async def boom(bound: BoundTemplate, result: AttackResult) -> Exchange | None:
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError, match="boom"):
        await loop([A], hooks, boom)
    assert hooks.calls == [("a", "before"), ("a", "after")]


@pytest.mark.anyio
async def test_fault_results_survive_a_later_hooks_exception() -> None:
    """A control and the first fault's attack (with its leak) stay in the report."""
    hooks = Hooks(raising={("b", "before")})

    async def leaking_then_refusing(bound: BoundTemplate, result: AttackResult) -> Exchange | None:
        result.leaks.append(Hit("email", CANARY.value, "body.messages[0].content", "t", "email"))
        return Exchange(503, "no", None, [])

    report = Report(seed=0, target="t", capture_url="c", started_at="s")
    report.negative_control_caught = True
    records = [FaultRecord(A.name, A.expect), FaultRecord(B.name, B.expect)]
    try:
        await run_faults(
            [A, B],
            records,
            [BOUND],
            sender=leaking_then_refusing,
            hooks=hooks,
            out_dir=Path("out"),
            timeout=5,
            trust_problems=report.trust_problems,
            sink=report.attacks,
            control=controlled("restored"),
        )
    except OSError as exc:
        report.trust_problems.append(f"internal error: {exc!r}")

    names = [a.name for a in report.attacks]
    assert names == [
        "fault/control/t@openai-chat",
        "fault/a/t@openai-chat",
        "fault/b/t@openai-chat",
    ]
    leaking = report.attacks[1]
    assert [(hit.canary, hit.value) for hit in leaking.leaks] == [("email", CANARY.value)]
    aborted = report.attacks[2]
    assert (aborted.status, aborted.reason) == ("untrusted", "not run: fault phase aborted")
    assert any("internal error" in p for p in report.trust_problems)
    assert report.outcome() == "fail"


# --- control requests ---------------------------------------------------


def controlled(status: str) -> Callable[[BoundTemplate], Awaitable[AttackResult]]:
    async def control(bound: BoundTemplate) -> AttackResult:
        result = AttackResult(f"fault/control/{bound.label}")
        if status == "restored":
            result.status = "restored"
        else:
            result.untrusted("refused with HTTP 503, nothing verified")
        return result

    return control


@pytest.mark.anyio
async def test_failing_control_untrusts_every_fault_and_runs_no_hook() -> None:
    hooks = Hooks()
    results, records, problems = await loop([A, B], hooks, control=controlled("untrusted"))
    assert [r.name for r in results] == [
        "fault/control/t@openai-chat",
        "fault/a/t@openai-chat",
        "fault/b/t@openai-chat",
    ]
    reason = "fault control not restored: the gateway must work before it is faulted"
    assert [(r.status, r.reason) for r in results[1:]] == [("untrusted", reason)] * 2
    assert hooks.calls == []
    assert [(r.before, r.after) for r in records] == [(None, None), (None, None)]
    assert problems == []


@pytest.mark.anyio
async def test_restored_control_lets_faults_run() -> None:
    hooks = Hooks()
    results, _, _ = await loop([A], hooks, control=controlled("restored"))
    assert [(r.name, r.status) for r in results] == [
        ("fault/control/t@openai-chat", "restored"),
        ("fault/a/t@openai-chat", "refused"),
    ]
    assert hooks.calls == [("a", "before"), ("a", "after")]


def fixed_control(status: str) -> Callable[[BoundTemplate], Awaitable[AttackResult]]:
    async def control(bound: BoundTemplate) -> AttackResult:
        return AttackResult(f"fault/control/{bound.label}", status=status)

    return control


async def mask_only_loop(control_status: str) -> tuple[list[AttackResult], Hooks]:
    hooks = Hooks()

    async def delivering(bound: BoundTemplate, result: AttackResult) -> Exchange | None:
        return Exchange(200, MASKED, None, E1, E1)

    spec = FaultSpec("a", "x", "y", ("refuse", "deliver"))
    results: list[AttackResult] = []
    interrupted = await run_faults(
        [spec],
        [FaultRecord(spec.name, spec.expect)],
        [BOUND],
        sender=delivering,
        hooks=hooks,
        out_dir=Path("out"),
        timeout=5,
        trust_problems=[],
        sink=results,
        control=fixed_control(control_status),
        duty="mask-only",
    )
    assert interrupted is None
    return results, hooks


@pytest.mark.anyio
async def test_delivered_control_lets_faults_run_under_mask_only() -> None:
    results, hooks = await mask_only_loop("delivered")
    assert [(r.name, r.status) for r in results] == [
        ("fault/control/t@openai-chat", "delivered"),
        ("fault/a/t@openai-chat", "delivered"),
    ]
    assert hooks.calls == [("a", "before"), ("a", "after")]


@pytest.mark.anyio
async def test_control_must_be_delivered_under_mask_only() -> None:
    results, hooks = await mask_only_loop("restored")
    assert (results[1].status, results[1].reason) == (
        "untrusted",
        "fault control not delivered: the gateway must work before it is faulted",
    )
    assert hooks.calls == []


@pytest.mark.anyio
@pytest.mark.parametrize("signum", [signal.SIGTERM, signal.SIGINT])
async def test_signal_during_a_fault_runs_after_and_reports_the_signal(signum: int) -> None:
    hooks = Hooks()

    async def signal_self(bound: BoundTemplate, result: AttackResult) -> Exchange | None:
        os.kill(os.getpid(), signum)
        await anyio.sleep(5)
        return None

    records = [FaultRecord(A.name, A.expect), FaultRecord(B.name, B.expect)]
    results: list[AttackResult] = []
    interrupted = await run_faults(
        [A, B],
        records,
        [BOUND],
        sender=signal_self,
        hooks=hooks,
        out_dir=Path("out"),
        timeout=5,
        trust_problems=[],
        sink=results,
    )
    assert interrupted == signum
    assert hooks.calls == [("a", "before"), ("a", "after")]
    assert [(r.name, r.reason) for r in results] == [("fault/a/t@openai-chat", "interrupted")]


@pytest.mark.anyio
async def test_second_signal_during_after_is_absorbed() -> None:
    def signal_again() -> None:
        os.kill(os.getpid(), signal.SIGINT)
        os.kill(os.getpid(), signal.SIGTERM)

    hooks = Hooks(delays={("a", "after"): 0.5}, actions={("a", "after"): signal_again})

    async def signal_self(bound: BoundTemplate, result: AttackResult) -> Exchange | None:
        os.kill(os.getpid(), signal.SIGINT)
        await anyio.sleep(5)
        return None

    records = [FaultRecord(A.name, A.expect)]
    interrupted = await run_faults(
        [A],
        records,
        [BOUND],
        sender=signal_self,
        hooks=hooks,
        out_dir=Path("out"),
        timeout=5,
        trust_problems=[],
        sink=[],
    )
    assert interrupted == signal.SIGINT
    assert hooks.finished == [("a", "before"), ("a", "after")]
    assert records[0].after is not None


@pytest.mark.anyio
async def test_one_attack_and_one_control_per_route() -> None:
    claude = BoundTemplate(TEMPLATE, (CANARY,), Route("claude", "anthropic-messages", "/m"))
    sent: list[str] = []

    async def send(bound: BoundTemplate, result: AttackResult) -> Exchange | None:
        sent.append(bound.label)
        return Exchange(503, "no", None, [])

    results: list[AttackResult] = []
    await run_faults(
        [A],
        [FaultRecord(A.name, A.expect)],
        [BOUND, claude],
        sender=send,
        hooks=Hooks(),
        out_dir=Path("out"),
        timeout=5,
        trust_problems=[],
        sink=results,
        control=controlled("restored"),
    )
    assert [(r.name, r.status) for r in results] == [
        ("fault/control/t@openai-chat", "restored"),
        ("fault/control/t@claude", "restored"),
        ("fault/a/t@openai-chat", "refused"),
        ("fault/a/t@claude", "refused"),
    ]
    assert sent == ["t@openai-chat", "t@claude"]
