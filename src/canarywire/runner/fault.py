"""The fault generator: break the environment, send templated requests, repair it."""

from __future__ import annotations

import signal
from dataclasses import dataclass
from typing import TYPE_CHECKING

import anyio
import httpx

from canarywire.config import ok_word
from canarywire.runner.attacks import (
    RESTORE,
    AttackResult,
    check_response,
    judge_mangled,
    ok_status,
)
from canarywire.runner.hooks import HookResult, run_hook

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Sequence
    from pathlib import Path

    from anyio.abc import TaskStatus

    from canarywire.config import FaultSpec
    from canarywire.runner.attacks import Exchange
    from canarywire.runner.prepare import BoundTemplate

    HookRunner = Callable[..., Awaitable[HookResult]]
    Sender = Callable[[BoundTemplate, AttackResult], Awaitable[Exchange | None]]
    Control = Callable[[BoundTemplate], Awaitable[AttackResult]]

GENERATOR = "fault"
SKIPPED = "skipped: an earlier fault's after-hook failed"
NO_EFFECT = "fault had no effect: the answer was {status}"
INTERRUPTED = "interrupted"
ABORTED = "not run: fault phase aborted"
CONTROL_FAILED = "fault control not {status}: the gateway must work before it is faulted"


@dataclass
class FaultRecord:
    """What one configured fault did; a hook is None until it has run."""

    name: str
    expect: tuple[str, ...]
    before: HookResult | None = None
    after: HookResult | None = None


def judge_fault(
    result: AttackResult,
    *,
    expect: tuple[str, ...],
    outcome: Exchange,
    bound: BoundTemplate,
    duty: str = RESTORE,
) -> None:
    """Judge one answer given while a fault is in effect (the spec's rules 3-5).

    A success (`restored`, or `delivered` under `mask-only`) is allowed only when `expect` has
    the duty's word (`restore` or `deliver`); otherwise the fault had no effect. A mangled
    request fails the attack even when the client got a 4xx/5xx from the gateway.
    """
    if judge_mangled(result):
        return
    if outcome.masked_problem is not None:
        result.untrusted(outcome.masked_problem)
        return
    if not httpx.codes.is_success(outcome.status):
        result.status = "refused"
        result.reason = f"refused with HTTP {outcome.status}"
        return
    check_response(
        result,
        text=outcome.text,
        bound=bound,
        occurrences=outcome.occurrences,
        last_occurrences=outcome.last_occurrences,
        duty=duty,
    )
    success = ok_status(duty)
    if result.status == success and ok_word(duty) not in expect:
        result.untrusted(NO_EFFECT.format(status=success))


async def run_faults(
    faults: Sequence[FaultSpec],
    records: Sequence[FaultRecord],
    templates: Sequence[BoundTemplate],
    *,
    sender: Sender,
    hooks: HookRunner = run_hook,
    out_dir: Path,
    timeout: float,
    trust_problems: list[str],
    sink: list[AttackResult],
    control: Control | None = None,
    duty: str = RESTORE,
) -> int | None:
    """Run every fault in config order; return the interrupting signal, if any.

    Every control and fault attack is appended to `sink` as soon as it exists (control results
    right after they are judged; a fault's attacks before the fault runs, so they survive even
    if a later hook raises). `templates` holds (template, route) pairs. First, `control` (when
    given) sends one unfaulted request per pair, named `fault/control/<template>@<route>`;
    unless every control is restored (`delivered` under duty `mask-only`), every fault's attacks
    are untrusted and no hook runs. A fault's `after` hook always runs once its turn has come. A
    failed `after` hook is a trust problem and makes every later fault untrusted without running
    it.
    """
    skip: str | None = None
    if control is not None:
        controls: list[AttackResult] = []
        for bound in templates:
            result = await control(bound)
            controls.append(result)
            sink.append(result)
        success = ok_status(duty)
        if any(result.status != success for result in controls):
            skip = CONTROL_FAILED.format(status=success)
    for spec, record in zip(faults, records, strict=True):
        attacks = [AttackResult(f"{GENERATOR}/{spec.name}/{bound.label}") for bound in templates]
        sink.extend(attacks)
        if skip is not None:
            for attack in attacks:
                attack.untrusted(skip)
            continue
        try:
            interrupted = await _one(
                spec,
                record,
                templates,
                attacks,
                sender,
                hooks,
                out_dir,
                timeout,
                trust_problems,
                duty=duty,
            )
        except Exception:
            # A judged attack (restored/refused/leaked/…) or one marked "interrupted" by _one
            # keeps its reason; only an attack _one never touched is left unexplained.
            for attack in attacks:
                if attack.status == "untrusted" and attack.reason is None:
                    attack.untrusted(ABORTED)
            raise
        after = record.after
        if after is None:  # the after-hook itself raised; _one recorded the trust problem
            skip = SKIPPED
        elif after.timed_out or after.exit != 0:
            skip = SKIPPED
            detail = (
                f"timed out after {timeout:g} s"
                if after.timed_out
                else f"failed (exit {after.exit})"
            )
            trust_problems.append(
                f"fault {spec.name}: after-hook {detail}; environment may still be faulted"
            )
        if interrupted is not None:
            return interrupted
    return None


async def _one(  # noqa: PLR0917 - one argument per input the fault needs
    spec: FaultSpec,
    record: FaultRecord,
    templates: Sequence[BoundTemplate],
    attacks: list[AttackResult],
    sender: Sender,
    hooks: HookRunner,
    out_dir: Path,
    timeout: float,
    trust_problems: list[str],
    *,
    duty: str,
) -> int | None:
    """One fault: before, settle, requests, then after in a shielded scope, whatever happened.

    SIGINT and SIGTERM cancel the fault instead of killing the process; the caller turns the
    returned signal number into an exit status. The signal receiver stays open until `after` has
    finished, so a second signal during `after` is absorbed; the first one is reported. Errors
    from the requests are kept out of the task group (which would wrap them) and re-raised after
    `after` has run. An error raised by `after` itself becomes a trust problem, with
    `record.after` left None.
    """
    interrupted: int | None = None
    error: Exception | None = None
    body = anyio.CancelScope()

    async def watch(*, task_status: TaskStatus[None] = anyio.TASK_STATUS_IGNORED) -> None:
        nonlocal interrupted
        with anyio.open_signal_receiver(signal.SIGINT, signal.SIGTERM) as signals:
            task_status.started()
            async for signum in signals:  # until the task group is cancelled, after `after`
                if interrupted is None:
                    interrupted = signum
                    body.cancel()

    async with anyio.create_task_group() as tg:
        await tg.start(watch)  # signals are caught from here on, before `before` runs
        try:
            with body:
                try:
                    await _break_and_send(
                        spec,
                        record,
                        templates,
                        attacks,
                        sender,
                        hooks,
                        out_dir,
                        timeout,
                        duty=duty,
                    )
                except Exception as exc:  # re-raised below, after the after-hook
                    error = exc
        finally:
            with anyio.CancelScope(shield=True):
                try:
                    record.after = await hooks(
                        spec.after, fault=spec.name, hook="after", out_dir=out_dir, timeout=timeout
                    )
                except Exception as exc:  # never leaves the task group; later faults are skipped
                    record.after = None
                    trust_problems.append(
                        f"fault {spec.name}: after-hook could not run ({exc!r}); "
                        "environment may still be faulted"
                    )
            tg.cancel_scope.cancel()
    if interrupted is not None:
        for attack in attacks:
            if attack.status == "untrusted" and attack.reason is None:
                attack.untrusted(INTERRUPTED)
    if error is not None:
        raise error
    return interrupted


async def _break_and_send(  # noqa: PLR0917 - one argument per input the fault needs
    spec: FaultSpec,
    record: FaultRecord,
    templates: Sequence[BoundTemplate],
    attacks: list[AttackResult],
    sender: Sender,
    hooks: HookRunner,
    out_dir: Path,
    timeout: float,
    *,
    duty: str,
) -> None:
    record.before = await hooks(
        spec.before, fault=spec.name, hook="before", out_dir=out_dir, timeout=timeout
    )
    if record.before.timed_out or record.before.exit != 0:
        reason = (
            f"before-hook timed out after {timeout:g} s"
            if record.before.timed_out
            else f"before-hook failed: exit {record.before.exit}"
        )
        for attack in attacks:
            attack.untrusted(reason)
        return
    if spec.settle_ms:
        await anyio.sleep(spec.settle_ms / 1000)
    for bound, attack in zip(templates, attacks, strict=True):
        outcome = await sender(bound, attack)
        if outcome is not None:
            judge_fault(attack, expect=spec.expect, outcome=outcome, bound=bound, duty=duty)
