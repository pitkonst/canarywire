"""One canarywire run: connect to the capture, run the attacks, collect a Report."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import anyio
import httpx

from canarywire.config import CONTROL, DEFAULT_ROUTES, Config, Generators
from canarywire.loopback import DIRECT_MOUNTS
from canarywire.report import Report, now_iso
from canarywire.runner.attacks import AttackResult, baseline, evaluate, exchange, negative_control
from canarywire.runner.fault import FaultRecord, run_faults
from canarywire.runner.fragmentation import fragmentation
from canarywire.runner.messages import ResponseSpec
from canarywire.runner.prepare import Prepared, prepare
from canarywire.runner.scan import scan
from canarywire.runner.session import CaptureSession, CaptureUnavailableError, open_capture

if TYPE_CHECKING:
    from collections.abc import Sequence

    from canarywire.canaries import Canary
    from canarywire.config import FaultSpec, Route, Timeouts
    from canarywire.runner.attacks import Exchange
    from canarywire.runner.messages import UpstreamRequest
    from canarywire.runner.prepare import BoundTemplate


@dataclass(frozen=True)
class RunSettings:
    """Everything a run needs, after config and CLI merging."""

    target_url: str
    capture_url: str
    seed: int
    timeouts: Timeouts
    generators: Generators = field(default_factory=Generators)
    prepared: Prepared | None = None
    faults: tuple[FaultSpec, ...] = ()
    out_dir: Path = Path("out")
    routes: tuple[Route, ...] = DEFAULT_ROUTES
    duty: str = "restore"


async def execute(settings: RunSettings) -> Report:
    """Run every attack and return the report; never raises Exception (a crash is untrusted)."""
    report = Report(
        seed=settings.seed,
        target=settings.target_url,
        capture_url=settings.capture_url,
        duty=settings.duty,
    )
    if settings.generators.fault.enabled and settings.faults:
        # Listed before anything can fail, so a run that never reaches the faults still shows them.
        report.faults = [FaultRecord(spec.name, spec.expect) for spec in settings.faults]
    try:
        await _execute(settings, report)
    except Exception as exc:
        report.trust_problems.append(f"internal error: {exc!r}")
    report.finished_at = now_iso()
    return report


async def _execute(settings: RunSettings, report: Report) -> None:
    """Connect, run the attacks, fill the report.

    Without `settings.prepared`, values are prepared here from the built-in templates only
    (no inline templates or custom types); the CLI always passes a prepared run.
    """
    if settings.prepared is None:
        config = Config(
            generators=settings.generators,
            faults=settings.faults,
            routes=settings.routes,
            duty=settings.duty,
        )
        prepared = prepare(config, settings.seed)
    else:
        prepared = settings.prepared
    run_canaries = prepared.all_canaries()
    try:
        connection = await open_capture(settings.capture_url, settings.timeouts.capture_connect)
    except CaptureUnavailableError as exc:
        report.trust_problems.append(str(exc))
        return

    async def unexpected(request: UpstreamRequest) -> ResponseSpec:
        report.unexpected_upstream += 1
        report.unexpected_leaks.extend(scan(run_canaries, request))
        return ResponseSpec(404, "canarywire: no attack in progress")

    async with (
        connection,
        httpx.AsyncClient(timeout=settings.timeouts.client_request, mounts=DIRECT_MOUNTS) as http,
    ):
        session = CaptureSession(connection, unexpected)
        async with anyio.create_task_group() as tg:
            tg.start_soon(session.run)
            try:
                await _attacks(settings, report, session, http, prepared, run_canaries)
            except Exception as exc:
                report.trust_problems.append(f"internal error: {exc!r}")
            finally:
                tg.cancel_scope.cancel()


async def _attacks(  # noqa: PLR0917 - one argument per input the attacks need
    settings: RunSettings,
    report: Report,
    session: CaptureSession,
    http: httpx.AsyncClient,
    prepared: Prepared,
    run_canaries: list[Canary],
) -> None:
    try:
        await session.start(
            run_id=uuid.uuid4().hex,
            seed=settings.seed,
            upstream_response_timeout=settings.timeouts.upstream_response,
            timeout=settings.timeouts.capture_connect,
        )
    except CaptureUnavailableError as exc:
        report.trust_problems.append(str(exc))
        return
    report.canaries = run_canaries
    for bound in prepared.templates.values():
        report.negative_controls.append(
            await negative_control(session, http, settings.capture_url, bound)
        )
    report.negative_control_caught = bool(report.negative_controls) and all(
        control.caught for control in report.negative_controls
    )
    if report.negative_controls and not report.negative_control_caught:
        # With no template at all, "negative control did not run" and "no attack ran" say it.
        missed = "; ".join(
            f"{c.template}: {', '.join(c.missed)}" for c in report.negative_controls if not c.caught
        )
        report.trust_problems.append(f"negative control not caught ({missed})")
    generators = settings.generators
    if generators.baseline.enabled:
        for bound in _expand(prepared, generators.baseline.templates):
            report.attacks.append(
                await baseline(
                    session,
                    http,
                    settings.target_url,
                    bound,
                    run_canaries,
                    deadline=settings.timeouts.client_request,
                    duty=settings.duty,
                )
            )
    if generators.fragmentation.enabled:
        for bound in _expand(prepared, generators.fragmentation.templates):
            report.attacks.extend(
                await fragmentation(
                    session,
                    http,
                    settings.target_url,
                    bound,
                    run_canaries,
                    settings=generators.fragmentation,
                    seed=settings.seed,
                    timeouts=settings.timeouts,
                    duty=settings.duty,
                )
            )
    if report.faults:
        await _faults(settings, report, session, http, prepared, run_canaries)
    report.trust_problems.extend(session.errors)
    if session.closed:
        report.trust_problems.append("lost connection to capture")


def _expand(prepared: Prepared, names: Sequence[str]) -> list[BoundTemplate]:
    """A generator's template list as (template, route) pairs: template order, then route order."""
    return [bound for name in names for bound in prepared.bound(name)]


async def _faults(  # noqa: PLR0917 - one argument per input the fault phase needs
    settings: RunSettings,
    report: Report,
    session: CaptureSession,
    http: httpx.AsyncClient,
    prepared: Prepared,
    run_canaries: list[Canary],
) -> None:
    """The fault phase: after the other generators, unfaulted controls, then one fault at a time."""
    templates = _expand(prepared, settings.generators.fault.templates)

    async def send(bound: BoundTemplate, result: AttackResult) -> Exchange | None:
        return await exchange(
            session,
            http,
            settings.target_url,
            bound,
            run_canaries,
            result,
            deadline=settings.timeouts.client_request,
        )

    async def control(bound: BoundTemplate) -> AttackResult:
        # Judged exactly like `baseline`: the gateway must work before faulting it means anything.
        result = AttackResult(f"fault/{CONTROL}/{bound.label}")
        outcome = await send(bound, result)
        if outcome is not None:
            evaluate(
                result,
                masked_problem=outcome.masked_problem,
                status=outcome.status,
                text=outcome.text,
                bound=bound,
                occurrences=outcome.occurrences,
                last_occurrences=outcome.last_occurrences,
                duty=settings.duty,
            )
        return result

    interrupted = await run_faults(
        settings.faults,
        report.faults,
        templates,
        sender=send,
        control=control,
        out_dir=settings.out_dir,
        timeout=settings.timeouts.fault_command,
        trust_problems=report.trust_problems,
        sink=report.attacks,
        duty=settings.duty,
    )
    report.interrupted = interrupted
