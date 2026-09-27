"""The fragmentation generator: streamed answers whose event boundaries cut the masked values."""

from __future__ import annotations

from typing import TYPE_CHECKING

import anyio
import httpx

from canarywire.runner import protocols
from canarywire.runner.attacks import (
    ALTERED_NOTE,
    RESTORE,
    AttackResult,
    Unrestored,
    extract_or_record,
    judge_mangled,
    settle,
)
from canarywire.runner.catalog import (
    TemplateError,
    first_placeholders,
    render,
    slotted_strings,
)
from canarywire.runner.consistency import add_note, collision_notes, inconsistencies
from canarywire.runner.messages import ResponseSpec
from canarywire.runner.scan import scan
from canarywire.runner.splits import case_rng, cuts, delays, ordered_cases, pieces

if TYPE_CHECKING:
    from collections.abc import Collection, Mapping, Sequence

    from canarywire.canaries import Canary
    from canarywire.config import FragmentationSettings, Timeouts
    from canarywire.runner.catalog import Occurrence
    from canarywire.runner.consistency import Inconsistent
    from canarywire.runner.messages import UpstreamRequest
    from canarywire.runner.prepare import BoundTemplate
    from canarywire.runner.session import CaptureSession
    from canarywire.runner.splits import Case

GENERATOR = "fragmentation"
STREAM_LOCATION = "stream"
CONTENT_LOCATIONS = {
    "openai-chat": "stream.choices[0].delta.content",
    "anthropic-messages": "stream.delta.text",
}


async def fragmentation(
    session: CaptureSession,
    http: httpx.AsyncClient,
    target_url: str,
    bound: BoundTemplate,
    run_canaries: Sequence[Canary],
    *,
    settings: FragmentationSettings,
    seed: int,
    timeouts: Timeouts,
    duty: str = RESTORE,
) -> list[AttackResult]:
    """Run every configured case over one (template, route) pair.

    `fragmentation/<template>@<route>/baseline` runs first.
    """
    raw = bound.raw()
    expected = bound.module.content_text(render(bound.template.response, raw, raw))
    content_names = {
        name
        for path, names in slotted_strings(bound.template.response)
        if path == bound.module.CONTENT_PATH
        for name in names
    }
    in_content = [canary for canary in bound.canaries if canary.name in content_names]
    if not in_content:
        # Defence in depth: prepare's check_streamed_content rejects such templates first.
        raise TemplateError("response template has no canary in the streamed content")
    results: list[AttackResult] = []
    stream_baseline: str | None = None
    for case in ordered_cases(settings, seed):
        result = await _run_case(
            case,
            session,
            http,
            target_url,
            bound,
            run_canaries,
            settings=settings,
            seed=seed,
            timeouts=timeouts,
            expected=expected,
            in_content=in_content,
            stream_baseline=stream_baseline,
            duty=duty,
        )
        if case.kind == "baseline":
            stream_baseline = result.status
        results.append(result)
    return results


async def _run_case(  # noqa: PLR0917 - one argument per input the case needs
    case: Case,
    session: CaptureSession,
    http: httpx.AsyncClient,
    target_url: str,
    bound: BoundTemplate,
    run_canaries: Sequence[Canary],
    *,
    settings: FragmentationSettings,
    seed: int,
    timeouts: Timeouts,
    expected: str,
    in_content: Sequence[Canary],
    stream_baseline: str | None,
    duty: str,
) -> AttackResult:
    result = AttackResult(f"{GENERATOR}/{bound.label}/{case.name}")
    raw_values = bound.raw()
    protocol = bound.module
    # Seeded by template and case, not route: every route gets the same cuts (spec).
    rng = case_rng(seed, f"{bound.name}/{case.name}")
    problems: list[str] = []
    answered: list[str] = []
    planned: dict[str, int] = {}
    occurrences: list[Occurrence] = []
    streamed: list[str] = []

    async def handle(request: UpstreamRequest) -> ResponseSpec:
        result.upstream_requests += 1
        result.leaks.extend(scan(run_canaries, request))
        answered.append(request.request_id)
        found = extract_or_record(result, bound, problems, request.json)
        if found is None:
            return ResponseSpec(502, "canarywire: masked value not found")
        occurrences.extend(found)
        masked = first_placeholders(found)
        content = protocol.content_text(render(bound.template.response, raw_values, masked))
        streamed.append(content)
        parts = pieces(content, cuts(len(content), case, settings, rng))
        stream = protocol.encode(parts, delays(len(parts), settings, rng))
        planned[request.request_id] = len(stream)
        return ResponseSpec(200, headers=protocol.STREAM_HEADERS, stream=stream)

    body = protocol.stream_request(render(bound.template.request, raw_values, {}))
    headers = {**protocol.EXTRA_HEADERS, **protocol.ACCEPT_STREAM}
    session.handler = handle
    try:
        with anyio.fail_after(timeouts.client_request):
            async with http.stream(
                "POST", target_url.rstrip("/") + bound.route.path, json=body, headers=headers
            ) as response:
                status = response.status_code
                raw = (await response.aread()).decode("utf-8", errors="replace")
    except TimeoutError:
        result.untrusted("timeout: no client response")
        return result
    except (httpx.ConnectTimeout, httpx.PoolTimeout) as exc:
        result.untrusted(f"request error: {exc!r}")
        return result
    except httpx.TimeoutException:
        result.untrusted("timeout: no client response")
        return result
    except httpx.HTTPError as exc:
        result.untrusted(f"request error: {exc!r}")
        return result
    finally:
        session.handler = None
    result.client_status = status
    missing = await session.wait_done(answered, timeouts.upstream_done)
    result.upstream_aborted = aborted_summary(
        answered, session.outcomes, session.delivered, planned
    )
    evaluate_stream(
        result,
        is_baseline=case.kind == "baseline",
        masked_problem=problems[0] if problems else None,
        missing_done=len(missing),
        status=status,
        raw=raw,
        expected=expected,
        canaries=in_content,
        stream_baseline=stream_baseline,
        inconsistent=inconsistencies(occurrences, bound),
        notes=collision_notes(occurrences),
        protocol=bound.route.protocol,
        duty=duty,
        streamed=streamed[-1] if streamed else None,
    )
    return result


def aborted_summary(
    answered: Collection[str],
    outcomes: dict[str, str],
    delivered: dict[str, int],
    planned: dict[str, int],
) -> str | None:
    """`"k/n"` for the first answered request the capture reports `aborted`, else `None`."""
    for request_id in answered:
        if outcomes.get(request_id) == "aborted":
            return f"{delivered.get(request_id, 0)}/{planned.get(request_id, 0)}"
    return None


def _per_duty(
    duty: str, expected: str, streamed: str | None, notes: Mapping[str, str] | None
) -> tuple[str, Mapping[str, str], str | None]:
    """The expected text, the collision notes and the note every entry gets, for the duty."""
    if duty == RESTORE:
        return expected, notes or {}, None
    return (streamed if streamed is not None else expected), {}, ALTERED_NOTE


def evaluate_stream(
    result: AttackResult,
    *,
    is_baseline: bool,
    masked_problem: str | None,
    missing_done: int,
    status: int,
    raw: str,
    expected: str,
    canaries: Sequence[Canary],
    stream_baseline: str | None,
    inconsistent: Sequence[Inconsistent] = (),
    notes: Mapping[str, str] | None = None,
    protocol: str,
    duty: str = RESTORE,
    streamed: str | None = None,
) -> None:
    """Set a case's status from the client stream; first matching rule wins (spec table).

    `protocol` (a route's protocol id) picks the stream decoder and the content location.
    Under `mask-only` the client must see `streamed`, the content streamed upstream in the last
    upstream request, instead of `expected`; mismatches are noted as altered, without collision
    notes.
    """
    if result.upstream_requests == 0:
        result.untrusted("no upstream traffic")
        return
    if judge_mangled(result):
        return
    if masked_problem is not None:
        result.untrusted(masked_problem)
        return
    if missing_done:
        result.untrusted(f"capture did not confirm delivery of {missing_done} upstream response(s)")
        return
    if not httpx.codes.is_success(status):
        if is_baseline:
            result.untrusted(f"stream baseline refused with HTTP {status}, nothing verified")
        elif stream_baseline in (None, "untrusted", "mangled"):
            result.untrusted("stream baseline unverified")
        else:
            result.status = "refused"
            result.reason = f"refused with HTTP {status}"
        return
    result.inconsistent = list(inconsistent)
    expected, notes, duty_note = _per_duty(duty, expected, streamed, notes)
    decoded = protocols.module(protocol).decode(raw)
    if decoded.outcome != "ok":
        result.unrestored.extend(
            Unrestored(
                c.name,
                c.value,
                STREAM_LOCATION,
                expected,
                raw,
                c.template,
                c.type,
                add_note(duty_note, notes.get(c.name)),
            )
            for c in canaries
        )
        settle(result, duty)
        result.reason = f"client stream {decoded.outcome}"
        return
    if decoded.text == expected:
        result.restored += len(canaries)
    else:
        result.unrestored.extend(
            Unrestored(
                c.name,
                c.value,
                CONTENT_LOCATIONS[protocol],
                expected,
                decoded.text,
                c.template,
                c.type,
                add_note(duty_note, notes.get(c.name)),
            )
            for c in canaries
        )
    settle(result, duty)
