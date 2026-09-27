"""Attacks: each sends client requests and answers the upstream requests they cause."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import anyio
import httpx

from canarywire.runner.catalog import (
    MaskedValueNotFoundError,
    RequestMangledError,
    extract_occurrences,
    first_placeholders,
    render,
)
from canarywire.runner.consistency import add_note, collision_notes, inconsistencies
from canarywire.runner.messages import ResponseSpec, json_response
from canarywire.runner.restore import compare_response
from canarywire.runner.scan import Hit, scan

if TYPE_CHECKING:
    from collections.abc import Sequence

    from canarywire.canaries import Canary
    from canarywire.runner.catalog import Occurrence
    from canarywire.runner.consistency import Inconsistent
    from canarywire.runner.messages import UpstreamRequest
    from canarywire.runner.prepare import BoundTemplate
    from canarywire.runner.session import CaptureSession

RESTORE = "restore"
ALTERED_NOTE = "altered under duty mask-only"
MANGLED = "mangled"


def ok_status(duty: str) -> str:
    """The status of an answer that came back as the duty requires."""
    return "restored" if duty == RESTORE else "delivered"


def fail_status(duty: str) -> str:
    """The status of an answer that did not come back as the duty requires."""
    return "unrestored" if duty == RESTORE else "altered"


@dataclass(frozen=True)
class Unrestored:
    """A templated string of the client response that did not come back as expected."""

    canary: str
    value: str
    location: str
    expected: str | None
    actual: str | None
    template: str = ""
    type: str = ""
    note: str | None = None


@dataclass(frozen=True)
class Mangled:
    """A request slot whose upstream text was recognisably the template's, but changed."""

    location: str
    expected: str
    actual: str
    template: str = ""


@dataclass(frozen=True)
class NegativeControl:
    """Whether a (template, route) pair's canaries were caught when sent straight to the capture.

    `template` is the pair's label, `<template>@<route>`.
    """

    template: str
    caught: bool
    missed: tuple[str, ...]


@dataclass
class AttackResult:
    """What one attack observed."""

    name: str
    status: str = "untrusted"
    reason: str | None = None
    client_status: int | None = None
    upstream_requests: int = 0
    leaks: list[Hit] = field(default_factory=list)
    restored: int = 0
    unrestored: list[Unrestored] = field(default_factory=list)
    inconsistent: list[Inconsistent] = field(default_factory=list)
    upstream_aborted: str | None = None
    mangled: list[Mangled] = field(default_factory=list)

    def untrusted(self, reason: str) -> None:
        """Mark the attack untrusted."""
        self.status = "untrusted"
        self.reason = reason


def judge_mangled(result: AttackResult) -> bool:
    """A gateway that changed request text around a canary fails the attack (spec)."""
    if not result.mangled:
        return False
    result.status = MANGLED
    result.reason = f"request text changed around a canary at {result.mangled[0].location}"
    return True


def extract_or_record(
    result: AttackResult, bound: BoundTemplate, problems: list[str], request_json: Any
) -> list[Occurrence] | None:
    """Extract one upstream request's occurrences, recording a mangled or plain problem.

    Returns None (and records on `result`/`problems`) when extraction fails; the caller then
    answers 502.
    """
    try:
        return extract_occurrences(bound.template.request, request_json)
    except RequestMangledError as exc:
        result.mangled.append(Mangled(exc.location, exc.expected, exc.actual, bound.name))
        return None
    except MaskedValueNotFoundError as exc:
        problems.append(str(exc))
        return None


async def negative_control(
    session: CaptureSession, http: httpx.AsyncClient, capture_url: str, bound: BoundTemplate
) -> NegativeControl:
    """Send a template's canaries straight to the capture, on the route's path.

    The scan must find each one. A template without canaries is never caught: it would test
    nothing.
    """
    if not bound.canaries:
        return NegativeControl(bound.label, False, ())
    raw = bound.raw()
    everything = tuple(canary.name for canary in bound.canaries)
    seen: list[UpstreamRequest] = []

    async def handle(request: UpstreamRequest) -> ResponseSpec:
        seen.append(request)
        return json_response(200, render(bound.template.response, raw, raw))

    session.handler = handle
    try:
        await http.post(
            capture_url.rstrip("/") + bound.route.path,
            json=render(bound.template.request, raw, {}),
            headers=bound.module.EXTRA_HEADERS,
        )
    except httpx.HTTPError:
        return NegativeControl(bound.label, False, everything)
    finally:
        session.handler = None
    if not seen:
        return NegativeControl(bound.label, False, everything)
    found = {hit.canary for request in seen for hit in scan(bound.canaries, request)}
    missed = tuple(name for name in everything if name not in found)
    return NegativeControl(bound.label, not missed, missed)


@dataclass(frozen=True)
class Exchange:
    """A client request's outcome before judging: status, body, extraction problem, placeholders.

    `occurrences` holds every upstream request's; `last_occurrences` the last one's.
    """

    status: int
    text: str
    masked_problem: str | None
    occurrences: list[Occurrence]
    last_occurrences: list[Occurrence] = field(default_factory=list)


async def baseline(
    session: CaptureSession,
    http: httpx.AsyncClient,
    target_url: str,
    bound: BoundTemplate,
    run_canaries: Sequence[Canary],
    *,
    deadline: float,
    duty: str = RESTORE,
) -> AttackResult:
    """One templated client request through the gateway; the answer must come back per duty."""
    result = AttackResult(f"baseline/{bound.label}")
    outcome = await exchange(
        session, http, target_url, bound, run_canaries, result, deadline=deadline
    )
    if outcome is not None:
        evaluate(
            result,
            masked_problem=outcome.masked_problem,
            status=outcome.status,
            text=outcome.text,
            bound=bound,
            occurrences=outcome.occurrences,
            last_occurrences=outcome.last_occurrences,
            duty=duty,
        )
    return result


async def exchange(  # noqa: PLR0917 - one argument per input the request needs
    session: CaptureSession,
    http: httpx.AsyncClient,
    target_url: str,
    bound: BoundTemplate,
    run_canaries: Sequence[Canary],
    result: AttackResult,
    *,
    deadline: float,
) -> Exchange | None:
    """Send one templated request and answer the upstream requests it causes.

    Scans every upstream request for every run value and records it on `result`. Returns None
    after marking `result` untrusted on a timeout or a transport error.
    """
    raw = bound.raw()
    problems: list[str] = []
    occurrences: list[Occurrence] = []
    last: list[Occurrence] = []

    async def handle(request: UpstreamRequest) -> ResponseSpec:
        result.upstream_requests += 1
        result.leaks.extend(scan(run_canaries, request))
        found = extract_or_record(result, bound, problems, request.json)
        if found is None:
            return ResponseSpec(502, "canarywire: masked value not found")
        occurrences.extend(found)
        last[:] = found
        return json_response(200, render(bound.template.response, raw, first_placeholders(found)))

    session.handler = handle
    try:
        with anyio.fail_after(deadline):
            response = await http.post(
                target_url.rstrip("/") + bound.route.path,
                json=render(bound.template.request, raw, {}),
                headers=bound.module.EXTRA_HEADERS,
            )
    except TimeoutError:
        result.untrusted("timeout: no client response")
        return None
    except (httpx.ConnectTimeout, httpx.PoolTimeout) as exc:
        # Connection-level failures, even though both are httpx.TimeoutException subclasses.
        result.untrusted(f"request error: {exc!r}")
        return None
    except httpx.TimeoutException:
        result.untrusted("timeout: no client response")
        return None
    except httpx.HTTPError as exc:
        result.untrusted(f"request error: {exc!r}")
        return None
    finally:
        session.handler = None
    result.client_status = response.status_code
    return Exchange(
        response.status_code,
        response.text,
        problems[0] if problems else None,
        occurrences,
        list(last),
    )


def settle(result: AttackResult, duty: str = RESTORE) -> None:
    """Final status once the checks ran: inconsistent, else unrestored/altered, else success.

    Under `restore` the statuses are `unrestored` and `restored`; under `mask-only`, `altered`
    and `delivered`.
    """
    if result.inconsistent:
        result.status = "inconsistent"
    elif result.unrestored:
        result.status = fail_status(duty)
    else:
        result.status = ok_status(duty)


def evaluate(
    result: AttackResult,
    *,
    masked_problem: str | None,
    status: int,
    text: str,
    bound: BoundTemplate,
    occurrences: Sequence[Occurrence] = (),
    last_occurrences: Sequence[Occurrence],
    duty: str = RESTORE,
) -> None:
    """Set the attack's status from the client response; first matching rule wins."""
    if result.upstream_requests == 0:
        result.untrusted("no upstream traffic")
        return
    if judge_mangled(result):
        return
    if masked_problem is not None:
        result.untrusted(masked_problem)
        return
    if not httpx.codes.is_success(status):
        result.untrusted(f"refused with HTTP {status}, nothing verified")
        return
    check_response(
        result,
        text=text,
        bound=bound,
        occurrences=occurrences,
        last_occurrences=last_occurrences,
        duty=duty,
    )


def check_response(
    result: AttackResult,
    *,
    text: str,
    bound: BoundTemplate,
    occurrences: Sequence[Occurrence],
    last_occurrences: Sequence[Occurrence],
    duty: str = RESTORE,
) -> None:
    """Duty and consistency checks of a successful answer; sets the final status.

    Under `restore` the answer must carry the original values, and shared placeholders add a
    collision note. Under `mask-only` it must be the answer canarywire sent upstream, rendered
    with the last upstream request's placeholders (`last_occurrences`); every mismatch is noted
    as altered, and there are no collision notes.
    """
    result.inconsistent = inconsistencies(occurrences, bound)
    values = bound.raw()
    by_name = {canary.name: canary for canary in bound.canaries}
    if duty == RESTORE:
        notes = collision_notes(occurrences)
        duty_note: str | None = None
        expected_doc = render(bound.template.response, values, values)
    else:
        notes = {}
        duty_note = ALTERED_NOTE
        masked = first_placeholders(last_occurrences)
        expected_doc = render(bound.template.response, values, masked)
    try:
        actual_doc = json.loads(text)
    except ValueError:
        result.unrestored.extend(
            Unrestored(
                c.name,
                c.value,
                "body",
                json.dumps(expected_doc),
                text,
                bound.name,
                c.type,
                add_note(duty_note, notes.get(c.name)),
            )
            for c in bound.canaries
        )
        settle(result, duty)
        return
    comparison = compare_response(bound.template.response, expected_doc, actual_doc)
    result.restored += comparison.restored
    for mismatch in comparison.mismatches:
        result.unrestored.extend(
            Unrestored(
                name,
                by_name[name].value,
                mismatch.location,
                mismatch.expected,
                mismatch.actual,
                bound.name,
                by_name[name].type,
                add_note(duty_note, add_note(mismatch.note, notes.get(name))),
            )
            for name in mismatch.names
        )
    settle(result, duty)
