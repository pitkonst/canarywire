import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import cast

import anyio
import httpx
import pytest
from live import free_port, live_server
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response, StreamingResponse
from starlette.routing import Route

from canarywire.canaries import Canary
from canarywire.capture.app import create_app
from canarywire.capture.recorder import Recorder
from canarywire.config import DEFAULT_ROUTES
from canarywire.config import Route as TargetRoute
from canarywire.runner.attacks import (
    AttackResult,
    Mangled,
    NegativeControl,
    Unrestored,
    baseline,
    evaluate,
    exchange,
    judge_mangled,
    negative_control,
)
from canarywire.runner.catalog import Occurrence, for_protocol, parse_template
from canarywire.runner.consistency import Inconsistent, Seen
from canarywire.runner.messages import ResponseSpec, UpstreamRequest
from canarywire.runner.prepare import BoundTemplate
from canarywire.runner.session import CaptureSession, open_capture

CHAT = DEFAULT_ROUTES[0]
ROUTE = CHAT.path
CLAUDE = TargetRoute("claude", "anthropic-messages", "/v1/messages")
TEMPLATE_RAW = {
    "protocol": "openai-chat",
    "canaries": {"email": "email"},
    "request": {"messages": [{"role": "user", "content": "mail {{ email.raw }} now"}]},
    "response": {"choices": [{"message": {"content": "To {{ email.masked }}."}}]},
}
TEMPLATE = parse_template("t", TEMPLATE_RAW)
CANARY = Canary("email", "ann.lee1234@example.org", "email", "t")
BOUND = BoundTemplate(TEMPLATE, (CANARY,), CHAT)
GOOD = json.dumps({"choices": [{"message": {"content": "To ann.lee1234@example.org."}}]})


def result(upstream_requests: int = 1) -> AttackResult:
    attack = AttackResult("baseline")
    attack.upstream_requests = upstream_requests
    return attack


def run_evaluate(
    attack: AttackResult, *, status: int = 200, text: str = GOOD, masked: str | None = None
) -> AttackResult:
    evaluate(
        attack,
        masked_problem=masked,
        status=status,
        text=text,
        bound=BOUND,
        last_occurrences=(),
    )
    return attack


def test_restored() -> None:
    attack = run_evaluate(result())
    assert (attack.status, attack.restored, attack.unrestored) == ("restored", 1, [])


def test_no_traffic_wins_over_wrong_text() -> None:
    attack = run_evaluate(result(0), text='{"choices": []}')
    assert (attack.status, attack.reason) == ("untrusted", "no upstream traffic")


def test_masked_problem_is_untrusted() -> None:
    attack = run_evaluate(result(), masked="masked value not found at body.x")
    assert (attack.status, attack.reason) == ("untrusted", "masked value not found at body.x")


def test_refusal_is_untrusted() -> None:
    attack = run_evaluate(result(), status=502, text="refused")
    assert attack.status == "untrusted"
    assert attack.reason == "refused with HTTP 502, nothing verified"


def test_placeholder_left_in_place_is_unrestored() -> None:
    text = json.dumps({"choices": [{"message": {"content": "To <EMAIL_1>."}}]})
    attack = run_evaluate(result(), text=text)
    assert attack.status == "unrestored"
    assert attack.unrestored == [
        Unrestored(
            "email",
            "ann.lee1234@example.org",
            "body.choices[0].message.content",
            "To ann.lee1234@example.org.",
            "To <EMAIL_1>.",
            "t",
            "email",
        )
    ]


def test_missing_path_is_unrestored_with_no_actual() -> None:
    attack = run_evaluate(result(), text="{}")
    assert attack.unrestored[0].actual is None


def test_non_json_response_is_unrestored_at_body() -> None:
    attack = run_evaluate(result(), text="oops")
    assert attack.status == "unrestored"
    assert (attack.unrestored[0].location, attack.unrestored[0].actual) == ("body", "oops")


# --- mangled requests ----------------------------------------------------


def test_judge_mangled_sets_status_and_reason() -> None:
    attack = result()
    attack.mangled = [Mangled("body.m", "e", "a")]
    assert judge_mangled(attack) is True
    assert (attack.status, attack.reason) == (
        "mangled",
        "request text changed around a canary at body.m",
    )


def test_judge_mangled_leaves_status_alone_when_none() -> None:
    attack = result()
    assert judge_mangled(attack) is False
    assert attack.status == "untrusted"


def test_evaluate_reports_mangled() -> None:
    attack = result()
    attack.mangled = [Mangled("body.m", "e", "a")]
    attack = run_evaluate(attack, masked=None)
    assert (attack.status, attack.reason) == (
        "mangled",
        "request text changed around a canary at body.m",
    )


def test_evaluate_no_upstream_traffic_wins_over_mangled() -> None:
    attack = result(0)
    attack.mangled = [Mangled("body.m", "e", "a")]
    attack = run_evaluate(attack)
    assert (attack.status, attack.reason) == ("untrusted", "no upstream traffic")


MANGLE_TEMPLATE = parse_template(
    "m",
    {
        "protocol": "openai-chat",
        "canaries": {"email": "email"},
        "request": {"messages": [{"role": "user", "content": "Send {{ email.raw }} please."}]},
        "response": {"choices": [{"message": {"content": "To {{ email.masked }}."}}]},
    },
)
MANGLE_CANARY = Canary("email", "ann.lee1234@example.org", "email", "m")
MANGLE_BOUND = BoundTemplate(MANGLE_TEMPLATE, (MANGLE_CANARY,), CHAT)


@pytest.mark.anyio
async def test_mangled_request_records_mangled_and_answers_502(tmp_path: Path) -> None:
    """A gateway that changes the request text around a canary: recorded, not a plain problem."""
    capture_url = ""

    async def mangling_gateway(request: Request) -> Response:
        body = await request.json()
        body["messages"][0]["content"] = "Send <X>garbled"
        async with httpx.AsyncClient(timeout=5) as client:
            upstream = await client.post(capture_url.rstrip("/") + ROUTE, json=body)
        return Response(upstream.content, upstream.status_code, media_type="application/json")

    target_app = Starlette(routes=[Route(ROUTE, mangling_gateway, methods=["POST"])])

    async def not_found(request: UpstreamRequest) -> ResponseSpec:
        return ResponseSpec(404, "")

    async with (
        live_server(create_app(Recorder(tmp_path / "c.jsonl"))) as capture,
        live_server(target_app) as target,
    ):
        capture_url = capture
        connection = await open_capture(capture, timeout=5)
        async with connection, httpx.AsyncClient(timeout=10) as http:
            session = CaptureSession(connection, not_found)
            async with anyio.create_task_group() as tg:
                tg.start_soon(session.run)
                await session.start(run_id="r", seed=1, upstream_response_timeout=5, timeout=5)
                attack = AttackResult("x")
                outcome = await exchange(
                    session, http, target, MANGLE_BOUND, [MANGLE_CANARY], attack, deadline=5
                )
                tg.cancel_scope.cancel()
    assert outcome is not None
    assert outcome.status == 502
    assert outcome.masked_problem is None
    assert len(attack.mangled) == 1
    entry = attack.mangled[0]
    assert entry.expected == "Send {{email}} please."
    assert entry.actual == "Send <X>garbled"
    assert entry.template == "m"


@pytest.mark.anyio
async def test_negative_control_is_not_caught_when_canary_is_absent(tmp_path: Path) -> None:
    """The relay reaches the capture, but the request carries no canary: the scan finds nothing."""

    async def not_found(request: UpstreamRequest) -> ResponseSpec:
        return ResponseSpec(404, "")

    no_slot = parse_template(
        "t",
        {
            "protocol": "openai-chat",
            "canaries": {"email": "email"},
            "request": {"model": "gpt-4", "messages": [{"role": "user", "content": "hello"}]},
            "response": {"choices": [{"message": {"content": "hi"}}]},
        },
    )
    bound = BoundTemplate(no_slot, (CANARY,), CHAT)
    async with live_server(create_app(Recorder(tmp_path / "c.jsonl"))) as url:
        connection = await open_capture(url, timeout=5)
        async with connection, httpx.AsyncClient(timeout=5) as http:
            session = CaptureSession(connection, not_found)
            async with anyio.create_task_group() as tg:
                tg.start_soon(session.run)
                await session.start(run_id="r", seed=1, upstream_response_timeout=5, timeout=5)
                control = await negative_control(session, http, url, bound)
                tg.cancel_scope.cancel()
    assert control.caught is False
    assert control.missed == ("email",)


@pytest.mark.anyio
async def test_negative_control_is_caught(tmp_path: Path) -> None:
    async def not_found(request: UpstreamRequest) -> ResponseSpec:
        return ResponseSpec(404, "")

    async with live_server(create_app(Recorder(tmp_path / "c.jsonl"))) as url:
        connection = await open_capture(url, timeout=5)
        async with connection, httpx.AsyncClient(timeout=5) as http:
            session = CaptureSession(connection, not_found)
            async with anyio.create_task_group() as tg:
                tg.start_soon(session.run)
                await session.start(run_id="r", seed=1, upstream_response_timeout=5, timeout=5)
                caught = await negative_control(session, http, url, BOUND)
                missed = await negative_control(
                    session, http, f"http://127.0.0.1:{free_port()}", BOUND
                )
                tg.cancel_scope.cancel()
    assert caught == NegativeControl("t@openai-chat", True, ())
    assert missed.caught is False
    assert missed.missed == ("email",)


@pytest.mark.anyio
async def test_baseline_deadline_covers_a_trickling_response(tmp_path: Path) -> None:
    async def trickle(_: Request) -> Response:
        async def body() -> AsyncIterator[bytes]:
            while True:
                yield b" "
                await anyio.sleep(0.1)

        return StreamingResponse(body(), media_type="application/json")

    target_app = Starlette(routes=[Route("/v1/chat/completions", trickle, methods=["POST"])])

    async def not_found(request: UpstreamRequest) -> ResponseSpec:
        return ResponseSpec(404, "")

    async with (
        live_server(create_app(Recorder(tmp_path / "c.jsonl"))) as capture,
        live_server(target_app) as target,
    ):
        connection = await open_capture(capture, timeout=5)
        async with connection, httpx.AsyncClient(timeout=30) as http:
            session = CaptureSession(connection, not_found)
            async with anyio.create_task_group() as tg:
                tg.start_soon(session.run)
                await session.start(run_id="r", seed=1, upstream_response_timeout=5, timeout=5)
                with anyio.fail_after(5):
                    result = await baseline(session, http, target, BOUND, [CANARY], deadline=0.5)
                tg.cancel_scope.cancel()
    assert result.name == "baseline/t@openai-chat"
    assert (result.status, result.reason) == ("untrusted", "timeout: no client response")


@pytest.mark.anyio
async def test_negative_control_without_canaries_is_not_caught() -> None:
    empty = BoundTemplate(TEMPLATE, (), CHAT)
    control = await negative_control(
        cast("CaptureSession", None), cast("httpx.AsyncClient", None), "http://x.invalid", empty
    )
    assert control == NegativeControl("t@openai-chat", False, ())


@pytest.mark.anyio
async def test_baseline_attributes_another_templates_leak(tmp_path: Path) -> None:
    """A value of template A leaking during B's baseline: recorded under baseline/B, template A."""
    canary_a = Canary("email", "ann.lee1234@example.org", "email", "A")
    canary_b = Canary("email", "bo.kim5678@example.org", "email", "B")
    bound_b = BoundTemplate(parse_template("B", TEMPLATE_RAW), (canary_b,), CHAT)
    capture_url = ""

    async def leaky_gateway(request: Request) -> Response:
        body = await request.json()
        message = body["messages"][0]
        message["content"] = message["content"].replace(canary_b.value, "<EMAIL_1>")
        body["note"] = f"earlier: {canary_a.value}"
        async with httpx.AsyncClient(timeout=5) as client:
            upstream = await client.post(capture_url.rstrip("/") + ROUTE, json=body)
        return Response(upstream.content, upstream.status_code, media_type="application/json")

    target_app = Starlette(routes=[Route(ROUTE, leaky_gateway, methods=["POST"])])

    async def not_found(request: UpstreamRequest) -> ResponseSpec:
        return ResponseSpec(404, "")

    async with (
        live_server(create_app(Recorder(tmp_path / "c.jsonl"))) as capture,
        live_server(target_app) as target,
    ):
        capture_url = capture
        connection = await open_capture(capture, timeout=5)
        async with connection, httpx.AsyncClient(timeout=10) as http:
            session = CaptureSession(connection, not_found)
            async with anyio.create_task_group() as tg:
                tg.start_soon(session.run)
                await session.start(run_id="r", seed=1, upstream_response_timeout=5, timeout=5)
                result = await baseline(
                    session, http, target, bound_b, [canary_a, *bound_b.canaries], deadline=5
                )
                tg.cancel_scope.cancel()
    assert result.name == "baseline/B@openai-chat"
    assert [
        (hit.canary, hit.value, hit.location, hit.template, hit.type) for hit in result.leaks
    ] == [("email", canary_a.value, "body.note", "A", "email")]


@pytest.mark.anyio
async def test_baseline_accumulates_occurrences_across_upstream_requests(tmp_path: Path) -> None:
    """One attack, two upstream requests: occurrences from both feed the consistency check.

    The target forwards the client body to the capture twice, masking `email` differently each
    time, then answers with the capture's second response. If occurrences were reset for each
    request instead of accumulated over the attack, this attack would see only the second
    forward's single placeholder and never notice the inconsistency.
    """
    capture_url = ""

    async def double_forward(request: Request) -> Response:
        body = await request.json()
        first = json.loads(json.dumps(body))
        first["messages"][0]["content"] = first["messages"][0]["content"].replace(
            CANARY.value, "<E1>"
        )
        second = json.loads(json.dumps(body))
        second["messages"][0]["content"] = second["messages"][0]["content"].replace(
            CANARY.value, "<E2>"
        )
        async with httpx.AsyncClient(timeout=5) as client:
            await client.post(capture_url.rstrip("/") + ROUTE, json=first)
            upstream = await client.post(capture_url.rstrip("/") + ROUTE, json=second)
        return Response(upstream.content, upstream.status_code, media_type="application/json")

    target_app = Starlette(routes=[Route(ROUTE, double_forward, methods=["POST"])])

    async def not_found(request: UpstreamRequest) -> ResponseSpec:
        return ResponseSpec(404, "")

    async with (
        live_server(create_app(Recorder(tmp_path / "c.jsonl"))) as capture,
        live_server(target_app) as target,
    ):
        capture_url = capture
        connection = await open_capture(capture, timeout=5)
        async with connection, httpx.AsyncClient(timeout=10) as http:
            session = CaptureSession(connection, not_found)
            async with anyio.create_task_group() as tg:
                tg.start_soon(session.run)
                await session.start(run_id="r", seed=1, upstream_response_timeout=5, timeout=5)
                result = await baseline(session, http, target, BOUND, [CANARY], deadline=5)
                tg.cancel_scope.cancel()
    assert result.upstream_requests == 2
    assert result.status == "inconsistent"
    assert len(result.inconsistent) == 1
    [inconsistent] = result.inconsistent
    assert inconsistent.instance == "email"
    assert {seen.placeholder for seen in inconsistent.occurrences} == {"<E1>", "<E2>"}


TOOL_RAW = {
    "protocol": "openai-chat",
    "canaries": {"email": "email", "card": "card"},
    "request": {
        "messages": [
            {"role": "user", "content": "mail {{ email.raw }} card {{ card.raw }}"},
            {"role": "user", "content": "again {{ email.raw }}"},
        ]
    },
    "response": {
        "choices": [
            {
                "message": {
                    "content": "To {{ email.masked }}",
                    "tool_calls": [
                        {"function": {"arguments": {"$json": {"card": "{{ card.masked }}"}}}}
                    ],
                }
            }
        ]
    },
}
TOOL = parse_template("tc", TOOL_RAW)
EMAIL = Canary("email", "ann.lee1234@example.org", "email", "tc")
CARD = Canary("card", "4000001234567899", "card", "tc")
TOOL_BOUND = BoundTemplate(TOOL, (EMAIL, CARD), CHAT)


def tool_text(content: str, arguments: str) -> str:
    message = {"content": content, "tool_calls": [{"function": {"arguments": arguments}}]}
    return json.dumps({"choices": [{"message": message}]})


def evaluate_tool(text: str, occurrences: list[Occurrence]) -> AttackResult:
    attack = result()
    evaluate(
        attack,
        masked_problem=None,
        status=200,
        text=text,
        bound=TOOL_BOUND,
        occurrences=occurrences,
        last_occurrences=occurrences,
    )
    return attack


CONSISTENT = [
    Occurrence("email", "body.messages[0].content", "<E1>"),
    Occurrence("card", "body.messages[0].content", "<C1>"),
    Occurrence("email", "body.messages[1].content", "<E1>"),
]


def test_reencoded_tool_arguments_are_restored() -> None:
    text = tool_text(f"To {EMAIL.value}", json.dumps({"card": CARD.value}, indent=1))
    attack = evaluate_tool(text, CONSISTENT)
    assert (attack.status, attack.restored, attack.unrestored) == ("restored", 2, [])


def test_inconsistent_wins_over_unrestored_and_keeps_both() -> None:
    occurrences = [*CONSISTENT[:2], Occurrence("email", "body.messages[1].content", "<E2>")]
    attack = evaluate_tool(tool_text("To <E1>", json.dumps({"card": CARD.value})), occurrences)
    assert attack.status == "inconsistent"
    assert attack.inconsistent == [
        Inconsistent(
            "tc",
            "email",
            "email",
            (Seen("body.messages[0].content", "<E1>"), Seen("body.messages[1].content", "<E2>")),
        )
    ]
    assert [u.canary for u in attack.unrestored] == ["email"]


def test_collision_note_on_unrestored() -> None:
    occurrences = [
        Occurrence("email", "body.messages[0].content", "<X1>"),
        Occurrence("card", "body.messages[0].content", "<X1>"),
        Occurrence("email", "body.messages[1].content", "<X1>"),
    ]
    text = tool_text(f"To {CARD.value}", json.dumps({"card": CARD.value}))
    attack = evaluate_tool(text, occurrences)
    assert attack.status == "unrestored"
    [entry] = attack.unrestored
    assert entry.canary == "email"
    assert entry.note == "instances card, email were masked to the same placeholder <X1>"


def test_refusal_wins_over_inconsistent() -> None:
    occurrences = [*CONSISTENT[:2], Occurrence("email", "body.messages[1].content", "<E2>")]
    attack = result()
    evaluate(
        attack,
        masked_problem=None,
        status=502,
        text="no",
        bound=TOOL_BOUND,
        occurrences=occurrences,
        last_occurrences=occurrences,
    )
    assert (attack.status, attack.inconsistent) == ("untrusted", [])


NEUTRAL = parse_template(
    "n",
    {
        "canaries": {"email": "email"},
        "request": {"messages": [{"role": "user", "content": "mail {{ email.raw }} now"}]},
        "response": {"content": "To {{ email.masked }}."},
    },
)
CLAUDE_CANARY = Canary("email", "ann.lee1234@example.org", "email", "n")
CLAUDE_BOUND = BoundTemplate(for_protocol(NEUTRAL, "anthropic-messages"), (CLAUDE_CANARY,), CLAUDE)


@pytest.mark.anyio
async def test_anthropic_route_path_and_headers_against_the_capture(tmp_path: Path) -> None:
    """The negative control and the baseline post to the route's path with its extra headers."""

    async def not_found(request: UpstreamRequest) -> ResponseSpec:
        return ResponseSpec(404, "")

    log = tmp_path / "c.jsonl"
    async with live_server(create_app(Recorder(log))) as url:
        connection = await open_capture(url, timeout=5)
        async with connection, httpx.AsyncClient(timeout=5) as http:
            session = CaptureSession(connection, not_found)
            async with anyio.create_task_group() as tg:
                tg.start_soon(session.run)
                await session.start(run_id="r", seed=1, upstream_response_timeout=5, timeout=5)
                control = await negative_control(session, http, url, CLAUDE_BOUND)
                result = await baseline(
                    session, http, url, CLAUDE_BOUND, [CLAUDE_CANARY], deadline=5
                )
                tg.cancel_scope.cancel()
    assert control == NegativeControl("n@claude", True, ())
    assert (result.name, result.status, result.restored) == ("baseline/n@claude", "restored", 1)
    assert result.leaks
    requests = [json.loads(line)["request"] for line in log.read_text().splitlines()]
    assert [r["path"] for r in requests] == ["/v1/messages", "/v1/messages"]
    for request in requests:
        assert ["anthropic-version", "2023-06-01"] in request["headers"]
        assert request["json"]["max_tokens"] == 1024


@pytest.mark.anyio
async def test_openai_route_sends_no_anthropic_header(tmp_path: Path) -> None:
    async def not_found(request: UpstreamRequest) -> ResponseSpec:
        return ResponseSpec(404, "")

    log = tmp_path / "c.jsonl"
    async with live_server(create_app(Recorder(log))) as url:
        connection = await open_capture(url, timeout=5)
        async with connection, httpx.AsyncClient(timeout=5) as http:
            session = CaptureSession(connection, not_found)
            async with anyio.create_task_group() as tg:
                tg.start_soon(session.run)
                await session.start(run_id="r", seed=1, upstream_response_timeout=5, timeout=5)
                await baseline(session, http, url, BOUND, [CANARY], deadline=5)
                tg.cancel_scope.cancel()
    [request] = [json.loads(line)["request"] for line in log.read_text().splitlines()]
    assert request["path"] == ROUTE
    assert all(name != "anthropic-version" for name, _ in request["headers"])


# --- duty mask-only -----------------------------------------------------

ALTERED = "altered under duty mask-only"
MASKED_TEXT = json.dumps({"choices": [{"message": {"content": "To <E1>."}}]})
E1 = [Occurrence("email", "body.messages[0].content", "<E1>")]


def run_mask_only(text: str, last_occurrences: list[Occurrence] = E1) -> AttackResult:
    attack = result()
    evaluate(
        attack,
        masked_problem=None,
        status=200,
        text=text,
        bound=BOUND,
        last_occurrences=last_occurrences,
        duty="mask-only",
    )
    return attack


def test_mask_only_placeholder_delivered() -> None:
    attack = run_mask_only(MASKED_TEXT)
    assert (attack.status, attack.restored, attack.unrestored) == ("delivered", 1, [])


def test_mask_only_restored_original_is_altered() -> None:
    attack = run_mask_only(GOOD)
    assert attack.status == "altered"
    assert attack.unrestored == [
        Unrestored(
            "email",
            "ann.lee1234@example.org",
            "body.choices[0].message.content",
            "To <E1>.",
            "To ann.lee1234@example.org.",
            "t",
            "email",
            ALTERED,
        )
    ]


def test_mask_only_non_json_is_altered_at_body() -> None:
    attack = run_mask_only("oops")
    assert attack.status == "altered"
    [entry] = attack.unrestored
    assert (entry.location, entry.actual, entry.note) == ("body", "oops", ALTERED)


def test_mask_only_inconsistent_wins_over_altered() -> None:
    occurrences = [*CONSISTENT[:2], Occurrence("email", "body.messages[1].content", "<E2>")]
    attack = result()
    evaluate(
        attack,
        masked_problem=None,
        status=200,
        text=tool_text(f"To {EMAIL.value}", json.dumps({"card": "<C1>"})),
        bound=TOOL_BOUND,
        occurrences=occurrences,
        last_occurrences=occurrences,
        duty="mask-only",
    )
    assert attack.status == "inconsistent"
    assert [(u.canary, u.note) for u in attack.unrestored] == [("email", ALTERED)]


def test_mask_only_has_no_collision_note() -> None:
    occurrences = [
        Occurrence("email", "body.messages[0].content", "<X1>"),
        Occurrence("card", "body.messages[0].content", "<X1>"),
        Occurrence("email", "body.messages[1].content", "<X1>"),
    ]
    attack = result()
    evaluate(
        attack,
        masked_problem=None,
        status=200,
        text=tool_text(f"To {EMAIL.value}", json.dumps({"card": "<X1>"})),
        bound=TOOL_BOUND,
        occurrences=occurrences,
        last_occurrences=occurrences,
        duty="mask-only",
    )
    assert attack.status == "altered"
    assert [(u.canary, u.note) for u in attack.unrestored] == [("email", ALTERED)]


@pytest.mark.anyio
async def test_mask_only_expects_the_last_upstream_requests_placeholders(tmp_path: Path) -> None:
    """Two upstream requests masked differently; the client gets the second answer untouched.

    The expected answer is the one canarywire sent last, rendered with the last request's
    placeholders (`<E2>`), not the attack's first placeholder (`<E1>`).
    """
    capture_url = ""
    ignoring = BoundTemplate(
        parse_template("t", {**TEMPLATE_RAW, "consistency": "ignore"}), (CANARY,), CHAT
    )

    async def double_forward(request: Request) -> Response:
        body = await request.json()
        answers = []
        async with httpx.AsyncClient(timeout=5) as client:
            for placeholder in ("<E1>", "<E2>"):
                masked = json.loads(json.dumps(body))
                content = masked["messages"][0]["content"]
                masked["messages"][0]["content"] = content.replace(CANARY.value, placeholder)
                answers.append(await client.post(capture_url.rstrip("/") + ROUTE, json=masked))
        last = answers[-1]
        return Response(last.content, last.status_code, media_type="application/json")

    target_app = Starlette(routes=[Route(ROUTE, double_forward, methods=["POST"])])

    async def not_found(request: UpstreamRequest) -> ResponseSpec:
        return ResponseSpec(404, "")

    async with (
        live_server(create_app(Recorder(tmp_path / "c.jsonl"))) as capture,
        live_server(target_app) as target,
    ):
        capture_url = capture
        connection = await open_capture(capture, timeout=5)
        async with connection, httpx.AsyncClient(timeout=10) as http:
            session = CaptureSession(connection, not_found)
            async with anyio.create_task_group() as tg:
                tg.start_soon(session.run)
                await session.start(run_id="r", seed=1, upstream_response_timeout=5, timeout=5)
                attack = await baseline(
                    session, http, target, ignoring, [CANARY], deadline=5, duty="mask-only"
                )
                tg.cancel_scope.cancel()
    assert attack.upstream_requests == 2
    assert (attack.status, attack.unrestored) == ("delivered", []), attack.unrestored


@pytest.mark.anyio
async def test_mask_only_expects_the_last_upstream_requests_streamed_content(
    tmp_path: Path,
) -> None:
    """As above, but the target streams its forwarded answer back to the client in chunks.

    Mirrors `test_mask_only_expects_the_last_upstream_requests_placeholders`: the same two
    upstream forwards with different placeholders, but the answer reaches the client as a
    chunked, streamed body rather than in one piece.
    """
    capture_url = ""
    ignoring = BoundTemplate(
        parse_template("t", {**TEMPLATE_RAW, "consistency": "ignore"}), (CANARY,), CHAT
    )

    async def double_forward(request: Request) -> Response:
        body = await request.json()
        answers = []
        async with httpx.AsyncClient(timeout=5) as client:
            for placeholder in ("<E1>", "<E2>"):
                masked = json.loads(json.dumps(body))
                content = masked["messages"][0]["content"]
                masked["messages"][0]["content"] = content.replace(CANARY.value, placeholder)
                answers.append(await client.post(capture_url.rstrip("/") + ROUTE, json=masked))
        last = answers[-1]
        payload = last.content

        async def chunks() -> AsyncIterator[bytes]:
            for i in range(0, len(payload), 8):
                yield payload[i : i + 8]

        return StreamingResponse(
            chunks(), status_code=last.status_code, media_type="application/json"
        )

    target_app = Starlette(routes=[Route(ROUTE, double_forward, methods=["POST"])])

    async def not_found(request: UpstreamRequest) -> ResponseSpec:
        return ResponseSpec(404, "")

    async with (
        live_server(create_app(Recorder(tmp_path / "c.jsonl"))) as capture,
        live_server(target_app) as target,
    ):
        capture_url = capture
        connection = await open_capture(capture, timeout=5)
        async with connection, httpx.AsyncClient(timeout=10) as http:
            session = CaptureSession(connection, not_found)
            async with anyio.create_task_group() as tg:
                tg.start_soon(session.run)
                await session.start(run_id="r", seed=1, upstream_response_timeout=5, timeout=5)
                attack = await baseline(
                    session, http, target, ignoring, [CANARY], deadline=5, duty="mask-only"
                )
                tg.cancel_scope.cancel()
    assert attack.upstream_requests == 2
    assert (attack.status, attack.unrestored) == ("delivered", []), attack.unrestored
