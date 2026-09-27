import contextlib
import json
from collections.abc import AsyncIterator, Mapping, Sequence
from pathlib import Path
from typing import cast

import anyio
import httpx
import pytest
from live import live_server
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response, StreamingResponse
from starlette.routing import Route

from canarywire.canaries import Canary
from canarywire.capture.app import create_app
from canarywire.capture.recorder import Recorder
from canarywire.config import DEFAULT_ROUTES, FragmentationSettings, Timeouts
from canarywire.config import Route as TargetRoute
from canarywire.runner import fragmentation as fragmentation_module
from canarywire.runner.attacks import AttackResult, Mangled, Unrestored
from canarywire.runner.catalog import TemplateError, for_protocol, parse_template
from canarywire.runner.consistency import Inconsistent, Seen
from canarywire.runner.fragmentation import aborted_summary, evaluate_stream, fragmentation
from canarywire.runner.messages import ResponseSpec, UpstreamRequest
from canarywire.runner.prepare import BoundTemplate
from canarywire.runner.protocols import anthropic
from canarywire.runner.protocols.openai import encode
from canarywire.runner.session import CaptureSession, open_capture
from canarywire.runner.splits import pieces

CHAT = DEFAULT_ROUTES[0]
ROUTE = CHAT.path
CLAUDE = TargetRoute("claude", "anthropic-messages", "/v1/messages")
REQUEST = {
    "model": "canarywire-test",
    "messages": [{"role": "user", "content": "Send the invoice to {{ email.raw }} please."}],
}
TEMPLATE = parse_template(
    "t",
    {
        "protocol": "openai-chat",
        "canaries": {"email": "email"},
        "request": REQUEST,
        "response": {
            "choices": [{"message": {"content": "Done: the invoice goes to {{ email.masked }}."}}]
        },
    },
)
CANARY = Canary("email", "ann.lee1234@example.org", "email", "t")
BOUND = BoundTemplate(TEMPLATE, (CANARY,), CHAT)
EXPECTED = "Done: the invoice goes to ann.lee1234@example.org."


def sse(text: str) -> str:
    return "".join(c.data for c in encode([text[:5], text[5:]], [0, 0]))


def evaluated(
    *,
    upstream: int = 1,
    status: int = 200,
    raw: str = sse(EXPECTED),
    masked: str | None = None,
    missing_done: int = 0,
    is_baseline: bool = False,
    stream_baseline: str | None = "restored",
    inconsistent: Sequence[Inconsistent] = (),
    notes: Mapping[str, str] | None = None,
    protocol: str = "openai-chat",
    mangled: Sequence[Mangled] = (),
) -> AttackResult:
    result = AttackResult("fragmentation/x")
    result.upstream_requests = upstream
    result.mangled = list(mangled)
    evaluate_stream(
        result,
        is_baseline=is_baseline,
        masked_problem=masked,
        missing_done=missing_done,
        status=status,
        raw=raw,
        expected=EXPECTED,
        canaries=[CANARY],
        stream_baseline=stream_baseline,
        inconsistent=inconsistent,
        notes=notes,
        protocol=protocol,
    )
    return result


INCONSISTENT = [
    Inconsistent("t", "email", "email", (Seen("body.a", "<E1>"), Seen("body.b", "<E2>")))
]
NOTE = "instances a, email were masked to the same placeholder <E1>"


def test_inconsistent_stream_case() -> None:
    result = evaluated(inconsistent=INCONSISTENT)
    assert (result.status, result.inconsistent, result.restored) == (
        "inconsistent",
        INCONSISTENT,
        1,
    )


def test_refused_case_is_not_inconsistent() -> None:
    result = evaluated(status=502, raw="no", inconsistent=INCONSISTENT)
    assert (result.status, result.inconsistent) == ("refused", [])


def test_inconsistent_wins_over_unrestored_stream() -> None:
    result = evaluated(raw=sse("Done: the invoice goes to <EMAIL_1>."), inconsistent=INCONSISTENT)
    assert result.status == "inconsistent"
    assert [u.canary for u in result.unrestored] == ["email"]


def test_collision_note_on_stream_unrestored() -> None:
    result = evaluated(raw=sse("Done: the invoice goes to <EMAIL_1>."), notes={"email": NOTE})
    assert result.unrestored[0].note == NOTE


def test_collision_note_on_undecodable_stream() -> None:
    result = evaluated(raw='{"choices": []}', notes={"email": NOTE})
    assert (result.status, result.unrestored[0].note) == ("unrestored", NOTE)


def test_restored() -> None:
    result = evaluated()
    assert (result.status, result.restored) == ("restored", 1)


def test_no_traffic_wins() -> None:
    result = evaluated(upstream=0, raw="garbage")
    assert (result.status, result.reason) == ("untrusted", "no upstream traffic")


def test_masked_problem() -> None:
    assert evaluated(masked="masked value not found at body.x").status == "untrusted"


ONE_MANGLED = [Mangled("stream.m", "e", "a")]


def test_mangled_case() -> None:
    result = evaluated(mangled=ONE_MANGLED)
    assert (result.status, result.reason) == (
        "mangled",
        "request text changed around a canary at stream.m",
    )


def test_no_traffic_wins_over_mangled() -> None:
    result = evaluated(upstream=0, mangled=ONE_MANGLED)
    assert (result.status, result.reason) == ("untrusted", "no upstream traffic")


def test_mangled_wins_over_masked_problem() -> None:
    result = evaluated(mangled=ONE_MANGLED, masked="masked value not found at body.x")
    assert (result.status, result.reason) == (
        "mangled",
        "request text changed around a canary at stream.m",
    )


def test_missing_done() -> None:
    result = evaluated(missing_done=1)
    assert result.status == "untrusted"
    assert result.reason == "capture did not confirm delivery of 1 upstream response(s)"


@pytest.mark.parametrize(
    ("stream_baseline", "status"),
    [
        ("restored", "refused"),
        ("unrestored", "refused"),
        ("untrusted", "untrusted"),
        ("mangled", "untrusted"),
    ],
)
def test_split_refusal(stream_baseline: str, status: str) -> None:
    assert evaluated(status=502, raw="no", stream_baseline=stream_baseline).status == status


def test_stream_baseline_refusal_is_untrusted() -> None:
    result = evaluated(status=502, raw="no", is_baseline=True)
    assert result.status == "untrusted"


def test_not_sse_is_unrestored_at_stream() -> None:
    result = evaluated(raw='{"choices": []}')
    assert result.status == "unrestored"
    assert result.unrestored == [
        Unrestored("email", CANARY.value, "stream", EXPECTED, '{"choices": []}', "t", "email")
    ]


def anthropic_sse(text: str) -> str:
    return "".join(c.data for c in anthropic.encode([text[:5], text[5:]], [0, 0]))


def test_anthropic_stream_is_decoded_as_anthropic() -> None:
    result = evaluated(raw=anthropic_sse(EXPECTED), protocol="anthropic-messages")
    assert (result.status, result.restored) == ("restored", 1)


def test_anthropic_mismatch_is_unrestored_at_text_delta() -> None:
    result = evaluated(
        raw=anthropic_sse("Done: the invoice goes to <EMAIL_1>."), protocol="anthropic-messages"
    )
    assert result.status == "unrestored"
    assert result.unrestored[0].location == "stream.delta.text"
    assert result.unrestored[0].actual == "Done: the invoice goes to <EMAIL_1>."


def test_openai_stream_is_not_sse_for_anthropic() -> None:
    result = evaluated(raw=sse(EXPECTED), protocol="anthropic-messages")
    assert result.status == "unrestored"
    assert result.reason is not None
    assert result.reason.startswith("client stream ")


ALTERED = "altered under duty mask-only"
STREAMED = "Done: the invoice goes to <E1>."


def mask_only(raw: str, *, notes: Mapping[str, str] | None = None) -> AttackResult:
    result = AttackResult("fragmentation/x")
    result.upstream_requests = 1
    evaluate_stream(
        result,
        is_baseline=False,
        masked_problem=None,
        missing_done=0,
        status=200,
        raw=raw,
        expected=EXPECTED,
        canaries=[CANARY],
        stream_baseline="delivered",
        notes=notes,
        protocol="openai-chat",
        duty="mask-only",
        streamed=STREAMED,
    )
    return result


def test_mask_only_stream_delivered() -> None:
    result = mask_only(sse(STREAMED))
    assert (result.status, result.restored, result.unrestored) == ("delivered", 1, [])


def test_mask_only_restored_stream_is_altered_without_collision_note() -> None:
    result = mask_only(sse(EXPECTED), notes={"email": NOTE})
    assert result.status == "altered"
    assert result.unrestored == [
        Unrestored(
            "email",
            CANARY.value,
            "stream.choices[0].delta.content",
            STREAMED,
            EXPECTED,
            "t",
            "email",
            ALTERED,
        )
    ]


def test_mask_only_truncated_stream_is_altered() -> None:
    raw = sse(STREAMED).replace("data: [DONE]\n\n", "")
    result = mask_only(raw)
    assert (result.status, result.reason) == ("altered", "client stream truncated")
    assert result.unrestored == [
        Unrestored("email", CANARY.value, "stream", STREAMED, raw, "t", "email", ALTERED)
    ]


@pytest.mark.anyio
async def test_mask_only_expects_the_content_streamed_upstream(tmp_path: Path) -> None:
    """A relay that masks the request and passes the stream through: every case is delivered."""
    capture_url = ""

    async def relay(request: Request) -> Response:
        body = await request.json()
        content = body["messages"][0]["content"]
        body["messages"][0]["content"] = content.replace(CANARY.value, "<E1>")
        async with httpx.AsyncClient(timeout=5) as client:
            upstream = await client.post(capture_url.rstrip("/") + ROUTE, json=body)
        return Response(upstream.content, upstream.status_code, media_type="text/event-stream")

    async def not_found(request: UpstreamRequest) -> ResponseSpec:
        return ResponseSpec(404, "")

    timeouts = Timeouts(client_request=5, upstream_done=2)
    target_app = Starlette(routes=[Route(ROUTE, relay, methods=["POST"])])
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
                results = await fragmentation(
                    session,
                    http,
                    target,
                    BOUND,
                    [CANARY],
                    settings=FragmentationSettings(),
                    seed=3,
                    timeouts=timeouts,
                    duty="mask-only",
                )
                tg.cancel_scope.cancel()
    assert {r.status for r in results} == {"delivered"}, [(r.name, r.reason) for r in results]
    assert not any(r.leaks for r in results)


@pytest.mark.anyio
async def test_mangling_gateway_records_mangled_and_answers_502(tmp_path: Path) -> None:
    """A gateway that changes the request text around a canary: recorded, not a plain problem."""
    capture_url = ""

    async def mangling_gateway(request: Request) -> Response:
        body = await request.json()
        body["messages"][0]["content"] = "Send the invoice to <X>garbled"
        async with httpx.AsyncClient(timeout=5) as client:
            upstream = await client.post(capture_url.rstrip("/") + ROUTE, json=body)
        return Response(upstream.content, upstream.status_code, media_type="text/event-stream")

    target_app = Starlette(routes=[Route(ROUTE, mangling_gateway, methods=["POST"])])

    async def not_found(request: UpstreamRequest) -> ResponseSpec:
        return ResponseSpec(404, "")

    timeouts = Timeouts(client_request=5, upstream_done=2)
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
                results = await fragmentation(
                    session,
                    http,
                    target,
                    BOUND,
                    [CANARY],
                    settings=FragmentationSettings(cases=("baseline",)),
                    seed=3,
                    timeouts=timeouts,
                )
                tg.cancel_scope.cancel()
    [result] = results
    assert result.client_status == 502
    assert len(result.mangled) == 1
    entry = result.mangled[0]
    assert entry.expected == "Send the invoice to {{email}} please."
    assert entry.actual == "Send the invoice to <X>garbled"
    assert entry.template == "t"


def test_mismatch_is_unrestored_at_delta_content() -> None:
    result = evaluated(raw=sse("Done: the invoice goes to <EMAIL_1>."))
    assert result.status == "unrestored"
    assert result.unrestored[0].location == "stream.choices[0].delta.content"
    assert result.unrestored[0].actual == "Done: the invoice goes to <EMAIL_1>."


@pytest.mark.anyio
async def test_against_the_capture_itself_every_case_restores_and_leaks(tmp_path: Path) -> None:
    """No gateway in between: masked == original, so every case restores and every case leaks."""

    async def not_found(request: UpstreamRequest) -> ResponseSpec:
        return ResponseSpec(404, "")

    timeouts = Timeouts(client_request=5, upstream_done=2)
    async with live_server(create_app(Recorder(tmp_path / "c.jsonl"))) as url:
        connection = await open_capture(url, timeout=5)
        async with connection, httpx.AsyncClient(timeout=10) as http:
            session = CaptureSession(connection, not_found)
            async with anyio.create_task_group() as tg:
                tg.start_soon(session.run)
                await session.start(run_id="r", seed=1, upstream_response_timeout=5, timeout=5)
                results = await fragmentation(
                    session,
                    http,
                    url,
                    BOUND,
                    [CANARY],
                    settings=FragmentationSettings(),
                    seed=3,
                    timeouts=timeouts,
                )
                tg.cancel_scope.cancel()
    assert len(results) == 16
    assert all(r.name.startswith("fragmentation/t@openai-chat/") for r in results)
    assert results[0].name == "fragmentation/t@openai-chat/baseline"
    assert {r.status for r in results} == {"restored"}, [(r.name, r.reason) for r in results]
    assert all(r.leaks and r.upstream_requests == 1 for r in results)


@pytest.mark.anyio
async def test_trickling_stream_hits_client_deadline_after_upstream_leaks(tmp_path: Path) -> None:
    """A gateway that forwards upstream (leaking the canary) but never finishes its own stream."""
    capture_url = ""

    async def relay_then_trickle(request: Request) -> Response:
        body = await request.json()
        async with httpx.AsyncClient(timeout=5) as client:
            with contextlib.suppress(httpx.HTTPError):
                await client.post(capture_url.rstrip("/") + ROUTE, json=body)

        async def sse() -> AsyncIterator[bytes]:
            piece = encode(["x"], [0])[1].data.encode()
            while True:
                yield piece
                await anyio.sleep(0.1)

        return StreamingResponse(sse(), media_type="text/event-stream")

    target_app = Starlette(
        routes=[Route("/v1/chat/completions", relay_then_trickle, methods=["POST"])]
    )

    async def not_found(request: UpstreamRequest) -> ResponseSpec:
        return ResponseSpec(404, "")

    timeouts = Timeouts(client_request=0.5, upstream_done=2)
    async with (
        live_server(create_app(Recorder(tmp_path / "c.jsonl"))) as capture,
        live_server(target_app) as target,
    ):
        capture_url = capture
        connection = await open_capture(capture, timeout=5)
        async with connection, httpx.AsyncClient(timeout=30) as http:
            session = CaptureSession(connection, not_found)
            async with anyio.create_task_group() as tg:
                tg.start_soon(session.run)
                await session.start(run_id="r", seed=1, upstream_response_timeout=5, timeout=5)
                with anyio.fail_after(5):
                    results = await fragmentation(
                        session,
                        http,
                        target,
                        BOUND,
                        [CANARY],
                        settings=FragmentationSettings(cases=("baseline",)),
                        seed=1,
                        timeouts=timeouts,
                    )
                tg.cancel_scope.cancel()
    assert len(results) == 1
    result = results[0]
    assert (result.status, result.reason) == ("untrusted", "timeout: no client response")
    assert result.leaks


def test_aborted_summary_is_none_when_nothing_aborted() -> None:
    assert aborted_summary(["a"], {"a": "completed"}, {}, {"a": 3}) is None


def test_aborted_summary_reports_first_aborted() -> None:
    outcomes = {"a": "completed", "b": "aborted", "c": "aborted"}
    delivered = {"b": 2, "c": 5}
    planned = {"a": 3, "b": 4, "c": 6}
    assert aborted_summary(["a", "b", "c"], outcomes, delivered, planned) == "2/4"


@pytest.mark.anyio
async def test_no_canary_in_content_raises_template_error() -> None:
    no_content_slot = parse_template(
        "t",
        {
            "protocol": "openai-chat",
            "canaries": {"email": "email"},
            "request": REQUEST,
            "response": {
                "choices": [{"message": {"content": "Done: the invoice goes to nowhere."}}],
                "note": "{{ email.masked }}",
            },
        },
    )
    with pytest.raises(TemplateError, match="response template has no canary"):
        await fragmentation(
            cast("CaptureSession", None),
            cast("httpx.AsyncClient", None),
            "http://example.invalid",
            BoundTemplate(no_content_slot, (CANARY,), CHAT),
            [CANARY],
            settings=FragmentationSettings(),
            seed=1,
            timeouts=Timeouts(client_request=1, upstream_done=1),
        )


NEUTRAL = parse_template(
    "t",
    {
        "canaries": {"email": "email"},
        "request": {"messages": REQUEST["messages"]},
        "response": {"content": "Done: the invoice goes to {{ email.masked }}."},
    },
)


async def run_against_capture(tmp_path: Path, bound: BoundTemplate) -> list[AttackResult]:
    async def not_found(request: UpstreamRequest) -> ResponseSpec:
        return ResponseSpec(404, "")

    timeouts = Timeouts(client_request=5, upstream_done=2)
    async with live_server(create_app(Recorder(tmp_path / f"{bound.label}.jsonl"))) as url:
        connection = await open_capture(url, timeout=5)
        async with connection, httpx.AsyncClient(timeout=10) as http:
            session = CaptureSession(connection, not_found)
            async with anyio.create_task_group() as tg:
                tg.start_soon(session.run)
                await session.start(run_id="r", seed=1, upstream_response_timeout=5, timeout=5)
                results = await fragmentation(
                    session,
                    http,
                    url,
                    bound,
                    [CANARY],
                    settings=FragmentationSettings(),
                    seed=3,
                    timeouts=timeouts,
                )
                tg.cancel_scope.cancel()
    return results


@pytest.mark.anyio
async def test_anthropic_route_against_the_capture_restores_with_the_same_cuts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every case restores on the Anthropic route too, and both routes get the same pieces."""
    cut: list[list[str]] = []

    def recording(text: str, at: Sequence[int]) -> list[str]:
        result = pieces(text, at)
        cut.append(result)
        return result

    monkeypatch.setattr(fragmentation_module, "pieces", recording)
    chat = BoundTemplate(for_protocol(NEUTRAL, "openai-chat"), (CANARY,), CHAT)
    claude = BoundTemplate(for_protocol(NEUTRAL, "anthropic-messages"), (CANARY,), CLAUDE)
    chat_results = await run_against_capture(tmp_path, chat)
    chat_cuts, cut[:] = list(cut), []
    claude_results = await run_against_capture(tmp_path, claude)
    assert [r.name for r in claude_results] == [
        r.name.replace("t@openai-chat", "t@claude") for r in chat_results
    ]
    assert claude_results[0].name == "fragmentation/t@claude/baseline"
    assert {r.status for r in claude_results} == {"restored"}, [
        (r.name, r.reason) for r in claude_results
    ]
    assert len(chat_cuts) == 16
    assert cut == chat_cuts
    lines = (tmp_path / "t@claude.jsonl").read_text().splitlines()
    requests = [json.loads(line)["request"] for line in lines]
    assert len(requests) == 16
    for request in requests:
        assert request["path"] == "/v1/messages"
        assert ["anthropic-version", "2023-06-01"] in request["headers"]
        assert ["accept", "text/event-stream"] in request["headers"]
        assert request["json"]["stream"] is True
