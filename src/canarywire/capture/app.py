"""The capture server: records every upstream request and relays it to the connected runner."""

from __future__ import annotations

import contextlib
import itertools
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

import anyio
from starlette.applications import Starlette
from starlette.background import BackgroundTask
from starlette.responses import PlainTextResponse, Response, StreamingResponse
from starlette.routing import Route, WebSocketRoute
from starlette.websockets import WebSocketDisconnect

from canarywire.capture.relay import (
    NoRunnerError,
    Relay,
    RunnerLostError,
    Session,
    forward,
    notify_done,
)
from canarywire.rpc import ChannelClosedError, Peer, RpcError

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    from starlette.requests import Request
    from starlette.types import Receive, Scope, Send
    from starlette.websockets import WebSocket

    from canarywire.capture.recorder import Recorder

METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
SESSION_CONFLICT = -32000
POLICY_VIOLATION = 1008
MIN_STATUS = 100
MAX_STATUS = 599
SUCCESS_MIN = 200
NO_CONTENT = 204
NOT_MODIFIED = 304
HEADER_PAIR = 2
PID_HEADER = "x-canarywire-pid"
DROPPED_HEADERS = frozenset({"content-length", "transfer-encoding", "connection"})
# Credentials the gateway sends its upstream: relayed to the runner, never written to disk.
SECRET_HEADERS = frozenset(
    {"authorization", "proxy-authorization", "x-api-key", "api-key", "x-goog-api-key", "cookie"}
)
REDACTED = "[redacted]"


class StarletteChannel:
    """RPC channel over the capture's side of the runner WebSocket."""

    def __init__(self, websocket: WebSocket) -> None:
        """Wrap an accepted WebSocket."""
        self._websocket = websocket

    async def send(self, text: str) -> None:
        """Send one text frame."""
        try:
            await self._websocket.send_text(text)
        except (WebSocketDisconnect, RuntimeError) as exc:
            raise ChannelClosedError from exc

    async def receive(self) -> str:
        """Receive one text frame."""
        try:
            return await self._websocket.receive_text()
        except (WebSocketDisconnect, RuntimeError, KeyError) as exc:
            raise ChannelClosedError from exc

    async def close(self) -> None:
        """Close the socket with a policy-violation code."""
        with contextlib.suppress(RuntimeError):
            await self._websocket.close(code=POLICY_VIOLATION)


@dataclass(frozen=True)
class ResponsePlan:
    """A validated `upstream.request` result: a plain body or a list of stream chunks."""

    status: int
    headers: list[tuple[str, str]]
    body: str | None
    chunks: list[tuple[str, int]] | None

    @classmethod
    def parse(cls, result: object) -> ResponsePlan:
        """Validate a runner answer; raise ValueError if malformed."""
        try:
            return cls._parse(result)
        except (AttributeError, TypeError) as exc:
            raise ValueError(f"malformed response spec: {exc!r}") from exc

    @classmethod
    def _parse(cls, result: object) -> ResponsePlan:
        if not isinstance(result, dict):
            raise ValueError("response spec must be an object")
        status = result.get("status")
        if isinstance(status, bool) or not isinstance(status, int):
            raise ValueError("status must be an integer")
        if not MIN_STATUS <= status <= MAX_STATUS:
            raise ValueError("status out of range")
        headers = _parse_headers(result.get("headers", []))
        body = result.get("body")
        stream = result.get("stream")
        if (body is None) == (stream is None):
            raise ValueError("exactly one of body and stream is required")
        if body is not None:
            if not isinstance(body, str):
                raise ValueError("body must be a string")
            if body and not _may_have_body(status):
                raise ValueError(f"status {status} cannot carry a body")
            return cls(status, headers, body, None)
        if not isinstance(stream, list):
            raise ValueError("stream must be a list")
        chunks: list[tuple[str, int]] = []
        for chunk in stream:
            data = chunk.get("data")
            delay = chunk.get("delay_ms", 0)
            if not isinstance(data, str) or isinstance(delay, bool) or not isinstance(delay, int):
                raise ValueError("stream chunk needs data (string) and delay_ms (integer)")
            chunks.append((data, max(delay, 0)))
        if chunks and not _may_have_body(status):
            raise ValueError(f"status {status} cannot carry a body")
        return cls(status, headers, None, chunks)


def _may_have_body(status: int) -> bool:
    """1xx, 204 and 304 responses must not carry a body (RFC 9110)."""
    return status >= SUCCESS_MIN and status not in (NO_CONTENT, NOT_MODIFIED)


def _parse_headers(raw: object) -> list[tuple[str, str]]:
    """Headers must be a list of [name, value] string pairs; anything else is a runner error."""
    if not isinstance(raw, list):
        raise ValueError("headers must be a list of [name, value] pairs")
    headers: list[tuple[str, str]] = []
    for pair in raw:
        if not (
            isinstance(pair, list)
            and len(pair) == HEADER_PAIR
            and all(isinstance(part, str) for part in pair)
        ):
            raise ValueError("each header must be a [name, value] pair of strings")
        headers.append((pair[0], pair[1]))
    return headers


def create_app(recorder: Recorder) -> Starlette:
    """Build the capture ASGI app; `recorder` receives one entry per upstream request."""
    relay = Relay()
    ids = itertools.count(1)

    async def health(_: Request) -> Response:
        # The pid lets `serve --detach` tell its own child from another capture on the same port.
        return PlainTextResponse("ok", headers={PID_HEADER: str(os.getpid())})

    async def reserved(_: Request) -> Response:
        return PlainTextResponse("not found", status_code=404)

    async def runner_socket(websocket: WebSocket) -> None:
        await websocket.accept()
        started: list[Session] = []

        async def start(params: object) -> object:
            if started:
                raise RpcError(SESSION_CONFLICT, "session already started")
            if relay.session is not None:
                raise RpcError(SESSION_CONFLICT, "another runner session is active", close=True)
            session = Session.from_params(peer, params)
            started.append(session)
            relay.start(session)
            return {}

        peer = Peer(StarletteChannel(websocket), {"session.start": start})
        try:
            await peer.run()
        finally:
            for session in started:
                relay.end(session)

    async def upstream(request: Request) -> Response:
        body = (await request.body()).decode("utf-8", errors="replace")
        params: dict[str, Any] = {
            "id": f"u{next(ids)}",
            "method": request.method,
            "path": request.url.path,
            "query": request.url.query,
            "headers": [
                [name.decode("latin-1").lower(), value.decode("latin-1")]
                for name, value in request.headers.raw
            ],
            "body": body,
            "json": _parse_json(body),
        }
        session = relay.session
        entry: dict[str, Any] = {
            "ts": _now(),
            "run_id": session.run_id if session else None,
            "seed": session.seed if session else None,
            "id": params["id"],
            "request": _redacted(params),
        }
        try:
            plan = ResponsePlan.parse(await forward(session, params))
        except NoRunnerError:
            return _refused(recorder, entry, 503, "no_runner", "no canarywire runner connected")
        except RunnerLostError:
            return _refused(recorder, entry, 503, "runner_lost", "canarywire runner disconnected")
        except TimeoutError:
            return _refused(recorder, entry, 504, "timeout", "canarywire runner did not answer")
        except (RpcError, ValueError):
            return _refused(recorder, entry, 502, "runner_error", "canarywire runner failed")
        if plan.body is not None:
            return _body_response(plan, plan.body, entry, recorder, session)
        return _stream_response(plan, plan.chunks or [], entry, recorder, session)

    return Starlette(
        routes=[
            Route("/_canarywire/health", health),
            WebSocketRoute("/_canarywire/ws", runner_socket),
            Route("/_canarywire/{rest:path}", reserved, methods=METHODS),
            Route("/{path:path}", upstream, methods=METHODS),
        ]
    )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_json(body: str) -> Any:
    if not body:
        return None
    try:
        return json.loads(body)
    except (ValueError, RecursionError):
        return None


def _redacted(params: dict[str, Any]) -> dict[str, Any]:
    """The request as recorded: `params` with secret header values replaced."""
    headers = [
        [name, REDACTED if name in SECRET_HEADERS else value] for name, value in params["headers"]
    ]
    return {**params, "headers": headers}


def _refused(
    recorder: Recorder, entry: dict[str, Any], status: int, outcome: str, message: str
) -> Response:
    entry["response"] = {"status": status, "body": message}
    entry["outcome"] = outcome
    recorder.write(entry)
    return PlainTextResponse(message, status_code=status)


def _with_headers(response: Response, headers: list[tuple[str, str]]) -> Response:
    for name, value in headers:
        if name.lower() not in DROPPED_HEADERS:
            response.headers.append(name, value)
    return response


def _body_response(
    plan: ResponsePlan,
    body: str,
    entry: dict[str, Any],
    recorder: Recorder,
    session: Session | None,
) -> Response:
    async def finish() -> None:
        entry["response"] = {"status": plan.status, "headers": plan.headers, "body": body}
        entry["outcome"] = "completed"
        recorder.write(entry)
        await notify_done(
            session, {"id": entry["id"], "outcome": "completed", "delivered_chunks": 1}
        )

    response = Response(body.encode(), status_code=plan.status, background=BackgroundTask(finish))
    return _with_headers(response, plan.headers)


class ClosingStreamingResponse(StreamingResponse):
    """A StreamingResponse that always closes its generator when the response task ends.

    On client disconnect Starlette cancels the send loop but never closes the body iterator, so
    the generator's `finally` (which records the outcome and sends `upstream.done`) would
    otherwise wait for garbage collection.
    """

    def __init__(self, content: AsyncGenerator[bytes, None], status_code: int) -> None:
        """Stream `content` with `status_code`."""
        super().__init__(content, status_code=status_code)
        self._generator = content

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Send the response, then close the generator however sending ended."""
        try:
            await super().__call__(scope, receive, send)
        finally:
            with anyio.CancelScope(shield=True):
                await self._generator.aclose()


def _stream_response(
    plan: ResponsePlan,
    chunks: list[tuple[str, int]],
    entry: dict[str, Any],
    recorder: Recorder,
    session: Session | None,
) -> Response:
    async def content() -> AsyncGenerator[bytes, None]:
        delivered: list[str] = []
        outcome = "aborted"
        try:
            for data, delay_ms in chunks:
                if delay_ms:
                    await anyio.sleep(delay_ms / 1000)
                yield data.encode()
                delivered.append(data)
            outcome = "completed"
        finally:
            with anyio.CancelScope(shield=True):
                entry["response"] = {
                    "status": plan.status,
                    "headers": plan.headers,
                    "chunks": delivered,
                }
                entry["outcome"] = outcome
                recorder.write(entry)
                await notify_done(
                    session,
                    {"id": entry["id"], "outcome": outcome, "delivered_chunks": len(delivered)},
                )

    return _with_headers(ClosingStreamingResponse(content(), status_code=plan.status), plan.headers)
