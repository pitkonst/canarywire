"""The runner's side of the capture WebSocket."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

import anyio
from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed, WebSocketException

from canarywire.loopback import is_loopback
from canarywire.rpc import INVALID_PARAMS, ChannelClosedError, Peer, RpcError
from canarywire.runner.messages import ResponseSpec, UpstreamRequest

if TYPE_CHECKING:
    from collections.abc import Collection

    from websockets.asyncio.client import ClientConnection

WS_PATH = "/_canarywire/ws"
WS_SCHEMES = {"http": "ws", "https": "wss"}
DONE_POLL = 0.01


class CaptureUnavailableError(Exception):
    """The capture cannot be reached, or it refused the session."""


def ws_url(capture_url: str) -> str:
    """Derive the capture's WebSocket URL from its HTTP URL."""
    scheme, separator, rest = capture_url.partition("://")
    if not separator or scheme not in WS_SCHEMES:
        raise CaptureUnavailableError(f"capture URL must be http(s)://, got {capture_url!r}")
    return f"{WS_SCHEMES[scheme]}://{rest.rstrip('/')}{WS_PATH}"


class WebsocketsChannel:
    """RPC channel over the runner's `websockets` client connection."""

    def __init__(self, connection: ClientConnection) -> None:
        """Wrap an open client connection."""
        self._connection = connection

    async def send(self, text: str) -> None:
        """Send one text frame."""
        try:
            await self._connection.send(text)
        except ConnectionClosed as exc:
            raise ChannelClosedError from exc

    async def receive(self) -> str:
        """Receive one frame as text."""
        try:
            message = await self._connection.recv()
        except ConnectionClosed as exc:
            raise ChannelClosedError from exc
        return message if isinstance(message, str) else message.decode("utf-8", errors="replace")

    async def close(self) -> None:
        """Close the connection."""
        await self._connection.close()


Handler = Callable[[UpstreamRequest], Awaitable[ResponseSpec]]


async def open_capture(capture_url: str, timeout: float) -> ClientConnection:
    """Open the WebSocket to the capture; raise CaptureUnavailableError if it cannot."""
    url = ws_url(capture_url)
    try:
        return await connect(
            url,
            open_timeout=timeout,
            max_size=None,
            proxy=None if is_loopback(urlsplit(url).hostname) else True,
        )
    # asyncio.TimeoutError is distinct from the builtin TimeoutError before Python 3.11, and
    # websockets raises the asyncio one when `open_timeout` expires.
    except (OSError, TimeoutError, asyncio.TimeoutError, WebSocketException) as exc:
        raise CaptureUnavailableError(f"cannot connect to capture at {url}: {exc}") from exc


class CaptureSession:
    """Answers the capture's `upstream.request` calls with the active handler."""

    def __init__(self, connection: ClientConnection, unexpected: Handler) -> None:
        """Serve `connection`; `unexpected` answers requests while no attack is active."""
        self.handler: Handler | None = None
        self.outcomes: dict[str, str] = {}
        self.delivered: dict[str, int] = {}
        self.errors: list[str] = []
        self.closed = False
        self._unexpected = unexpected
        self._peer = Peer(
            WebsocketsChannel(connection),
            {"upstream.request": self._on_request, "upstream.done": self._on_done},
        )

    async def run(self) -> None:
        """Serve the socket until it closes; `closed` is True afterwards."""
        try:
            await self._peer.run()
        finally:
            self.closed = True

    async def start(
        self, *, run_id: str, seed: int, upstream_response_timeout: float, timeout: float
    ) -> None:
        """Claim the capture for this run."""
        params = {
            "run_id": run_id,
            "seed": seed,
            "upstream_response_timeout": upstream_response_timeout,
        }
        try:
            await self._peer.call("session.start", params, timeout=timeout)
        except RpcError as exc:
            raise CaptureUnavailableError(f"capture rejected the session: {exc.message}") from exc
        except (TimeoutError, ChannelClosedError) as exc:
            raise CaptureUnavailableError("capture did not accept the session") from exc

    async def _on_request(self, params: object) -> object:
        try:
            request = UpstreamRequest.from_params(params)
        except ValueError as exc:
            raise RpcError(INVALID_PARAMS, str(exc)) from exc
        handler = self.handler or self._unexpected
        try:
            spec = await handler(request)
        except Exception as exc:
            self.errors.append(f"error answering {request.method} {request.path}: {exc!r}")
            raise
        return spec.to_result()

    async def _on_done(self, params: object) -> object:
        if isinstance(params, dict) and isinstance(params.get("id"), str):
            self.outcomes[params["id"]] = str(params.get("outcome"))
            delivered = params.get("delivered_chunks")
            if isinstance(delivered, int) and not isinstance(delivered, bool):
                self.delivered[params["id"]] = delivered
        return None

    async def wait_done(self, request_ids: Collection[str], timeout: float) -> list[str]:
        """Wait until every id has an `upstream.done`; return the ids still missing."""
        with anyio.move_on_after(timeout):
            while any(request_id not in self.outcomes for request_id in request_ids):
                await anyio.sleep(DONE_POLL)
        return [request_id for request_id in request_ids if request_id not in self.outcomes]
