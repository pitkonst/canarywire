"""JSON-RPC 2.0 peers over a text-message channel (a WebSocket, on either side)."""

from __future__ import annotations

import contextlib
import itertools
import json
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any, Protocol

import anyio

if TYPE_CHECKING:
    from collections.abc import Mapping

    from anyio.abc import TaskGroup

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

Handler = Callable[[Any], Awaitable[Any]]


class ChannelClosedError(Exception):
    """The channel is closed; no more messages can be sent or received."""


class RpcError(Exception):
    """A JSON-RPC error: returned by the other side, or raised by a handler to answer with one."""

    def __init__(self, code: int, message: str, *, close: bool = False) -> None:
        """Error `code` and `message`; `close` asks the peer to close the channel after replying."""
        super().__init__(message)
        self.code = code
        self.message = message
        self.close = close


class Channel(Protocol):
    """A bidirectional stream of text messages."""

    async def send(self, text: str) -> None:
        """Send one message; raise ChannelClosedError if closed."""

    async def receive(self) -> str:
        """Receive one message; raise ChannelClosedError once closed."""

    async def close(self) -> None:
        """Close the channel."""


class _Pending:
    def __init__(self) -> None:
        self.event = anyio.Event()
        self.result: Any = None
        self.error: Exception | None = None


class Peer:
    """One side of a JSON-RPC connection: calls the other side and serves its calls."""

    def __init__(self, channel: Channel, handlers: Mapping[str, Handler]) -> None:
        """Serve `handlers` (method name to async function of params) over `channel`."""
        self._channel = channel
        self._handlers = dict(handlers)
        self._ids = itertools.count(1)
        self._pending: dict[int, _Pending] = {}
        self._send_lock = anyio.Lock()
        self._closed = False

    async def run(self) -> None:
        """Read messages until the channel closes, handling each call in its own task."""
        try:
            async with anyio.create_task_group() as tg:
                while True:
                    try:
                        text = await self._channel.receive()
                    except ChannelClosedError:
                        break
                    self._dispatch(text, tg)
                tg.cancel_scope.cancel()
        finally:
            # Fail pending calls first: if run() itself was cancelled, the shielded close
            # below must not stop that from happening, and callers must not be left hanging.
            self._closed = True
            for pending in self._pending.values():
                pending.error = ChannelClosedError()
                pending.event.set()
            with anyio.CancelScope(shield=True), contextlib.suppress(Exception):
                await self._channel.close()

    async def call(self, method: str, params: Any, timeout: float | None = None) -> Any:
        """Call `method` on the other side and return its result.

        Raises RpcError (error reply), TimeoutError or ChannelClosedError.
        """
        if self._closed:
            raise ChannelClosedError
        msg_id = next(self._ids)
        pending = _Pending()
        self._pending[msg_id] = pending
        try:
            with anyio.fail_after(timeout):
                await self._send(
                    {"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params}
                )
                await pending.event.wait()
        finally:
            self._pending.pop(msg_id, None)
        if pending.error is not None:
            raise pending.error
        return pending.result

    async def notify(self, method: str, params: Any) -> None:
        """Send a notification; no reply is expected."""
        await self._send({"jsonrpc": "2.0", "method": method, "params": params})

    async def _send(self, message: dict[str, Any]) -> None:
        async with self._send_lock:
            await self._channel.send(json.dumps(message))

    def _dispatch(self, text: str, tg: TaskGroup) -> None:
        try:
            message = json.loads(text)
        except (ValueError, RecursionError):
            tg.start_soon(self._reply_error, None, PARSE_ERROR, "parse error")
            return
        if not isinstance(message, dict):
            tg.start_soon(self._reply_error, None, INVALID_REQUEST, "invalid request")
            return
        if "method" in message:
            tg.start_soon(self._handle, message)
            return
        msg_id = message.get("id")
        pending = self._pending.get(msg_id) if isinstance(msg_id, int) else None
        if pending is None:
            return
        error = message.get("error")
        if isinstance(error, dict):
            code = error.get("code")
            pending.error = RpcError(
                code if isinstance(code, int) else INTERNAL_ERROR, str(error.get("message", ""))
            )
        else:
            pending.result = message.get("result")
        pending.event.set()

    async def _handle(self, message: dict[str, Any]) -> None:
        msg_id = message.get("id")
        try:
            await self._handle_call(message, msg_id)
        except Exception as exc:  # backstop: never let this task die silently
            with contextlib.suppress(Exception):
                await self._reply_error(msg_id, INTERNAL_ERROR, f"{type(exc).__name__}: {exc}")

    async def _handle_call(self, message: dict[str, Any], msg_id: Any) -> None:
        method = message.get("method")
        handler = self._handlers.get(method) if isinstance(method, str) else None
        if handler is None:
            await self._reply_error(msg_id, METHOD_NOT_FOUND, f"method not found: {method}")
            return
        try:
            result = await handler(message.get("params"))
        except RpcError as exc:
            await self._reply_error(msg_id, exc.code, exc.message)
            if exc.close:
                await self._channel.close()
            return
        except Exception as exc:
            await self._reply_error(msg_id, INTERNAL_ERROR, f"{type(exc).__name__}: {exc}")
            return
        if msg_id is None:
            return
        try:
            await self._reply({"jsonrpc": "2.0", "id": msg_id, "result": result})
        except (TypeError, ValueError) as exc:
            await self._reply_error(msg_id, INTERNAL_ERROR, f"{type(exc).__name__}: {exc}")

    async def _reply_error(self, msg_id: Any, code: int, message: str) -> None:
        if msg_id is None and code not in (PARSE_ERROR, INVALID_REQUEST):
            return  # notifications never get a reply
        await self._reply(
            {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}
        )

    async def _reply(self, message: dict[str, Any]) -> None:
        with contextlib.suppress(ChannelClosedError):
            await self._send(message)
