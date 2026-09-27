from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from typing import Any

import anyio
import pytest
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream

from canarywire.rpc import (
    INTERNAL_ERROR,
    METHOD_NOT_FOUND,
    ChannelClosedError,
    Handler,
    Peer,
    RpcError,
)

pytestmark = pytest.mark.anyio


class MemoryChannel:
    def __init__(
        self, send: MemoryObjectSendStream[str], receive: MemoryObjectReceiveStream[str]
    ) -> None:
        self._send = send
        self._receive = receive

    async def send(self, text: str) -> None:
        try:
            await self._send.send(text)
        except (anyio.BrokenResourceError, anyio.ClosedResourceError) as exc:
            raise ChannelClosedError from exc

    async def receive(self) -> str:
        try:
            return await self._receive.receive()
        except (anyio.EndOfStream, anyio.ClosedResourceError) as exc:
            raise ChannelClosedError from exc

    async def close(self) -> None:
        await self._send.aclose()


@asynccontextmanager
async def peers(
    a_handlers: Mapping[str, Handler], b_handlers: Mapping[str, Handler]
) -> AsyncIterator[tuple[Peer, Peer]]:
    a_send, b_receive = anyio.create_memory_object_stream[str](16)
    b_send, a_receive = anyio.create_memory_object_stream[str](16)
    streams = (a_send, b_receive, b_send, a_receive)
    a = Peer(MemoryChannel(a_send, a_receive), a_handlers)
    b = Peer(MemoryChannel(b_send, b_receive), b_handlers)
    error: Exception | None = None
    async with anyio.create_task_group() as tg:
        tg.start_soon(a.run)
        tg.start_soon(b.run)
        try:
            yield a, b
        except Exception as exc:
            error = exc
        finally:
            tg.cancel_scope.cancel()
    for stream in streams:
        await stream.aclose()
    if error is not None:
        raise error


async def test_call_returns_result() -> None:
    async def add(params: Any) -> Any:
        return params[0] + params[1]

    async with peers({}, {"add": add}) as (a, _):
        assert await a.call("add", [1, 2], timeout=5) == 3


async def test_notification_is_delivered() -> None:
    received: list[Any] = []
    arrived = anyio.Event()

    async def note(params: Any) -> Any:
        received.append(params)
        arrived.set()

    async with peers({}, {"note": note}) as (a, _):
        await a.notify("note", {"x": 1})
        with anyio.fail_after(5):
            await arrived.wait()
    assert received == [{"x": 1}]


async def test_handler_rpc_error_is_returned() -> None:
    async def refuse(params: Any) -> Any:
        raise RpcError(-32000, "nope")

    async with peers({}, {"refuse": refuse}) as (a, _):
        with pytest.raises(RpcError, match="nope") as exc:
            await a.call("refuse", None, timeout=5)
    assert exc.value.code == -32000


async def test_unknown_method() -> None:
    async with peers({}, {}) as (a, _):
        with pytest.raises(RpcError) as exc:
            await a.call("missing", None, timeout=5)
    assert exc.value.code == METHOD_NOT_FOUND


async def test_crashing_handler_is_internal_error() -> None:
    async def crash(params: Any) -> Any:
        raise RuntimeError("boom")

    async with peers({}, {"crash": crash}) as (a, _):
        with pytest.raises(RpcError, match="boom") as exc:
            await a.call("crash", None, timeout=5)
    assert exc.value.code == INTERNAL_ERROR


async def test_call_timeout() -> None:
    async def hang(params: Any) -> Any:
        await anyio.sleep_forever()

    async with peers({}, {"hang": hang}) as (a, _):
        with pytest.raises(TimeoutError):
            await a.call("hang", None, timeout=0.1)


async def test_handler_can_call_back_while_its_caller_waits() -> None:
    """The negative-control shape: A calls B, B's handler calls A before answering."""
    peer_b: list[Peer] = []

    async def inner(params: Any) -> Any:
        return "inner"

    async def outer(params: Any) -> Any:
        return await peer_b[0].call("inner", None, timeout=5)

    async with peers({"inner": inner}, {"outer": outer}) as (a, b):
        peer_b.append(b)
        assert await a.call("outer", None, timeout=5) == "inner"


async def test_non_serializable_result_is_internal_error_and_peer_keeps_working() -> None:
    """A handler result that json.dumps can't serialize must not crash the peer."""

    async def give_object(params: Any) -> Any:
        return object()

    async def add(params: Any) -> Any:
        return params[0] + params[1]

    async with peers({}, {"bad": give_object, "add": add}) as (a, _):
        with pytest.raises(RpcError) as exc:
            await a.call("bad", None, timeout=5)
        assert exc.value.code == INTERNAL_ERROR
        assert await a.call("add", [1, 2], timeout=5) == 3


async def test_call_raises_channel_closed_when_channel_closes_while_pending() -> None:
    """If the channel closes mid-call, it must raise ChannelClosedError, not time out."""
    entered = anyio.Event()

    async def hang(params: Any) -> Any:
        entered.set()
        await anyio.sleep_forever()

    a_send, b_receive = anyio.create_memory_object_stream[str](16)
    b_send, a_receive = anyio.create_memory_object_stream[str](16)
    a = Peer(MemoryChannel(a_send, a_receive), {})
    b = Peer(MemoryChannel(b_send, b_receive), {"hang": hang})

    async with anyio.create_task_group() as tg:
        tg.start_soon(a.run)
        tg.start_soon(b.run)
        with anyio.fail_after(5):
            async with anyio.create_task_group() as call_tg:

                async def do_call() -> None:
                    with pytest.raises(ChannelClosedError):
                        await a.call("hang", None, timeout=5)

                call_tg.start_soon(do_call)
                await entered.wait()
                await b_send.aclose()
        tg.cancel_scope.cancel()

    for stream in (a_send, b_receive, b_send, a_receive):
        await stream.aclose()


async def test_cancelling_run_fails_pending_calls() -> None:
    """If run() itself is cancelled, pending calls must fail, not hang forever."""
    entered = anyio.Event()

    async def hang(params: Any) -> Any:
        entered.set()
        await anyio.sleep_forever()

    a_send, b_receive = anyio.create_memory_object_stream[str](16)
    b_send, a_receive = anyio.create_memory_object_stream[str](16)
    a = Peer(MemoryChannel(a_send, a_receive), {})
    b = Peer(MemoryChannel(b_send, b_receive), {"hang": hang})
    run_scope: list[anyio.CancelScope] = []

    async def run_a() -> None:
        with anyio.CancelScope() as scope:
            run_scope.append(scope)
            await a.run()

    async with anyio.create_task_group() as tg:
        tg.start_soon(run_a)
        tg.start_soon(b.run)
        with anyio.fail_after(5):
            async with anyio.create_task_group() as call_tg:

                async def do_call() -> None:
                    with pytest.raises(ChannelClosedError):
                        await a.call("hang", None, timeout=5)

                call_tg.start_soon(do_call)
                await entered.wait()
                run_scope[0].cancel()
        tg.cancel_scope.cancel()
    for stream in (a_send, b_receive, b_send, a_receive):
        await stream.aclose()


async def test_close_after_error_reply_closes_the_channel() -> None:
    """B replies with an error, then closes its sending side; A's next call cannot proceed."""

    async def stop(params: Any) -> Any:
        raise RpcError(-32000, "bye", close=True)

    async def echo(params: Any) -> Any:
        return params

    async with peers({}, {"stop": stop, "echo": echo}) as (a, _):
        with pytest.raises(RpcError, match="bye"):
            await a.call("stop", None, timeout=5)
        with anyio.fail_after(5):
            while True:  # A's reader sees end-of-stream shortly after the reply
                try:
                    await a.call("echo", 1, timeout=0.2)
                except (ChannelClosedError, TimeoutError):
                    break
                await anyio.sleep(0.01)
        with pytest.raises(ChannelClosedError):
            await a.call("echo", 1, timeout=5)
