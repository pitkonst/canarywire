"""Real sockets for unit tests: an in-process uvicorn server and a raw runner peer."""

from __future__ import annotations

import socket
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

import anyio
import uvicorn
from websockets.asyncio.client import connect

from canarywire.rpc import Peer
from canarywire.runner.session import WebsocketsChannel, ws_url

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Mapping

    import pytest
    from starlette.types import ASGIApp

    from canarywire.rpc import Handler


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


PROXY_VARIABLES = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY")


def dead_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Point every proxy variable at a port nothing listens on, with no NO_PROXY exemption.

    Any client that honours the environment for loopback traffic then fails to connect.
    """
    proxy = f"http://127.0.0.1:{free_port()}"
    for name in PROXY_VARIABLES:
        monkeypatch.setenv(name, proxy)
        monkeypatch.setenv(name.lower(), proxy)
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)


@asynccontextmanager
async def live_server(app: ASGIApp) -> AsyncIterator[str]:
    port = free_port()
    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=port,
        log_level="warning",
        ws="websockets-sansio",
        lifespan="off",
    )
    server = uvicorn.Server(config)
    error: Exception | None = None
    async with anyio.create_task_group() as tg:
        tg.start_soon(server.serve)
        with anyio.fail_after(5):
            while not server.started:
                await anyio.sleep(0.01)
        try:
            yield f"http://127.0.0.1:{port}"
        except Exception as exc:
            error = exc
        finally:
            server.should_exit = True
    if error is not None:
        raise error


@asynccontextmanager
async def runner_peer(
    base_url: str,
    handlers: Mapping[str, Handler],
    *,
    upstream_response_timeout: float = 5.0,
    start: bool = True,
) -> AsyncIterator[Peer]:
    async with connect(ws_url(base_url)) as connection:
        peer = Peer(WebsocketsChannel(connection), handlers)
        error: Exception | None = None
        async with anyio.create_task_group() as tg:
            tg.start_soon(peer.run)
            try:
                if start:
                    await peer.call(
                        "session.start",
                        {
                            "run_id": "run-1",
                            "seed": 7,
                            "upstream_response_timeout": upstream_response_timeout,
                        },
                        timeout=5,
                    )
                yield peer
            except Exception as exc:
                error = exc
            finally:
                tg.cancel_scope.cancel()
        if error is not None:
            raise error
