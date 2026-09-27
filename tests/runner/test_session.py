import socket
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import anyio
import httpx
import pytest
from live import free_port, live_server

from canarywire.capture.app import create_app
from canarywire.capture.recorder import Recorder
from canarywire.runner.messages import ResponseSpec, UpstreamRequest, json_response
from canarywire.runner.session import (
    CaptureSession,
    CaptureUnavailableError,
    open_capture,
    ws_url,
)

pytestmark = pytest.mark.anyio


async def not_found(request: UpstreamRequest) -> ResponseSpec:
    return ResponseSpec(404, "no attack")


@asynccontextmanager
async def running_session(url: str) -> AsyncIterator[CaptureSession]:
    connection = await open_capture(url, timeout=5)
    async with connection:
        session = CaptureSession(connection, not_found)
        error: Exception | None = None
        async with anyio.create_task_group() as tg:
            tg.start_soon(session.run)
            try:
                await session.start(run_id="r", seed=1, upstream_response_timeout=5, timeout=5)
                yield session
            except Exception as exc:
                error = exc
            finally:
                tg.cancel_scope.cancel()
        if error is not None:
            raise error


def test_ws_url() -> None:
    assert ws_url("http://h:1") == "ws://h:1/_canarywire/ws"
    assert ws_url("https://h/") == "wss://h/_canarywire/ws"
    with pytest.raises(CaptureUnavailableError):
        ws_url("ftp://h")


async def test_unreachable_capture() -> None:
    with pytest.raises(CaptureUnavailableError, match="cannot connect"):
        await open_capture(f"http://127.0.0.1:{free_port()}", timeout=1)


async def test_stalled_handshake_is_unavailable() -> None:
    """A TCP listener that never answers must surface as CaptureUnavailableError, not escape."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    port = listener.getsockname()[1]
    try:
        with pytest.raises(CaptureUnavailableError, match="cannot connect"):
            await open_capture(f"http://127.0.0.1:{port}", timeout=0.5)
    finally:
        listener.close()


async def test_session_answers_while_its_owner_posts(tmp_path: Path) -> None:
    """The negative-control shape: the runner POSTs to the capture and answers the relay."""
    seen: list[UpstreamRequest] = []

    async def handler(request: UpstreamRequest) -> ResponseSpec:
        seen.append(request)
        return json_response(200, {"ok": True})

    async with (
        live_server(create_app(Recorder(tmp_path / "c.jsonl"))) as url,
        running_session(url) as session,
        httpx.AsyncClient() as http,
    ):
        session.handler = handler
        response = await http.post(f"{url}/v1/chat/completions", json={"q": 1})
    assert response.json() == {"ok": True}
    assert seen[0].json == {"q": 1}


async def test_unexpected_handler_without_attack(tmp_path: Path) -> None:
    async with (
        live_server(create_app(Recorder(tmp_path / "c.jsonl"))) as url,
        running_session(url),
        httpx.AsyncClient() as http,
    ):
        response = await http.post(f"{url}/v1/chat/completions", json={})
    assert (response.status_code, response.text) == (404, "no attack")


async def test_handler_error_is_recorded(tmp_path: Path) -> None:
    async def broken(request: UpstreamRequest) -> ResponseSpec:
        raise RuntimeError("bug")

    async with (
        live_server(create_app(Recorder(tmp_path / "c.jsonl"))) as url,
        running_session(url) as session,
        httpx.AsyncClient() as http,
    ):
        session.handler = broken
        response = await http.post(f"{url}/v1/chat/completions", json={})
        errors = list(session.errors)
    assert response.status_code == 502
    assert len(errors) == 1
    assert "bug" in errors[0]


async def test_done_outcomes_are_tracked(tmp_path: Path) -> None:
    async with (
        live_server(create_app(Recorder(tmp_path / "c.jsonl"))) as url,
        running_session(url) as session,
        httpx.AsyncClient() as http,
    ):
        await http.post(f"{url}/v1/chat/completions", json={})
        with anyio.fail_after(5):
            while not session.outcomes:
                await anyio.sleep(0.01)
        outcomes = dict(session.outcomes)
    assert list(outcomes.values()) == ["completed"]


async def test_second_runner_is_rejected(tmp_path: Path) -> None:
    async with (
        live_server(create_app(Recorder(tmp_path / "c.jsonl"))) as url,
        running_session(url),
    ):
        with pytest.raises(CaptureUnavailableError, match="another runner session"):
            async with running_session(url):
                pass


async def test_closed_when_capture_goes_away(tmp_path: Path) -> None:
    async with live_server(create_app(Recorder(tmp_path / "c.jsonl"))) as url:
        connection = await open_capture(url, timeout=5)
    async with connection:
        session = CaptureSession(connection, not_found)
        with anyio.fail_after(5):
            await session.run()
    assert session.closed


async def test_wait_done_and_delivered(tmp_path: Path) -> None:
    seen: list[str] = []

    async def handler(request: UpstreamRequest) -> ResponseSpec:
        seen.append(request.request_id)
        return json_response(200, {"ok": True})

    async with (
        live_server(create_app(Recorder(tmp_path / "c.jsonl"))) as url,
        running_session(url) as session,
        httpx.AsyncClient() as http,
    ):
        session.handler = handler
        await http.post(f"{url}/v1/chat/completions", json={})
        assert await session.wait_done(seen, timeout=2) == []
        assert session.delivered[seen[0]] == 1
        with anyio.fail_after(2):
            assert await session.wait_done(["never"], timeout=0.2) == ["never"]
