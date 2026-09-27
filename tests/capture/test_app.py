import json
import os
from pathlib import Path
from typing import Any

import anyio
import httpx
import pytest
from live import live_server, runner_peer

from canarywire.capture.app import PID_HEADER, create_app
from canarywire.capture.recorder import Recorder
from canarywire.rpc import RpcError

pytestmark = pytest.mark.anyio

SESSION = {"run_id": "run-2", "seed": 1, "upstream_response_timeout": 5}


def records(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines()]


async def test_health(tmp_path: Path) -> None:
    async with (
        live_server(create_app(Recorder(tmp_path / "c.jsonl"))) as url,
        httpx.AsyncClient() as http,
    ):
        response = await http.get(f"{url}/_canarywire/health")
    assert (response.status_code, response.text) == (200, "ok")
    assert response.headers[PID_HEADER] == str(os.getpid())


async def test_reserved_paths_are_not_relayed(tmp_path: Path) -> None:
    path = tmp_path / "c.jsonl"
    async with live_server(create_app(Recorder(path))) as url, httpx.AsyncClient() as http:
        response = await http.get(f"{url}/_canarywire/other")
    assert response.status_code == 404
    assert not path.exists()


async def test_no_runner_is_503_and_recorded(tmp_path: Path) -> None:
    path = tmp_path / "c.jsonl"
    async with live_server(create_app(Recorder(path))) as url, httpx.AsyncClient() as http:
        response = await http.post(f"{url}/v1/chat/completions", json={"a": 1})
    assert response.status_code == 503
    [entry] = records(path)
    assert entry["outcome"] == "no_runner"
    assert entry["run_id"] is None
    assert entry["request"]["json"] == {"a": 1}


async def test_deeply_nested_body_with_no_runner_is_503_and_recorded(tmp_path: Path) -> None:
    """A pathologically nested body must still be relayed/recorded, not crash the capture."""
    path = tmp_path / "c.jsonl"
    body = "[" * 200000
    async with live_server(create_app(Recorder(path))) as url, httpx.AsyncClient() as http:
        response = await http.post(f"{url}/v1/chat/completions", content=body)
    assert response.status_code == 503
    [entry] = records(path)
    assert entry["outcome"] == "no_runner"
    assert entry["request"]["json"] is None


async def test_relays_body_response(tmp_path: Path) -> None:
    path = tmp_path / "c.jsonl"
    seen: list[Any] = []
    outcomes: list[Any] = []
    done = anyio.Event()

    async def on_request(params: Any) -> Any:
        seen.append(params)
        return {"status": 201, "headers": [["x-test", "1"]], "body": "hello"}

    async def on_done(params: Any) -> Any:
        outcomes.append(params)
        done.set()

    handlers = {"upstream.request": on_request, "upstream.done": on_done}
    async with (
        live_server(create_app(Recorder(path))) as url,
        runner_peer(url, handlers),
        httpx.AsyncClient() as http,
    ):
        response = await http.post(f"{url}/v1/x?q=1", content=b"not json", headers={"X-Key": "v"})
        with anyio.fail_after(5):
            await done.wait()
    assert (response.status_code, response.text) == (201, "hello")
    assert response.headers["x-test"] == "1"
    [params] = seen
    assert (params["method"], params["path"], params["query"]) == ("POST", "/v1/x", "q=1")
    assert ["x-key", "v"] in params["headers"]
    assert (params["body"], params["json"]) == ("not json", None)
    assert outcomes == [{"id": params["id"], "outcome": "completed", "delivered_chunks": 1}]
    [entry] = records(path)
    assert (entry["run_id"], entry["seed"], entry["outcome"]) == ("run-1", 7, "completed")
    assert entry["response"]["body"] == "hello"


async def test_secret_headers_are_relayed_but_not_recorded(tmp_path: Path) -> None:
    """The runner scans every header, but credentials never land in capture.jsonl."""
    path = tmp_path / "c.jsonl"
    seen: list[Any] = []
    done = anyio.Event()

    async def on_request(params: Any) -> Any:
        seen.append(params)
        return {"status": 200, "body": "ok"}

    async def on_done(params: Any) -> Any:
        done.set()

    secrets = {
        "Authorization": "Bearer sk-synthetic",
        "Proxy-Authorization": "Basic c3ludGhldGlj",
        "X-Api-Key": "key-synthetic",
        "Api-Key": "azure-synthetic",
        "X-Goog-Api-Key": "goog-synthetic",
        "Cookie": "session=synthetic",
    }
    handlers = {"upstream.request": on_request, "upstream.done": on_done}
    async with (
        live_server(create_app(Recorder(path))) as url,
        runner_peer(url, handlers),
        httpx.AsyncClient() as http,
    ):
        await http.post(f"{url}/v1/x", json={}, headers={**secrets, "X-Other": "kept"})
        with anyio.fail_after(5):
            await done.wait()
    [params] = seen
    for name, value in secrets.items():
        assert [name.lower(), value] in params["headers"]
    [entry] = records(path)
    recorded = dict(entry["request"]["headers"])
    assert {name.lower(): recorded[name.lower()] for name in secrets} == {
        name.lower(): "[redacted]" for name in secrets
    }
    assert recorded["x-other"] == "kept"
    assert "synthetic" not in path.read_text()


async def test_relays_stream_response(tmp_path: Path) -> None:
    path = tmp_path / "c.jsonl"
    outcomes: list[Any] = []
    done = anyio.Event()

    async def on_request(params: Any) -> Any:
        return {
            "status": 200,
            "headers": [["content-type", "text/event-stream"]],
            "stream": [{"data": "a", "delay_ms": 0}, {"data": "b", "delay_ms": 10}],
        }

    async def on_done(params: Any) -> Any:
        outcomes.append(params)
        done.set()

    handlers = {"upstream.request": on_request, "upstream.done": on_done}
    async with (
        live_server(create_app(Recorder(path))) as url,
        runner_peer(url, handlers),
        httpx.AsyncClient() as http,
    ):
        response = await http.post(f"{url}/v1/chat/completions", json={})
        with anyio.fail_after(5):
            await done.wait()
    assert response.text == "ab"
    assert outcomes[0]["outcome"] == "completed"
    assert outcomes[0]["delivered_chunks"] == 2
    assert records(path)[0]["response"]["chunks"] == ["a", "b"]


async def test_runner_timeout_is_504(tmp_path: Path) -> None:
    path = tmp_path / "c.jsonl"

    async def on_request(params: Any) -> Any:
        await anyio.sleep_forever()

    handlers = {"upstream.request": on_request}
    async with (
        live_server(create_app(Recorder(path))) as url,
        runner_peer(url, handlers, upstream_response_timeout=0.2),
        httpx.AsyncClient() as http,
    ):
        response = await http.post(f"{url}/v1/chat/completions", json={})
    assert response.status_code == 504
    assert records(path)[0]["outcome"] == "timeout"


@pytest.mark.parametrize(
    "answer",
    [
        RpcError(-32000, "no"),
        {"status": "x", "body": ""},
        {"status": 200},
        {"status": 200, "headers": {"ab": "x"}, "body": ""},
        {"status": 200, "headers": "ab", "body": ""},
        {"status": 200, "headers": [["x-a", 1]], "body": ""},
    ],
)
async def test_runner_error_is_502(tmp_path: Path, answer: Any) -> None:
    path = tmp_path / "c.jsonl"

    async def on_request(params: Any) -> Any:
        if isinstance(answer, Exception):
            raise answer
        return answer

    async with (
        live_server(create_app(Recorder(path))) as url,
        runner_peer(url, {"upstream.request": on_request}),
        httpx.AsyncClient() as http,
    ):
        response = await http.post(f"{url}/v1/chat/completions", json={})
    assert response.status_code == 502
    assert records(path)[0]["outcome"] == "runner_error"


async def test_runner_lost_mid_request_is_503(tmp_path: Path) -> None:
    path = tmp_path / "c.jsonl"
    received = anyio.Event()
    responses: list[httpx.Response] = []

    async def on_request(params: Any) -> Any:
        received.set()
        await anyio.sleep_forever()

    async with live_server(create_app(Recorder(path))) as url, httpx.AsyncClient() as http:

        async def post() -> None:
            responses.append(await http.post(f"{url}/v1/chat/completions", json={}))

        async with (
            anyio.create_task_group() as tg,
            runner_peer(url, {"upstream.request": on_request}),
        ):
            tg.start_soon(post)
            with anyio.fail_after(5):
                await received.wait()
    assert responses[0].status_code == 503
    assert records(path)[0]["outcome"] == "runner_lost"


async def test_second_session_is_rejected(tmp_path: Path) -> None:
    async with (
        live_server(create_app(Recorder(tmp_path / "c.jsonl"))) as url,
        runner_peer(url, {}),
        runner_peer(url, {}, start=False) as second,
    ):
        with pytest.raises(RpcError, match="another runner session is active"):
            await second.call("session.start", SESSION, timeout=5)


async def test_second_start_on_same_socket_is_rejected(tmp_path: Path) -> None:
    async with (
        live_server(create_app(Recorder(tmp_path / "c.jsonl"))) as url,
        runner_peer(url, {}) as peer,
    ):
        with pytest.raises(RpcError, match="session already started"):
            await peer.call("session.start", SESSION, timeout=5)


async def test_session_is_freed_when_runner_disconnects(tmp_path: Path) -> None:
    async with live_server(create_app(Recorder(tmp_path / "c.jsonl"))) as url:
        async with runner_peer(url, {}):
            pass
        async with runner_peer(url, {}, start=False) as peer:
            with anyio.fail_after(5):
                while True:
                    try:
                        await peer.call("session.start", SESSION, timeout=5)
                        break
                    except RpcError:
                        await anyio.sleep(0.02)


@pytest.mark.parametrize(
    "answer",
    [
        {"status": 204, "body": "x"},
        {"status": 304, "body": "x"},
        {"status": 101, "body": "x"},
        {"status": 204, "stream": [{"data": "x", "delay_ms": 0}]},
    ],
)
async def test_no_body_status_with_body_is_502(tmp_path: Path, answer: Any) -> None:
    path = tmp_path / "c.jsonl"

    async def on_request(params: Any) -> Any:
        return answer

    async with (
        live_server(create_app(Recorder(path))) as url,
        runner_peer(url, {"upstream.request": on_request}),
        httpx.AsyncClient() as http,
    ):
        response = await http.post(f"{url}/v1/chat/completions", json={})
    assert response.status_code == 502
    assert records(path)[0]["outcome"] == "runner_error"


async def test_no_body_status_without_body_is_relayed(tmp_path: Path) -> None:
    async def on_request(params: Any) -> Any:
        return {"status": 204, "body": ""}

    async with (
        live_server(create_app(Recorder(tmp_path / "c.jsonl"))) as url,
        runner_peer(url, {"upstream.request": on_request}),
        httpx.AsyncClient() as http,
    ):
        response = await http.post(f"{url}/v1/chat/completions", json={})
    assert response.status_code == 204


async def test_client_disconnect_mid_stream_is_recorded_promptly(tmp_path: Path) -> None:
    path = tmp_path / "c.jsonl"
    outcomes: list[Any] = []
    done = anyio.Event()

    async def on_request(params: Any) -> Any:
        return {
            "status": 200,
            "headers": [["content-type", "text/event-stream"]],
            "stream": [{"data": "a", "delay_ms": 0}, {"data": "b", "delay_ms": 3000}],
        }

    async def on_done(params: Any) -> Any:
        outcomes.append(params)
        done.set()

    handlers = {"upstream.request": on_request, "upstream.done": on_done}
    async with (
        live_server(create_app(Recorder(path))) as url,
        runner_peer(url, handlers),
        httpx.AsyncClient() as http,
    ):
        async with http.stream("POST", f"{url}/v1/chat/completions", json={}) as response:
            async for _ in response.aiter_bytes():
                break  # got "a"; leaving the block closes the connection mid-stream
        with anyio.fail_after(2):
            await done.wait()
    assert outcomes[0]["outcome"] == "aborted"
    assert outcomes[0]["delivered_chunks"] == 1
    assert records(path)[0]["outcome"] == "aborted"
