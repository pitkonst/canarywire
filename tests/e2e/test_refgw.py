"""The reference gateway must be right before it is trusted to judge canarywire."""

import ast
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest
from harness import E2E, ECHO_UPSTREAM, REFGW, free_port, refgw_spec, wait_ready

pytestmark = [pytest.mark.e2e, pytest.mark.anyio]

ALICE = "alice.roe@example.org"
BOB = "bob.doe@example.net"


@dataclass(frozen=True)
class Upstream:
    url: str
    log: Path

    def raw(self) -> str:
        return self.log.read_text() if self.log.exists() else ""

    def recorded(self) -> list[dict[str, Any]]:
        return [json.loads(line) for line in self.raw().splitlines()]


@pytest.fixture
async def upstream(e2e: E2E) -> Upstream:
    port = free_port()
    log = e2e.workdir / "upstream.jsonl"
    proc = await e2e.start(
        "echo-upstream",
        [sys.executable, str(ECHO_UPSTREAM), "--listen", f"127.0.0.1:{port}", "--log", str(log)],
    )
    await wait_ready(f"http://127.0.0.1:{port}/healthz", proc)
    return Upstream(f"http://127.0.0.1:{port}", log)


async def chat(base_url: str, content: str) -> httpx.Response:
    async with httpx.AsyncClient(timeout=10.0) as client:
        return await client.post(
            f"{base_url}/v1/chat/completions",
            json={"model": "test", "messages": [{"role": "user", "content": content}]},
        )


def reply(response: httpx.Response) -> str:
    content: str = response.json()["choices"][0]["message"]["content"]
    return content


async def test_masks_upstream_and_restores_client(e2e: E2E, upstream: Upstream) -> None:
    gw = refgw_spec(upstream=upstream.url, port=free_port())
    await e2e.start_gateway(gw)

    response = await chat(gw.url, f"mail {ALICE}, {BOB}, {ALICE}")

    assert response.status_code == 200, e2e.diagnostics()
    assert ALICE not in upstream.raw()
    assert BOB not in upstream.raw()
    sent = upstream.recorded()[0]["body"]["messages"][0]["content"]
    assert sent == "mail <EMAIL_1>, <EMAIL_2>, <EMAIL_1>"
    assert reply(response) == f"echo: mail {ALICE}, {BOB}, {ALICE}"


async def test_passthrough_bug_leaks_upstream(e2e: E2E, upstream: Upstream) -> None:
    gw = refgw_spec(upstream=upstream.url, port=free_port(), bug="passthrough")
    await e2e.start_gateway(gw)

    response = await chat(gw.url, f"mail {ALICE}")

    assert response.status_code == 200, e2e.diagnostics()
    assert ALICE in upstream.raw()


async def test_unreachable_upstream_is_refused(e2e: E2E) -> None:
    gw = refgw_spec(upstream=f"http://127.0.0.1:{free_port()}", port=free_port())
    await e2e.start_gateway(gw)

    response = await chat(gw.url, f"mail {ALICE}")

    assert response.status_code == 502
    assert ALICE not in response.text


async def test_malformed_json_is_refused(e2e: E2E, upstream: Upstream) -> None:
    gw = refgw_spec(upstream=upstream.url, port=free_port())
    await e2e.start_gateway(gw)

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(
            f"{gw.url}/v1/chat/completions",
            content=b"{not json",
            headers={"content-type": "application/json"},
        )

    assert response.status_code == 502
    assert upstream.recorded() == []


async def test_blackhole_bug_never_forwards(e2e: E2E, upstream: Upstream) -> None:
    gw = refgw_spec(upstream=upstream.url, port=free_port(), bug="blackhole")
    await e2e.start_gateway(gw)

    response = await chat(gw.url, f"mail {ALICE}")

    assert response.status_code == 200
    assert upstream.recorded() == []


def stream_text(raw: str) -> str:
    """Independent SSE reassembly for tests (no canarywire imports needed here)."""
    text = ""
    for block in raw.replace("\r\n", "\n").split("\n\n"):
        for line in block.split("\n"):
            if line.startswith("data: ") and line != "data: [DONE]":
                text += json.loads(line[len("data: ") :])["choices"][0]["delta"].get("content", "")
    return text


async def chat_stream(base_url: str, content: str) -> httpx.Response:
    async with httpx.AsyncClient(timeout=10.0) as client:
        return await client.post(
            f"{base_url}/v1/chat/completions",
            json={
                "model": "test",
                "stream": True,
                "messages": [{"role": "user", "content": content}],
            },
            headers={"accept": "text/event-stream"},
        )


async def test_streaming_restores_placeholders_split_across_events(
    e2e: E2E, upstream: Upstream
) -> None:
    gw = refgw_spec(upstream=upstream.url, port=free_port())
    await e2e.start_gateway(gw)

    response = await chat_stream(gw.url, f"mail {ALICE}, {BOB}, {ALICE}")

    assert response.status_code == 200, e2e.diagnostics()
    assert response.headers["content-type"].startswith("text/event-stream")
    assert response.text.rstrip().endswith("data: [DONE]")
    assert ALICE not in upstream.raw()
    assert stream_text(response.text) == f"echo: mail {ALICE}, {BOB}, {ALICE}"


async def test_split_sse_bug_leaves_split_placeholders(e2e: E2E, upstream: Upstream) -> None:
    gw = refgw_spec(upstream=upstream.url, port=free_port(), bug="split-sse")
    await e2e.start_gateway(gw)

    response = await chat_stream(gw.url, f"mail {ALICE}")

    assert response.status_code == 200, e2e.diagnostics()
    text = stream_text(response.text)
    assert ALICE not in text
    assert "EMA" in text  # the placeholder arrived in pieces and was never restored


ALL_TYPES = {
    "email": "ann.lee1234@example.org",
    "phone": "+12025550123",
    "iban": "DE89370400440532013000",
    "card": "4000001234567899",
    "ssn": "123-45-6789",
}


async def test_masks_every_builtin_default_type(e2e: E2E, upstream: Upstream) -> None:
    gw = refgw_spec(upstream=upstream.url, port=free_port())
    await e2e.start_gateway(gw)
    content = ", ".join(f"{name} {value}" for name, value in ALL_TYPES.items())

    response = await chat(gw.url, content)

    assert response.status_code == 200, e2e.diagnostics()
    sent = upstream.recorded()[0]["body"]["messages"][0]["content"]
    for value in ALL_TYPES.values():
        assert value not in sent
    for prefix in ("<EMAIL_1>", "<PHONE_1>", "<IBAN_1>", "<CARD_1>", "<SSN_1>"):
        assert prefix in sent
    assert reply(response) == f"echo: {content}"


async def test_streaming_restores_every_type(e2e: E2E, upstream: Upstream) -> None:
    gw = refgw_spec(upstream=upstream.url, port=free_port())
    await e2e.start_gateway(gw)
    content = " / ".join(ALL_TYPES.values())

    response = await chat_stream(gw.url, content)

    assert stream_text(response.text) == f"echo: {content}"


def test_refgw_never_imports_canarywire() -> None:
    tree = ast.parse(REFGW.read_text())
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        (node.module or "").split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert "canarywire" not in imported


CARD = "4000001234567899"


async def post(base_url: str, body: dict[str, Any]) -> httpx.Response:
    async with httpx.AsyncClient(timeout=10.0) as client:
        return await client.post(f"{base_url}/v1/chat/completions", json=body)


def tool_body() -> dict[str, Any]:
    call = {"name": "f", "arguments": json.dumps({"z": 1, "card": CARD})}
    return {
        "model": "test",
        "messages": [
            {"role": "user", "content": f"card {CARD} mail {ALICE}"},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [{"id": "c1", "type": "function", "function": call}],
            },
            {"role": "user", "content": f"colleague {BOB} and {ALICE}"},
        ],
    }


def sent_messages(upstream: Upstream) -> list[dict[str, Any]]:
    messages: list[dict[str, Any]] = upstream.recorded()[-1]["body"]["messages"]
    return messages


def arguments(message: dict[str, Any]) -> str:
    value: str = message["tool_calls"][0]["function"]["arguments"]
    return value


async def test_json_strings_are_masked_field_by_field(e2e: E2E, upstream: Upstream) -> None:
    gw = refgw_spec(upstream=upstream.url, port=free_port())
    await e2e.start_gateway(gw)

    response = await post(gw.url, tool_body())

    assert response.status_code == 200, e2e.diagnostics()
    sent = sent_messages(upstream)
    assert arguments(sent[1]) == '{"card":"<CARD_1>","z":1}'
    assert sent[0]["content"] == "card <CARD_1> mail <EMAIL_1>"
    assert sent[2]["content"] == "colleague <EMAIL_2> and <EMAIL_1>"
    message = response.json()["choices"][0]["message"]
    assert message["content"] == f"echo: colleague {BOB} and {ALICE}"
    assert json.loads(arguments(message)) == {"card": CARD, "z": 1}


async def test_inconsistent_bug_gives_fresh_placeholders(e2e: E2E, upstream: Upstream) -> None:
    gw = refgw_spec(upstream=upstream.url, port=free_port(), bug="inconsistent")
    await e2e.start_gateway(gw)

    response = await post(gw.url, tool_body())

    assert response.status_code == 200, e2e.diagnostics()
    sent = sent_messages(upstream)
    assert sent[0]["content"] == "card <CARD_1> mail <EMAIL_1>"
    assert arguments(sent[1]) == '{"card":"<CARD_2>","z":1}'
    assert sent[2]["content"] == "colleague <EMAIL_2> and <EMAIL_3>"
    assert response.json()["choices"][0]["message"]["content"] == (
        f"echo: colleague {BOB} and {ALICE}"
    )


async def test_collision_bug_reuses_numbers_per_scope(e2e: E2E, upstream: Upstream) -> None:
    gw = refgw_spec(upstream=upstream.url, port=free_port(), bug="collision")
    await e2e.start_gateway(gw)

    response = await post(gw.url, tool_body())

    assert response.status_code == 200, e2e.diagnostics()
    sent = sent_messages(upstream)
    assert sent[0]["content"] == "card <CARD_1> mail <EMAIL_1>"
    assert arguments(sent[1]) == '{"card":"<CARD_1>","z":1}'
    assert sent[2]["content"] == "colleague <EMAIL_1> and <EMAIL_1>"
    assert response.json()["choices"][0]["message"]["content"] == (
        f"echo: colleague {BOB} and {BOB}"
    )


async def test_tool_args_bug_leaves_arguments_masked(e2e: E2E, upstream: Upstream) -> None:
    gw = refgw_spec(upstream=upstream.url, port=free_port(), bug="tool-args")
    await e2e.start_gateway(gw)

    response = await post(gw.url, tool_body())

    assert response.status_code == 200, e2e.diagnostics()
    message = response.json()["choices"][0]["message"]
    assert message["content"] == f"echo: colleague {BOB} and {ALICE}"
    assert arguments(message) == '{"card":"<CARD_1>","z":1}'


# --- Anthropic route (/v1/messages) --------------------------------------------------------

ANTHROPIC_VERSION = "2023-06-01"


async def messages(base_url: str, body: dict[str, Any]) -> httpx.Response:
    async with httpx.AsyncClient(timeout=10.0) as client:
        return await client.post(
            f"{base_url}/v1/messages",
            json=body,
            headers={"anthropic-version": ANTHROPIC_VERSION},
        )


def anthropic_body(content: str, *, stream: bool = False) -> dict[str, Any]:
    body: dict[str, Any] = {
        "model": "test",
        "max_tokens": 1024,
        "messages": [{"role": "user", "content": content}],
    }
    if stream:
        body["stream"] = True
    return body


def anthropic_reply(response: httpx.Response) -> str:
    content: str = response.json()["content"][0]["text"]
    return content


def anthropic_stream_text(raw: str) -> str:
    """Independent reassembly of `text_delta` texts (no canarywire imports needed here)."""
    text = ""
    event = None
    for block in raw.replace("\r\n", "\n").split("\n\n"):
        for line in block.split("\n"):
            if line.startswith("event:"):
                event = line[len("event:") :].strip()
            elif line.startswith("data: "):
                doc = json.loads(line[len("data: ") :])
                delta = doc.get("delta", {})
                if event == "content_block_delta" and delta.get("type") == "text_delta":
                    text += delta.get("text", "")
    return text


def anthropic_tool_body() -> dict[str, Any]:
    return {
        "model": "test",
        "max_tokens": 1024,
        "messages": [
            {"role": "user", "content": f"card {CARD} mail {ALICE}"},
            {
                "role": "assistant",
                "content": [
                    {"type": "tool_use", "id": "c1", "name": "f", "input": {"z": 1, "card": CARD}}
                ],
            },
            {"role": "user", "content": f"colleague {BOB} and {ALICE}"},
        ],
    }


def anthropic_sent_messages(upstream: Upstream) -> list[dict[str, Any]]:
    messages_: list[dict[str, Any]] = upstream.recorded()[-1]["body"]["messages"]
    return messages_


def anthropic_tool_input(message: dict[str, Any]) -> dict[str, Any]:
    for block in message["content"]:
        if block.get("type") == "tool_use":
            value: dict[str, Any] = block["input"]
            return value
    raise AssertionError("no tool_use block in message")


async def test_anthropic_masks_upstream_and_restores_client(e2e: E2E, upstream: Upstream) -> None:
    gw = refgw_spec(upstream=upstream.url, port=free_port())
    await e2e.start_gateway(gw)

    response = await messages(gw.url, anthropic_body(f"mail {ALICE}, {BOB}, {ALICE}"))

    assert response.status_code == 200, e2e.diagnostics()
    assert ALICE not in upstream.raw()
    assert BOB not in upstream.raw()
    sent = upstream.recorded()[0]["body"]["messages"][0]["content"]
    assert sent == "mail <EMAIL_1>, <EMAIL_2>, <EMAIL_1>"
    assert anthropic_reply(response) == f"echo: mail {ALICE}, {BOB}, {ALICE}"


async def test_anthropic_missing_version_header_is_refused_before_upstream(
    e2e: E2E, upstream: Upstream
) -> None:
    gw = refgw_spec(upstream=upstream.url, port=free_port())
    await e2e.start_gateway(gw)

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(f"{gw.url}/v1/messages", json=anthropic_body(f"mail {ALICE}"))

    assert response.status_code == 400, e2e.diagnostics()
    assert response.json() == {"error": {"message": "anthropic-version header required"}}
    assert upstream.raw() == "", e2e.diagnostics()


async def test_anthropic_streaming_restores_placeholders(e2e: E2E, upstream: Upstream) -> None:
    gw = refgw_spec(upstream=upstream.url, port=free_port())
    await e2e.start_gateway(gw)

    response = await messages(gw.url, anthropic_body(f"mail {ALICE}, {BOB}, {ALICE}", stream=True))

    assert response.status_code == 200, e2e.diagnostics()
    assert response.headers["content-type"].startswith("text/event-stream")
    assert ALICE not in upstream.raw()
    assert anthropic_stream_text(response.text) == f"echo: mail {ALICE}, {BOB}, {ALICE}"
    assert "event: message_stop" in response.text


async def test_anthropic_mask_only_leaves_placeholders_in_answer(
    e2e: E2E, upstream: Upstream
) -> None:
    gw = refgw_spec(upstream=upstream.url, port=free_port(), duty="mask-only")
    await e2e.start_gateway(gw)

    response = await messages(gw.url, anthropic_body(f"mail {ALICE}"))

    assert response.status_code == 200, e2e.diagnostics()
    assert anthropic_reply(response) == "echo: mail <EMAIL_1>"


async def test_anthropic_mask_only_leaves_placeholders_in_stream(
    e2e: E2E, upstream: Upstream
) -> None:
    gw = refgw_spec(upstream=upstream.url, port=free_port(), duty="mask-only")
    await e2e.start_gateway(gw)

    response = await messages(gw.url, anthropic_body(f"mail {ALICE}", stream=True))

    assert response.status_code == 200, e2e.diagnostics()
    assert anthropic_stream_text(response.text) == "echo: mail <EMAIL_1>"


async def test_anthropic_tool_args_bug_leaves_input_masked(e2e: E2E, upstream: Upstream) -> None:
    gw = refgw_spec(upstream=upstream.url, port=free_port(), bug="tool-args")
    await e2e.start_gateway(gw)

    response = await messages(gw.url, anthropic_tool_body())

    assert response.status_code == 200, e2e.diagnostics()
    sent = anthropic_sent_messages(upstream)
    assert sent[0]["content"] == "card <CARD_1> mail <EMAIL_1>"
    assert anthropic_tool_input(sent[1]) == {"z": 1, "card": "<CARD_1>"}
    assert sent[2]["content"] == "colleague <EMAIL_2> and <EMAIL_1>"
    body = response.json()
    text_block, tool_block = body["content"][0], body["content"][1]
    assert text_block["text"] == f"echo: colleague {BOB} and {ALICE}"
    assert tool_block["input"] == {"z": 1, "card": "<CARD_1>"}


async def test_anthropic_split_sse_bug_leaves_split_placeholder(
    e2e: E2E, upstream: Upstream
) -> None:
    gw = refgw_spec(upstream=upstream.url, port=free_port(), bug="split-sse")
    await e2e.start_gateway(gw)

    response = await messages(gw.url, anthropic_body(f"mail {ALICE}", stream=True))

    assert response.status_code == 200, e2e.diagnostics()
    text = anthropic_stream_text(response.text)
    assert ALICE not in text
    assert "EMA" in text  # the placeholder arrived in pieces and was never restored
