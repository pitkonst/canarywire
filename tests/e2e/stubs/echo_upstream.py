"""Recording OpenAI-compatible upstream, used to verify the reference gateway in isolation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import TYPE_CHECKING

import uvicorn
from starlette.applications import Starlette
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from starlette.requests import Request


def _event(delta: dict[str, object], finish: str | None = None) -> str:
    choice = {"index": 0, "delta": delta, "finish_reason": finish}
    return f"data: {json.dumps({'object': 'chat.completion.chunk', 'choices': [choice]})}\n\n"


def _anthropic_event(event: str, doc: dict[str, object]) -> str:
    return f"event: {event}\ndata: {json.dumps(doc)}\n\n"


def _last_user_text(messages: list[dict[str, object]]) -> str:
    """The text of the last user message: its content, or its last text block."""
    for message in reversed(messages):
        if message.get("role") != "user":
            continue
        content = message.get("content")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            for block in reversed(content):
                if isinstance(block, dict) and block.get("type") == "text":
                    return str(block.get("text", ""))
    return ""


def _last_tool_use_blocks(messages: list[dict[str, object]]) -> list[dict[str, object]]:
    """The `tool_use` blocks of the last assistant message that has any."""
    for message in reversed(messages):
        if message.get("role") != "assistant":
            continue
        content = message.get("content")
        if isinstance(content, list):
            blocks = [b for b in content if isinstance(b, dict) and b.get("type") == "tool_use"]
            if blocks:
                return blocks
    return []


def create_app(log: Path) -> Starlette:
    """App that appends every request to log and echoes the last message back.

    Non-streaming answers also echo the `tool_calls` (OpenAI) or `tool_use` blocks (Anthropic)
    of the last assistant message that has any.
    """

    async def chat(request: Request) -> Response:
        body = await request.json()
        with log.open("a") as file:
            file.write(json.dumps({"path": request.url.path, "body": body}) + "\n")
        content = body["messages"][-1]["content"]

        if body.get("stream"):
            text = f"echo: {content}"

            async def events() -> AsyncIterator[str]:
                yield _event({"role": "assistant"})
                for start in range(0, len(text), 3):  # 3 characters: splits every placeholder
                    yield _event({"content": text[start : start + 3]})
                yield _event({}, "stop")
                yield "data: [DONE]\n\n"

            return StreamingResponse(events(), media_type="text/event-stream")

        message: dict[str, object] = {"role": "assistant", "content": f"echo: {content}"}
        calls = [m["tool_calls"] for m in body["messages"] if m.get("tool_calls")]
        if calls:
            message["tool_calls"] = calls[-1]
        return JSONResponse(
            {
                "id": "chatcmpl-echo",
                "object": "chat.completion",
                "model": body.get("model", "echo"),
                "choices": [{"index": 0, "message": message, "finish_reason": "stop"}],
            }
        )

    async def messages(request: Request) -> Response:
        body = await request.json()
        with log.open("a") as file:
            file.write(json.dumps({"path": request.url.path, "body": body}) + "\n")
        content = _last_user_text(body.get("messages", []))
        text = f"echo: {content}"

        if body.get("stream"):

            async def events() -> AsyncIterator[str]:
                yield _anthropic_event(
                    "message_start",
                    {
                        "type": "message_start",
                        "message": {
                            "id": "msg_echo",
                            "type": "message",
                            "role": "assistant",
                            "model": body.get("model", "echo"),
                            "content": [],
                            "stop_reason": None,
                            "usage": {"input_tokens": 0, "output_tokens": 0},
                        },
                    },
                )
                yield _anthropic_event(
                    "content_block_start",
                    {
                        "type": "content_block_start",
                        "index": 0,
                        "content_block": {"type": "text", "text": ""},
                    },
                )
                for start in range(0, len(text), 3):  # 3 characters: splits every placeholder
                    yield _anthropic_event(
                        "content_block_delta",
                        {
                            "type": "content_block_delta",
                            "index": 0,
                            "delta": {"type": "text_delta", "text": text[start : start + 3]},
                        },
                    )
                yield _anthropic_event(
                    "content_block_stop", {"type": "content_block_stop", "index": 0}
                )
                yield _anthropic_event(
                    "message_delta",
                    {
                        "type": "message_delta",
                        "delta": {"stop_reason": "end_turn"},
                        "usage": {"output_tokens": 0},
                    },
                )
                yield _anthropic_event("message_stop", {"type": "message_stop"})

            return StreamingResponse(events(), media_type="text/event-stream")

        content_blocks: list[dict[str, object]] = [{"type": "text", "text": text}]
        content_blocks += _last_tool_use_blocks(body.get("messages", []))
        return JSONResponse(
            {
                "id": "msg_echo",
                "type": "message",
                "role": "assistant",
                "model": body.get("model", "echo"),
                "content": content_blocks,
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 0, "output_tokens": 0},
            }
        )

    async def healthz(_: Request) -> Response:
        return Response("ok")

    return Starlette(
        routes=[
            Route("/v1/chat/completions", chat, methods=["POST"]),
            Route("/v1/messages", messages, methods=["POST"]),
            Route("/healthz", healthz),
        ]
    )


def main() -> None:
    """Parse --listen/--log and serve."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", required=True, help="HOST:PORT")
    parser.add_argument("--log", required=True, type=Path)
    args = parser.parse_args()
    host, _, port = args.listen.rpartition(":")
    uvicorn.run(create_app(args.log), host=host, port=int(port), log_level="warning")


if __name__ == "__main__":
    main()
