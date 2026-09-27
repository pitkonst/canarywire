"""Anthropic Messages: template adapter, request flag, upstream SSE encoding, SSE decoding."""

from __future__ import annotations

import copy
import json
from typing import TYPE_CHECKING, Any

from canarywire.runner.jsonpath import JSON_NODE, get_path
from canarywire.runner.messages import StreamChunk
from canarywire.runner.neutral import DEFAULT_MODEL, TemplateError
from canarywire.runner.protocols import sse_events
from canarywire.runner.protocols.openai import Decoded as Decoded  # noqa: PLC0414 - re-export

if TYPE_CHECKING:
    from collections.abc import Sequence

    from canarywire.runner.jsonpath import JsonPath

CONTENT_PATH: JsonPath = ("content", 0, "text")
MAX_TOKENS = 1024
STREAM_HEADERS = (("content-type", "text/event-stream"), ("cache-control", "no-cache"))
ACCEPT_STREAM = {"accept": "text/event-stream"}
EXTRA_HEADERS = {"anthropic-version": "2023-06-01"}
MODEL = "canarywire-test"


def translate(request: Any, response: Any) -> tuple[Any, Any]:
    """Neutral template documents → Anthropic Messages documents (slots kept).

    Consecutive `tool` messages merge into one user message of `tool_result` blocks.
    """
    messages: list[Any] = []
    results: list[Any] | None = None  # blocks of the user message collecting tool results
    for message in request["messages"]:
        role = message["role"]
        if role == "tool":
            if results is None:
                results = []
                messages.append({"role": "user", "content": results})
            results.append(
                {
                    "type": "tool_result",
                    "tool_use_id": message["tool_call_id"],
                    "content": _json_or_text(message["content"]),
                }
            )
            continue
        results = None
        if role == "user":
            messages.append({"role": "user", "content": message["content"]})
        else:  # assistant
            messages.append({"role": "assistant", "content": _blocks(message)})
    doc: dict[str, Any] = {"model": request.get("model", DEFAULT_MODEL), "max_tokens": MAX_TOKENS}
    if "system" in request:
        doc["system"] = request["system"]
    if request.get("tools"):  # before messages, as in openai-chat: key order is document order
        doc["tools"] = [
            {
                "name": tool["name"],
                "description": tool.get("description", ""),
                # Anthropic requires an object schema; OpenAI accepts an empty one.
                "input_schema": tool.get("parameters", {"type": "object"}),
            }
            for tool in request["tools"]
        ]
    doc["messages"] = messages
    answer = {
        "id": "msg_canarywire",
        "type": "message",
        "role": "assistant",
        "model": doc["model"],
        "content": _blocks(response),
        "stop_reason": "tool_use" if response.get("tool_calls") else "end_turn",
        "stop_sequence": None,
        "usage": {"input_tokens": 0, "output_tokens": 0},
    }
    return copy.deepcopy((doc, answer))  # share nothing with the neutral documents


def _blocks(message: dict[str, Any]) -> list[dict[str, Any]]:
    """A text block if there is content, then one `tool_use` block per tool call."""
    content = message.get("content")
    blocks: list[dict[str, Any]] = []
    if isinstance(content, str) and content:
        blocks.append({"type": "text", "text": content})
    blocks += [
        {"type": "tool_use", "id": call["id"], "name": call["name"], "input": call["arguments"]}
        for call in message.get("tool_calls") or []
    ]
    return blocks


def _json_or_text(content: Any) -> Any:
    return content if isinstance(content, str) else {JSON_NODE: content}


def stream_request(request_doc: Any) -> dict[str, Any]:
    """The rendered request with `"stream": true`."""
    return {**request_doc, "stream": True}


def content_text(response_doc: Any) -> str:
    """The text of `content[0]`, which must be a text block; otherwise a template error."""
    block = get_path(response_doc, ("content", 0))
    if (
        not isinstance(block, dict)
        or block.get("type") != "text"
        or not isinstance(block.get("text"), str)
    ):
        raise TemplateError("response template has no text block at content[0]")
    text: str = block["text"]
    return text


def encode(pieces: Sequence[str], delays: Sequence[int]) -> tuple[StreamChunk, ...]:
    """The full event sequence for a streamed response.

    `message_start`, `content_block_start`, one `content_block_delta` per piece (with its
    delay), `content_block_stop`, `message_delta`, `message_stop`.
    """
    deltas = [
        StreamChunk(
            _event(
                "content_block_delta",
                {
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {"type": "text_delta", "text": piece},
                },
            ),
            delay,
        )
        for piece, delay in zip(pieces, delays, strict=True)
    ]
    return (
        StreamChunk(
            _event(
                "message_start",
                {
                    "type": "message_start",
                    "message": {
                        "id": "msg_canarywire",
                        "type": "message",
                        "role": "assistant",
                        "model": MODEL,
                        "content": [],
                        "stop_reason": None,
                        "usage": {"input_tokens": 0, "output_tokens": 0},
                    },
                },
            )
        ),
        StreamChunk(
            _event(
                "content_block_start",
                {
                    "type": "content_block_start",
                    "index": 0,
                    "content_block": {"type": "text", "text": ""},
                },
            )
        ),
        *deltas,
        StreamChunk(_event("content_block_stop", {"type": "content_block_stop", "index": 0})),
        StreamChunk(
            _event(
                "message_delta",
                {
                    "type": "message_delta",
                    "delta": {"stop_reason": "end_turn"},
                    "usage": {"output_tokens": 0},
                },
            )
        ),
        StreamChunk(_event("message_stop", {"type": "message_stop"})),
    )


def decode(raw: str) -> Decoded:
    r"""Reassemble the index-0 `text_delta` texts from an SSE body.

    Events are split as in slice 1 (see `protocols.sse_events`); the `event:` line is
    informational, and the `type` inside `data` decides. `ping` and other event types, a JSON
    object with no `type` or an unknown one, `content_block_delta` events whose delta is not
    `text_delta`, and deltas for an index other than 0 are all ignored, not malformed. A `data`
    payload that is not a JSON object, or a `text_delta` whose `text` is not a string, is
    `malformed`. `message_stop` ends the stream as `ok`; anything after it is ignored. No `data`
    event at all is `not_sse`; events without `message_stop` are `truncated`.
    """
    events = sse_events(raw)
    parts: list[str] = []
    for payload in events:
        try:
            doc = json.loads(payload)
        except (ValueError, RecursionError):
            return Decoded("malformed", "".join(parts), raw)
        if not isinstance(doc, dict):
            return Decoded("malformed", "".join(parts), raw)
        event_type = doc.get("type")
        if event_type == "message_stop":
            return Decoded("ok", "".join(parts), raw)
        if event_type != "content_block_delta" or doc.get("index") != 0:
            continue
        delta = doc.get("delta")
        if not isinstance(delta, dict) or delta.get("type") != "text_delta":
            continue
        text = delta.get("text")
        if not isinstance(text, str):
            return Decoded("malformed", "".join(parts), raw)
        parts.append(text)
    if not events:
        return Decoded("not_sse", "", raw)
    return Decoded("truncated", "".join(parts), raw)


def _event(event_type: str, payload: dict[str, Any]) -> str:
    return f"event: {event_type}\ndata: {json.dumps(payload)}\n\n"
