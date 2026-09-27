"""OpenAI Chat Completions: template adapter, request flag, upstream SSE encoding, SSE decoding."""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from canarywire.runner.jsonpath import JSON_NODE, get_path
from canarywire.runner.messages import StreamChunk
from canarywire.runner.neutral import DEFAULT_MODEL, TemplateError
from canarywire.runner.protocols import sse_events

if TYPE_CHECKING:
    from collections.abc import Sequence

    from canarywire.runner.jsonpath import JsonPath

CONTENT_PATH: JsonPath = ("choices", 0, "message", "content")
STREAM_HEADERS = (("content-type", "text/event-stream"), ("cache-control", "no-cache"))
ACCEPT_STREAM = {"accept": "text/event-stream"}
EXTRA_HEADERS: dict[str, str] = {}
DONE = "[DONE]"
DATA = "data:"
ENVELOPE = {
    "id": "chatcmpl-canarywire",
    "object": "chat.completion.chunk",
    "created": 0,
    "model": "canarywire-test",
}


@dataclass(frozen=True)
class Decoded:
    """A decoded client stream: `ok`, `not_sse`, `truncated` or `malformed`."""

    outcome: str
    text: str
    raw: str


def translate(request: Any, response: Any) -> tuple[Any, Any]:
    """Neutral template documents → OpenAI Chat Completions documents (slots kept)."""
    messages: list[Any] = []
    if "system" in request:
        messages.append({"role": "system", "content": request["system"]})
    for message in request["messages"]:
        role = message["role"]
        if role == "user":
            messages.append({"role": "user", "content": message["content"]})
        elif role == "assistant":
            out: dict[str, Any] = {"role": "assistant", "content": message.get("content")}
            if message.get("tool_calls"):
                out["tool_calls"] = [_call(call) for call in message["tool_calls"]]
            messages.append(out)
        else:  # tool
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": message["tool_call_id"],
                    "content": _json_or_text(message["content"]),
                }
            )
    # Key order is document order, which orders occurrences: tools come before messages.
    doc: dict[str, Any] = {"model": request.get("model", DEFAULT_MODEL)}
    if request.get("tools"):
        doc["tools"] = [
            {
                "type": "function",
                "function": {
                    "name": tool["name"],
                    "description": tool.get("description", ""),
                    "parameters": tool.get("parameters", {}),
                },
            }
            for tool in request["tools"]
        ]
    doc["messages"] = messages
    answer: dict[str, Any] = {"role": "assistant", "content": response.get("content")}
    if response.get("tool_calls"):
        answer["tool_calls"] = [_call(call) for call in response["tool_calls"]]
    choice = {
        "index": 0,
        "finish_reason": "tool_calls" if response.get("tool_calls") else "stop",
        "message": answer,
    }
    completion = {
        "id": "chatcmpl-canarywire",
        "object": "chat.completion",
        "created": 0,
        "model": doc["model"],
        "choices": [choice],
    }
    return copy.deepcopy((doc, completion))  # share nothing with the neutral documents


def _call(call: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": call["id"],
        "type": "function",
        "function": {"name": call["name"], "arguments": {JSON_NODE: call["arguments"]}},
    }


def _json_or_text(content: Any) -> Any:
    return content if isinstance(content, str) else {JSON_NODE: content}


def stream_request(request_doc: Any) -> dict[str, Any]:
    """The rendered request with `"stream": true`."""
    return {**request_doc, "stream": True}


def content_text(response_doc: Any) -> str:
    """The assistant content of a rendered (non-streaming) response template."""
    content = get_path(response_doc, CONTENT_PATH)
    if not isinstance(content, str):
        raise TemplateError("response template has no string at choices[0].message.content")
    return content


def encode(pieces: Sequence[str], delays: Sequence[int]) -> tuple[StreamChunk, ...]:
    """Role event, one content event per piece (with its delay), finish event, `[DONE]`."""
    content = [
        StreamChunk(_event({"content": piece}, None), delay)
        for piece, delay in zip(pieces, delays, strict=True)
    ]
    return (
        StreamChunk(_event({"role": "assistant"}, None)),
        *content,
        StreamChunk(_event({}, "stop")),
        StreamChunk(f"{DATA} {DONE}\n\n"),
    )


def decode(raw: str) -> Decoded:
    r"""Reassemble `choices[0].delta.content` from an SSE body.

    `\r\n`/`\r` count as `\n`; an empty line ends an event; several `data:` lines in one
    event are joined with `\n`; other fields and `:` comments are ignored. The first
    non-conforming payload makes the stream `malformed`; a body without `data:` events is
    `not_sse`; events without `[DONE]` are `truncated`. Deliberately lenient: a final event
    without its closing blank line is still processed (so an unterminated `[DONE]` counts),
    and anything after `[DONE]` is ignored.
    """
    events = sse_events(raw)
    parts: list[str] = []
    for payload in events:
        if payload == DONE:
            return Decoded("ok", "".join(parts), raw)
        content = _delta_content(payload)
        if content is None:
            return Decoded("malformed", "".join(parts), raw)
        parts.append(content)
    if not events:
        return Decoded("not_sse", "", raw)
    return Decoded("truncated", "".join(parts), raw)


def _event(delta: dict[str, Any], finish_reason: str | None) -> str:
    choice = {"index": 0, "delta": delta, "finish_reason": finish_reason}
    return f"{DATA} {json.dumps({**ENVELOPE, 'choices': [choice]})}\n\n"


def _delta_content(payload: str) -> str | None:  # noqa: PLR0911 - one guard per malformed shape
    try:
        doc = json.loads(payload)
    except (ValueError, RecursionError):
        return None
    if not isinstance(doc, dict):
        return None
    choices = doc.get("choices")
    if not isinstance(choices, list):
        return None
    if not choices:
        return ""
    if not isinstance(choices[0], dict):
        return None
    delta = choices[0].get("delta", {})
    if not isinstance(delta, dict):
        return None
    content = delta.get("content", "")
    if content is None or isinstance(content, str):
        return content or ""
    return None
