"""Reference PII gateway for canarywire's e2e suite.

Masks emails, US phone numbers (E.164), German IBANs, Visa card numbers and US SSNs on the way
upstream and restores them on the way back. `--bug NAME` switches on exactly one defect;
everything else stays identical to the correct gateway.

Serves both `POST /v1/chat/completions` (OpenAI Chat Completions) and `POST /v1/messages`
(Anthropic Messages) with the same handler: masking walks the whole JSON document regardless of
protocol shape. `--duty mask-only` masks requests as usual but passes answers through untouched
(JSON and streams), instead of restoring.

Strings holding a JSON object or array are decoded, masked (or restored) value by value, and
re-encoded compactly with sorted keys.

Bugs: `passthrough` (skip masking, forward raw), `blackhole` (answer the client itself, never
contact the upstream), `split-sse` (restore each streamed event on its own: placeholders split
across events stay masked), `tool-args` (restore message text but not tool-call arguments),
`inconsistent` (a fresh placeholder for every occurrence), `collision` (placeholder numbers
restart for every message and tool while the value memo is kept), `fail-open` (with the
analyzer down, forward the request unmasked), `mangle` (corrupt the request text around each
placeholder), `key-leak` (the forwarded body also carries the first email from the original
request as a JSON object key, `@` written as `@` in the raw text so a raw-body substring
search misses it while a decoded-key scan finds it).

With `--analyzer-down-file PATH`, the detector counts as down while PATH exists; the correct
gateway then refuses with 503 and never contacts the upstream (fail-closed).

Must never import canarywire: shared code could carry the same bug on both sides and hide it.
"""

from __future__ import annotations

import argparse
import json
import re
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx
import uvicorn
from starlette.applications import Starlette
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable, Iterator

    from starlette.requests import Request

EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
DETECTORS = (
    ("IBAN", re.compile(r"\bDE\d{20}\b")),
    ("CARD", re.compile(r"\b4\d{15}\b")),
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("PHONE", re.compile(r"\+1\d{10}\b")),
    ("EMAIL", EMAIL),
)
PLACEHOLDER = re.compile(r"<[A-Z]+_\d+>")
BUGS = (
    "passthrough",
    "blackhole",
    "split-sse",
    "tool-args",
    "inconsistent",
    "collision",
    "fail-open",
    "mangle",
    "key-leak",
)
SCOPED = ("messages", "tools")


class Vault:
    """Per-request mapping between detected values and typed placeholders."""

    def __init__(self, bug: str | None = None) -> None:
        """Start with no mappings; `bug` selects the inconsistent or collision defect."""
        self._bug = bug
        self._placeholder_of: dict[str, str] = {}
        self._value_of: dict[str, str] = {}
        self._counts: dict[str, int] = {}

    def enter_scope(self) -> None:
        """Start a new message/tool scope (the collision bug restarts numbering here)."""
        if self._bug == "collision":
            self._counts = {}

    def mask(self, text: str) -> str:
        """Replace every detected value with its placeholder (IBAN and card before the rest)."""
        for kind, pattern in DETECTORS:

            def replace(match: re.Match[str], kind: str = kind) -> str:
                return self._placeholder(kind, match.group())

            text = pattern.sub(replace, text)
        return text

    def restore(self, text: str) -> str:
        """Replace every known placeholder with its original value."""
        return PLACEHOLDER.sub(lambda match: self._value_of.get(match.group(), match.group()), text)

    def _placeholder(self, kind: str, value: str) -> str:
        if self._bug == "inconsistent" or value not in self._placeholder_of:
            self._counts[kind] = self._counts.get(kind, 0) + 1
            placeholder = f"<{kind}_{self._counts[kind]}>"
            self._placeholder_of[value] = placeholder
            self._value_of[placeholder] = value
        return self._placeholder_of[value]


def walk(obj: Any, transform: Callable[[str], str]) -> Any:
    """Apply transform to every string value in a JSON document (keys untouched)."""
    if isinstance(obj, str):
        return transform(obj)
    if isinstance(obj, list):
        return [walk(item, transform) for item in obj]
    if isinstance(obj, dict):
        return {key: walk(value, transform) for key, value in obj.items()}
    return obj


def json_aware(transform: Callable[[str], str]) -> Callable[[str], str]:
    """Apply transform inside strings that hold a JSON object or array, re-encoding them."""

    def apply(text: str) -> str:
        if text.lstrip()[:1] in ("{", "["):
            try:
                doc = json.loads(text)
            except ValueError:
                return transform(text)
            if isinstance(doc, (dict, list)):
                return json.dumps(walk(doc, apply), separators=(",", ":"), sort_keys=True)
        return transform(text)

    return apply


def mangle(doc: Any) -> Any:
    """The mangle bug: drop the last space and everything after it in each masked string."""

    def cut(text: str) -> str:
        if not PLACEHOLDER.search(text) or " " not in text or text.lstrip()[:1] in ("{", "["):
            return text
        return text[: text.rfind(" ")]

    return walk(doc, cut)


def _iter_string_values(doc: Any) -> Iterator[str]:
    """Every string value in document order (keys untouched, matching `walk`)."""
    if isinstance(doc, str):
        yield doc
    elif isinstance(doc, list):
        for item in doc:
            yield from _iter_string_values(item)
    elif isinstance(doc, dict):
        for value in doc.values():
            yield from _iter_string_values(value)


def first_email(doc: Any) -> str | None:
    """The first email found in `doc`'s string values, in document order."""
    for text in _iter_string_values(doc):
        match = EMAIL.search(text)
        if match:
            return match.group()
    return None


def build_outbound_content(outbound: Any, original: Any, bug: str | None) -> tuple[bytes, str]:
    """Serialize the outbound JSON body; the key-leak bug adds a raw-escaped email key.

    The `key-leak` bug appends `"metadata": {"<original email>": true}` to the top-level
    object, with the key's `@` written as `\\u0040` in the raw text: a raw-body substring
    search for the email misses it, while a decoded-key scan finds it.
    """
    base = json.dumps(outbound, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    if bug == "key-leak" and isinstance(outbound, dict):
        email = first_email(original)
        if email is not None:
            key = json.dumps(email).replace("@", "\\u0040")
            fragment = f',"metadata":{{{key}:true}}'
            base = (base[:-1] + fragment + "}") if base != "{}" else ("{" + fragment[1:] + "}")
    return base.encode(), "application/json"


def mask_request(body: Any, vault: Vault) -> Any:
    """Mask a request; every `messages`/`tools` element is its own scope, the rest one more."""
    mask = json_aware(vault.mask)
    if not isinstance(body, dict):
        return walk(body, mask)
    masked: dict[str, Any] = {}
    rest_started = False
    for key, value in body.items():
        if key in SCOPED and isinstance(value, list):
            items = []
            for item in value:
                vault.enter_scope()
                items.append(walk(item, mask))
            masked[key] = items
        else:
            if not rest_started:  # all other strings share one scope
                vault.enter_scope()
                rest_started = True
            masked[key] = walk(value, mask)
    return masked


def restore_response(doc: Any, vault: Vault, *, skip_arguments: bool) -> Any:
    """Restore a JSON answer; with skip_arguments, tool-call arguments stay as they came.

    Covers both shapes: OpenAI `choices[*].message.tool_calls[*].function.arguments` and
    Anthropic `content[*].input` of `tool_use` blocks.
    """
    restored = walk(doc, json_aware(vault.restore))
    if not skip_arguments or not isinstance(doc, dict):
        return restored
    for choice, original in zip(restored.get("choices", []), doc.get("choices", []), strict=False):
        calls = (choice.get("message") or {}).get("tool_calls") or []
        originals = (original.get("message") or {}).get("tool_calls") or []
        for call, before in zip(calls, originals, strict=False):
            if isinstance(call.get("function"), dict) and isinstance(before.get("function"), dict):
                call["function"]["arguments"] = before["function"].get("arguments")
    content = zip(restored.get("content") or [], doc.get("content") or [], strict=False)
    for block, original_block in content:
        if (
            isinstance(block, dict)
            and isinstance(original_block, dict)
            and block.get("type") == "tool_use"
        ):
            block["input"] = original_block.get("input")
    return restored


PARTIAL = re.compile(r"<([A-Z]+(_\d*)?)?")
DATA = "data:"


class StreamRestorer:
    """Restores placeholders in streamed text; buffered, it holds back a partial placeholder."""

    def __init__(self, vault: Vault, *, buffered: bool) -> None:
        """Restore with `vault`; `buffered=False` is the split-sse bug."""
        self._vault = vault
        self._buffered = buffered
        self._pending = ""

    def feed(self, text: str) -> str:
        """Return the text that is safe to emit now, restored."""
        if not self._buffered:
            return self._vault.restore(text)
        self._pending += text
        cut = len(self._pending)
        start = self._pending.rfind("<")
        if start != -1 and PARTIAL.fullmatch(self._pending[start:]):
            cut = start
        ready, self._pending = self._pending[:cut], self._pending[cut:]
        return self._vault.restore(ready)

    def flush(self) -> str:
        """Return whatever is still held back, restored."""
        rest, self._pending = self._pending, ""
        return self._vault.restore(rest)


def sse_payloads(buffer: str) -> tuple[list[tuple[str | None, str]], str]:
    """Split complete SSE events off `buffer`.

    Returns their (event, data) pairs and the remainder.
    """
    payloads: list[tuple[str | None, str]] = []
    buffer = buffer.replace("\r\n", "\n")
    while "\n\n" in buffer:
        block, buffer = buffer.split("\n\n", 1)
        event: str | None = None
        lines: list[str] = []
        for line in block.split("\n"):
            if line.startswith("event:"):
                event = line[len("event:") :].removeprefix(" ")
            elif line.startswith(DATA):
                lines.append(line[len(DATA) :].removeprefix(" "))
        if lines:
            payloads.append((event, "\n".join(lines)))
    return payloads, buffer


def sse_event(doc: Any, event: str | None = None) -> str:
    """One SSE event carrying `doc`, with an optional `event:` line."""
    prefix = f"event: {event}\n" if event is not None else ""
    return f"{prefix}data: {json.dumps(doc)}\n\n"


def with_content(doc: Any, text: str) -> Any:
    """A copy of an OpenAI chunk event whose delta content is `text`."""
    choice = doc["choices"][0]
    return {**doc, "choices": [{**choice, "delta": {**choice.get("delta", {}), "content": text}}]}


def with_text_delta(doc: Any, text: str) -> Any:
    """A copy of an Anthropic `content_block_delta` event whose delta text is `text`."""
    return {**doc, "delta": {**doc["delta"], "text": text}}


FORWARDED_HEADERS = ("authorization", "anthropic-version")
DUTIES = ("restore", "mask-only")


def create_app(  # noqa: PLR0915 - one closure per route
    upstream: str,
    bug: str | None,
    analyzer_down_file: Path | None = None,
    duty: str = "restore",
) -> Starlette:
    """Gateway app forwarding to upstream; fail-closed on any error.

    `duty="mask-only"` masks requests as usual but passes answers through untouched, JSON and
    streams alike: no restore step.
    """
    client = httpx.AsyncClient(base_url=upstream, timeout=30.0)

    @asynccontextmanager
    async def lifespan(_: Starlette) -> AsyncIterator[None]:
        yield
        await client.aclose()

    async def relay_untouched(upstream_response: httpx.Response) -> Response:
        async def events() -> AsyncIterator[str]:
            try:
                async for text in upstream_response.aiter_text():
                    yield text
            finally:
                await upstream_response.aclose()

        return StreamingResponse(events(), media_type="text/event-stream")

    async def stream_openai(upstream_response: httpx.Response, vault: Vault) -> Response:
        restorer = StreamRestorer(vault, buffered=bug != "split-sse")

        async def events() -> AsyncIterator[str]:
            buffer = ""
            last_content: Any = None
            try:
                async for text in upstream_response.aiter_text():
                    payloads, buffer = sse_payloads(buffer + text)
                    for _event, payload in payloads:
                        if payload == "[DONE]":
                            tail = restorer.flush()
                            if tail and last_content is not None:
                                yield sse_event(with_content(last_content, tail))
                            yield "data: [DONE]\n\n"
                            return
                        doc = json.loads(payload)
                        delta = doc["choices"][0].get("delta", {})
                        if "content" in delta:
                            last_content = doc
                            ready = restorer.feed(delta["content"])
                            if ready:
                                yield sse_event(with_content(doc, ready))
                        else:
                            tail = restorer.flush()
                            if tail and last_content is not None:
                                yield sse_event(with_content(last_content, tail))
                            yield sse_event(doc)
            finally:
                await upstream_response.aclose()

        return StreamingResponse(events(), media_type="text/event-stream")

    async def stream_anthropic(upstream_response: httpx.Response, vault: Vault) -> Response:
        restorer = StreamRestorer(vault, buffered=bug != "split-sse")

        async def events() -> AsyncIterator[str]:
            buffer = ""
            last_delta: Any = None
            try:
                async for text in upstream_response.aiter_text():
                    payloads, buffer = sse_payloads(buffer + text)
                    for event, payload in payloads:
                        doc = json.loads(payload)
                        delta = doc.get("delta") if isinstance(doc, dict) else None
                        if (
                            event == "content_block_delta"
                            and isinstance(delta, dict)
                            and delta.get("type") == "text_delta"
                        ):
                            last_delta = doc
                            ready = restorer.feed(delta.get("text", ""))
                            if ready:
                                yield sse_event(with_text_delta(doc, ready), event)
                            continue
                        if event == "content_block_stop":
                            tail = restorer.flush()
                            if tail and last_delta is not None:
                                yield sse_event(
                                    with_text_delta(last_delta, tail), "content_block_delta"
                                )
                        yield sse_event(doc, event)
            finally:
                await upstream_response.aclose()

        return StreamingResponse(events(), media_type="text/event-stream")

    async def stream_chat(
        path: str, outbound: Any, original: Any, headers: dict[str, str], vault: Vault
    ) -> Response:
        content, content_type = build_outbound_content(outbound, original, bug)
        request = client.build_request(
            "POST", path, content=content, headers={**headers, "content-type": content_type}
        )
        upstream_response = await client.send(request, stream=True)
        if not upstream_response.is_success:
            await upstream_response.aclose()
            return JSONResponse(
                {"error": {"message": "gateway refused the request"}}, status_code=502
            )
        if duty == "mask-only":
            return await relay_untouched(upstream_response)
        if path == "/v1/messages":
            return await stream_anthropic(upstream_response, vault)
        return await stream_openai(upstream_response, vault)

    def early_refusal(request: Request, *, down: bool) -> Response | None:
        """Refusals decided before any masking or upstream contact."""
        if request.url.path == "/v1/messages" and "anthropic-version" not in request.headers:
            return JSONResponse(
                {"error": {"message": "anthropic-version header required"}}, status_code=400
            )
        if bug == "blackhole":
            return JSONResponse(
                {"choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}}]}
            )
        if down and bug != "fail-open":
            return JSONResponse({"error": {"message": "analyzer unavailable"}}, status_code=503)
        return None

    async def chat(request: Request) -> Response:
        down = analyzer_down_file is not None and analyzer_down_file.exists()
        refusal = early_refusal(request, down=down)
        if refusal is not None:
            return refusal
        vault = Vault(bug)
        try:
            body = await request.json()
            outbound = body if bug == "passthrough" or down else mask_request(body, vault)
            if bug == "mangle" and not down:
                outbound = mangle(outbound)
            headers = {
                key: value
                for key, value in request.headers.items()
                if key.lower() in FORWARDED_HEADERS
            }
            if isinstance(body, dict) and body.get("stream"):
                return await stream_chat(request.url.path, outbound, body, headers, vault)
            content, content_type = build_outbound_content(outbound, body, bug)
            upstream_response = await client.post(
                request.url.path, content=content, headers={**headers, "content-type": content_type}
            )
            upstream_response.raise_for_status()
            if duty == "mask-only":
                content_type = upstream_response.headers.get("content-type", "application/json")
                return Response(content=upstream_response.content, media_type=content_type)
            restored = restore_response(
                upstream_response.json(), vault, skip_arguments=bug == "tool-args"
            )
            return JSONResponse(restored)
        except Exception:  # fail closed: refuse rather than forward anything unmasked
            return JSONResponse(
                {"error": {"message": "gateway refused the request"}}, status_code=502
            )

    async def healthz(_: Request) -> Response:
        return Response("ok")

    return Starlette(
        routes=[
            Route("/v1/chat/completions", chat, methods=["POST"]),
            Route("/v1/messages", chat, methods=["POST"]),
            Route("/healthz", healthz),
        ],
        lifespan=lifespan,
    )


def main() -> None:
    """Parse arguments and serve."""
    parser = argparse.ArgumentParser(description="Reference PII gateway (test-only).")
    parser.add_argument("--upstream", required=True, help="upstream base URL")
    parser.add_argument("--listen", required=True, help="HOST:PORT")
    parser.add_argument("--bug", choices=BUGS, help="inject exactly one defect")
    parser.add_argument(
        "--analyzer-down-file", type=Path, help="the detector is down while this file exists"
    )
    parser.add_argument(
        "--duty", choices=DUTIES, default="restore", help="restore (default) or mask-only"
    )
    args = parser.parse_args()
    host, _, port = args.listen.rpartition(":")
    app = create_app(args.upstream, args.bug, args.analyzer_down_file, args.duty)
    uvicorn.run(app, host=host, port=int(port), log_level="warning")


if __name__ == "__main__":
    main()
