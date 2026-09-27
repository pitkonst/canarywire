"""Messages exchanged with the capture, as the runner sees them."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

STRING_FIELDS = ("id", "method", "path", "query", "body")


@dataclass(frozen=True)
class UpstreamRequest:
    """One request the gateway sent upstream, relayed by the capture."""

    request_id: str
    method: str
    path: str
    query: str
    headers: tuple[tuple[str, str], ...]
    body: str
    json: Any

    @classmethod
    def from_params(cls, params: object) -> UpstreamRequest:
        """Validate `upstream.request` params; raise ValueError if malformed."""
        if not isinstance(params, dict):
            raise ValueError("malformed upstream.request: params must be an object")
        try:
            values = {key: params[key] for key in STRING_FIELDS}
            headers = tuple((str(name), str(value)) for name, value in params["headers"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"malformed upstream.request: {exc!r}") from exc
        if not all(isinstance(value, str) for value in values.values()):
            raise ValueError(
                "malformed upstream.request: id/method/path/query/body must be strings"
            )
        return cls(
            request_id=values["id"],
            method=values["method"],
            path=values["path"],
            query=values["query"],
            headers=headers,
            body=values["body"],
            json=params.get("json"),
        )


@dataclass(frozen=True)
class StreamChunk:
    """One piece of a streamed response and the delay before sending it."""

    data: str
    delay_ms: int = 0


@dataclass(frozen=True)
class ResponseSpec:
    """The response the capture must send back to the gateway: a body or a stream."""

    status: int
    body: str = ""
    headers: tuple[tuple[str, str], ...] = ()
    stream: tuple[StreamChunk, ...] | None = None

    def to_result(self) -> dict[str, Any]:
        """Encode as an `upstream.request` result."""
        result: dict[str, Any] = {
            "status": self.status,
            "headers": [list(header) for header in self.headers],
        }
        if self.stream is None:
            result["body"] = self.body
        else:
            result["stream"] = [
                {"data": chunk.data, "delay_ms": chunk.delay_ms} for chunk in self.stream
            ]
        return result


def json_response(status: int, doc: Any) -> ResponseSpec:
    """A JSON response spec."""
    return ResponseSpec(status, json.dumps(doc), (("content-type", "application/json"),))
