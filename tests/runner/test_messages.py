import json

import pytest

from canarywire.runner.messages import ResponseSpec, StreamChunk, UpstreamRequest, json_response

PARAMS = {
    "id": "u1",
    "method": "POST",
    "path": "/v1/chat/completions",
    "query": "",
    "headers": [["content-type", "application/json"]],
    "body": '{"a": 1}',
    "json": {"a": 1},
}


def test_from_params() -> None:
    request = UpstreamRequest.from_params(PARAMS)
    assert request.request_id == "u1"
    assert request.headers == (("content-type", "application/json"),)
    assert request.json == {"a": 1}


@pytest.mark.parametrize(
    "params",
    [None, [], {**PARAMS, "path": 3}, {**PARAMS, "headers": [["only-name"]]}, {"id": "u1"}],
)
def test_from_params_rejects(params: object) -> None:
    with pytest.raises(ValueError, match=r"upstream\.request"):
        UpstreamRequest.from_params(params)


def test_json_response_result() -> None:
    result = json_response(200, {"ok": True}).to_result()
    assert result == {
        "status": 200,
        "headers": [["content-type", "application/json"]],
        "body": json.dumps({"ok": True}),
    }


def test_plain_response_result() -> None:
    assert ResponseSpec(404, "nope").to_result() == {"status": 404, "headers": [], "body": "nope"}


def test_stream_response_result() -> None:
    spec = ResponseSpec(
        200,
        headers=(("content-type", "text/event-stream"),),
        stream=(StreamChunk("a"), StreamChunk("b", 5)),
    )
    assert spec.to_result() == {
        "status": 200,
        "headers": [["content-type", "text/event-stream"]],
        "stream": [{"data": "a", "delay_ms": 0}, {"data": "b", "delay_ms": 5}],
    }
