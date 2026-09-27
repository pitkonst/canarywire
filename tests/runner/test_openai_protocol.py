import json

import pytest

from canarywire.runner.catalog import TemplateError
from canarywire.runner.protocols.openai import (
    ACCEPT_STREAM,
    EXTRA_HEADERS,
    content_text,
    decode,
    encode,
    stream_request,
)


def raw_of(pieces: list[str]) -> str:
    return "".join(chunk.data for chunk in encode(pieces, [0] * len(pieces)))


def event(content: str | None = None) -> str:
    delta = {} if content is None else {"content": content}
    return f"data: {json.dumps({'choices': [{'index': 0, 'delta': delta}]})}\n\n"


def test_stream_request_and_accept() -> None:
    assert stream_request({"model": "m"}) == {"model": "m", "stream": True}
    assert ACCEPT_STREAM == {"accept": "text/event-stream"}
    assert EXTRA_HEADERS == {}


def test_content_text() -> None:
    doc = {"choices": [{"message": {"content": "hi"}}]}
    assert content_text(doc) == "hi"
    with pytest.raises(TemplateError):
        content_text({"choices": []})


def test_encode_shape_and_delays() -> None:
    chunks = encode(["ab", "c"], [3, 4])
    assert [c.delay_ms for c in chunks] == [0, 3, 4, 0, 0]
    assert chunks[-1].data == "data: [DONE]\n\n"
    first = json.loads(chunks[0].data.removeprefix("data: "))
    assert first["object"] == "chat.completion.chunk"
    assert first["choices"][0]["delta"] == {"role": "assistant"}
    finish = json.loads(chunks[-2].data.removeprefix("data: "))
    assert finish["choices"][0]["finish_reason"] == "stop"


def test_round_trip() -> None:
    decoded = decode(raw_of(["Done: <EMA", "IL_1>", "."]))
    assert (decoded.outcome, decoded.text) == ("ok", "Done: <EMAIL_1>.")


def test_crlf_multiline_data_no_space_and_ignored_fields() -> None:
    # The JSON payload is split over two `data:` lines at a point where the joining "\n" is
    # valid JSON whitespace; the second line has no space after the colon.
    raw = (
        ": comment\r\n"
        "event: message\r\n"
        "id: 1\r\n"
        'data: {"choices": [{"index": 0,\r\n'
        'data:"delta": {"content": "x"}}]}\r\n'
        "\r\n"
        "data: [DONE]\r\n\r\n"
    )
    decoded = decode(raw)
    assert (decoded.outcome, decoded.text) == ("ok", "x")


def test_not_sse() -> None:
    body = json.dumps({"choices": [{"message": {"content": "hi"}}]})
    assert decode(body).outcome == "not_sse"


def test_truncated() -> None:
    decoded = decode(event("a") + event("b"))
    assert (decoded.outcome, decoded.text) == ("truncated", "ab")


def test_malformed_wins_over_truncated() -> None:
    assert decode(event("a") + "data: {not json}\n\n").outcome == "malformed"
    assert decode('data: {"choices": "x"}\n\n').outcome == "malformed"


def test_content_absent_is_empty() -> None:
    assert decode(event() + event("z") + "data: [DONE]\n\n").text == "z"


def test_content_null_is_empty() -> None:
    null_event = 'data: {"choices": [{"index": 0, "delta": {"content": null}}]}\n\n'
    decoded = decode(event("a") + null_event + event("b") + "data: [DONE]\n\n")
    assert (decoded.outcome, decoded.text) == ("ok", "ab")


def test_empty_choices_contributes_nothing() -> None:
    empty_choices = 'data: {"choices": []}\n\n'
    decoded = decode(event("a") + empty_choices + event("b") + "data: [DONE]\n\n")
    assert (decoded.outcome, decoded.text) == ("ok", "ab")
