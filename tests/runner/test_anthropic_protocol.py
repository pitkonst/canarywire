from canarywire.runner.protocols import anthropic


def joined(pieces: list[str]) -> str:
    return "".join(c.data for c in anthropic.encode(pieces, [0] * len(pieces)))


def test_round_trip() -> None:
    raw = joined(["Hel", "lo <E", "MAIL_1>"])
    assert anthropic.decode(raw) == anthropic.Decoded("ok", "Hello <EMAIL_1>", raw)
    assert raw.startswith("event: message_start\ndata: ")
    assert raw.rstrip().endswith('"type": "message_stop"}')


def test_split_events_across_reads_and_crlf() -> None:
    raw = joined(["ab", "cd"]).replace("\n", "\r\n")
    assert anthropic.decode(raw).text == "abcd"


def test_ignored_events() -> None:
    raw = joined(["ab"])
    extra = (
        'event: ping\ndata: {"type": "ping"}\n\n'
        'data: {"type": "content_block_delta", "index": 1, "delta": {"type": "text_delta", "text": "X"}}\n\n'  # noqa: E501
        'data: {"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": "{"}}\n\n'  # noqa: E501
        'data: {"no": "type"}\n\n'
    )
    start, rest = raw.split("event: content_block_stop", 1)
    assert anthropic.decode(start + extra + "event: content_block_stop" + rest).outcome == "ok"
    assert anthropic.decode(start + extra + "event: content_block_stop" + rest).text == "ab"


def test_outcomes() -> None:
    assert anthropic.decode('{"not": "sse"}').outcome == "not_sse"
    truncated = anthropic.decode(joined(["ab"]).split("event: message_stop")[0])
    assert truncated.outcome == "truncated"
    assert anthropic.decode("data: [1]\n\n").outcome == "malformed"
    bad = 'data: {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": 3}}\n\n'  # noqa: E501
    assert anthropic.decode(bad).outcome == "malformed"


def test_content_text_and_headers() -> None:
    doc = {"content": [{"type": "text", "text": "hi"}, {"type": "tool_use"}]}
    assert anthropic.content_text(doc) == "hi"
    assert anthropic.EXTRA_HEADERS == {"anthropic-version": "2023-06-01"}
    assert anthropic.stream_request({"a": 1}) == {"a": 1, "stream": True}
