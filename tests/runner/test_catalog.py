import copy
import datetime
import json
import re
from typing import Any

import pytest

from canarywire.runner import neutral as neutral_module
from canarywire.runner import protocols
from canarywire.runner.catalog import (
    MaskedValueNotFoundError,
    Occurrence,
    RequestMangledError,
    Template,
    TemplateError,
    build_catalog,
    builtin_templates,
    check_streamed_content,
    extract_masked,
    extract_occurrences,
    first_placeholders,
    for_protocol,
    json_nodes,
    parse_template,
    render,
    slotted_strings,
)
from canarywire.runner.jsonpath import JSON_NODE
from canarywire.runner.protocols import PROTOCOLS

REQUEST = {"messages": [{"role": "user", "content": "Mail {{ a.raw }} and {{b.raw}}!"}]}
RESPONSE = {"choices": [{"message": {"content": "To {{ a.masked }} / {{ b.raw }}"}}]}


def template(**overrides: Any) -> dict[str, Any]:
    raw: dict[str, Any] = {
        "protocol": "openai-chat",
        "canaries": {"a": "email", "b": {"type": "card", "brand": "amex"}, "unused": "phone"},
        "request": REQUEST,
        "response": RESPONSE,
    }
    raw.update(overrides)
    return raw


def test_parse_template() -> None:
    parsed = parse_template("t", template())
    assert parsed.instances["a"].type_name == "email"
    assert parsed.instances["b"].params == {"brand": "amex"}
    assert parsed.used_in_request() == ["a", "b"]


def test_render_and_extract() -> None:
    raw = {"a": "a@example.org", "b": "378282246310005"}
    request = render(REQUEST, raw, {})
    assert request["messages"][0]["content"] == "Mail a@example.org and 378282246310005!"
    upstream = {"messages": [{"role": "user", "content": "Mail <E1> and <C1>!"}]}
    assert extract_masked(REQUEST, upstream) == {"a": "<E1>", "b": "<C1>"}
    response = render(RESPONSE, raw, {"a": "<E1>"})
    assert response["choices"][0]["message"]["content"] == "To <E1> / 378282246310005"


def test_extract_not_found() -> None:
    with pytest.raises(MaskedValueNotFoundError) as exc:
        extract_masked(REQUEST, {"messages": []})
    assert exc.value.location == "body.messages[0].content"


MANGLE_DOC = {
    "messages": [{"role": "user", "content": "Send IBAN {{ iban.raw }} to {{ email.raw }} please."}]
}


def mangle_upstream(content: object) -> dict[str, Any]:
    return {"messages": [{"role": "user", "content": content}]}


def test_changed_tail_is_mangled() -> None:
    with pytest.raises(RequestMangledError) as info:
        extract_occurrences(MANGLE_DOC, mangle_upstream("Send IBAN <IBAN_1> to <EMAIL_2>ase."))
    exc = info.value
    assert exc.location == "body.messages[0].content"
    assert exc.expected == "Send IBAN {{iban}} to {{email}} please."
    assert exc.actual == "Send IBAN <IBAN_1> to <EMAIL_2>ase."
    assert str(exc) == "request text changed around a canary at body.messages[0].content"


def test_truncation_into_the_leading_literal_is_mangled() -> None:
    with pytest.raises(RequestMangledError):
        extract_occurrences(MANGLE_DOC, mangle_upstream("Send IBAN"))


def test_slot_redacted_to_empty_stays_plain() -> None:
    # The slot text vanished; the literal text around it is untouched, so this is a missing
    # value, not the surrounding text being changed.
    doc = {"messages": [{"role": "user", "content": "Send to {{ x.raw }} today."}]}
    with pytest.raises(MaskedValueNotFoundError) as info:
        extract_occurrences(doc, mangle_upstream("Send to  today."))
    assert type(info.value) is MaskedValueNotFoundError

    with pytest.raises(RequestMangledError):
        extract_occurrences(doc, mangle_upstream("Send to <X> tod"))


def test_empty_leading_uses_the_trailing_literal() -> None:
    # A single-slot pattern with empty leading always fullmatches anything ending with the
    # trailing literal (its capture group is unconstrained), so this branch needs a middle
    # literal ("to") that fails to match while the trailing literal ("please.") still does.
    doc = {"messages": [{"role": "user", "content": "{{ email.raw }} to {{ phone.raw }} please."}]}
    with pytest.raises(RequestMangledError):
        extract_occurrences(doc, mangle_upstream("<EMAIL_1>zz<PHONE_1> please."))


@pytest.mark.parametrize(
    "content",
    [
        "Hello there",  # leading does not match
        "",  # empty
        None,  # not a string
        42,  # not a string
    ],
)
def test_unrecognisable_stays_plain(content: object) -> None:
    with pytest.raises(MaskedValueNotFoundError) as info:
        extract_occurrences(MANGLE_DOC, mangle_upstream(content))
    assert type(info.value) is MaskedValueNotFoundError


def test_leading_mismatch_with_trailing_match_stays_plain() -> None:
    with pytest.raises(MaskedValueNotFoundError) as info:
        extract_occurrences(MANGLE_DOC, mangle_upstream("SYSTEM: Send IBAN <I> to <E> please."))
    assert type(info.value) is MaskedValueNotFoundError


def test_slot_only_string_and_missing_path_stay_plain() -> None:
    doc = {"messages": [{"role": "user", "content": "{{ email.raw }}"}]}
    with pytest.raises(MaskedValueNotFoundError) as info:
        extract_occurrences(doc, mangle_upstream(["not", "a", "string"]))
    assert type(info.value) is MaskedValueNotFoundError
    with pytest.raises(MaskedValueNotFoundError) as info:
        extract_occurrences(MANGLE_DOC, {"messages": []})
    assert type(info.value) is MaskedValueNotFoundError


def test_slotted_strings_name_instances() -> None:
    assert slotted_strings(RESPONSE) == [(("choices", 0, "message", "content"), ["a", "b"])]


T = "templates.t"


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        (
            {"protocol": "anthropic"},
            f"{T}.protocol: expected one of openai-chat, anthropic-messages",
        ),
        ({"canaries": []}, f"{T}.canaries: expected a mapping"),
        (
            {"canaries": {"1x": "email"}},
            f"{T}.canaries.1x: expected an instance name like customer",
        ),
        ({"canaries": {"a": {"brand": "x"}}}, f"{T}.canaries.a.type: expected a type name"),
        ({"canaries": {"a": 3}}, f"{T}.canaries.a: expected a type name or a mapping with type"),
        ({"extra": 1}, f"{T}.extra: unknown key"),
        (
            {"request": {"x": "{{ zz.raw }}"}},
            f"{T}.request.x: slot zz.raw names an undeclared instance",
        ),
        (
            {"request": {"x": "{{ a.masked }}"}},
            f"{T}.request.x: .masked is only allowed in the response",
        ),
        (
            {"request": {"x": "{{ a.raw }}{{ b.raw }}"}},
            f"{T}.request.x: adjacent slots make extraction ambiguous",
        ),
        ({"request": {"x": "{{ a }}"}}, f"{T}.request.x: malformed slot '{{{{ a }}}}'"),
        (
            {"response": {"x": "{{ unused.masked }}"}},
            f"{T}.response.x: slot unused.masked names an instance not used in the request",
        ),
        (
            {"response": {"x": "{{ unused.raw }}"}},
            f"{T}.response.x: slot unused.raw names an instance not used in the request",
        ),
    ],
)
def test_template_errors(overrides: dict[str, Any], message: str) -> None:
    with pytest.raises(TemplateError, match=f"^{re.escape(message)}$"):
        parse_template("t", template(**overrides))


def test_streamed_content_guard() -> None:
    no_slot = template(response={"choices": [{"message": {"content": "nothing"}}]})
    with pytest.raises(TemplateError, match=r"^templates\.t: the streamed content"):
        check_streamed_content(parse_template("t", no_slot))
    check_streamed_content(parse_template("t", template()))


def test_builtin_default() -> None:
    default = builtin_templates()["default"]
    assert default.protocol is None
    assert list(default.instances) == ["email", "phone", "iban", "card", "national_id"]
    assert default.used_in_request() == list(default.instances)
    for protocol in PROTOCOLS:
        check_streamed_content(for_protocol(default, protocol))


NEUTRAL: dict[str, Any] = {
    "canaries": {"c": "card", "m": "email"},
    "request": {
        "system": "Billing.",
        "messages": [
            {"role": "user", "content": "Refund card {{ c.raw }}"},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {"id": "c1", "name": "lookup", "arguments": {"card": "{{ c.raw }}"}}
                ],
            },
            {"role": "tool", "tool_call_id": "c1", "content": {"to": "{{ m.raw }}"}},
        ],
    },
    "response": {"content": "Done: {{ c.masked }}"},
}


def neutral(**overrides: Any) -> dict[str, Any]:
    return {**copy.deepcopy(NEUTRAL), **overrides}


def test_parse_neutral_template() -> None:
    parsed = parse_template("t", neutral(consistency="ignore"))
    assert parsed.protocol is None
    assert parsed.request == NEUTRAL["request"]
    assert parsed.response == NEUTRAL["response"]
    assert parsed.used_in_request() == ["c", "m"]
    assert parsed.consistency == "ignore"


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        (
            {"request": {"messages": []}},
            f"{T}.request.messages: expected a non-empty list",
        ),
        ({"response": {"content": None}}, f"{T}.response: needs content or tool_calls"),
        (
            {"response": {"content": "{{ c.masked }}", "tool_calls": [{"$json": {}}]}},
            f"{T}.response.tool_calls[0].$json: $json is not allowed in a neutral template",
        ),
        (
            {"response": {"content": "{{ c.raw}} {{ zz.masked }}"}},
            f"{T}.response.content: slot zz.masked names an undeclared instance",
        ),
        (
            {"request": {"messages": [{"role": "user", "content": "{{ c.masked }}"}]}},
            f"{T}.request.messages[0].content: .masked is only allowed in the response",
        ),
    ],
)
def test_neutral_template_errors(overrides: dict[str, Any], message: str) -> None:
    with pytest.raises(TemplateError, match=f"^{re.escape(message)}$"):
        parse_template("t", neutral(**overrides))


def test_template_error_is_shared_with_neutral() -> None:
    assert TemplateError is neutral_module.TemplateError


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_for_protocol_translates_neutral(protocol: str) -> None:
    parsed = parse_template("t", neutral())
    translated = for_protocol(parsed, protocol)
    request, response = protocols.module(protocol).translate(parsed.request, parsed.response)
    assert translated == Template(
        "t", protocol, parsed.instances, request, response, parsed.consistency
    )
    assert translated.used_in_request() == ["c", "m"]
    check_streamed_content(translated)


def test_for_protocol_keeps_raw_template_of_its_protocol() -> None:
    parsed = parse_template("t", template())
    assert for_protocol(parsed, "openai-chat") is parsed
    with pytest.raises(
        TemplateError,
        match=r"^templates\.t: protocol openai-chat cannot run on anthropic-messages$",
    ):
        for_protocol(parsed, "anthropic-messages")


def test_raw_anthropic_template() -> None:
    raw = template(
        protocol="anthropic-messages",
        response={"content": [{"type": "text", "text": "To {{ a.masked }}"}]},
    )
    parsed = parse_template("t", raw)
    assert parsed.protocol == "anthropic-messages"
    assert for_protocol(parsed, "anthropic-messages") is parsed
    check_streamed_content(parsed)
    no_text = template(protocol="anthropic-messages", response={"content": [{"type": "tool_use"}]})
    with pytest.raises(
        TemplateError, match=r"^templates\.t: the streamed content \(content\[0\]\.text\) has no"
    ):
        check_streamed_content(parse_template("t", no_text))


@pytest.mark.parametrize("protocol", PROTOCOLS)
@pytest.mark.parametrize(
    ("translated", "error"),
    [
        (
            ({"messages": [{"a": {"$json": "{{ c.raw }}"}}]}, {}),
            "request.messages[0].a.$json: expected a mapping or a list",
        ),
        (
            ({"x": "{{ c.raw }}"}, {"y": "{{ m.masked }}"}),
            "response.y: slot m.masked names an instance not used in the request",
        ),
    ],
)
def test_for_protocol_checks_translated_documents(
    monkeypatch: pytest.MonkeyPatch, protocol: str, translated: tuple[Any, Any], error: str
) -> None:
    # Valid neutral documents always translate cleanly; a stub adapter reaches the raw checks.
    parsed = parse_template("t", neutral())
    monkeypatch.setattr(protocols.module(protocol), "translate", lambda _req, _resp: translated)
    with pytest.raises(TemplateError, match=f"^{re.escape(f'templates.t@{protocol}.{error}')}$"):
        for_protocol(parsed, protocol)


def test_neutral_leaf_values_are_checked_before_translation() -> None:
    # YAML reads an unquoted date as a date: rejected in the neutral template itself.
    request = copy.deepcopy(NEUTRAL["request"])
    request["messages"][2]["content"] = {"to": "{{ m.raw }}", "when": datetime.date(2026, 1, 2)}
    with pytest.raises(
        TemplateError,
        match=r"^templates\.t\.request\.messages\[2\]\.content\.when: expected a JSON value$",
    ):
        parse_template("t", neutral(request=request))


def test_streamed_content_needs_a_translated_template() -> None:
    with pytest.raises(
        TemplateError, match=r"^templates\.t: the streamed content check needs a translated"
    ):
        check_streamed_content(parse_template("t", neutral()))


def test_inline_overrides_builtin() -> None:
    catalog = build_catalog({"default": template(), "extra": template()})
    assert set(catalog) >= {"default", "extra"}
    assert list(catalog["default"].instances) == ["a", "b", "unused"]


TOOL_REQUEST = {
    "messages": [
        {"role": "user", "content": "card {{ c.raw }} mail {{ m.raw }}"},
        {
            "role": "assistant",
            "tool_calls": [{"function": {"arguments": {"$json": {"card": "{{ c.raw }}"}}}}],
        },
        {"role": "tool", "content": {"$json": {"status": "found", "to": "{{ m.raw }}", "n": 1}}},
    ]
}
TOOL_RESPONSE = {
    "choices": [
        {
            "message": {
                "tool_calls": [{"function": {"arguments": {"$json": {"c": "{{ c.masked }}"}}}}]
            }
        }
    ]
}
ARGS_LOC = "body.messages[1].tool_calls[0].function.arguments$.card"


def tool_template(**overrides: Any) -> dict[str, Any]:
    raw: dict[str, Any] = {
        "protocol": "openai-chat",
        "canaries": {"c": "card", "m": "email"},
        "request": TOOL_REQUEST,
        "response": TOOL_RESPONSE,
    }
    raw.update(overrides)
    return raw


def upstream(args: str, tool: str) -> dict[str, Any]:
    return {
        "messages": [
            {"role": "user", "content": "card <C1> mail <M1>"},
            {"role": "assistant", "tool_calls": [{"function": {"arguments": args}}]},
            {"role": "tool", "content": tool},
        ]
    }


def test_json_nodes_count_as_request_use() -> None:
    parsed = parse_template("t", tool_template())
    assert parsed.used_in_request() == ["c", "m"]
    assert parsed.consistency == "required"


def test_render_serializes_json_nodes() -> None:
    rendered = render(TOOL_REQUEST, {"c": "4000", "m": "a@example.org"}, {})
    args = rendered["messages"][1]["tool_calls"][0]["function"]["arguments"]
    assert args == '{"card":"4000"}'
    assert json.loads(rendered["messages"][2]["content"]) == {
        "status": "found",
        "to": "a@example.org",
        "n": 1,
    }


def test_extract_occurrences_through_reencoded_json() -> None:
    doc = upstream('{ "card" : "<C1>" }', '{"n":1.0,"to":"<M2>","status":"found"}')
    assert extract_occurrences(TOOL_REQUEST, doc) == [
        Occurrence("c", "body.messages[0].content", "<C1>"),
        Occurrence("m", "body.messages[0].content", "<M1>"),
        Occurrence("c", ARGS_LOC, "<C1>"),
        Occurrence("m", "body.messages[2].content$.to", "<M2>"),
    ]
    assert first_placeholders(extract_occurrences(TOOL_REQUEST, doc)) == {"c": "<C1>", "m": "<M1>"}
    assert extract_masked(TOOL_REQUEST, doc) == {"c": "<C1>", "m": "<M1>"}


@pytest.mark.parametrize(
    ("args", "tool", "where"),
    [
        (
            "not json",
            '{"status":"found","to":"<M1>","n":1}',
            "body.messages[1].tool_calls[0].function.arguments",
        ),
        (
            '{"card":"<C1>","extra":1}',
            '{"status":"found","to":"<M1>","n":1}',
            "body.messages[1].tool_calls[0].function.arguments",
        ),
        ('{"card":"<C1>"}', '{"status":"found","to":"<M1>","n":true}', "body.messages[2].content"),
        ('{"card":"<C1>"}', '{"status":"found","to":"<M1>","n":2}', "body.messages[2].content"),
        (
            '{"card":7}',
            '{"status":"found","to":"<M1>","n":1}',
            "body.messages[1].tool_calls[0].function.arguments",
        ),
    ],
)
def test_json_shape_mismatch_is_not_found(args: str, tool: str, where: str) -> None:
    with pytest.raises(MaskedValueNotFoundError) as exc:
        extract_occurrences(TOOL_REQUEST, upstream(args, tool))
    assert exc.value.location == where


def test_json_shape_mismatch_stays_plain() -> None:
    # Text around the $json node's slot matches; the mangling is inside the JSON shape itself.
    tool = '{"status":"found","to":"<M1>","n":1}'
    with pytest.raises(MaskedValueNotFoundError) as info:
        extract_occurrences(TOOL_REQUEST, upstream("not json", tool))
    assert type(info.value) is MaskedValueNotFoundError


def test_json_nodes_lists_outermost_first() -> None:
    doc = {"a": {JSON_NODE: {"b": {JSON_NODE: ["x"]}}}, "c": [{JSON_NODE: {}}]}
    assert json_nodes(doc) == [("a",), ("a", JSON_NODE, "b"), ("c", 0)]


def test_consistency_values() -> None:
    assert parse_template("t", tool_template(consistency="ignore")).consistency == "ignore"
    with pytest.raises(
        TemplateError, match=r"^templates\.t\.consistency: expected one of required, ignore$"
    ):
        parse_template("t", tool_template(consistency="maybe"))


@pytest.mark.parametrize(
    ("request_doc", "message"),
    [
        (
            {"a": {"$json": {"x": "{{ c.raw }}"}, "b": 1}},
            r"^templates\.t\.request\.a: a \$json mapping has no other keys$",
        ),
        (
            {"a": {"$json": "{{ c.raw }}"}},
            r"^templates\.t\.request\.a\.\$json: expected a mapping or a list$",
        ),
        (
            {"a": {"$json": {"x": {"deep": {1, 2}}}}},
            r"^templates\.t\.request\.a\$\.x\.deep: unsupported value in \$json$",
        ),
    ],
)
def test_json_node_errors(request_doc: dict[str, Any], message: str) -> None:
    with pytest.raises(TemplateError, match=message):
        parse_template("t", tool_template(request=request_doc, response={"x": "{{ c.masked }}"}))


def test_nested_json_nodes_are_allowed() -> None:
    nested = {"a": {"$json": {"inner": {"$json": ["{{ c.raw }}"]}}}}
    parsed = parse_template("t", tool_template(request=nested, response={"x": "{{ c.masked }}"}))
    assert render(parsed.request, {"c": "4000"}, {}) == {"a": '{"inner":"[\\"4000\\"]"}'}


def test_streamed_content_cannot_be_a_json_node() -> None:
    response = {"choices": [{"message": {"content": {"$json": {"c": "{{ c.masked }}"}}}}]}
    with pytest.raises(TemplateError, match="streamed content"):
        check_streamed_content(parse_template("t", tool_template(response=response)))


def test_builtin_tool_calls_and_multi_turn() -> None:
    templates = builtin_templates()
    tool = templates["tool-calls"]
    assert tool.used_in_request() == ["card", "iban", "email"]
    assert tool.consistency == "required"
    openai_tool = for_protocol(tool, "openai-chat")
    args = ("choices", 0, "message", "tool_calls", 0, "function", "arguments")
    assert [path for path, _ in slotted_strings(openai_tool.response)] == [
        (*args, JSON_NODE, "card"),
        (*args, JSON_NODE, "iban"),
        (*args, JSON_NODE, "email"),
    ]
    anthropic_tool = for_protocol(tool, "anthropic-messages")
    assert [path for path, _ in slotted_strings(anthropic_tool.response)] == [
        ("content", 0, "input", "card"),
        ("content", 0, "input", "iban"),
        ("content", 0, "input", "email"),
    ]
    multi = templates["multi-turn"]
    assert multi.used_in_request() == ["email", "colleague", "phone", "card"]
    for protocol in PROTOCOLS:
        check_streamed_content(for_protocol(multi, protocol))
        with pytest.raises(TemplateError, match="streamed content"):
            check_streamed_content(for_protocol(tool, protocol))
