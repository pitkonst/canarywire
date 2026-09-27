import copy
import datetime
import re
from typing import Any

import pytest

from canarywire.runner.catalog import TemplateError
from canarywire.runner.neutral import DEFAULT_MODEL, check_neutral

REQUEST: dict[str, Any] = {
    "model": "canarywire-test",
    "system": "You are a billing assistant.",
    "tools": [
        {
            "name": "refund",
            "description": "Refund a card payment.",
            "parameters": {"type": "object", "properties": {"card": {"type": "string"}}},
        }
    ],
    "messages": [
        {"role": "user", "content": "Refund card {{ card.raw }}"},
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [{"id": "c1", "name": "lookup", "arguments": {"card": "{{ card.raw }}"}}],
        },
        {"role": "tool", "tool_call_id": "c1", "content": {"status": "found"}},
        {"role": "tool", "tool_call_id": "c2", "content": "plain"},
    ],
}
RESPONSE: dict[str, Any] = {
    "content": "Done: {{ card.masked }}",
    "tool_calls": [{"id": "c2", "name": "refund", "arguments": {"card": "{{ card.masked }}"}}],
}
T = "templates.t"


def check(request: Any = None, response: Any = None) -> None:
    check_neutral(
        copy.deepcopy(REQUEST) if request is None else request,
        copy.deepcopy(RESPONSE) if response is None else response,
        T,
    )


def with_message(index: int, message: dict[str, Any]) -> dict[str, Any]:
    request = copy.deepcopy(REQUEST)
    request["messages"][index] = message
    return request


def fails(message: str, request: Any = None, response: Any = None) -> None:
    with pytest.raises(TemplateError, match=f"^{re.escape(message)}$"):
        check(request, response)


def test_default_model() -> None:
    assert DEFAULT_MODEL == "canarywire-test"


def test_valid_full_template_passes() -> None:
    check()


def test_minimal_template_passes() -> None:
    check_neutral({"messages": [{"role": "user", "content": "hi"}]}, {"content": "ok"}, T)


def test_request_must_be_a_mapping() -> None:
    fails(f"{T}.request: expected a mapping", request=[])


def test_unknown_request_key() -> None:
    fails(f"{T}.request.foo: unknown key", request={**REQUEST, "foo": 1})


@pytest.mark.parametrize("messages", [None, [], "hi"])
def test_messages_missing_or_empty(messages: Any) -> None:
    request = {key: value for key, value in REQUEST.items() if key != "messages"}
    if messages is not None:
        request["messages"] = messages
    fails(f"{T}.request.messages: expected a non-empty list", request=request)


def test_model_and_system_are_strings() -> None:
    fails(f"{T}.request.model: expected a string", request={**REQUEST, "model": 3})
    fails(f"{T}.request.system: expected a string", request={**REQUEST, "system": None})


def test_tools_shape() -> None:
    fails(f"{T}.request.tools: expected a list", request={**REQUEST, "tools": {}})
    fails(f"{T}.request.tools[0]: expected a mapping", request={**REQUEST, "tools": ["x"]})
    fails(f"{T}.request.tools[0].name: expected a string", request={**REQUEST, "tools": [{}]})
    fails(
        f"{T}.request.tools[0].kind: unknown key",
        request={**REQUEST, "tools": [{"name": "x", "kind": 1}]},
    )
    fails(
        f"{T}.request.tools[0].description: expected a string",
        request={**REQUEST, "tools": [{"name": "x", "description": 1}]},
    )
    fails(
        f"{T}.request.tools[0].parameters: expected a mapping",
        request={**REQUEST, "tools": [{"name": "x", "parameters": []}]},
    )


def test_message_must_be_a_mapping() -> None:
    fails(f"{T}.request.messages[0]: expected a mapping", request=with_message(0, "hi"))  # type: ignore[arg-type]


def test_unknown_role() -> None:
    fails(
        f"{T}.request.messages[0].role: expected one of user, assistant, tool",
        request=with_message(0, {"role": "system", "content": "x"}),
    )


@pytest.mark.parametrize(
    ("message", "key"),
    [
        ({"role": "user", "content": "x", "name": "bob"}, "name"),
        ({"role": "assistant", "content": "x", "tool_call_id": "c1"}, "tool_call_id"),
        ({"role": "tool", "tool_call_id": "c1", "content": "x", "tool_calls": []}, "tool_calls"),
    ],
)
def test_unknown_message_key(message: dict[str, Any], key: str) -> None:
    fails(f"{T}.request.messages[0].{key}: unknown key", request=with_message(0, message))


@pytest.mark.parametrize("content", [None, 3, {"text": "x"}])
def test_user_content_is_a_string(content: Any) -> None:
    fails(
        f"{T}.request.messages[0].content: expected a string",
        request=with_message(0, {"role": "user", "content": content}),
    )


def test_assistant_content_is_a_string_or_null() -> None:
    fails(
        f"{T}.request.messages[1].content: expected a string or null",
        request=with_message(1, {"role": "assistant", "content": ["x"]}),
    )


@pytest.mark.parametrize(
    "message",
    [
        {"role": "assistant", "content": None},
        {"role": "assistant"},
        {"role": "assistant", "content": ""},
        {"role": "assistant", "content": None, "tool_calls": []},
    ],
)
def test_assistant_needs_content_or_tool_calls(message: dict[str, Any]) -> None:
    fails(
        f"{T}.request.messages[1]: an assistant message needs content or tool_calls",
        request=with_message(1, message),
    )


def test_assistant_with_content_only_passes() -> None:
    check(request=with_message(1, {"role": "assistant", "content": "Sure."}))


@pytest.mark.parametrize(
    ("call", "message"),
    [
        ("c1", "tool_calls[0]: expected a mapping"),
        ({"name": "x", "arguments": {}}, "tool_calls[0].id: expected a string"),
        ({"id": "c1", "arguments": {}}, "tool_calls[0].name: expected a string"),
        ({"id": "c1", "name": "x"}, "tool_calls[0].arguments: expected a mapping"),
        (
            {"id": "c1", "name": "x", "arguments": "{}"},
            "tool_calls[0].arguments: expected a mapping",
        ),
        (
            {"id": "c1", "name": "x", "arguments": {}, "type": "function"},
            "tool_calls[0].type: unknown key",
        ),
    ],
)
def test_tool_call_shape(call: Any, message: str) -> None:
    fails(
        f"{T}.request.messages[1].{message}",
        request=with_message(1, {"role": "assistant", "content": None, "tool_calls": [call]}),
    )


def test_tool_calls_must_be_a_list() -> None:
    fails(
        f"{T}.request.messages[1].tool_calls: expected a list",
        request=with_message(1, {"role": "assistant", "content": "x", "tool_calls": {}}),
    )


def test_tool_message_needs_tool_call_id() -> None:
    fails(
        f"{T}.request.messages[2].tool_call_id: expected a string",
        request=with_message(2, {"role": "tool", "content": "x"}),
    )


@pytest.mark.parametrize("content", [None, 3, ["x"]])
def test_tool_content_is_a_string_or_a_mapping(content: Any) -> None:
    fails(
        f"{T}.request.messages[2].content: expected a string or a mapping",
        request=with_message(2, {"role": "tool", "tool_call_id": "c1", "content": content}),
    )


def test_response_must_be_a_mapping() -> None:
    fails(f"{T}.response: expected a mapping", response="x")


@pytest.mark.parametrize(
    "response",
    [{}, {"content": None}, {"content": ""}, {"content": None, "tool_calls": []}],
)
def test_response_needs_content_or_tool_calls(response: dict[str, Any]) -> None:
    fails(f"{T}.response: needs content or tool_calls", response=response)


def test_response_content_and_tool_calls_shape() -> None:
    fails(f"{T}.response.content: expected a string or null", response={"content": 1})
    fails(
        f"{T}.response.tool_calls[0].arguments: expected a mapping",
        response={"tool_calls": [{"id": "c", "name": "n", "arguments": 1}]},
    )


def test_null_tool_calls_count_as_absent() -> None:
    check(
        request=with_message(1, {"role": "assistant", "content": "Sure.", "tool_calls": None}),
        response={"content": "ok", "tool_calls": None},
    )
    fails(
        f"{T}.request.messages[1]: an assistant message needs content or tool_calls",
        request=with_message(1, {"role": "assistant", "content": None, "tool_calls": None}),
    )
    fails(f"{T}.response: needs content or tool_calls", response={"tool_calls": None})


def test_date_in_parameters_is_not_a_json_value() -> None:
    tool = {"name": "x", "parameters": {"properties": {"d": datetime.date(2026, 1, 2)}}}
    fails(
        f"{T}.request.tools[0].parameters.properties.d: expected a JSON value",
        request={**REQUEST, "tools": [tool]},
    )


def test_set_in_arguments_is_not_a_json_value() -> None:
    call = {"id": "c1", "name": "x", "arguments": {"ids": [1, {2, 3}]}}
    fails(
        f"{T}.request.messages[1].tool_calls[0].arguments.ids[1]: expected a JSON value",
        request=with_message(1, {"role": "assistant", "content": None, "tool_calls": [call]}),
    )


def test_int_key_in_tool_content() -> None:
    fails(
        f"{T}.request.messages[2].content.nested: keys must be strings",
        request=with_message(
            2, {"role": "tool", "tool_call_id": "c1", "content": {"nested": {1: "x"}}}
        ),
    )


def test_bool_key_in_response_arguments() -> None:
    # YAML 1.1 reads an unquoted `yes:` key as True.
    fails(
        f"{T}.response.tool_calls[0].arguments: keys must be strings",
        response={"tool_calls": [{"id": "c", "name": "n", "arguments": {True: "x"}}]},
    )


def test_json_values_pass() -> None:
    call = {"id": "c1", "name": "x", "arguments": {"a": [None, 1, 2.5, True, "s", {"b": []}]}}
    check(request=with_message(1, {"role": "assistant", "content": None, "tool_calls": [call]}))


def test_unknown_response_key() -> None:
    fails(f"{T}.response.choices: unknown key", response={"content": "x", "choices": []})


@pytest.mark.parametrize(
    ("request_doc", "response", "where"),
    [
        (
            with_message(
                1,
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [{"id": "c1", "name": "x", "arguments": {"$json": {}}}],
                },
            ),
            None,
            "request.messages[1].tool_calls[0].arguments.$json",
        ),
        (
            with_message(2, {"role": "tool", "tool_call_id": "c1", "content": {"$json": {}}}),
            None,
            "request.messages[2].content.$json",
        ),
        (
            {**REQUEST, "tools": [{"name": "x", "parameters": {"a": [{"$json": 1}]}}]},
            None,
            "request.tools[0].parameters.a[0].$json",
        ),
        (None, {"content": "x", "$json": 1}, "response.$json"),
        ({**REQUEST, "$json": {}}, None, "request.$json"),
    ],
)
def test_json_node_is_not_allowed(request_doc: Any, response: Any, where: str) -> None:
    fails(
        f"{T}.{where}: $json is not allowed in a neutral template",
        request=request_doc,
        response=response,
    )
