import pytest

from canarywire.runner.jsonpath import (
    JSON_NODE,
    decode_json,
    format_path,
    get_path,
    is_json_node,
    json_equal,
)

ARGS = ("messages", 1, "tool_calls", 0, "function", "arguments")


def test_format_path_marks_json_strings() -> None:
    assert format_path((*ARGS, JSON_NODE, "card")) == (
        "messages[1].tool_calls[0].function.arguments$.card"
    )
    assert format_path(("content", JSON_NODE, 0)) == "content$[0]"


def test_get_path_decodes_json_strings() -> None:
    doc = {"a": '{"card": "<CARD_1>", "n": [1]}'}
    assert get_path(doc, ("a", JSON_NODE, "card")) == "<CARD_1>"
    assert get_path(doc, ("a", JSON_NODE, "n", 0)) == 1


def test_get_path_walks_template_nodes() -> None:
    template = {"a": {JSON_NODE: {"card": "{{ card.raw }}"}}}
    assert get_path(template, ("a", JSON_NODE, "card")) == "{{ card.raw }}"


@pytest.mark.parametrize("value", ["not json", 3, None, {"x": 1}])
def test_get_path_through_non_json_is_none(value: object) -> None:
    assert get_path({"a": value}, ("a", JSON_NODE, "card")) is None


def test_is_json_node() -> None:
    assert is_json_node({JSON_NODE: {}})
    assert not is_json_node({JSON_NODE: {}, "x": 1})
    assert not is_json_node("{}")


def test_decode_json() -> None:
    assert decode_json('{"a": 1}') == (True, {"a": 1})
    assert decode_json({JSON_NODE: [1]}) == (True, [1])
    assert decode_json("{") == (False, None)
    assert decode_json(7) == (False, None)


@pytest.mark.parametrize(
    ("a", "b", "equal"),
    [
        (1, 1.0, True),
        (True, 1, False),
        (None, 0, False),
        ({"a": [1, "x"]}, {"a": [1.0, "x"]}, True),
        ({"a": 1}, {"a": 1, "b": 2}, False),
        ([1, 2], [1], False),
        ("x", "x", True),
    ],
)
def test_json_equal(a: object, b: object, equal: bool) -> None:
    assert json_equal(a, b) is equal
