import json
from typing import Any

from canarywire.runner.catalog import render
from canarywire.runner.restore import Comparison, Mismatch, compare_response

TEMPLATE = {
    "choices": [
        {
            "message": {
                "content": "Hi {{ m.masked }}",
                "tool_calls": [
                    {
                        "function": {
                            "name": "refund",
                            "arguments": {
                                "$json": {
                                    "card": "{{ c.masked }}",
                                    "iban": "{{ i.masked }}",
                                    "n": 1,
                                }
                            },
                        }
                    }
                ],
            }
        }
    ]
}
RAW = {"m": "ann@example.org", "c": "4000000000000002", "i": "DE00123"}
EXPECTED = render(TEMPLATE, RAW, RAW)
ARGS = "body.choices[0].message.tool_calls[0].function.arguments"


def actual(arguments: str, content: str = "Hi ann@example.org") -> dict[str, Any]:
    doc: dict[str, Any] = json.loads(json.dumps(EXPECTED))
    doc["choices"][0]["message"]["content"] = content
    doc["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"] = arguments
    return doc


def test_reencoded_arguments_are_restored() -> None:
    arguments = json.dumps({"n": 1.0, "iban": RAW["i"], "card": RAW["c"]}, indent=2)
    assert compare_response(TEMPLATE, EXPECTED, actual(arguments)) == Comparison(3, [])


def test_placeholder_left_in_arguments_is_unrestored_at_inner_path() -> None:
    arguments = json.dumps({"card": "<CARD_1>", "iban": RAW["i"], "n": 1})
    assert compare_response(TEMPLATE, EXPECTED, actual(arguments)) == Comparison(
        2, [Mismatch(("c",), f"{ARGS}$.card", RAW["c"], "<CARD_1>")]
    )


def test_unparseable_arguments_fail_every_slot_at_the_node() -> None:
    result = compare_response(TEMPLATE, EXPECTED, actual("{broken"))
    assert result.restored == 1
    assert result.mismatches == [
        Mismatch(("c", "i"), ARGS, get_args(EXPECTED), "{broken"),
    ]


def test_difference_outside_slots_fails_every_slot_of_the_node() -> None:
    arguments = json.dumps({"card": RAW["c"], "iban": RAW["i"], "n": 2})
    result = compare_response(TEMPLATE, EXPECTED, actual(arguments))
    assert result.restored == 1
    assert result.mismatches == [
        Mismatch(
            ("c", "i"),
            ARGS,
            get_args(EXPECTED),
            arguments,
            f"JSON differs outside slots at {ARGS}$.n",
        )
    ]


def test_extra_key_is_a_difference_at_the_mapping() -> None:
    arguments = json.dumps({"card": RAW["c"], "iban": RAW["i"], "n": 1, "x": 0})
    [mismatch] = compare_response(TEMPLATE, EXPECTED, actual(arguments)).mismatches
    assert mismatch.note == f"JSON differs outside slots at {ARGS}$"


def test_plain_strings_still_compare_exactly() -> None:
    arguments = get_args(EXPECTED)
    result = compare_response(TEMPLATE, EXPECTED, actual(arguments, content="Hi <EMAIL_1>"))
    assert result == Comparison(
        2,
        [
            Mismatch(
                ("m",),
                "body.choices[0].message.content",
                "Hi ann@example.org",
                "Hi <EMAIL_1>",
            )
        ],
    )


def test_nested_node_difference_is_attributed_to_the_inner_node() -> None:
    template = {
        "a": {
            "$json": {
                "inner": {"$json": {"v": "{{ c.masked }}", "k": 1}},
                "w": "{{ i.masked }}",
            }
        }
    }
    expected = render(template, RAW, RAW)
    inner = json.dumps({"v": RAW["c"], "k": 2})
    got = {"a": json.dumps({"inner": inner, "w": RAW["i"]})}
    result = compare_response(template, expected, got)
    assert result.restored == 1
    assert result.mismatches == [
        Mismatch(
            ("c",),
            "body.a$.inner",
            json.loads(expected["a"])["inner"],
            inner,
            "JSON differs outside slots at body.a$.inner$.k",
        )
    ]


def get_args(doc: Any) -> str:
    value: str = doc["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
    return value
