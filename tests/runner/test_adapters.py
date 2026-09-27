import copy
from typing import Any

import pytest

from canarywire.runner import protocols
from canarywire.runner.protocols import anthropic, openai

PARAMETERS = {"type": "object", "properties": {"card": {"type": "string"}}}

# The spec's neutral example, plus a second (string) tool result right after the first.
REQUEST: dict[str, Any] = {
    "model": "canarywire-test",
    "system": "You are a billing assistant.",
    "tools": [{"name": "refund", "description": "Refund a card.", "parameters": PARAMETERS}],
    "messages": [
        {"role": "user", "content": "Refund card {{ card.raw }}"},
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [{"id": "c1", "name": "lookup", "arguments": {"card": "{{ card.raw }}"}}],
        },
        {
            "role": "tool",
            "tool_call_id": "c1",
            "content": {"status": "found", "to": "{{ email.raw }}"},
        },
        {"role": "tool", "tool_call_id": "c0", "content": "no history"},
        {"role": "user", "content": "Go ahead."},
        {"role": "assistant", "content": "Refunding."},
        {
            "role": "assistant",
            "content": "Calling refund.",
            "tool_calls": [{"id": "c9", "name": "note", "arguments": {}}],
        },
        {"role": "tool", "tool_call_id": "c9", "content": "noted"},
    ],
}
RESPONSE: dict[str, Any] = {
    "content": "Done: {{ card.masked }}",
    "tool_calls": [{"id": "c2", "name": "refund", "arguments": {"card": "{{ card.masked }}"}}],
}

OPENAI_REQUEST = {
    "model": "canarywire-test",
    "messages": [
        {"role": "system", "content": "You are a billing assistant."},
        {"role": "user", "content": "Refund card {{ card.raw }}"},
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": "c1",
                    "type": "function",
                    "function": {
                        "name": "lookup",
                        "arguments": {"$json": {"card": "{{ card.raw }}"}},
                    },
                }
            ],
        },
        {
            "role": "tool",
            "tool_call_id": "c1",
            "content": {"$json": {"status": "found", "to": "{{ email.raw }}"}},
        },
        {"role": "tool", "tool_call_id": "c0", "content": "no history"},
        {"role": "user", "content": "Go ahead."},
        {"role": "assistant", "content": "Refunding."},
        {
            "role": "assistant",
            "content": "Calling refund.",
            "tool_calls": [
                {
                    "id": "c9",
                    "type": "function",
                    "function": {"name": "note", "arguments": {"$json": {}}},
                }
            ],
        },
        {"role": "tool", "tool_call_id": "c9", "content": "noted"},
    ],
    "tools": [
        {
            "type": "function",
            "function": {
                "name": "refund",
                "description": "Refund a card.",
                "parameters": PARAMETERS,
            },
        }
    ],
}
OPENAI_RESPONSE = {
    "id": "chatcmpl-canarywire",
    "object": "chat.completion",
    "created": 0,
    "model": "canarywire-test",
    "choices": [
        {
            "index": 0,
            "finish_reason": "tool_calls",
            "message": {
                "role": "assistant",
                "content": "Done: {{ card.masked }}",
                "tool_calls": [
                    {
                        "id": "c2",
                        "type": "function",
                        "function": {
                            "name": "refund",
                            "arguments": {"$json": {"card": "{{ card.masked }}"}},
                        },
                    }
                ],
            },
        }
    ],
}

ANTHROPIC_REQUEST = {
    "model": "canarywire-test",
    "max_tokens": 1024,
    "system": "You are a billing assistant.",
    "messages": [
        {"role": "user", "content": "Refund card {{ card.raw }}"},
        {
            "role": "assistant",
            "content": [
                {
                    "type": "tool_use",
                    "id": "c1",
                    "name": "lookup",
                    "input": {"card": "{{ card.raw }}"},
                }
            ],
        },
        {
            "role": "user",
            "content": [
                {
                    "type": "tool_result",
                    "tool_use_id": "c1",
                    "content": {"$json": {"status": "found", "to": "{{ email.raw }}"}},
                },
                {"type": "tool_result", "tool_use_id": "c0", "content": "no history"},
            ],
        },
        {"role": "user", "content": "Go ahead."},
        {"role": "assistant", "content": [{"type": "text", "text": "Refunding."}]},
        {
            "role": "assistant",
            "content": [
                {"type": "text", "text": "Calling refund."},
                {"type": "tool_use", "id": "c9", "name": "note", "input": {}},
            ],
        },
        {
            "role": "user",
            "content": [{"type": "tool_result", "tool_use_id": "c9", "content": "noted"}],
        },
    ],
    "tools": [{"name": "refund", "description": "Refund a card.", "input_schema": PARAMETERS}],
}
ANTHROPIC_RESPONSE = {
    "id": "msg_canarywire",
    "type": "message",
    "role": "assistant",
    "model": "canarywire-test",
    "content": [
        {"type": "text", "text": "Done: {{ card.masked }}"},
        {"type": "tool_use", "id": "c2", "name": "refund", "input": {"card": "{{ card.masked }}"}},
    ],
    "stop_reason": "tool_use",
    "stop_sequence": None,
    "usage": {"input_tokens": 0, "output_tokens": 0},
}

MINIMAL_REQUEST = {"messages": [{"role": "user", "content": "Hi {{ a.raw }}"}]}
MINIMAL_RESPONSE = {"content": "Hello {{ a.masked }}"}


def test_protocol_registry() -> None:
    assert protocols.PROTOCOLS == ("openai-chat", "anthropic-messages")
    assert protocols.module("openai-chat") is openai
    assert protocols.module("anthropic-messages") is anthropic


def test_unknown_protocol_module() -> None:
    with pytest.raises(
        ValueError,
        match=r"^unknown protocol 'bogus'; expected one of openai-chat, anthropic-messages$",
    ):
        protocols.module("bogus")


def test_content_paths() -> None:
    assert openai.CONTENT_PATH == ("choices", 0, "message", "content")
    assert anthropic.CONTENT_PATH == ("content", 0, "text")


def test_openai_full() -> None:
    request, response = copy.deepcopy(REQUEST), copy.deepcopy(RESPONSE)
    doc, answer = openai.translate(request, response)
    assert (doc, answer) == (OPENAI_REQUEST, OPENAI_RESPONSE)
    assert (request, response) == (REQUEST, RESPONSE)  # pure: inputs untouched
    # Key order is document order, which orders occurrences.
    assert list(doc) == ["model", "tools", "messages"]
    assert list(answer) == ["id", "object", "created", "model", "choices"]


def test_anthropic_full() -> None:
    request, response = copy.deepcopy(REQUEST), copy.deepcopy(RESPONSE)
    doc, answer = anthropic.translate(request, response)
    assert (doc, answer) == (ANTHROPIC_REQUEST, ANTHROPIC_RESPONSE)
    assert (request, response) == (REQUEST, RESPONSE)
    assert list(doc) == ["model", "max_tokens", "system", "tools", "messages"]


def test_translation_shares_nothing_with_the_neutral_documents() -> None:
    request, response = copy.deepcopy(REQUEST), copy.deepcopy(RESPONSE)
    openai_doc, openai_answer = openai.translate(request, response)
    openai_doc["tools"][0]["function"]["parameters"]["type"] = "changed"
    openai_answer["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]["$json"][
        "card"
    ] = "changed"
    anthropic_doc, anthropic_answer = anthropic.translate(request, response)
    anthropic_doc["messages"][1]["content"][0]["input"]["card"] = "changed"
    anthropic_answer["content"][1]["input"]["card"] = "changed"
    assert (request, response) == (REQUEST, RESPONSE)


def test_openai_minimal_defaults() -> None:
    assert openai.translate(MINIMAL_REQUEST, MINIMAL_RESPONSE) == (
        {"model": "canarywire-test", "messages": [{"role": "user", "content": "Hi {{ a.raw }}"}]},
        {
            "id": "chatcmpl-canarywire",
            "object": "chat.completion",
            "created": 0,
            "model": "canarywire-test",
            "choices": [
                {
                    "index": 0,
                    "finish_reason": "stop",
                    "message": {"role": "assistant", "content": "Hello {{ a.masked }}"},
                }
            ],
        },
    )


def test_anthropic_minimal_defaults() -> None:
    assert anthropic.translate(MINIMAL_REQUEST, MINIMAL_RESPONSE) == (
        {
            "model": "canarywire-test",
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": "Hi {{ a.raw }}"}],
        },
        {
            "id": "msg_canarywire",
            "type": "message",
            "role": "assistant",
            "model": "canarywire-test",
            "content": [{"type": "text", "text": "Hello {{ a.masked }}"}],
            "stop_reason": "end_turn",
            "stop_sequence": None,
            "usage": {"input_tokens": 0, "output_tokens": 0},
        },
    )


def test_model_is_carried_to_the_response() -> None:
    request = {**MINIMAL_REQUEST, "model": "gpt-x"}
    assert openai.translate(request, MINIMAL_RESPONSE)[1]["model"] == "gpt-x"
    assert anthropic.translate(request, MINIMAL_RESPONSE)[1]["model"] == "gpt-x"


def test_tool_defaults() -> None:
    request = {**MINIMAL_REQUEST, "tools": [{"name": "noop"}]}
    assert openai.translate(request, MINIMAL_RESPONSE)[0]["tools"] == [
        {"type": "function", "function": {"name": "noop", "description": "", "parameters": {}}}
    ]
    assert anthropic.translate(request, MINIMAL_RESPONSE)[0]["tools"] == [
        {"name": "noop", "description": "", "input_schema": {"type": "object"}}
    ]


def test_null_tool_calls_are_absent() -> None:
    request = {
        "messages": [
            {"role": "user", "content": "Hi {{ a.raw }}"},
            {"role": "assistant", "content": "Hello.", "tool_calls": None},
        ]
    }
    response = {"content": "Bye {{ a.masked }}", "tool_calls": None}
    openai_doc, openai_answer = openai.translate(request, response)
    assert openai_doc["messages"][1] == {"role": "assistant", "content": "Hello."}
    assert openai_answer["choices"][0]["finish_reason"] == "stop"
    assert openai_answer["choices"][0]["message"] == {
        "role": "assistant",
        "content": "Bye {{ a.masked }}",
    }
    anthropic_doc, anthropic_answer = anthropic.translate(request, response)
    assert anthropic_doc["messages"][1] == {
        "role": "assistant",
        "content": [{"type": "text", "text": "Hello."}],
    }
    assert anthropic_answer["content"] == [{"type": "text", "text": "Bye {{ a.masked }}"}]
    assert anthropic_answer["stop_reason"] == "end_turn"


def test_tool_calls_only_response() -> None:
    response = {"content": None, "tool_calls": [{"id": "c", "name": "n", "arguments": {}}]}
    openai_answer = openai.translate(MINIMAL_REQUEST, response)[1]
    assert openai_answer["choices"][0]["message"] == {
        "role": "assistant",
        "content": None,
        "tool_calls": [
            {"id": "c", "type": "function", "function": {"name": "n", "arguments": {"$json": {}}}}
        ],
    }
    anthropic_answer = anthropic.translate(MINIMAL_REQUEST, response)[1]
    assert anthropic_answer["content"] == [
        {"type": "tool_use", "id": "c", "name": "n", "input": {}}
    ]
    assert anthropic_answer["stop_reason"] == "tool_use"
