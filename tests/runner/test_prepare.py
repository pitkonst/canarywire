import re
from typing import Any

import pytest

from canarywire.config import ConfigError, parse
from canarywire.runner.prepare import instance_rng, prepare
from canarywire.values.regex import PatternGenerator


def invoice(canaries: dict[str, Any], content: str) -> dict[str, Any]:
    return {
        "protocol": "openai-chat",
        "canaries": canaries,
        "request": {"messages": [{"role": "user", "content": content}]},
        "response": {"choices": [{"message": {"content": content.replace(".raw", ".masked")}}]},
    }


def test_default_template_values() -> None:
    prepared = prepare(parse({}), seed=5)
    default = prepared.templates["default@openai-chat"]
    assert [(c.name, c.type, c.template) for c in default.canaries] == [
        ("email", "email", "default"),
        ("phone", "phone", "default"),
        ("iban", "iban", "default"),
        ("card", "card", "default"),
        ("national_id", "national_id", "default"),
    ]
    assert len({c.value for c in default.canaries}) == 5


def test_deterministic_and_independent_of_other_templates() -> None:
    alone = prepare(parse({}), seed=9).templates["default@openai-chat"].raw()
    extra = parse(
        {
            "templates": {"invoice": invoice({"c": "email"}, "mail {{ c.raw }} now")},
            "generators": {"baseline": {"templates": ["default", "invoice"]}},
        }
    )
    assert prepare(extra, seed=9).templates["default@openai-chat"].raw() == alone
    assert prepare(parse({}), seed=9).templates["default@openai-chat"].raw() == alone
    assert prepare(parse({}), seed=10).templates["default@openai-chat"].raw() != alone


def test_values_pool_is_drawn_without_replacement() -> None:
    config = parse(
        {
            "canary_types": {"cid": {"values": ["CUST-0001", "CUST-0002"]}},
            "templates": {
                "t": invoice({"a": "cid", "b": "cid"}, "ids {{ a.raw }} and {{ b.raw }}")
            },
            "generators": {"baseline": {"templates": ["t"]}, "fragmentation": {"templates": ["t"]}},
        }
    )
    values = prepare(config, seed=1).templates["t@openai-chat"].raw()
    assert sorted(values.values()) == ["CUST-0001", "CUST-0002"]


def test_unused_instances_are_not_assigned() -> None:
    config = parse(
        {
            "templates": {"t": invoice({"a": "email", "spare": "phone"}, "mail {{ a.raw }} now")},
            "generators": {"baseline": {"templates": ["t"]}, "fragmentation": {"templates": ["t"]}},
        }
    )
    assert [c.name for c in prepare(config, seed=1).all_canaries()] == ["a"]


def config_error(raw: dict[str, Any]) -> str:
    with pytest.raises(ConfigError) as exc:
        prepare(parse(raw), seed=1)
    return str(exc.value)


def test_unknown_template_in_generator() -> None:
    message = config_error({"generators": {"baseline": {"templates": ["nope"]}}})
    assert message == "generators.baseline.templates: unknown template 'nope'"


def test_unknown_type_and_bad_params() -> None:
    raw = {
        "templates": {"t": invoice({"a": "nope"}, "x {{ a.raw }} y")},
        "generators": {"baseline": {"templates": ["t"]}, "fragmentation": {"templates": ["t"]}},
    }
    assert config_error(raw) == "templates.t.canaries.a: unknown type 'nope'"
    raw["templates"] = {"t": invoice({"a": {"type": "card", "brand": "x"}}, "x {{ a.raw }} y")}
    assert config_error(raw).startswith("templates.t.canaries.a: brand: expected one of")


def test_too_few_values() -> None:
    message = config_error(
        {
            "canary_types": {"cid": {"values": ["CUST-0001"]}},
            "templates": {"t": invoice({"a": "cid", "b": "cid"}, "{{ a.raw }} and {{ b.raw }}")},
            "generators": {"baseline": {"templates": ["t"]}, "fragmentation": {"templates": ["t"]}},
        }
    )
    assert message.startswith("templates.t.canaries.b: ")
    assert "fewer values than instances" in message


def test_substring_conflict_is_a_config_error() -> None:
    message = config_error(
        {
            "canary_types": {"country": {"schema": {"type": "string", "pattern": "^DE$"}}},
            "templates": {
                "t": invoice({"i": "iban", "c": "country"}, "iban {{ i.raw }} in {{ c.raw }}")
            },
            "generators": {"baseline": {"templates": ["t"]}, "fragmentation": {"templates": ["t"]}},
        }
    )
    assert message.startswith("templates.t.canaries.c: ")
    assert re.search(r"overlaps with 'DE\d{20}'", message)


def test_pool_values_overlapping_across_types_is_a_config_error() -> None:
    message = config_error(
        {
            "canary_types": {
                "cid_a": {"values": ["CUST-1"]},
                "cid_b": {"values": ["CUST-12"]},
            },
            "templates": {
                "t": invoice({"a": "cid_a", "b": "cid_b"}, "id {{ a.raw }} and {{ b.raw }}")
            },
            "generators": {"baseline": {"templates": ["t"]}, "fragmentation": {"templates": ["t"]}},
        }
    )
    assert message == (
        "canary_types.cid_a.values: 'CUST-1' is contained in 'CUST-12' "
        "(canary_types.cid_b.values); canary values must not contain each other"
    )


def test_pool_values_overlapping_within_one_pool_is_a_config_error_for_every_seed() -> None:
    raw = {
        "canary_types": {"cid": {"values": ["ORD-7", "ORD-77", "ORD-8"]}},
        "templates": {"t": invoice({"a": "cid"}, "id {{ a.raw }}")},
        "generators": {"baseline": {"templates": ["t"]}, "fragmentation": {"templates": ["t"]}},
    }
    expected = (
        "canary_types.cid.values: 'ORD-7' is contained in 'ORD-77' "
        "(canary_types.cid.values); canary values must not contain each other"
    )
    for seed in range(5):
        with pytest.raises(ConfigError) as exc:
            prepare(parse(raw), seed=seed)
        assert str(exc.value) == expected


def test_overlapping_pool_unused_in_this_run_is_not_checked() -> None:
    raw = {
        "canary_types": {"cid": {"values": ["ORD-7", "ORD-77"]}},
        "templates": {"t": invoice({"a": "email", "spare": "cid"}, "mail {{ a.raw }}")},
        "generators": {"baseline": {"templates": ["t"]}, "fragmentation": {"templates": ["t"]}},
    }
    assert [c.name for c in prepare(parse(raw), seed=1).all_canaries()] == ["a"]


def test_values_pool_shared_by_several_templates_prepares_for_every_seed() -> None:
    config = parse(
        {
            "canary_types": {
                "cid": {"values": ["CUST-AAAA01", "CUST-BBBB02", "CUST-CCCC03", "CUST-DDDD04"]}
            },
            "templates": {
                "a": invoice({"x": "cid"}, "id {{ x.raw }}"),
                "b": invoice({"y": "cid"}, "id {{ y.raw }}"),
            },
            "generators": {
                "baseline": {"templates": ["a", "b"]},
                "fragmentation": {"templates": ["a", "b"]},
            },
        }
    )
    for seed in range(50):
        prepared = prepare(config, seed=seed)
        values = [c.value for c in prepared.all_canaries()]
        assert len(values) == 2
        assert len(set(values)) == 2, f"seed {seed}: {values}"


def test_pool_exhausted_by_other_templates() -> None:
    message = config_error(
        {
            "canary_types": {"cid": {"values": ["CUST-AAAA01"]}},
            "templates": {
                "a": invoice({"x": "cid"}, "id {{ x.raw }}"),
                "b": invoice({"y": "cid"}, "id {{ y.raw }}"),
            },
            "generators": {
                "baseline": {"templates": ["a", "b"]},
                "fragmentation": {"templates": ["a", "b"]},
            },
        }
    )
    assert message == (
        "templates.b.canaries.y: no value left that is unused and does not overlap other run values"
    )


def first_draw_is_empty(seed: int) -> bool:
    return PatternGenerator("^[A-Z]*$")(instance_rng(seed, "t", "a")) == ""


def test_generated_value_is_never_empty() -> None:
    raw = {
        "canary_types": {"code": {"schema": {"type": "string", "pattern": "^[A-Z]*$"}}},
        "templates": {"t": invoice({"a": "code"}, "code {{ a.raw }}")},
        "generators": {"baseline": {"templates": ["t"]}, "fragmentation": {"enabled": False}},
    }
    seeds = [seed for seed in range(300) if first_draw_is_empty(seed)]
    assert seeds, "no seed in range draws an empty first value; widen the range"
    for seed in seeds:
        assert prepare(parse(raw), seed=seed).templates["t@openai-chat"].raw()["a"] != ""


@pytest.mark.parametrize("pattern", ["^a{0}$", "^(|)$"])
def test_pattern_that_only_matches_empty_is_a_config_error(pattern: str) -> None:
    raw = {
        "canary_types": {"code": {"schema": {"type": "string", "pattern": pattern}}},
        "templates": {"t": invoice({"a": "code"}, "code {{ a.raw }}")},
        "generators": {"baseline": {"templates": ["t"]}, "fragmentation": {"enabled": False}},
    }
    assert config_error(raw) == "templates.t.canaries.a: cannot generate a non-empty value"


@pytest.mark.parametrize("generator", ["baseline", "fragmentation"])
def test_unknown_template_under_disabled_generator(generator: str) -> None:
    raw = {"generators": {generator: {"enabled": False, "templates": ["nope"]}}}
    assert config_error(raw) == f"generators.{generator}.templates: unknown template 'nope'"


def test_templates_under_disabled_generator_are_not_assigned() -> None:
    raw = {
        "templates": {"t": invoice({"a": "email"}, "mail {{ a.raw }}")},
        "generators": {"fragmentation": {"enabled": False, "templates": ["t"]}},
    }
    assert list(prepare(parse(raw), seed=1).templates) == [
        "default@openai-chat",
        "tool-calls@openai-chat",
        "multi-turn@openai-chat",
    ]


def test_unused_instance_with_unknown_type_is_a_config_error() -> None:
    raw = {
        "templates": {"t": invoice({"a": "email", "spare": "nope"}, "mail {{ a.raw }} now")},
        "generators": {"baseline": {"templates": ["t"]}, "fragmentation": {"templates": ["t"]}},
    }
    assert config_error(raw) == "templates.t.canaries.spare: unknown type 'nope'"


def test_unreferenced_template_with_bad_param_is_a_config_error() -> None:
    raw = {
        "templates": {
            "unused": invoice({"a": {"type": "card", "brand": "bogus"}}, "card {{ a.raw }}")
        },
    }
    assert config_error(raw).startswith("templates.unused.canaries.a: brand: expected one of")


def test_fragmentation_only_template_is_bound_when_baseline_disabled() -> None:
    config = parse(
        {
            "templates": {"t": invoice({"a": "email"}, "mail {{ a.raw }} now")},
            "generators": {
                "baseline": {"enabled": False},
                "fragmentation": {"templates": ["t"]},
            },
        }
    )
    prepared = prepare(config, seed=1)
    assert "t@openai-chat" in prepared.templates
    assert prepared.templates["t@openai-chat"].raw().keys() == {"a"}


def test_pool_instance_value_is_independent_of_a_differently_typed_sibling() -> None:
    canary_types = {"cid": {"values": ["ID-100", "ID-200", "ID-300"]}}
    solo = parse(
        {
            "canary_types": canary_types,
            "templates": {"t": invoice({"a": "cid"}, "id {{ a.raw }}")},
            "generators": {"baseline": {"templates": ["t"]}, "fragmentation": {"templates": ["t"]}},
        }
    )
    with_sibling = parse(
        {
            "canary_types": canary_types,
            "templates": {
                "t": invoice({"b": "email", "a": "cid"}, "mail {{ b.raw }} id {{ a.raw }}")
            },
            "generators": {"baseline": {"templates": ["t"]}, "fragmentation": {"templates": ["t"]}},
        }
    )
    solo_value = prepare(solo, seed=3).templates["t@openai-chat"].raw()["a"]
    sibling_value = prepare(with_sibling, seed=3).templates["t@openai-chat"].raw()["a"]
    assert solo_value == sibling_value


def test_fragmentation_guard_is_a_config_error() -> None:
    raw = {
        "templates": {
            "t": {
                **invoice({"a": "email"}, "mail {{ a.raw }} now"),
                "response": {"choices": [{"message": {"content": "no slot"}}]},
            }
        },
        "generators": {"baseline": {"templates": ["t"]}, "fragmentation": {"templates": ["t"]}},
    }
    assert config_error(raw).startswith("templates.t@openai-chat: the streamed content")


def test_template_errors_become_config_errors() -> None:
    raw = {"templates": {"t": invoice({"a": "email"}, "{{ a.masked }}")}}
    assert (
        config_error(raw)
        == "templates.t.request.messages[0].content: .masked is only allowed in the response"
    )


@pytest.mark.parametrize("generator", ["baseline", "fragmentation"])
def test_template_without_request_instance_is_a_config_error(generator: str) -> None:
    other = "fragmentation" if generator == "baseline" else "baseline"
    raw = {
        "templates": {
            "t": {
                "protocol": "openai-chat",
                "canaries": {"a": "email"},
                "request": {"messages": [{"role": "user", "content": "hello"}]},
                "response": {"choices": [{"message": {"content": "hi"}}]},
            }
        },
        "generators": {generator: {"templates": ["t"]}, other: {"enabled": False}},
    }
    assert config_error(raw) == "templates.t: no canary instance is used in the request"


def test_request_instance_without_response_slot_is_allowed() -> None:
    raw = {
        "templates": {
            "t": {
                "protocol": "openai-chat",
                "canaries": {"a": "email"},
                "request": {"messages": [{"role": "user", "content": "mail {{ a.raw }} now"}]},
                "response": {"choices": [{"message": {"content": "done"}}]},
            }
        },
        "generators": {"baseline": {"templates": ["t"]}, "fragmentation": {"enabled": False}},
    }
    assert [c.name for c in prepare(parse(raw), seed=1).all_canaries()] == ["a"]


def test_unimportable_generator_fails_in_prepare_with_full_key_path() -> None:
    raw = {
        "canary_types": {"loyalty": {"generator": "nomodule_xyz:make"}},
        "templates": {"t": invoice({"a": "loyalty"}, "card {{ a.raw }}")},
    }
    assert config_error(raw).startswith(
        "templates.t.canaries.a: canary_types.loyalty.generator: cannot load nomodule_xyz:make"
    )


def test_fault_templates_are_prepared_when_faults_run() -> None:
    raw = {
        "templates": {"t": invoice({"a": "email"}, "mail {{ a.raw }}")},
        "faults": [{"name": "f", "before": "true", "after": "true"}],
        "generators": {"fault": {"templates": ["t"]}},
    }
    assert "t@openai-chat" in prepare(parse(raw), seed=1).templates


def test_fault_templates_without_faults_are_checked_not_prepared() -> None:
    assert config_error({"generators": {"fault": {"templates": ["nope"]}}}) == (
        "generators.fault.templates: unknown template 'nope'"
    )
    raw = {
        "templates": {"t": invoice({"a": "email"}, "mail {{ a.raw }}")},
        "generators": {"fault": {"templates": ["t"]}},
    }
    assert prepare(parse(raw), seed=1).bound("t") == []


CLAUDE = {"name": "claude", "protocol": "anthropic-messages", "path": "/v1/messages"}
TWO_ROUTES = [{"protocol": "openai-chat", "path": "/v1/chat/completions"}, CLAUDE]


def neutral(canaries: dict[str, Any], content: str) -> dict[str, Any]:
    return {
        "canaries": canaries,
        "request": {"messages": [{"role": "user", "content": content}]},
        "response": {"content": content.replace(".raw", ".masked")},
    }


def test_neutral_template_binds_to_every_route_sharing_its_canaries() -> None:
    config = parse(
        {
            "target": {"routes": TWO_ROUTES},
            "templates": {"t": neutral({"a": "email"}, "mail {{ a.raw }} now")},
            "generators": {"baseline": {"templates": ["t"]}, "fragmentation": {"enabled": False}},
        }
    )
    prepared = prepare(config, seed=1)
    assert list(prepared.templates) == ["t@openai-chat", "t@claude"]
    chat, claude = prepared.bound("t")
    assert (chat.name, chat.label, claude.name, claude.label) == (
        "t",
        "t@openai-chat",
        "t",
        "t@claude",
    )
    assert chat.canaries is claude.canaries
    assert (chat.template.protocol, claude.template.protocol) == (
        "openai-chat",
        "anthropic-messages",
    )
    assert claude.template.response["content"][0]["text"] == "mail {{ a.masked }} now"
    assert (chat.module.__name__, claude.module.__name__) == (
        "canarywire.runner.protocols.openai",
        "canarywire.runner.protocols.anthropic",
    )
    assert claude.route.path == "/v1/messages"
    assert [c.name for c in prepared.all_canaries()] == ["a"]


def test_values_do_not_depend_on_the_routes() -> None:
    raw: dict[str, Any] = {
        "templates": {"t": neutral({"a": "email"}, "mail {{ a.raw }} now")},
        "generators": {"baseline": {"templates": ["t", "default"]}},
    }
    one = prepare(parse(raw), seed=4)
    two = prepare(parse({**raw, "target": {"routes": TWO_ROUTES}}), seed=4)
    assert one.all_canaries() == two.all_canaries()


def test_raw_template_binds_only_to_routes_of_its_protocol() -> None:
    config = parse(
        {
            "target": {"routes": TWO_ROUTES},
            "templates": {"t": invoice({"a": "email"}, "mail {{ a.raw }} now")},
            "generators": {"baseline": {"templates": ["t", "default"]}},
        }
    )
    assert list(prepare(config, seed=1).templates)[:3] == [
        "t@openai-chat",
        "default@openai-chat",
        "default@claude",
    ]


def test_raw_template_without_a_route_of_its_protocol_is_a_config_error() -> None:
    raw = {
        "templates": {
            "t": {
                "protocol": "anthropic-messages",
                "canaries": {"a": "email"},
                "request": {"messages": [{"role": "user", "content": "mail {{ a.raw }}"}]},
                "response": {"content": [{"type": "text", "text": "to {{ a.masked }}"}]},
            }
        },
        "generators": {"baseline": {"templates": ["t"]}, "fragmentation": {"enabled": False}},
    }
    assert config_error(raw) == (
        "generators.baseline.templates: template t has protocol anthropic-messages "
        "but no route serves it"
    )


def test_streamed_content_is_checked_per_route() -> None:
    raw = {
        "target": {"routes": [CLAUDE]},
        "templates": {
            "t": {
                "canaries": {"a": "email"},
                "request": {"messages": [{"role": "user", "content": "mail {{ a.raw }}"}]},
                "response": {
                    "content": None,
                    "tool_calls": [
                        {"id": "c1", "name": "send", "arguments": {"to": "{{ a.masked }}"}}
                    ],
                },
            }
        },
        "generators": {"baseline": {"templates": ["t"]}, "fragmentation": {"templates": ["t"]}},
    }
    assert config_error(raw).startswith(
        "templates.t@claude: the streamed content (content[0].text)"
    )
