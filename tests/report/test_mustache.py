"""Tests for the strict Mustache-subset template engine."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from canarywire.report.mustache import TemplateError, parse

SPEC = json.loads((Path(__file__).parents[1] / "support" / "mustache_spec.json").read_text())
# Spec cases whose expected output relies on a missing name rendering empty: strict mode raises.
STRICT_RAISES = {
    ("interpolation", "Basic Context Miss Interpolation"),
    ("interpolation", "Triple Mustache Context Miss Interpolation"),
    ("interpolation", "Ampersand Context Miss Interpolation"),
    ("interpolation", "Dotted Names - Broken Chains"),
    ("interpolation", "Dotted Names - Broken Chain Resolution"),
    ("interpolation", "Dotted Names are never single keys"),
    ("interpolation", "Dotted Names - Context Precedence"),
    ("sections", "Context Misses"),
    ("sections", "Dotted Names - Broken Chains"),
    ("inverted", "Context Misses"),
    ("inverted", "Dotted Names - Broken Chains"),
}
CASES = [pytest.param(t, id=f"{t['file']}: {t['name']}") for t in SPEC["tests"]]


@pytest.mark.parametrize("case", CASES)
def test_spec(case: dict[str, Any]) -> None:
    template = parse(case["template"], "spec")
    if (case["file"], case["name"]) in STRICT_RAISES:
        with pytest.raises(TemplateError, match="unknown name"):
            template.render(case["data"], escape="xml")
    else:
        assert template.render(case["data"], escape="xml") == case["expected"]


def test_strict_raises_list_names_real_cases() -> None:
    names = {(t["file"], t["name"]) for t in SPEC["tests"]}
    assert names >= STRICT_RAISES


def test_null_present_key_renders_empty_and_skips_section() -> None:
    assert parse("[{{a}}]{{#a}}x{{/a}}{{^a}}y{{/a}}", "t").render({"a": None}) == "[]y"


def test_scalar_sections_push_the_scalar() -> None:
    template = parse("{{#s}}{{.}}|{{outer}}{{/s}}", "t")
    assert template.render({"s": "str", "outer": "o"}) == "str|o"
    assert template.render({"s": 7, "outer": "o"}) == "7|o"
    assert template.render({"s": True, "outer": "o"}) == "true|o"


def test_values() -> None:
    assert parse("{{a}} {{b}} {{c}}", "t").render({"a": False, "b": 1.5, "c": 0}) == "false 1.5 0"


def test_list_or_object_interpolation_is_an_error() -> None:
    with pytest.raises(TemplateError, match=r"t:1: .*not a scalar"):
        parse("{{a}}", "t").render({"a": [1]})


def test_escape_none_and_xml() -> None:
    template = parse("{{v}}|{{{v}}}|{{& v}}", "t")
    escaped = "&lt;&#39;&amp;&quot;&gt;|<'&\">|<'&\">"
    assert template.render({"v": "<'&\">"}, escape="xml") == escaped
    assert template.render({"v": "<'&\">"}) == "<'&\">|<'&\">|<'&\">"


@pytest.mark.parametrize(
    ("source", "message"),
    [
        ("a\n{{> part}}", "t:2: unsupported tag"),
        ("{{=<% %>=}}", "t:1: unsupported tag"),
        ("{{$block}}{{/block}}", "t:1: unsupported tag"),
        ("{{<parent}}{{/parent}}", "t:1: unsupported tag"),
        ("{{#a}}\n\nx", 't:1: unclosed section "a"'),
        ("{{#a}}{{/b}}", 't:1: mismatched close "b", expected "a"'),
        ("{{/a}}", 't:1: unexpected close "a"'),
        ("x {{a", "t:1: unclosed tag"),
        ("{{}}", "t:1: empty tag"),
    ],
)
def test_parse_errors(source: str, message: str) -> None:
    with pytest.raises(TemplateError) as info:
        parse(source, "t")
    assert str(info.value).startswith(message)


def test_unknown_name_error_has_line() -> None:
    with pytest.raises(TemplateError, match=r'^t:3: unknown name "leak"$'):
        parse("a\nb\n{{leak}}", "t").render({})


SHAPE = {
    "findings": [{"title": "x", "diff_excerpt": {"expected": "e"}}],
    "untrusted": False,
    "reason": "r",
}


@pytest.mark.parametrize(
    "source",
    [
        "{{^findings}}{{typo}}{{/findings}}",
        "{{#untrusted}}{{typo}}{{/untrusted}}",
        "{{#findings}}{{#diff_excerpt}}{{typo}}{{/diff_excerpt}}{{/findings}}",
        "{{findings}}",
    ],
)
def test_check_walks_both_branches(source: str) -> None:
    with pytest.raises(TemplateError):
        parse(source, "t").check(SHAPE)


def test_check_accepts_valid_names_everywhere() -> None:
    source = (
        "{{^findings}}{{reason}}{{/findings}}{{#untrusted}}{{reason}}{{/untrusted}}"
        "{{#findings}}{{title}}{{#diff_excerpt}}{{expected}}{{title}}{{/diff_excerpt}}{{/findings}}"
    )
    parse(source, "t").check(SHAPE)


def test_dotted_part_on_null_renders_as_null() -> None:
    template = parse("[{{a.b.c}}]{{#a.b}}x{{/a.b}}{{^a.b}}y{{/a.b}}", "t")
    assert template.render({"a": None}) == "[]y"
    assert template.render({"a": {"b": None}}) == "[]y"


def test_dotted_part_on_a_scalar_still_raises() -> None:
    with pytest.raises(TemplateError, match=r't:1: unknown name "a.b"'):
        parse("{{a.b}}", "t").render({"a": "text"})
    with pytest.raises(TemplateError, match=r'unknown name "a.b"'):
        parse("{{a.b}}", "t").render({"a": {"c": 1}})


def test_check_is_still_strict_through_null() -> None:
    with pytest.raises(TemplateError, match=r'unknown name "a.b"'):
        parse("{{a.b}}", "t").check({"a": None})


def test_check_rejects_an_empty_list_in_the_shape() -> None:
    with pytest.raises(TemplateError, match=r'^t:2: shape has an empty list at "items"$'):
        parse("x\n{{#items}}{{name}}{{/items}}", "t").check({"items": []})


def test_xml_escape_replaces_characters_not_allowed_in_xml() -> None:
    text = "a\x01b\x1f\tc\nd\re￾￿\ud800f<"
    rendered = parse("{{v}}", "t").render({"v": text}, escape="xml")
    assert rendered == "a�b�\tc\nd\re���f&lt;"
    assert parse("{{v}}", "t").render({"v": "\x01"}) == "\x01"  # escape none leaves it
