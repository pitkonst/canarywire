import json as json_module
from typing import Any
from urllib.parse import unquote_plus

from canarywire.canaries import Canary
from canarywire.report.findings import leak_excerpt
from canarywire.runner.messages import UpstreamRequest
from canarywire.runner.scan import Hit, scan

EMAIL = Canary("email", "ann.lee1234@example.org")


def request(
    *,
    path: str = "/v1/chat/completions",
    query: str = "",
    headers: tuple[tuple[str, str], ...] = (),
    body: str = "",
    json: Any = None,
) -> UpstreamRequest:
    return UpstreamRequest("u1", "POST", path, query, headers, body, json)


def test_no_hit() -> None:
    assert scan([EMAIL], request(body="{}", json={})) == []


def test_hit_in_json_body_path() -> None:
    text = f"mail {EMAIL.value}"
    doc = {"messages": [{"content": text}]}
    assert scan([EMAIL], request(body="...", json=doc)) == [
        Hit(
            "email",
            EMAIL.value,
            "body.messages[0].content",
            excerpt=leak_excerpt(text, EMAIL.value),
        )
    ]


NUMBER = Canary("acct", "554433221")


def test_hit_only_in_raw_json_is_reported_at_body() -> None:
    # The value is a JSON number, not a string value or a key, so only the raw-body
    # fallback can find it.
    raw = f'{{"balance": {NUMBER.value}}}'
    assert scan([NUMBER], request(body=raw, json={"balance": 554433221})) == [
        Hit("acct", NUMBER.value, "body", excerpt=leak_excerpt(raw, NUMBER.value))
    ]


def test_hit_in_top_level_json_key() -> None:
    raw = f'{{"{EMAIL.value}": 1}}'
    assert scan([EMAIL], request(body=raw, json={EMAIL.value: 1})) == [
        Hit("email", EMAIL.value, "body{key}", excerpt=leak_excerpt(EMAIL.value, EMAIL.value))
    ]


def test_hit_in_nested_json_key() -> None:
    doc = {"metadata": {EMAIL.value: True}}
    assert scan([EMAIL], request(body="x", json=doc)) == [
        Hit(
            "email",
            EMAIL.value,
            "body.metadata{key}",
            excerpt=leak_excerpt(EMAIL.value, EMAIL.value),
        )
    ]


def test_hit_in_json_key_with_unicode_escape() -> None:
    name = Canary("name", "Jürgen", "customer", "t")
    doc = {name.value: "ok"}
    body = json_module.dumps(doc)  # ensure_ascii escapes the key
    assert name.value not in body
    assert scan([name], request(body=body, json=doc)) == [
        Hit(
            "name",
            name.value,
            "body{key}",
            "t",
            "customer",
            leak_excerpt(name.value, name.value),
        )
    ]


def test_hit_in_json_key_with_unicode_escaped_at_sign() -> None:
    key_raw = EMAIL.value.replace("@", "\\u0040")
    body = f'{{"{key_raw}": true}}'
    doc = {EMAIL.value: True}
    assert EMAIL.value not in body
    assert scan([EMAIL], request(body=body, json=doc)) == [
        Hit("email", EMAIL.value, "body{key}", excerpt=leak_excerpt(EMAIL.value, EMAIL.value))
    ]


def test_hit_in_quote_escaped_json_key() -> None:
    name = Canary("name", 'Jürgen "Q7X41"', "customer", "t")
    doc = {name.value: 1}
    body = json_module.dumps(doc)
    assert name.value not in body
    assert scan([name], request(body=body, json=doc)) == [
        Hit(
            "name",
            name.value,
            "body{key}",
            "t",
            "customer",
            leak_excerpt(name.value, name.value),
        )
    ]


def test_hit_in_json_key_inside_a_decoded_json_string() -> None:
    name = Canary("name", 'Jürgen "Q7X41"', "customer", "t")
    inner = json_module.dumps({name.value: 1})
    assert name.value not in inner  # escaped, not visible in the encoded string
    doc = {"metadata": inner}
    assert scan([name], request(body="x", json=doc)) == [
        Hit(
            "name",
            name.value,
            "body.metadata${key}",
            "t",
            "customer",
            leak_excerpt(name.value, name.value),
        )
    ]


def test_key_visible_in_encoded_string_is_reported_once_there() -> None:
    text = json_module.dumps({EMAIL.value: True})
    doc = {"a": text}
    assert scan([EMAIL], request(body="x", json=doc)) == [
        Hit("email", EMAIL.value, "body.a", excerpt=leak_excerpt(text, EMAIL.value))
    ]


def test_hit_in_non_json_body() -> None:
    body = f"to={EMAIL.value}"
    assert scan([EMAIL], request(body=body)) == [
        Hit("email", EMAIL.value, "body", excerpt=leak_excerpt(body, EMAIL.value))
    ]


def test_hit_in_header() -> None:
    hits = scan([EMAIL], request(headers=(("x-user", EMAIL.value),)))
    assert hits == [
        Hit(
            "email",
            EMAIL.value,
            "headers.x-user",
            excerpt=leak_excerpt(EMAIL.value, EMAIL.value),
        )
    ]


def test_hit_in_percent_encoded_query() -> None:
    query = "to=ann.lee1234%40example.org"
    hits = scan([EMAIL], request(query=query))
    url = "/v1/chat/completions" + f"?{query}"
    assert hits == [
        Hit("email", EMAIL.value, "url", excerpt=leak_excerpt(unquote_plus(url), EMAIL.value))
    ]


def test_hits_carry_their_own_template_and_type() -> None:
    card = Canary("cc", "4111111111111111", "corporate_card", "cards")
    email = Canary("email", "ann.lee1234@example.org", "email", "default")
    text = f"{email.value} pays with {card.value}"
    doc = {"messages": [{"content": text}]}
    hits = scan([email, card], request(body="...", json=doc))
    assert hits == [
        Hit(
            "email",
            email.value,
            "body.messages[0].content",
            "default",
            "email",
            leak_excerpt(text, email.value),
        ),
        Hit(
            "cc",
            card.value,
            "body.messages[0].content",
            "cards",
            "corporate_card",
            leak_excerpt(text, card.value),
        ),
    ]


NAME = Canary("name", 'Jürgen "Q7X41"', "customer", "t")


def escaped_request() -> UpstreamRequest:
    arguments = json_module.dumps({"customer": NAME.value})  # ensure_ascii escapes ü and "
    doc = {"messages": [{"tool_calls": [{"function": {"arguments": arguments}}]}]}
    return request(body=json_module.dumps(doc), json=doc)


def test_hit_inside_an_escaped_json_string() -> None:
    assert NAME.value not in escaped_request().body
    assert scan([NAME], escaped_request()) == [
        Hit(
            "name",
            NAME.value,
            "body.messages[0].tool_calls[0].function.arguments$.customer",
            "t",
            "customer",
            leak_excerpt(NAME.value, NAME.value),
        )
    ]


def test_hit_inside_nested_json_strings() -> None:
    inner = json_module.dumps({"v": NAME.value})
    doc = {"a": json_module.dumps({"b": inner})}
    assert [hit.location for hit in scan([NAME], request(body="x", json=doc))] == ["body.a$.b$.v"]


def test_unescaped_hit_in_a_json_string_is_reported_once_at_the_string() -> None:
    text = json_module.dumps({"b": EMAIL.value})
    doc = {"a": text}
    assert scan([EMAIL], request(body="x", json=doc)) == [
        Hit("email", EMAIL.value, "body.a", excerpt=leak_excerpt(text, EMAIL.value))
    ]


def test_key_hit_location_never_leaks_a_value_hiding_in_an_ancestor_key() -> None:
    doc = {EMAIL.value: {EMAIL.value: 1}}
    hits = scan([EMAIL], request(body="x", json=doc))
    assert all(EMAIL.value not in hit.location for hit in hits)
    assert [hit.location for hit in hits] == ["body{key}", "body.{key}{key}"]


def test_value_hit_location_never_leaks_a_value_hiding_in_an_ancestor_key() -> None:
    doc = {EMAIL.value: {"note": f"x {EMAIL.value}"}}
    hits = scan([EMAIL], request(body="x", json=doc))
    assert all(EMAIL.value not in hit.location for hit in hits)
    assert [hit.location for hit in hits] == ["body.{key}.note", "body{key}"]


def test_two_leaking_keys_in_one_object_dedupe_to_one_hit() -> None:
    doc = {f"primary {EMAIL.value}": 1, f"secondary {EMAIL.value}": 2}
    hits = scan([EMAIL], request(body="x", json=doc))
    assert [hit.location for hit in hits] == ["body{key}"]
