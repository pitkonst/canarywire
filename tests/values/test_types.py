import random
import re

import pytest

from canarywire.values.checksums import luhn_valid, mod97_valid
from canarywire.values.errors import CanaryTypeError
from canarywire.values.types import CustomType, make_source, parse_custom_types


def draw(source_type: str, params: dict[str, object] | None = None, **custom: object) -> str:
    types = parse_custom_types(custom)
    source = make_source(source_type, params or {}, types)
    assert source.draw is not None
    return source.draw(random.Random(3))  # noqa: S311 - test seed, not security


def test_values_type() -> None:
    types = parse_custom_types({"customer_id": {"values": ["CUST-1", "CUST-2"]}})
    assert types["customer_id"] == CustomType("customer_id", values=("CUST-1", "CUST-2"))
    assert make_source("customer_id", {}, types).pool == ("CUST-1", "CUST-2")


def test_pattern_type_with_luhn() -> None:
    value = draw(
        "corporate_card",
        corporate_card={
            "schema": {"type": "string", "pattern": "^4[0-9]{15}$"},
            "checksum": "luhn",
        },
    )
    assert re.fullmatch(r"4\d{15}", value)
    assert luhn_valid(value)


def test_format_type() -> None:
    value = draw("work_email", work_email={"schema": {"type": "string", "format": "email"}})
    assert value.endswith("@example.org")


def test_generator_type_with_params() -> None:
    value = draw(
        "loyalty_no",
        {"tier": "gold"},
        loyalty_no={"generator": "sample_generators:loyalty"},
    )
    assert re.fullmatch(r"LOY-GOLD-\d{6}", value)


def test_entry_point_checksum() -> None:
    value = draw(
        "code",
        code={
            "schema": {"type": "string", "pattern": "^[A-Z]{1,6}$"},
            "checksum": "sample_generators:is_even_length",
        },
    )
    assert len(value) % 2 == 0


def test_builtin_through_make_source() -> None:
    source = make_source("card", {"brand": "amex"}, {})
    assert source.draw is not None
    assert source.draw(random.Random(1)).startswith("378282")  # noqa: S311 - test seed, not security


def test_mod97_pattern_type() -> None:
    value = draw(
        "iban_like",
        iban_like={"schema": {"type": "string", "pattern": "^DE[0-9]{20}$"}, "checksum": "mod97"},
    )
    assert re.fullmatch(r"DE\d{20}", value)
    assert mod97_valid(value)


P = "canary_types"


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ([], f"{P}: expected a mapping"),
        ({"bad name": {"values": ["a"]}}, f"{P}.bad name: expected a name like customer_id"),
        ({"email": {"values": ["a"]}}, f"{P}.email: is a built-in type name"),
        ({"t": "x"}, f"{P}.t: expected a mapping"),
        ({"t": {"values": ["a"], "extra": 1}}, f"{P}.t.extra: unknown key"),
        ({"t": {}}, f"{P}.t: expected exactly one of values, schema, generator"),
        (
            {"t": {"values": ["a"], "generator": "m:f"}},
            f"{P}.t: expected exactly one of values, schema, generator",
        ),
        ({"t": {"values": []}}, f"{P}.t.values: expected a non-empty list of non-empty strings"),
        (
            {"t": {"values": ["a", ""]}},
            f"{P}.t.values: expected a non-empty list of non-empty strings",
        ),
        ({"t": {"values": ["a", "a"]}}, f"{P}.t.values: duplicate values"),
        (
            {"t": {"values": ["4111111111111111", "4111111111111112"], "checksum": "luhn"}},
            f"{P}.t.values: entries failing luhn: 4111111111111112",
        ),
        ({"t": {"schema": {"pattern": "^a$"}}}, f"{P}.t.schema.type: expected string"),
        (
            {"t": {"schema": {"type": "string"}}},
            f"{P}.t.schema: expected exactly one of pattern, format",
        ),
        (
            {"t": {"schema": {"type": "string", "minLength": 3, "pattern": "^a$"}}},
            f"{P}.t.schema.minLength: unknown key",
        ),
        (
            {"t": {"schema": {"type": "string", "format": "hostname"}}},
            f"{P}.t.schema.format: expected one of email, uuid, date, date-time, ipv4, ipv6",
        ),
        (
            {"t": {"schema": {"type": "string", "pattern": "^(?=a)a$"}}},
            f"{P}.t.schema.pattern: lookahead is not supported",
        ),
        (
            {"t": {"values": ["a"], "checksum": "crc32"}},
            f"{P}.t.checksum: expected one of luhn, mod97, mod11 or package.module:function",
        ),
        ({"t": {"generator": "no-colon"}}, f"{P}.t.generator: expected package.module:function"),
        ({"t": {"generator": ":f"}}, f"{P}.t.generator: expected package.module:function"),
        ({"t": {"generator": 3}}, f"{P}.t.generator: expected package.module:function"),
        (
            {"t": {"values": ["a"], "checksum": None}},
            f"{P}.t.checksum: expected one of luhn, mod97, mod11 or package.module:function",
        ),
        (
            {"t": {"values": ["a"], "checksum": "mod:"}},
            f"{P}.t.checksum: expected one of luhn, mod97, mod11 or package.module:function",
        ),
    ],
)
def test_parse_errors(raw: object, message: str) -> None:
    with pytest.raises(CanaryTypeError, match=f"^{re.escape(message)}"):
        parse_custom_types(raw)


def test_parsing_never_imports_entry_points() -> None:
    types = parse_custom_types(
        {
            "gen": {"generator": "nomodule_xyz:f"},
            "pool": {"values": ["a"], "checksum": "nomodule_xyz:check"},
        }
    )
    assert types["gen"].generator == "nomodule_xyz:f"
    assert types["pool"].checksum == "nomodule_xyz:check"


@pytest.mark.parametrize(
    ("spec", "message"),
    [
        ({"generator": "nomodule_xyz:f"}, f"{P}.t.generator: cannot load nomodule_xyz:f"),
        (
            {"generator": "sample_generators:NOT_CALLABLE"},
            f"{P}.t.generator: sample_generators:NOT_CALLABLE is not callable",
        ),
        (
            {"generator": "broken_import_module:f"},
            f"{P}.t.generator: cannot load broken_import_module:f",
        ),
        (
            {"values": ["a"], "checksum": "nomodule_xyz:f"},
            f"{P}.t.checksum: cannot load nomodule_xyz:f",
        ),
        (
            {"values": ["a"], "checksum": "sample_generators:raising_check"},
            f"{P}.t.checksum: checksum sample_generators:raising_check failed: "
            "RuntimeError('checksum boom')",
        ),
        (
            {"values": ["ab", "abc"], "checksum": "sample_generators:is_even_length"},
            f"{P}.t.values: entries failing sample_generators:is_even_length: abc",
        ),
        (
            {"schema": {"type": "string", "pattern": "^a$"}, "checksum": "nomodule_xyz:f"},
            f"{P}.t.checksum: cannot load nomodule_xyz:f",
        ),
    ],
)
def test_entry_point_errors_surface_in_make_source(spec: dict[str, object], message: str) -> None:
    types = parse_custom_types({"t": spec})
    with pytest.raises(CanaryTypeError, match=f"^{re.escape(message)}"):
        make_source("t", {}, types)


@pytest.mark.parametrize(
    ("spec", "params", "message"),
    [
        ({"generator": "sample_generators:unseeded"}, {}, "is not deterministic for a seed"),
        ({"generator": "sample_generators:not_a_string"}, {}, "must return a non-empty string"),
        ({"generator": "sample_generators:broken"}, {}, "failed: RuntimeError('boom')"),
        (
            {"schema": {"type": "string", "pattern": "^1$"}, "checksum": "luhn"},
            {},
            "cannot generate a value for t that passes luhn",
        ),
        ({"values": ["a"]}, {"x": "y"}, "type t takes no parameters"),
        (
            {
                "schema": {"type": "string", "pattern": "^a$"},
                "checksum": "sample_generators:raising_check",
            },
            {},
            "checksum sample_generators:raising_check failed: RuntimeError('checksum boom')",
        ),
    ],
)
def test_source_errors(spec: dict[str, object], params: dict[str, object], message: str) -> None:
    types = parse_custom_types({"t": spec})
    with pytest.raises(CanaryTypeError, match=re.escape(message)):  # noqa: PT012
        source = make_source("t", params, types)
        if source.draw is not None:
            source.draw(random.Random(0))  # noqa: S311 - test seed, not security


def test_unknown_type() -> None:
    with pytest.raises(CanaryTypeError, match="unknown type 'nope'"):
        make_source("nope", {}, {})
