import random
import re

import pytest

from canarywire.values.builtins import BUILTINS
from canarywire.values.checksums import luhn_valid, mod11_valid, mod97_valid
from canarywire.values.errors import CanaryTypeError
from canarywire.values.formats import FORMATS, generate_format


def values(type_name: str, **params: str) -> list[str]:
    builtin = BUILTINS[type_name]
    resolved = builtin.resolve(params)
    return [builtin.make(random.Random(seed), resolved) for seed in range(100)]  # noqa: S311


@pytest.mark.parametrize(
    ("type_name", "params", "pattern"),
    [
        ("email", {}, r"[a-z]+\.[a-z]+\d{4}@example\.org"),
        ("email", {"domain": "corp.example"}, r"[a-z]+\.[a-z]+\d{4}@corp\.example"),
        ("phone", {}, r"\+120255501\d{2}"),
        ("phone", {"format": "national"}, r"\(202\) 555-01\d{2}"),
        ("phone", {"region": "uk"}, r"\+447700900\d{3}"),
        ("phone", {"region": "uk", "format": "national"}, r"07700 900\d{3}"),
        ("phone", {"region": "de"}, r"\+49301234\d{5}"),
        ("phone", {"region": "de", "format": "national"}, r"030 1234\d{5}"),
        ("phone", {"region": "fr"}, r"\+33199\d{6}"),
        ("phone", {"region": "fr", "format": "national"}, r"01 99 \d{2} \d{2} \d{2}"),
        ("iban", {}, r"DE\d{20}"),
        ("iban", {"country": "fr"}, r"FR\d{25}"),
        ("iban", {"country": "gb"}, r"GB\d{2}[A-Z]{4}\d{14}"),
        ("iban", {"country": "nl"}, r"NL\d{2}[A-Z]{4}\d{10}"),
        ("iban", {"country": "es"}, r"ES\d{22}"),
        ("iban", {"format": "grouped"}, r"DE\d{2}( \d{4}){4} \d{2}"),
        ("card", {}, r"400000\d{10}"),
        ("card", {"brand": "mastercard"}, r"555555\d{10}"),
        ("card", {"brand": "amex"}, r"378282\d{9}"),
        ("card", {"format": "grouped"}, r"4000 00\d{2} \d{4} \d{4}"),
        ("card", {"brand": "amex", "format": "grouped"}, r"3782 82\d{4} \d{5}"),
        ("national_id", {}, r"\d{3}-\d{2}-\d{4}"),
        ("national_id", {"format": "compact"}, r"\d{9}"),
        ("national_id", {"country": "uk"}, r"[A-Z]{2} \d{2} \d{2} \d{2} [A-D]"),
        ("national_id", {"country": "uk", "format": "compact"}, r"[A-Z]{2}\d{6}[A-D]"),
        ("national_id", {"country": "de"}, r"[1-9]\d \d{3} \d{3} \d{3}"),
        ("national_id", {"country": "de", "format": "compact"}, r"[1-9]\d{10}"),
    ],
)
def test_formats(type_name: str, params: dict[str, str], pattern: str) -> None:
    for value in values(type_name, **params):
        assert re.fullmatch(pattern, value), value


@pytest.mark.parametrize("country", ["de", "fr", "gb", "nl", "es"])
def test_iban_check_digits_are_valid(country: str) -> None:
    for fmt in ("compact", "grouped"):
        assert all(mod97_valid(v) for v in values("iban", country=country, format=fmt))


@pytest.mark.parametrize("brand", ["visa", "mastercard", "amex"])
def test_cards_pass_luhn(brand: str) -> None:
    for fmt in ("compact", "grouped"):
        assert all(luhn_valid(v) for v in values("card", brand=brand, format=fmt))


def test_ssn_rules() -> None:
    for value in values("national_id"):
        area, group, serial = value.split("-")
        assert area not in ("000", "666")
        assert int(area) < 900
        assert group != "00"
        assert serial != "0000"


def test_nino_prefix_rules() -> None:
    excluded = {"BG", "GB", "KN", "NK", "NT", "TN", "ZZ"}
    for value in values("national_id", country="uk", format="compact"):
        assert value[:2] not in excluded
        assert value[0] not in "DFIQUV"
        assert value[1] not in "DFIOQUV"


def test_de_tax_id_passes_mod11() -> None:
    assert all(mod11_valid(v) for v in values("national_id", country="de"))


def test_de_tax_id_structure() -> None:
    builtin = BUILTINS["national_id"]
    resolved = builtin.resolve({"country": "de", "format": "compact"})
    counts_seen = set()
    for seed in range(2000):
        value = builtin.make(random.Random(seed), resolved)  # noqa: S311 - test seed
        assert mod11_valid(value), value
        body = value[:10]
        assert body[0] != "0", value
        counts = sorted((body.count(d) for d in set(body)), reverse=True)
        assert counts[0] in (2, 3), value
        assert all(c == 1 for c in counts[1:]), value
        assert len(set(body)) < 10, value
        repeated = next(d for d in set(body) if body.count(d) > 1)
        assert repeated * 3 not in body, value
        counts_seen.add(counts[0])
    assert counts_seen == {2, 3}


def test_deterministic() -> None:
    assert values("iban") == values("iban")


@pytest.mark.parametrize(
    ("type_name", "params", "message"),
    [
        ("card", {"colour": "red"}, "colour: unknown parameter for type card"),
        ("card", {"brand": "diners"}, "brand: expected one of visa, mastercard, amex"),
        ("phone", {"region": 1}, "region: expected a string"),
        ("email", {"domain": "not a domain"}, "domain: expected a hostname like example.org"),
        ("email", {"domain": "-bad.example"}, "domain: expected a hostname like example.org"),
        ("email", {"domain": "localhost"}, "domain: expected a hostname like example.org"),
    ],
)
def test_parameter_errors(type_name: str, params: dict[str, object], message: str) -> None:
    with pytest.raises(CanaryTypeError, match=re.escape(message)):
        BUILTINS[type_name].resolve(params)


@pytest.mark.parametrize(
    ("name", "pattern"),
    [
        ("email", r"[a-z]+\.[a-z]+\d{4}@example\.org"),
        ("uuid", r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"),
        ("date", r"\d{4}-\d{2}-\d{2}"),
        ("date-time", r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"),
        ("ipv4", r"198\.51\.100\.\d{1,3}"),
        ("ipv6", r"2001:db8:[0-9a-f]{1,4}::[0-9a-f]{1,4}"),
    ],
)
def test_json_schema_formats(name: str, pattern: str) -> None:
    assert name in FORMATS
    for seed in range(50):
        assert re.fullmatch(pattern, generate_format(name, random.Random(seed)))  # noqa: S311
