import pytest

from canarywire.values.checksums import (
    iban_check_digits,
    luhn_check_digit,
    luhn_valid,
    mod11_check_digit,
    mod11_valid,
    mod97_valid,
)


@pytest.mark.parametrize("value", ["4111111111111111", "79927398713", "3782 822463 10005"])
def test_luhn_valid(value: str) -> None:
    assert luhn_valid(value)


@pytest.mark.parametrize("value", ["4111111111111112", "", "1", "4111-1111", "abcd"])
def test_luhn_invalid(value: str) -> None:
    assert not luhn_valid(value)


def test_luhn_check_digit_round_trip() -> None:
    assert luhn_check_digit("7992739871") == "3"
    for payload in ("400000123456789", "55555512345678", "37828212345678"):
        assert luhn_valid(payload + luhn_check_digit(payload))


@pytest.mark.parametrize(
    "value",
    ["DE89370400440532013000", "GB82WEST12345698765432", "DE89 3704 0044 0532 0130 00"],
)
def test_mod97_valid(value: str) -> None:
    assert mod97_valid(value)


@pytest.mark.parametrize("value", ["DE89370400440532013001", "DE8", "DE89-3704"])
def test_mod97_invalid(value: str) -> None:
    assert not mod97_valid(value)


def test_iban_check_digits() -> None:
    assert iban_check_digits("DE", "370400440532013000") == "89"
    assert iban_check_digits("GB", "WEST12345698765432") == "82"


def test_mod11() -> None:
    assert mod11_check_digit("1234567890") == "3"
    assert mod11_valid("12345678903")
    assert mod11_valid("12 345 678 903")
    assert not mod11_valid("12345678904")
    assert not mod11_valid("1234567890")
