import pytest

from canarywire.loopback import DIRECT_MOUNTS, is_loopback


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "::1"])
def test_loopback_hosts(host: str) -> None:
    assert is_loopback(host)


# 127.0.0.2 is loopback too, but httpx mounts name exact hosts: the list stays the three names.
@pytest.mark.parametrize("host", [None, "", "[::1]", "127.0.0.2", "10.0.0.1", "gateway.internal"])
def test_other_hosts_follow_the_environment(host: str | None) -> None:
    assert not is_loopback(host)


def test_direct_mounts_bracket_ipv6() -> None:
    assert DIRECT_MOUNTS == {"all://localhost": None, "all://127.0.0.1": None, "all://[::1]": None}
