"""Loopback traffic never goes through a proxy from the environment.

CI runners often set `HTTP(S)_PROXY` without exempting localhost; neither httpx nor websockets
exempts it on its own. Traffic to other hosts (a remote gateway, a tunnelled capture) still
honours the environment.
"""

from __future__ import annotations

LOOPBACK_HOSTS = ("localhost", "127.0.0.1", "::1")
# An httpx mount of None means "the client's own transport", which has no proxy.
DIRECT_MOUNTS: dict[str, None] = {
    f"all://{f'[{host}]' if ':' in host else host}": None for host in LOOPBACK_HOSTS
}


def is_loopback(host: str | None) -> bool:
    """True for the loopback host names that bypass proxies (`::1` without brackets)."""
    return host in LOOPBACK_HOSTS
