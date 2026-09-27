"""The single runner session and forwarding of upstream requests to it."""

from __future__ import annotations

import contextlib
import math
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from canarywire.rpc import INVALID_PARAMS, ChannelClosedError, RpcError

if TYPE_CHECKING:
    from canarywire.rpc import Peer


class NoRunnerError(Exception):
    """No runner session is active."""


class RunnerLostError(Exception):
    """The runner's socket closed before it answered."""


@dataclass(frozen=True)
class Session:
    """The connected runner: its RPC peer and what it sent in `session.start`."""

    peer: Peer
    run_id: str
    seed: int
    upstream_response_timeout: float

    @classmethod
    def from_params(cls, peer: Peer, params: object) -> Session:
        """Validate `session.start` params; raise RpcError(INVALID_PARAMS) if malformed."""
        if not isinstance(params, dict):
            raise RpcError(INVALID_PARAMS, "params must be an object")
        run_id = params.get("run_id")
        seed = params.get("seed")
        timeout = params.get("upstream_response_timeout")
        if not isinstance(run_id, str) or not run_id:
            raise RpcError(INVALID_PARAMS, "run_id: expected a non-empty string")
        if isinstance(seed, bool) or not isinstance(seed, int):
            raise RpcError(INVALID_PARAMS, "seed: expected an integer")
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, int | float)
            or not math.isfinite(timeout)  # json.loads accepts Infinity and NaN
            or timeout <= 0
        ):
            raise RpcError(
                INVALID_PARAMS, "upstream_response_timeout: expected a finite positive number"
            )
        return cls(peer, run_id, seed, float(timeout))


class Relay:
    """Holds the single active runner session."""

    def __init__(self) -> None:
        """Start with no session."""
        self._session: Session | None = None

    @property
    def session(self) -> Session | None:
        """The active session, if any."""
        return self._session

    def start(self, session: Session) -> None:
        """Make `session` the active one."""
        self._session = session

    def end(self, session: Session) -> None:
        """Forget `session` if it is still the active one."""
        if self._session is session:
            self._session = None


async def forward(session: Session | None, params: dict[str, Any]) -> Any:
    """Ask the runner how to answer an upstream request.

    Raises NoRunnerError, RunnerLostError, TimeoutError or RpcError.
    """
    if session is None:
        raise NoRunnerError
    try:
        return await session.peer.call(
            "upstream.request", params, timeout=session.upstream_response_timeout
        )
    except ChannelClosedError as exc:
        raise RunnerLostError from exc


async def notify_done(session: Session | None, params: dict[str, Any]) -> None:
    """Tell the runner how delivery of its answer ended; ignored if it is gone."""
    if session is None:
        return
    with contextlib.suppress(ChannelClosedError):
        await session.peer.notify("upstream.done", params)
