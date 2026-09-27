from typing import Any, cast

import pytest

from canarywire.capture.relay import Session
from canarywire.rpc import INVALID_PARAMS, Peer, RpcError

PEER = cast("Peer", object())


def test_session_from_params() -> None:
    session = Session.from_params(PEER, {"run_id": "r", "seed": 3, "upstream_response_timeout": 2})
    assert (session.run_id, session.seed, session.upstream_response_timeout) == ("r", 3, 2.0)


@pytest.mark.parametrize(
    "params",
    [
        None,
        {"run_id": "", "seed": 1, "upstream_response_timeout": 1},
        {"run_id": "r", "seed": "1", "upstream_response_timeout": 1},
        {"run_id": "r", "seed": 1, "upstream_response_timeout": 0},
        {"run_id": "r", "seed": 1, "upstream_response_timeout": float("inf")},
        {"run_id": "r", "seed": 1, "upstream_response_timeout": float("nan")},
    ],
)
def test_session_from_params_rejects(params: Any) -> None:
    with pytest.raises(RpcError) as exc:
        Session.from_params(PEER, params)
    assert exc.value.code == INVALID_PARAMS
