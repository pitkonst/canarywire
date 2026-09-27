from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from harness import E2E, Capture, free_port, is_listening, kill_pidfile


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
async def e2e(tmp_path: Path) -> AsyncIterator[E2E]:
    world = E2E(tmp_path)
    try:
        yield world
    finally:
        await world.aclose()


@pytest.fixture
async def capture(e2e: E2E) -> AsyncIterator[Capture]:
    """`canarywire serve --detach`; teardown always runs `canarywire stop` (post must run)."""
    cap = Capture(free_port())
    try:
        serve = await e2e.canarywire("serve", "--detach", "--listen", f"127.0.0.1:{cap.port}")
        assert serve.returncode == 0, e2e.diagnostics()
        yield cap
    finally:
        stop = await e2e.canarywire("stop")
    # Reached whenever setup succeeded (pytest resumes the generator normally, even after a failed
    # test): a broken `stop` must not pass silently.
    try:
        assert stop.returncode == 0, e2e.diagnostics()
        assert not is_listening(cap.port), (
            "capture still listening after stop\n" + e2e.diagnostics()
        )
    finally:
        # `serve --detach` daemonizes outside this session's process group, so a broken `stop`
        # could otherwise leak it; the asserts above still run and fail first.
        kill_pidfile(e2e.workdir / ".canarywire" / "capture.pid")
