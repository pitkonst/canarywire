import os
import subprocess
import time
from pathlib import Path

import anyio
import pytest

from canarywire.runner.hooks import run_hook

pytestmark = pytest.mark.anyio


def gone(pid: int) -> bool:
    """The process no longer exists, or is a zombie waiting to be reaped by init."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    state = subprocess.run(  # noqa: S603 - fixed argv, test-only
        ["/bin/ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True, check=False
    ).stdout.strip()
    return state.startswith("Z") or state == ""


async def test_exit_code_log_and_environment(tmp_path: Path) -> None:
    result = await run_hook(
        'echo "$CANARYWIRE_FAULT/$CANARYWIRE_FAULT_HOOK"; echo oops >&2; exit 3',
        fault="down",
        hook="before",
        out_dir=tmp_path,
        timeout=10,
    )
    assert (result.exit, result.timed_out, result.log) == (3, False, "faults/down.before.log")
    assert (tmp_path / result.log).read_text() == "down/before\noops\n"
    assert result.duration_ms >= 0


async def test_success(tmp_path: Path) -> None:
    result = await run_hook("true", fault="f", hook="after", out_dir=tmp_path, timeout=10)
    assert (result.exit, result.timed_out) == (0, False)


async def test_runs_in_the_process_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    await run_hook("touch here", fault="f", hook="after", out_dir=tmp_path / "out", timeout=10)
    assert (tmp_path / "here").exists()


async def test_timeout_kills_the_process_group(tmp_path: Path) -> None:
    marker = tmp_path / "child.pid"
    start = time.monotonic()
    result = await run_hook(
        f"sleep 30 & echo $! > {marker}; wait",
        fault="f",
        hook="before",
        out_dir=tmp_path,
        timeout=0.5,
    )
    assert (result.exit, result.timed_out) == (None, True)
    assert time.monotonic() - start < 5
    await anyio.sleep(0.2)
    assert gone(int(marker.read_text()))


async def test_cancellation_kills_and_propagates(tmp_path: Path) -> None:
    marker = tmp_path / "child.pid"
    with anyio.move_on_after(0.5) as scope:
        await run_hook(
            f"sleep 30 & echo $! > {marker}; wait",
            fault="f",
            hook="before",
            out_dir=tmp_path,
            timeout=30,
        )
    assert scope.cancelled_caught
    await anyio.sleep(0.2)
    assert gone(int(marker.read_text()))
