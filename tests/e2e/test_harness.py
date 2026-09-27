import os
import sys
from pathlib import Path

import anyio
import pytest
from harness import E2E, ProcessExitedError, free_port, is_listening, kill_pidfile, wait_ready

pytestmark = [pytest.mark.e2e, pytest.mark.anyio]


async def test_process_lifecycle(e2e: E2E) -> None:
    port = free_port()
    proc = await e2e.start(
        "http", [sys.executable, "-m", "http.server", str(port), "--bind", "127.0.0.1"]
    )
    await wait_ready(f"http://127.0.0.1:{port}/", proc)
    assert is_listening(port)

    await proc.terminate()

    assert proc.returncode is not None
    assert not is_listening(port)


async def test_early_exit_is_reported_with_stderr(e2e: E2E) -> None:
    proc = await e2e.start(
        "crash", [sys.executable, "-c", "import sys; print('boom', file=sys.stderr); sys.exit(3)"]
    )
    with pytest.raises(ProcessExitedError, match=r"(?s)exit code: 3.*boom"):
        await wait_ready(f"http://127.0.0.1:{free_port()}/", proc)


async def test_canarywire_entry_point_runs(e2e: E2E) -> None:
    proc = await e2e.canarywire("--version")
    assert proc.returncode == 0, e2e.diagnostics()
    assert proc.stdout().startswith("canarywire ")


async def test_diagnostics_list_every_process(e2e: E2E) -> None:
    await e2e.canarywire("--version")
    await e2e.start("sleeper", [sys.executable, "-c", "import time; time.sleep(30)"])

    text = e2e.diagnostics()

    assert "canarywire --version" in text
    assert "sleeper" in text


async def test_kill_pidfile_kills_the_process(e2e: E2E) -> None:
    pidfile = e2e.workdir / "sleeper.pid"
    await e2e.start(
        "sleeper",
        [
            sys.executable,
            "-c",
            "import os, pathlib, sys, time\n"
            "pathlib.Path(sys.argv[1]).write_text(str(os.getpid()))\n"
            "time.sleep(30)\n",
            str(pidfile),
        ],
    )
    with anyio.fail_after(5):
        while not pidfile.exists():
            await anyio.sleep(0.05)
    pid = int(pidfile.read_text())

    kill_pidfile(pidfile)

    with anyio.fail_after(5):
        while _pid_alive(pid):
            await anyio.sleep(0.05)


async def test_kill_pidfile_ignores_missing_and_unparsable(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist.pid"
    kill_pidfile(missing)  # must not raise

    garbage = tmp_path / "garbage.pid"
    garbage.write_text("not-a-pid")
    kill_pidfile(garbage)  # must not raise


async def test_aclose_terminates_all_even_if_one_raises(tmp_path: Path) -> None:
    world = E2E(tmp_path)
    boom = RuntimeError("boom")
    proc_a = await world.start("a", [sys.executable, "-c", "import time; time.sleep(30)"])
    proc_b = await world.start("b", [sys.executable, "-c", "import time; time.sleep(30)"])

    real_terminate = proc_a.terminate

    async def raising_terminate() -> None:
        await real_terminate()  # still clean up the real process
        raise boom

    proc_a.terminate = raising_terminate  # type: ignore[method-assign]

    with pytest.raises(RuntimeError, match="boom"):
        await world.aclose()

    assert proc_a.returncode is not None
    assert proc_b.returncode is not None


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    else:
        return True
