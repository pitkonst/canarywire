import contextlib
import signal
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import anyio
import httpx
import pytest
from live import dead_proxy, free_port

from canarywire.capture import daemon
from canarywire.capture.daemon import (
    PID_FILE,
    is_capture,
    live_pid,
    read_pid,
    serve_detached,
    stop,
)

SLEEP = "import time; time.sleep(60)"
HEALTH_TIMEOUT = 10.0


@pytest.fixture
def sleeper() -> Iterator[subprocess.Popen[bytes]]:
    """A process that is not a capture."""
    process = subprocess.Popen([sys.executable, "-c", SLEEP])  # noqa: S603 - fixed argv
    yield process
    process.kill()
    process.wait()


@pytest.fixture
def fake_capture() -> Iterator[subprocess.Popen[bytes]]:
    """A process whose command line looks like `canarywire serve`."""
    process = subprocess.Popen(  # noqa: S603 - fixed argv
        [sys.executable, "-c", SLEEP, "canarywire", "serve"]
    )
    yield process
    process.kill()
    process.wait()


def write_pid(state_dir: Path, pid: int) -> Path:
    state_dir.mkdir(exist_ok=True)
    path = state_dir / PID_FILE
    path.write_text(f"{pid}\n")
    return path


def test_read_pid(tmp_path: Path) -> None:
    assert read_pid(tmp_path / "missing") is None
    (tmp_path / "bad").write_text("nope")
    assert read_pid(tmp_path / "bad") is None
    (tmp_path / "ok").write_text("123\n")
    assert read_pid(tmp_path / "ok") == 123


def test_is_capture(
    sleeper: subprocess.Popen[bytes], fake_capture: subprocess.Popen[bytes]
) -> None:
    assert not is_capture(sleeper.pid)
    assert is_capture(fake_capture.pid)


@pytest.mark.parametrize(
    "words",
    [["canarywire", "serverless"], ["notcanarywire", "serve"], ["xcanarywire", "serve-proxy"]],
)
def test_lookalike_command_is_not_a_capture(words: list[str]) -> None:
    process = subprocess.Popen([sys.executable, "-c", SLEEP, *words])  # noqa: S603 - fixed argv
    try:
        assert not is_capture(process.pid)
    finally:
        process.kill()
        process.wait()


def test_dead_pid_is_not_a_capture() -> None:
    process = subprocess.Popen([sys.executable, "-c", "pass"])
    process.wait()
    assert not is_capture(process.pid)


def test_live_pid_ignores_recycled_foreign_pid(
    tmp_path: Path, sleeper: subprocess.Popen[bytes]
) -> None:
    write_pid(tmp_path, sleeper.pid)
    assert live_pid(tmp_path) is None


@pytest.mark.anyio
async def test_detach_refuses_when_capture_is_live(
    tmp_path: Path, fake_capture: subprocess.Popen[bytes], capsys: pytest.CaptureFixture[str]
) -> None:
    write_pid(tmp_path, fake_capture.pid)
    assert await serve_detached("127.0.0.1:1", tmp_path, ready_timeout=1) == 1
    assert "already running" in capsys.readouterr().err


@pytest.mark.anyio
async def test_stop_without_pid_file(tmp_path: Path) -> None:
    assert await stop(tmp_path, grace=1) == 0


@pytest.mark.anyio
async def test_stop_removes_stale_file_and_spares_foreign_process(
    tmp_path: Path, sleeper: subprocess.Popen[bytes]
) -> None:
    path = write_pid(tmp_path, sleeper.pid)
    assert await stop(tmp_path, grace=1) == 0
    assert not path.exists()
    assert sleeper.poll() is None


@pytest.mark.anyio
async def test_stop_terminates_capture(
    tmp_path: Path, fake_capture: subprocess.Popen[bytes]
) -> None:
    path = write_pid(tmp_path, fake_capture.pid)
    assert await stop(tmp_path, grace=5) == 0
    assert fake_capture.wait(timeout=5) is not None
    assert not path.exists()


@pytest.mark.anyio
async def test_stop_reports_permission_denied(
    tmp_path: Path,
    fake_capture: subprocess.Popen[bytes],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    write_pid(tmp_path, fake_capture.pid)

    def raise_permission(pid: int, sig: int) -> None:
        raise PermissionError

    monkeypatch.setattr("canarywire.capture.daemon.os.kill", raise_permission)
    assert await stop(tmp_path, grace=1) == 1
    assert "permission denied" in capsys.readouterr().err


@pytest.mark.anyio
async def test_stop_warns_if_still_running_after_sigkill(
    tmp_path: Path,
    fake_capture: subprocess.Popen[bytes],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = write_pid(tmp_path, fake_capture.pid)

    async def never_gone(pid: int, timeout: float) -> bool:
        return False

    monkeypatch.setattr(daemon, "_wait_gone", never_gone)
    assert await stop(tmp_path, grace=0.01) == 1
    assert "did not stop" in capsys.readouterr().err
    assert path.exists()


async def _wait_for_health(url: str) -> None:
    async with httpx.AsyncClient(timeout=1.0) as client:
        with anyio.fail_after(HEALTH_TIMEOUT):
            while True:
                with contextlib.suppress(httpx.TransportError):
                    if (await client.get(url)).status_code == httpx.codes.OK:
                        return
                await anyio.sleep(0.05)


@pytest.mark.anyio
async def test_foreground_sigterm_exits_cleanly_and_removes_pid_file(tmp_path: Path) -> None:
    port = free_port()
    process = subprocess.Popen(  # noqa: S603 - fixed argv
        [sys.executable, "-m", "canarywire", "serve", "--listen", f"127.0.0.1:{port}"],
        cwd=tmp_path,
    )
    try:
        await _wait_for_health(f"http://127.0.0.1:{port}/_canarywire/health")
        process.send_signal(signal.SIGTERM)
        with anyio.fail_after(HEALTH_TIMEOUT):
            while process.poll() is None:
                await anyio.sleep(0.05)
        assert process.returncode == 0
        assert not (tmp_path / ".canarywire" / PID_FILE).exists()
    finally:
        process.kill()
        process.wait()


@pytest.mark.anyio
async def test_detach_fails_when_another_process_owns_the_port(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    port = free_port()
    dir_a = tmp_path / "a"
    dir_b = tmp_path / "b"
    dir_a.mkdir()
    dir_b.mkdir()
    other = subprocess.Popen(  # noqa: S603 - fixed argv
        [sys.executable, "-m", "canarywire", "serve", "--listen", f"127.0.0.1:{port}"],
        cwd=dir_a,
    )
    try:
        await _wait_for_health(f"http://127.0.0.1:{port}/_canarywire/health")
        monkeypatch.chdir(dir_b)
        assert (
            await serve_detached(f"127.0.0.1:{port}", dir_b / ".canarywire", ready_timeout=5) == 1
        )
    finally:
        other.kill()
        other.wait()


def test_detach_health_probe_ignores_proxy_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dead_proxy(monkeypatch)
    cli = [sys.executable, "-m", "canarywire"]
    serve = [*cli, "serve", "--detach", "--listen", f"127.0.0.1:{free_port()}"]
    try:
        started = subprocess.run(  # noqa: S603 - fixed argv
            serve, cwd=tmp_path, capture_output=True, text=True, check=False, timeout=30
        )
        assert started.returncode == 0, started.stderr
    finally:
        subprocess.run([*cli, "stop"], cwd=tmp_path, check=False, timeout=30)  # noqa: S603
