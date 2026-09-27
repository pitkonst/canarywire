"""Capture process lifecycle: foreground serve, --detach, stop, and the pid file."""

from __future__ import annotations

import contextlib
import ipaddress
import os
import re
import signal
import subprocess
import sys
from pathlib import Path

import anyio
import httpx
import uvicorn

from canarywire.capture.app import PID_HEADER, create_app
from canarywire.capture.recorder import Recorder
from canarywire.config import parse_listen

STATE_DIR = Path(".canarywire")
PID_FILE = "capture.pid"
LOG_FILE = "capture.log"
RECORD_FILE = "capture.jsonl"
PS = "/bin/ps"
POLL = 0.05
KILL_WAIT = 5.0
LOG_TAIL = 20
# `canarywire serve` as whole words: `python -m canarywire serve …` or `…/bin/canarywire serve …`,
# never `notcanarywire serve` or `canarywire serverless`.
CAPTURE_COMMAND = re.compile(r"(?:^|[\s/])canarywire serve(?:\s|$)")


def read_pid(path: Path) -> int | None:
    """The pid in a pid file, or None if it is missing or unparsable."""
    try:
        return int(path.read_text().strip())
    except (OSError, ValueError):
        return None


def is_capture(pid: int) -> bool:
    """True if `pid` is a running `canarywire serve` (not a recycled pid, not a zombie)."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        pass  # exists but belongs to someone else; ps decides
    result = subprocess.run(  # noqa: S603 - fixed argv, pid is an int
        [PS, "-o", "command=", "-p", str(pid)], capture_output=True, text=True, check=False
    )
    return CAPTURE_COMMAND.search(result.stdout) is not None


def live_pid(state_dir: Path) -> int | None:
    """The pid of the live capture named by the pid file, if any."""
    pid = read_pid(state_dir / PID_FILE)
    return pid if pid is not None and is_capture(pid) else None


def serve_foreground(host: str, port: int, state_dir: Path) -> int:
    """Run the capture in this process until SIGTERM or SIGINT."""
    if (pid := live_pid(state_dir)) is not None:
        print(f"canarywire: capture already running (pid {pid})", file=sys.stderr)
        return 1
    state_dir.mkdir(parents=True, exist_ok=True)
    pid_file = state_dir / PID_FILE
    pid_file.write_text(f"{os.getpid()}\n")
    # uvicorn installs its own SIGTERM handler, shuts down gracefully, then restores the
    # previous handler and re-raises the signal. Without a no-op handler in place first, that
    # re-raise kills the process before this function's `finally` (and the pid file cleanup) runs.
    previous_sigterm = signal.signal(signal.SIGTERM, lambda *_: None)
    try:
        uvicorn.run(
            create_app(Recorder(state_dir / RECORD_FILE)),
            host=host,
            port=port,
            log_level="warning",
            ws="websockets-sansio",
            lifespan="off",
        )
    finally:
        signal.signal(signal.SIGTERM, previous_sigterm)
        if read_pid(pid_file) == os.getpid():
            pid_file.unlink(missing_ok=True)
    return 0


async def serve_detached(listen: str, state_dir: Path, ready_timeout: float) -> int:
    """Start `canarywire serve` in a new session; return once it answers its health check."""
    if (pid := live_pid(state_dir)) is not None:
        print(f"canarywire: capture already running (pid {pid})", file=sys.stderr)
        return 1
    host, port = parse_listen(listen)
    state_dir.mkdir(parents=True, exist_ok=True)
    log_path = state_dir / LOG_FILE
    with log_path.open("ab") as log:
        process = subprocess.Popen(  # noqa: S603 - argv built from our own interpreter
            [sys.executable, "-m", "canarywire", "serve", "--listen", listen],
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    url = f"http://{_probe_host(host)}:{port}/_canarywire/health"
    if await _wait_healthy(url, process, ready_timeout):
        print(f"canarywire: capture listening on {listen} (pid {process.pid})")
        return 0
    process.kill()
    process.wait()
    print("canarywire: capture failed to start; last log lines:", file=sys.stderr)
    print(_tail(log_path), file=sys.stderr)
    return 1


async def stop(state_dir: Path, grace: float) -> int:
    """Stop the capture named by the pid file; succeed when none is running."""
    pid_file = state_dir / PID_FILE
    pid = read_pid(pid_file)
    if pid is None or not is_capture(pid):
        pid_file.unlink(missing_ok=True)
        print("canarywire: no capture running")
        return 0
    if not _signal(pid, signal.SIGTERM):
        return 1
    gone = await _wait_gone(pid, grace)
    if not gone:
        if not _signal(pid, signal.SIGKILL):
            return 1
        gone = await _wait_gone(pid, KILL_WAIT)
    if not gone:
        print(f"canarywire: capture did not stop (pid {pid})", file=sys.stderr)
        return 1
    pid_file.unlink(missing_ok=True)
    print(f"canarywire: capture stopped (pid {pid})")
    return 0


def _probe_host(host: str) -> str:
    with contextlib.suppress(ValueError):
        address = ipaddress.ip_address(host)
        if address.is_unspecified:
            return "127.0.0.1"
        if address.version == 6:  # noqa: PLR2004 - IP version number
            return f"[{host}]"
    return host


async def _wait_healthy(url: str, process: subprocess.Popen[bytes], timeout: float) -> bool:
    """True once *our child* answers the health check.

    Another capture already bound to the port would answer too; its pid header tells it apart.
    The child writes the pid file before it serves, so a healthy child also owns the pid file.
    """
    # Our own child on the address it bound: never through a proxy from the environment.
    async with httpx.AsyncClient(timeout=1.0, trust_env=False) as client:
        with anyio.move_on_after(timeout):
            while process.poll() is None:
                with contextlib.suppress(httpx.TransportError):
                    response = await client.get(url)
                    if response.status_code == httpx.codes.OK and response.headers.get(
                        PID_HEADER
                    ) == str(process.pid):
                        return True
                await anyio.sleep(POLL)
    return False


async def _wait_gone(pid: int, timeout: float) -> bool:
    with anyio.move_on_after(timeout):
        while is_capture(pid):
            await anyio.sleep(POLL)
        return True
    return False


def _signal(pid: int, sig: signal.Signals) -> bool:
    """Send `sig` to `pid`; False (with a stderr message) only if permission was denied."""
    try:
        os.kill(pid, sig)
    except ProcessLookupError:
        return True
    except PermissionError:
        print(f"canarywire: cannot signal pid {pid}: permission denied", file=sys.stderr)
        return False
    return True


def _tail(path: Path) -> str:
    try:
        return "\n".join(path.read_text(errors="replace").splitlines()[-LOG_TAIL:])
    except OSError:
        return "<no log>"
