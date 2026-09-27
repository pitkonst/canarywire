"""Run a fault's before/after shell command: own session, logged, killed as a group on timeout."""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

import anyio

if TYPE_CHECKING:
    from pathlib import Path

    from anyio.abc import Process


@dataclass(frozen=True)
class HookResult:
    """What one hook did: exit code (None if it timed out), duration, log path (relative)."""

    exit: int | None
    timed_out: bool
    duration_ms: int
    log: str


async def run_hook(
    command: str, *, fault: str, hook: str, out_dir: Path, timeout: float
) -> HookResult:
    """Run `/bin/sh -c command`; stdout and stderr go to `<out_dir>/faults/<fault>.<hook>.log`.

    The command runs in its own session so that a timeout or a cancellation kills its whole
    process group, children included; a timeout counts as a failure (`exit` None).
    """
    relative = f"faults/{fault}.{hook}.log"
    log_path = out_dir / relative
    log_path.parent.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "CANARYWIRE_FAULT": fault, "CANARYWIRE_FAULT_HOOK": hook}
    start = time.monotonic()
    with log_path.open("wb") as log:
        process = await anyio.open_process(
            ["/bin/sh", "-c", command],
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            env=env,
            start_new_session=True,
        )
        try:
            with anyio.fail_after(timeout):
                code = await process.wait()
        except TimeoutError:
            await _kill(process)
            return HookResult(None, True, _ms(start), relative)
        except BaseException:
            await _kill(process)
            raise
    return HookResult(code, False, _ms(start), relative)


async def _kill(process: Process) -> None:
    with anyio.CancelScope(shield=True):
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        await process.wait()


def _ms(start: float) -> int:
    return int((time.monotonic() - start) * 1000)
