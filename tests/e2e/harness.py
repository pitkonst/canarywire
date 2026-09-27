"""Process harness for the e2e suite: real processes, real TCP, output in files."""

from __future__ import annotations

import contextlib
import json
import os
import shlex
import signal
import socket
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, TYPE_CHECKING, Any

import anyio
import httpx
import yaml

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from anyio.abc import Process

E2E_DIR = Path(__file__).parent
REFGW = E2E_DIR / "gateways" / "refgw.py"
ECHO_UPSTREAM = E2E_DIR / "stubs" / "echo_upstream.py"
CANARYWIRE = Path(sys.executable).parent / "canarywire"
REPORT_DIR = "out"

READY_TIMEOUT = 10.0
STOP_TIMEOUT = 5.0
TAIL_LINES = 40


def free_port() -> int:
    """Return a port that was free a moment ago. The allocate-then-bind race is accepted."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def is_listening(port: int) -> bool:
    """Return True if something accepts TCP connections on 127.0.0.1:port."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            return True
    except OSError:
        return False


def tail(path: Path, lines: int = TAIL_LINES) -> str:
    """Return the last lines of a text file, or a marker if it does not exist."""
    if not path.exists():
        return "<missing>"
    return "\n".join(path.read_text(errors="replace").splitlines()[-lines:])


def _killpg(pid: int, sig: signal.Signals) -> None:
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(pid, sig)


class ProcessExitedError(RuntimeError):
    """A process exited while the harness was waiting for it to become ready."""


def kill_pidfile(path: Path) -> None:
    """SIGKILL the pid in `path` if it exists and holds an integer; ignore anything else."""
    if not path.is_file():
        return
    try:
        pid = int(path.read_text().strip())
    except ValueError:
        return
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.kill(pid, signal.SIGKILL)


@dataclass
class Proc:
    """A child process in its own process group, with stdout/stderr redirected to files."""

    name: str
    argv: list[str]
    stdout_path: Path
    stderr_path: Path
    _process: Process
    _files: list[IO[bytes]] = field(default_factory=list)

    @classmethod
    async def start(
        cls,
        name: str,
        argv: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str] | None = None,
    ) -> Proc:
        """Spawn argv in cwd; output goes to cwd/<name>.stdout and cwd/<name>.stderr."""
        stdout_path = cwd / f"{name}.stdout"
        stderr_path = cwd / f"{name}.stderr"
        out = stdout_path.open("wb")
        err = stderr_path.open("wb")
        try:
            process = await anyio.open_process(
                list(argv),
                cwd=cwd,
                env={**os.environ, "PYTHONUNBUFFERED": "1", **(env or {})},
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=err,
                start_new_session=True,
            )
        except BaseException:
            out.close()
            err.close()
            raise
        return cls(name, list(argv), stdout_path, stderr_path, process, [out, err])

    @property
    def returncode(self) -> int | None:
        """Exit code, or None while running."""
        return self._process.returncode

    @property
    def pid(self) -> int:
        """Process id (also the process group id: each child leads its own group)."""
        return self._process.pid

    async def wait(self, timeout: float) -> int:
        """Wait for exit; raise TimeoutError with diagnostics after timeout seconds."""
        try:
            with anyio.fail_after(timeout):
                return await self._process.wait()
        except TimeoutError as exc:
            raise TimeoutError(
                f"{self.name} did not exit in {timeout}s\n{self.describe()}"
            ) from exc

    async def terminate(self) -> None:
        """SIGTERM the process group, SIGKILL after a grace period, then close output files."""
        if self._process.returncode is None:
            _killpg(self._process.pid, signal.SIGTERM)
            with anyio.move_on_after(STOP_TIMEOUT):
                await self._process.wait()
        if self._process.returncode is None:
            _killpg(self._process.pid, signal.SIGKILL)
            await self._process.wait()
        # Sweep children the leader may have left in its group.
        _killpg(self._process.pid, signal.SIGKILL)
        for file in self._files:
            file.close()

    def stdout(self) -> str:
        """Full stdout captured so far."""
        return self.stdout_path.read_text(errors="replace")

    def describe(self) -> str:
        """Argv, exit code and output tails, for assertion messages."""
        return "\n".join(
            [
                f"--- {self.name}: {shlex.join(self.argv)}",
                f"exit code: {self.returncode}",
                "stdout (tail):",
                tail(self.stdout_path),
                "stderr (tail):",
                tail(self.stderr_path),
            ]
        )


async def wait_ready(url: str, proc: Proc, timeout: float = READY_TIMEOUT) -> None:
    """Poll url until any HTTP response arrives; fail fast if proc exits first."""
    try:
        async with httpx.AsyncClient(timeout=1.0) as client:
            with anyio.fail_after(timeout):
                while True:
                    if proc.returncode is not None:
                        raise ProcessExitedError(
                            f"{proc.name} exited before becoming ready\n{proc.describe()}"
                        )
                    try:
                        await client.get(url)
                    except httpx.TransportError:
                        await anyio.sleep(0.05)
                    else:
                        return
    except TimeoutError as exc:
        raise TimeoutError(f"{url} not ready after {timeout}s\n{proc.describe()}") from exc


ZERO_DELAY = {"generators": {"fragmentation": {"delay_ms": {"min": 0, "max": 0}}}}


def _has_delay_ms(doc: object) -> bool:
    """Whether a parsed config document already sets `generators.fragmentation.delay_ms`."""
    if not isinstance(doc, dict):
        return False
    generators = doc.get("generators")
    if not isinstance(generators, dict):
        return False
    fragmentation = generators.get("fragmentation")
    return isinstance(fragmentation, dict) and "delay_ms" in fragmentation


def _fast_config_args(argv: Sequence[str], workdir: Path) -> list[str]:
    """Rewrite a `canarywire run` argv to zero the fragmentation per-event delay.

    Speeds up the e2e suite without changing the product: `DelaySettings`
    defaults to `min_ms=0, max_ms=5` (see `src/canarywire/config.py`), which is
    real product behaviour worth exercising, but not on every e2e test. If
    `--config X` is present, X is loaded (relative to `workdir`, the process
    cwd) and, unless it already sets `delay_ms` itself, rewritten with it
    forced to 0/0 into a sibling file `.<X basename>.fast.yaml` in X's
    directory (so relative template paths and `config_dir` still resolve the
    same way); argv then points at that file instead. With no `--config`, a
    `.fast.yaml` holding just that setting is written into `workdir` and
    `--config .fast.yaml` is appended.
    """
    args = list(argv)
    if not args or args[0] != "run":
        return args
    if "--config" in args:
        index = args.index("--config")
        original_arg = args[index + 1]
        original_rel = Path(original_arg)
        original_abs = workdir / original_rel
        doc: object = {}
        if original_abs.is_file():
            loaded = yaml.safe_load(original_abs.read_text())
            doc = {} if loaded is None else loaded
        if _has_delay_ms(doc):
            return args
        if not isinstance(doc, dict):
            doc = {}
        merged = dict(doc)
        generators = dict(merged.get("generators") or {})
        fragmentation = dict(generators.get("fragmentation") or {})
        fragmentation["delay_ms"] = {"min": 0, "max": 0}
        generators["fragmentation"] = fragmentation
        merged["generators"] = generators
        fast_rel = original_rel.parent / f".{original_rel.name}.fast.yaml"
        (workdir / fast_rel).write_text(yaml.safe_dump(merged, sort_keys=False))
        args[index + 1] = str(fast_rel)
        return args
    (workdir / ".fast.yaml").write_text(yaml.safe_dump(ZERO_DELAY, sort_keys=False))
    return [*args, "--config", ".fast.yaml"]


@dataclass(frozen=True)
class GatewaySpec:
    """How to launch a gateway under test and where to reach it."""

    name: str
    argv: list[str]
    url: str
    ready_url: str
    env: dict[str, str] = field(default_factory=dict)


def refgw_spec(
    *,
    upstream: str,
    port: int,
    bug: str | None = None,
    analyzer_down_file: Path | None = None,
    duty: str | None = None,
) -> GatewaySpec:
    """Launch spec for the reference gateway, optionally with one injected bug.

    With `analyzer_down_file`, the gateway's detector counts as down while that file exists.
    `duty` is `restore` (the gateway's default, so `None` leaves it unset) or `mask-only`.
    """
    url = f"http://127.0.0.1:{port}"
    argv = [sys.executable, str(REFGW), "--upstream", upstream, "--listen", f"127.0.0.1:{port}"]
    if bug is not None:
        argv += ["--bug", bug]
    if analyzer_down_file is not None:
        argv += ["--analyzer-down-file", str(analyzer_down_file)]
    if duty is not None:
        argv += ["--duty", duty]
    return GatewaySpec(
        name=f"refgw-{bug or 'correct'}", argv=argv, url=url, ready_url=f"{url}/healthz"
    )


class E2E:
    """One test's world: a working directory and every process started in it."""

    def __init__(self, workdir: Path) -> None:
        """Bind to workdir; every process started here uses it as cwd."""
        self.workdir = workdir
        self._procs: list[Proc] = []

    async def start(
        self, name: str, argv: Sequence[str], env: Mapping[str, str] | None = None
    ) -> Proc:
        """Start a tracked process; names get a sequence prefix so output files never clash."""
        proc = await Proc.start(f"{len(self._procs):02d}-{name}", argv, cwd=self.workdir, env=env)
        self._procs.append(proc)
        return proc

    async def start_gateway(self, spec: GatewaySpec) -> Proc:
        """Start a gateway and wait until it answers on its ready URL."""
        proc = await self.start(spec.name, spec.argv, spec.env)
        await wait_ready(spec.ready_url, proc)
        return proc

    async def canarywire(
        self, *args: str, timeout: float = 30.0, real_delays: bool = False
    ) -> Proc:
        """Run the canarywire console script to completion.

        For a `run` invocation, the fragmentation per-event delay is zeroed by
        rewriting/adding `--config` (see `_fast_config_args`) unless
        `real_delays=True`.
        """
        proc = await self.start_canarywire(*args, real_delays=real_delays)
        await proc.wait(timeout)
        return proc

    async def start_canarywire(self, *args: str, real_delays: bool = False) -> Proc:
        """Start the canarywire console script without waiting for it.

        See `canarywire` for what `real_delays` does.
        """
        argv = list(args) if real_delays else _fast_config_args(args, self.workdir)
        return await self.start("canarywire", [str(CANARYWIRE), *argv])

    def report(self) -> dict[str, Any]:
        """Parse out/report.json written by `canarywire run`."""
        path = self.workdir / REPORT_DIR / "report.json"
        assert path.is_file(), f"no report at {path}\n{self.diagnostics()}"
        data: dict[str, Any] = json.loads(path.read_text())
        return data

    def diagnostics(self) -> str:
        """Every process's argv, exit code and output tails, plus the workdir listing."""
        files = sorted(str(p.relative_to(self.workdir)) for p in self.workdir.rglob("*"))
        return "\n\n".join(
            [*(proc.describe() for proc in self._procs), "workdir: " + ", ".join(files)]
        )

    async def aclose(self) -> None:
        """Terminate every process, newest first, even if one `terminate()` raises."""
        first_error: BaseException | None = None
        for proc in reversed(self._procs):
            try:
                await proc.terminate()
            except BaseException as exc:
                if first_error is None:
                    first_error = exc
        if first_error is not None:
            raise first_error


@dataclass(frozen=True)
class Capture:
    """Address of a running capture server."""

    port: int

    @property
    def url(self) -> str:
        """Base URL of the capture."""
        return f"http://127.0.0.1:{self.port}"
