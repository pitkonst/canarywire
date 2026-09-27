"""Command-line entry point."""

from __future__ import annotations

import argparse
import secrets
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import anyio

from canarywire import __version__
from canarywire.capture import daemon
from canarywire.config import (
    DEFAULT_LISTEN,
    TIMEOUT_KEYS,
    ConfigError,
    load,
    override,
    parse_generator_names,
    parse_listen,
)
from canarywire.report import EXIT_CODES, UNTRUSTED
from canarywire.report.context import run_context
from canarywire.report.outputs import load_outputs, resolve_outputs, write
from canarywire.runner.prepare import prepare
from canarywire.runner.runner import RunSettings, execute

if TYPE_CHECKING:
    from collections.abc import Sequence

    from canarywire.config import Config

CONFIG_EXIT = {"run": 2, "serve": 1, "stop": 1}
SEED_BITS = 31


def positive_float(text: str) -> float:
    """Argparse type: a positive number of seconds."""
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected a number, got {text!r}") from None
    if value <= 0:
        raise argparse.ArgumentTypeError(f"expected a positive number, got {text!r}")
    return value


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with the serve, run and stop commands."""
    parser = argparse.ArgumentParser(
        prog="canarywire",
        description="A regression test for your PII gateway's trust boundary.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", metavar="COMMAND")

    serve = commands.add_parser("serve", help="run the capture server (the fake upstream)")
    serve.add_argument("--listen", default=DEFAULT_LISTEN, help="HOST:PORT to bind")
    serve.add_argument("--detach", action="store_true", help="run in the background")
    serve.add_argument("--config", type=Path, help="YAML config file")
    serve.add_argument("--timeout-serve-ready", type=positive_float, metavar="S")

    run = commands.add_parser("run", help="attack the gateway and check the boundary")
    run.add_argument("--target", help="gateway base URL")
    run.add_argument("--capture", help="capture base URL (default http://127.0.0.1:8765)")
    run.add_argument("--seed", type=int, help="replay a previous run")
    run.add_argument("--out", type=Path, default=None, help="report directory")
    run.add_argument("--config", type=Path, help="YAML config file")
    run.add_argument("--junit", type=Path, help="also write a JUnit XML report to PATH")
    for name in ("capture-connect", "client-request", "upstream-response", "upstream-done"):
        run.add_argument(f"--timeout-{name}", type=positive_float, metavar="S")
    run.add_argument(
        "--generators", metavar="NAMES", help="comma-separated: baseline,fragmentation,fault"
    )

    stop = commands.add_parser("stop", help="stop a detached capture server")
    stop.add_argument("--config", type=Path, help="YAML config file")
    stop.add_argument("--timeout-stop-grace", type=positive_float, metavar="S")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    timeouts = {key: getattr(args, f"timeout_{key}", None) for key in TIMEOUT_KEYS}
    try:
        names = getattr(args, "generators", None)
        generators = parse_generator_names(names) if names is not None else None
        config = override(load(args.config), timeouts=timeouts, generators=generators)
    except ConfigError as exc:
        print(f"canarywire: config error: {exc}", file=sys.stderr)
        return CONFIG_EXIT[args.command]
    if args.command == "serve":
        return _serve(args, config)
    if args.command == "run":
        return _run(args, config)
    return _stop(config)


def _serve(args: argparse.Namespace, config: Config) -> int:
    try:
        host, port = parse_listen(args.listen)
    except ConfigError as exc:
        print(f"canarywire: {exc}", file=sys.stderr)
        return 1
    if args.detach:
        return anyio.run(
            daemon.serve_detached, args.listen, daemon.STATE_DIR, config.timeouts.serve_ready
        )
    return daemon.serve_foreground(host, port, daemon.STATE_DIR)


def _stop(config: Config) -> int:
    return anyio.run(daemon.stop, daemon.STATE_DIR, config.timeouts.stop_grace)


def _run(args: argparse.Namespace, config: Config) -> int:
    config = override(config, seed=args.seed, capture_url=args.capture, target_url=args.target)
    if config.target_url is None:
        print("canarywire: no target: pass --target or set target.base_url", file=sys.stderr)
        return 2
    seed = config.seed if config.seed is not None else secrets.randbits(SEED_BITS)
    out_dir = args.out or config.report.dir or Path("out")
    try:
        prepared = prepare(config, seed)
        loaded = load_outputs(
            resolve_outputs(config.report, out_dir, args.junit), config.config_dir
        )
        run = run_context(config, args.config)
    except ConfigError as exc:
        print(f"canarywire: config error: {exc}", file=sys.stderr)
        return 2
    report = anyio.run(
        execute,
        RunSettings(
            config.target_url,
            config.capture_url,
            seed,
            config.timeouts,
            config.generators,
            prepared,
            faults=config.faults,
            out_dir=out_dir,
            routes=config.routes,
            duty=config.duty,
        ),
    )
    if report.interrupted is not None:
        # A signal arrived during a fault: its after-hook has run; the run itself is incomplete.
        # With no report written, stderr is the only place an after-hook failure can show.
        failed = [p for p in report.trust_problems if p.startswith("fault ")]
        for problem in failed:
            print(f"canarywire: {problem}", file=sys.stderr)
        after = (
            "fault after-hook failed, environment may still be faulted"
            if failed
            else "fault after-hook ran"
        )
        print(
            f"canarywire: interrupted by signal {report.interrupted}; {after}; no report written",
            file=sys.stderr,
        )
        return 128 + report.interrupted
    report.run = run
    # Anything going wrong from here on (writing the report, deciding its outcome, rendering the
    # summary) is a crash, not a gateway failure or a pass: it must exit 2 like any other
    # untrusted run, never fall through to the default success-looking exit of a bare crash.
    try:
        path, errors = write(report, out_dir, loaded)
        outcome = report.outcome()
        problems = report.problems()
        reason = f" ({problems[0]})" if outcome == UNTRUSTED and problems else ""
        for error in errors:
            print(error, file=sys.stderr)
        unwritten = f"; {len(errors)} output(s) not written" if errors else ""
        print(f"canarywire: {outcome}{reason}; seed {seed}; report: {path}{unwritten}")
    except Exception as exc:
        print(f"canarywire: cannot write report: {exc}", file=sys.stderr)
        return 2
    if errors:
        return 2
    return EXIT_CODES[outcome]
