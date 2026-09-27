"""Per-protocol modules: template adapters and stream codecs, looked up by protocol id."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from types import ModuleType

PROTOCOLS = ("openai-chat", "anthropic-messages")
_MODULES = {"openai-chat": "openai", "anthropic-messages": "anthropic"}


def module(protocol: str) -> ModuleType:
    """The module implementing `protocol` (one of PROTOCOLS); ValueError for any other.

    Imported on first use: the protocol modules import `sse_events` from this package, so
    importing them at the top of this file would run them before `sse_events` exists.
    """
    if protocol not in _MODULES:
        raise ValueError(f"unknown protocol {protocol!r}; expected one of {', '.join(PROTOCOLS)}")
    return import_module(f"{__name__}.{_MODULES[protocol]}")


def sse_events(raw: str) -> list[str]:
    r"""Split an SSE body into its event payloads.

    `\r\n`/`\r` count as `\n`; an empty line ends an event; several `data:` lines in one event
    are joined with `\n` (their leading space, if any, is stripped); other fields and `:`
    comments are ignored. Events without a `data:` line contribute nothing to the result, so an
    empty result means the body had no `data:` events at all.
    """
    normalized = raw.replace("\r\n", "\n").replace("\r", "\n")
    events: list[str] = []
    for block in normalized.split("\n\n"):
        lines = [line[len("data:") :] for line in block.split("\n") if line.startswith("data:")]
        if lines:
            events.append("\n".join(line.removeprefix(" ") for line in lines))
    return events
