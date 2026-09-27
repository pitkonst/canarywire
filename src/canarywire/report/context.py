"""The run context recorded in the report: the effective configuration, minus secrets."""

from __future__ import annotations

from dataclasses import asdict
from typing import TYPE_CHECKING, Any

from canarywire import __version__

if TYPE_CHECKING:
    from pathlib import Path

    from canarywire.config import Config


def _listify(value: Any) -> Any:
    """Recursively turn tuples into lists so the result is plain, JSON-native data."""
    if isinstance(value, tuple):
        return [_listify(item) for item in value]
    if isinstance(value, dict):
        return {key: _listify(item) for key, item in value.items()}
    return value


def run_context(config: Config, config_path: Path | None) -> dict[str, Any]:
    """Version, config file hash, routes, generators, faults (no commands) and timeouts.

    The hash is `config.config_sha256`, taken by `config.load` from the bytes it parsed; the
    file is never read again here.
    """
    return {
        "canarywire_version": __version__,
        "config": None
        if config_path is None
        else {
            "path": str(config_path),
            "sha256": config.config_sha256,
        },
        "routes": [asdict(route) for route in config.routes],
        "generators": _listify(asdict(config.generators)),
        "faults": [
            {"name": f.name, "expect": list(f.expect), "settle_ms": f.settle_ms}
            for f in config.faults
        ],
        "timeouts": asdict(config.timeouts),
    }
