"""Append-only record of every upstream exchange."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path


class Recorder:
    """Appends one JSON line per upstream exchange; every line is flushed immediately."""

    def __init__(self, path: Path) -> None:
        """Record to `path`, creating its directory on first write."""
        self.path = path

    def write(self, entry: Mapping[str, Any]) -> None:
        """Append one entry."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(entry) + "\n")
