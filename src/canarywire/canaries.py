"""Canaries: synthetic values in real formats, assigned per template instance for a run."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Canary:
    """One tested value: a template's canary instance (`name`) with its type and template."""

    name: str
    value: str
    type: str = ""
    template: str = ""
