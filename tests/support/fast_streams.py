"""Pytest plugin: zero the fragmentation generator's per-event delay by default.

Most unit tests don't exercise the seeded per-event delay
(`DelaySettings` default `min_ms=0, max_ms=5` in `canarywire.config`); it only
costs wall-clock time, via real `anyio.sleep` calls in live-server tests. This
autouse fixture patches the dataclass's `__init__` defaults to 0/0 for the
duration of each test, unless the test is marked `real_delays`.

This only reaches tests that build `Config`/`FragmentationSettings` via their
Python dataclass defaults (e.g. `FragmentationSettings()`, `Config()`, or
`canarywire.config.load(None)`). It does not reach configs parsed from YAML
(`canarywire.config.parse`/`load(path)`): `_fragmentation()` there falls back
to its own literal `0`/`5` when `delay_ms` is absent, independent of the
dataclass default. That divergence surfaces in a few config-equality tests
(`tests/test_config.py`) that compare a
dataclass-built `Config`/`Generators` against a parsed one; those are marked
`real_delays` (see below) since they fail only because of the delay default,
per the parser/dataclass split above. See the e2e harness rewrite
(`tests/e2e/harness.py`) for how config-file-driven runs are sped up instead.

This deliberately does not use pytest's `monkeypatch` fixture: requesting it
from an autouse fixture pulls its setup earlier in the fixture graph, which
flips its teardown order relative to any `monkeypatch` the test itself
requests (observed to break `tests/capture/test_daemon.py`, where a test's own
`os.kill` patch would then outlive the test body into a later fixture's
teardown). A manual save/restore avoids touching fixture ordering entirely.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from canarywire import config

if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture(autouse=True)
def _zero_stream_delays(request: pytest.FixtureRequest) -> Iterator[None]:
    """Zero `DelaySettings` defaults for this test, unless marked `real_delays`."""
    if request.node.get_closest_marker("real_delays") is not None:
        yield
        return
    original = config.DelaySettings.__init__.__defaults__
    config.DelaySettings.__init__.__defaults__ = (0, 0)
    try:
        yield
    finally:
        config.DelaySettings.__init__.__defaults__ = original
