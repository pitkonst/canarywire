"""Sample reports, the view shape they imply, and the shape/merge-shape helpers."""

from __future__ import annotations

from typing import Any

from canarywire.canaries import Canary
from canarywire.config import Config, FaultSpec
from canarywire.report import Report
from canarywire.report.context import run_context
from canarywire.report.findings import Excerpt
from canarywire.report.view import view
from canarywire.runner.attacks import AttackResult, Mangled, NegativeControl, Unrestored
from canarywire.runner.consistency import Inconsistent, Seen
from canarywire.runner.fault import FaultRecord
from canarywire.runner.hooks import HookResult
from canarywire.runner.scan import Hit

# Synthetic fault hook commands: they must never reach report.json or any output.
BEFORE_COMMAND = "echo stop-analyzer"
AFTER_COMMAND = "echo start-analyzer"
SAMPLE_CONFIG = Config(
    faults=(
        FaultSpec("down", BEFORE_COMMAND, AFTER_COMMAND, ("refuse",), 100),
        FaultSpec("slow", BEFORE_COMMAND, AFTER_COMMAND, ("restore",), 0),
    )
)
STARTED_AT = "2026-09-26T09:00:00+00:00"
FINISHED_AT = "2026-09-26T09:01:00+00:00"


def _run() -> dict[str, Any]:
    """The fixed `run` dict every sample report uses, so goldens never drift with the version."""
    return {
        **run_context(SAMPLE_CONFIG, None),
        "canarywire_version": "0.0.0",
        "config": {"path": "canarywire.yaml", "sha256": "0" * 64},
    }


def passing_report() -> Report:
    """A minimal passing report: one restored attack, negative control caught."""
    report = Report(
        seed=0,
        target="http://gw.example.org",
        capture_url="http://127.0.0.1:8765",
        started_at=STARTED_AT,
        finished_at=FINISHED_AT,
        run=_run(),
    )
    report.negative_control_caught = True
    report.canaries.append(Canary("email", "a@example.org", "email", "greeting"))
    report.attacks.append(
        AttackResult(
            "baseline/greeting@main",
            status="restored",
            client_status=200,
            upstream_requests=1,
            restored=1,
        )
    )
    return report


def _failing_report() -> Report:
    """Fail on a leak; also exercises unrestored (with note), inconsistent, refused and faults."""
    report = Report(
        seed=1,
        target="http://gw.example.org",
        capture_url="http://127.0.0.1:8765",
        started_at=STARTED_AT,
        finished_at=FINISHED_AT,
        run=_run(),
    )
    report.negative_control_caught = True
    report.canaries += [
        Canary("email", "a@example.org", "email", "greeting"),
        Canary("card", "4000000000000002", "card", "greeting"),
    ]
    report.negative_controls.append(NegativeControl("greeting@main", False, ("card",)))
    report.unexpected_upstream = 1
    report.unexpected_leaks.append(Hit("email", "a@example.org", "url", "greeting", "email"))

    leaking = AttackResult(
        "baseline/greeting@main",
        status="restored",
        client_status=200,
        upstream_requests=1,
        restored=1,
    )
    leaking.leaks.append(
        Hit(
            "email",
            "a@example.org",
            "body.messages[0].content",
            "greeting",
            "email",
            Excerpt("Contact ", "a@example.org", " for details"),
        )
    )
    unrestored = AttackResult(
        "fragmentation/greeting@main", status="unrestored", client_status=200, upstream_requests=1
    )
    unrestored.unrestored.append(
        Unrestored(
            "card",
            "4000000000000002",
            "body.x",
            "Card ending 0002 approved",
            "Card ending REDACTED approved",
            "greeting",
            "card",
            "masked twice",
        )
    )
    inconsistent = AttackResult(
        "fault/down/greeting@main", status="inconsistent", client_status=200, upstream_requests=1
    )
    inconsistent.inconsistent.append(
        Inconsistent("greeting", "email", "email", (Seen("body.a", "<E1>"), Seen("body.b", "<E2>")))
    )
    refused = AttackResult(
        "fault/down/farewell@main",
        status="refused",
        client_status=502,
        reason="refused with HTTP 502",
        upstream_aborted="1/3",
        upstream_requests=1,
    )
    mangled = AttackResult(
        "baseline/farewell@main",
        status="mangled",
        client_status=200,
        upstream_requests=1,
        reason="request text changed around a canary at body.x",
    )
    mangled.mangled.append(
        Mangled("body.x", "Send {{email}} the invoice.", "Send <EMAIL_1>ice.", "farewell")
    )
    report.attacks += [leaking, mangled, unrestored, inconsistent, refused]

    report.faults = [
        FaultRecord(
            "down",
            ("refuse",),
            HookResult(0, False, 120, "faults/down.before.log"),
            HookResult(None, True, 60000, "faults/down.after.log"),
        ),
        FaultRecord(
            "slow",
            ("restore",),
            HookResult(0, False, 50, "faults/slow.before.log"),
            HookResult(0, False, 80, "faults/slow.after.log"),
        ),
    ]
    return report


def _untrusted_report() -> Report:
    """Untrusted: a run-level trust problem, an untrusted attack, negative control not caught."""
    report = Report(
        seed=2,
        target="http://gw.example.org",
        capture_url="http://127.0.0.1:8765",
        started_at=STARTED_AT,
        finished_at=FINISHED_AT,
        run=_run(),
    )
    report.negative_control_caught = False
    report.trust_problems.append("upstream did not respond within budget")
    report.attacks.append(
        AttackResult(
            "baseline/greeting@main",
            status="untrusted",
            reason="timeout: no client response",
        )
    )
    return report


def sample_reports() -> list[Report]:
    """The two sample reports: `[failing, untrusted]`."""
    return [_failing_report(), _untrusted_report()]


def shape(value: Any) -> Any:
    """The structure of a view: objects keep keys, a list becomes one merged item."""
    if isinstance(value, dict):
        return {key: shape(item) for key, item in value.items()}
    if isinstance(value, list):
        merged: Any = None
        for item in value:
            merged = merge_shape(merged, shape(item))
        return [] if merged is None else [merged]
    return value


def merge_shape(a: Any, b: Any) -> Any:
    """Combine two shapes; a non-null side wins, objects merge key by key."""
    if a is None:
        return b
    if b is None:
        return a
    if isinstance(a, dict) and isinstance(b, dict):
        return {key: merge_shape(a.get(key), b.get(key)) for key in {**a, **b}}
    if isinstance(a, list) and isinstance(b, list):
        return shape([*a, *b])
    return a


def sample_shape() -> Any:
    """The merged shape of the two sample reports' views."""
    merged: Any = None
    for report in sample_reports():
        merged = merge_shape(merged, shape(view(report.to_dict())))
    return merged
