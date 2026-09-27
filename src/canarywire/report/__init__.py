"""The run report: its data, the outcome decision and the report.json document (`to_dict`).

Writing report.json and the configured outputs lives in `canarywire.report.outputs`.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from importlib import resources
from typing import TYPE_CHECKING, Any

from canarywire.config import Config
from canarywire.report.context import run_context
from canarywire.report.findings import diff_excerpt, group_findings, group_problems

if TYPE_CHECKING:
    from collections.abc import Sequence

    from canarywire.canaries import Canary
    from canarywire.runner.attacks import AttackResult, NegativeControl
    from canarywire.runner.fault import FaultRecord
    from canarywire.runner.hooks import HookResult
    from canarywire.runner.scan import Hit

PASS = "pass"  # noqa: S105 - a verdict name, not a credential
FAIL = "fail"
UNTRUSTED = "untrusted"
EXIT_CODES = {PASS: 0, FAIL: 1, UNTRUSTED: 2}
REPORT_VERSION = 4
NO_REASON = "no reason recorded"  # an untrusted attack that never set one
BUILTINS = {"builtin:markdown": "markdown.md.mustache", "builtin:junit": "junit.xml.mustache"}


def builtin_source(name: str) -> str:
    """The Mustache source of a built-in template, read from package data."""
    file = BUILTINS[name]
    return (resources.files("canarywire.report") / "templates" / file).read_text()


def decide(
    *,
    leaks: bool,
    problems: Sequence[str],
    unrestored: bool,
    inconsistent: bool = False,
    mangled: bool = False,
) -> str:
    """Verdict order: any leak, trust problem, unrestored/inconsistent/mangled value, then pass.

    `unrestored` covers `altered` values too: under duty `mask-only` they share the list.
    """
    if leaks:
        return FAIL
    if problems:
        return UNTRUSTED
    if unrestored or inconsistent or mangled:
        return FAIL
    return PASS


def now_iso() -> str:
    """Current UTC time, ISO 8601, seconds precision."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Report:
    """Everything one run observed; the outcome is derived, never stored."""

    seed: int
    target: str
    capture_url: str
    started_at: str = field(default_factory=now_iso)
    finished_at: str | None = None
    negative_control_caught: bool = False
    negative_controls: list[NegativeControl] = field(default_factory=list)
    canaries: list[Canary] = field(default_factory=list)
    attacks: list[AttackResult] = field(default_factory=list)
    unexpected_upstream: int = 0
    unexpected_leaks: list[Hit] = field(default_factory=list)
    trust_problems: list[str] = field(default_factory=list)
    faults: list[FaultRecord] = field(default_factory=list)
    interrupted: int | None = None
    duty: str = "restore"
    run: dict[str, Any] = field(default_factory=lambda: run_context(Config(), None))

    def problem_entries(self) -> list[tuple[str, bool, str | None]]:
        """Every trust problem as (reason, run_level, attack): the run's, attacks', then checks."""
        entries: list[tuple[str, bool, str | None]] = [(p, True, None) for p in self.trust_problems]
        entries += [
            (a.reason or NO_REASON, False, a.name) for a in self.attacks if a.status == UNTRUSTED
        ]
        if not self.negative_control_caught:
            entries.append(("negative control did not run", True, None))
        if not self.attacks:
            entries.append(("no attack ran", True, None))
        return entries

    def problems(self) -> list[str]:
        """Trust problems: the run's own, its untrusted attacks', then defense-in-depth checks.

        A `pass` verdict is only trustworthy if the negative control ran and was caught and at
        least one attack actually ran; otherwise it is flagged here so `decide` never passes it.
        """
        return [
            reason if attack is None else f"{attack}: {reason}"
            for reason, _, attack in self.problem_entries()
        ]

    def leaks(self) -> list[dict[str, Any]]:
        """Every canary hit upstream, attributed to its attack."""
        return [
            *({"attack": a.name, **asdict(hit)} for a in self.attacks for hit in a.leaks),
            *({"attack": "unexpected", **asdict(hit)} for hit in self.unexpected_leaks),
        ]

    def unrestored(self) -> list[dict[str, Any]]:
        """Every value that did not come back restored, attributed to its attack."""
        return [
            {"attack": a.name, **asdict(item), "excerpt": diff_excerpt(item.expected, item.actual)}
            for a in self.attacks
            for item in a.unrestored
        ]

    def inconsistent(self) -> list[dict[str, Any]]:
        """Every instance masked to several placeholders, attributed to its attack."""
        return [
            {
                "attack": a.name,
                **asdict(item),
                "occurrences": [asdict(seen) for seen in item.occurrences],
            }
            for a in self.attacks
            for item in a.inconsistent
        ]

    def mangled(self) -> list[dict[str, Any]]:
        """Every request string the gateway changed around a canary, attributed to its attack."""
        return [
            {"attack": a.name, **asdict(item), "excerpt": diff_excerpt(item.expected, item.actual)}
            for a in self.attacks
            for item in a.mangled
        ]

    def outcome(self) -> str:
        """`pass`, `fail` or `untrusted`."""
        return decide(
            leaks=bool(self.leaks()),
            problems=self.problems(),
            unrestored=bool(self.unrestored()),
            inconsistent=bool(self.inconsistent()),
            mangled=bool(self.mangled()),
        )

    def to_dict(self) -> dict[str, Any]:
        """The report.json document."""
        problems = self.problems()
        outcome = self.outcome()
        leaks = self.leaks()
        unrestored = self.unrestored()
        inconsistent = self.inconsistent()
        mangled = self.mangled()
        return {
            "version": REPORT_VERSION,
            "outcome": outcome,
            "reason": problems[0] if outcome == UNTRUSTED and problems else None,
            "duty": self.duty,
            "seed": self.seed,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "target": self.target,
            "run": self.run,
            "capture": {
                "url": self.capture_url,
                "requests": sum(a.upstream_requests for a in self.attacks),
                "unexpected_upstream": self.unexpected_upstream,
            },
            "negative_control": {
                "caught": self.negative_control_caught,
                "templates": [
                    {"template": c.template, "caught": c.caught, "missed": list(c.missed)}
                    for c in self.negative_controls
                ],
            },
            "canaries": [
                {"template": c.template, "instance": c.name, "type": c.type, "value": c.value}
                for c in self.canaries
            ],
            "verified": sum(a.restored for a in self.attacks),
            "leaks": leaks,
            "unrestored": unrestored,
            "inconsistent": inconsistent,
            "mangled": mangled,
            "findings": group_findings(leaks, unrestored, inconsistent, self.duty, mangled),
            "problems": group_problems(self.problem_entries()),
            "attacks": [
                {
                    "name": a.name,
                    "status": a.status,
                    "client_status": a.client_status,
                    "upstream_requests": a.upstream_requests,
                    "reason": a.reason,
                    "upstream_aborted": a.upstream_aborted,
                }
                for a in self.attacks
            ],
            "faults": [_fault_dict(record) for record in self.faults],
        }


def _fault_dict(record: FaultRecord) -> dict[str, Any]:
    return {
        "name": record.name,
        "expect": list(record.expect),
        "before": _hook_dict(record.before),
        "after": _hook_dict(record.after),
    }


def _hook_dict(hook: HookResult | None) -> dict[str, Any] | None:
    return None if hook is None else asdict(hook)
