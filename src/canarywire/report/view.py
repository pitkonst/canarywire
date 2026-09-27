"""The report view model: display-ready fields layered over `Report.to_dict()`'s data."""

from __future__ import annotations

import copy
from collections import Counter
from datetime import datetime, timezone
from typing import Any

OK_STATUSES = ("restored", "delivered")
ACCEPTABLE_STATUSES = (*OK_STATUSES, "refused")
FAILING_STATUSES = ("unrestored", "altered", "inconsistent", "mangled")
FINDING_TITLES = {
    "leak": "Leak",
    "mangled": "Mangled request",
    "unrestored": "Not restored",
    "altered": "Altered",
    "inconsistent": "Inconsistent placeholders",
}
GENERATOR_ORDER = ("baseline", "fragmentation", "fault")


def view(data: dict[str, Any]) -> dict[str, Any]:
    """A display-ready copy of `data` (report.json's shape) with derived fields added.

    Never mutates `data`. Every object keeps a fixed key set: a value that does not apply
    is `None`, never a missing key.
    """
    data = copy.deepcopy(data)
    outcome = data["outcome"]
    findings = _view_findings(data["findings"])
    leaked_attacks = {leak["attack"] for leak in data["leaks"]}
    attacks = _view_attacks(data["attacks"], findings, leaked_attacks)
    problems = _view_problems(data["problems"])
    run_problems = [
        {"reason": p["reason"], "count": p["count"]} for p in problems if p["run_level"]
    ]
    run_failures = _run_failures(findings)
    counts = {
        "attacks": len(attacks),
        "findings": len(findings),
        "leaks": len(data["leaks"]),
        "unrestored": len(data["unrestored"]),
        "inconsistent": len(data["inconsistent"]),
        "mangled": len(data["mangled"]),
        "problems": len(problems),
        "verified": data["verified"],
        "failures": sum(1 for a in attacks if a["failure"] is not None),
        "errors": sum(1 for a in attacks if a["error"] is not None),
    }
    run = _view_run(data["run"])
    data.update(
        {
            "passed": outcome == "pass",
            "failed": outcome == "fail",
            "untrusted": outcome == "untrusted",
            "outcome_upper": outcome.upper(),
            "finished": _finished(data["finished_at"]),
            "findings": findings,
            "attacks": attacks,
            "problems": problems,
            "counts": counts,
            "generators": _view_generators(attacks),
            "run_problems": run_problems,
            "run_problem_count": len(run_problems),
            "has_findings": bool(findings),
            "has_problems": bool(problems),
            "has_faults": bool(data["faults"]),
            "has_run_problems": bool(run_problems),
            "run_failures": run_failures,
            "has_run_suite": bool(run_problems) or bool(run_failures),
            "run_suite_tests": len(run_problems) + len(run_failures),
            "run_suite_failures": len(run_failures),
            "run_suite_errors": len(run_problems),
            "junit_tests": counts["attacks"] + len(run_problems) + len(run_failures),
            "junit_failures": counts["failures"] + len(run_failures),
            "junit_errors": counts["errors"] + len(run_problems),
            "faults": _view_faults(data["faults"], attacks),
            "run": run,
            "replay": _replay(data["seed"], run),
        }
    )
    return data


def _finished(finished_at: str | None) -> str | None:
    """`finished_at` as `YYYY-MM-DD HH:MM UTC`; the raw string if it does not parse."""
    if finished_at is None:
        return None
    try:
        return (
            datetime.fromisoformat(finished_at)
            .astimezone(timezone.utc)
            .strftime("%Y-%m-%d %H:%M UTC")
        )
    except ValueError:
        return finished_at


def _view_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Every finding, numbered from 1, with its title and derived text fields."""
    return [_view_finding(number, finding) for number, finding in enumerate(findings, start=1)]


def _view_finding(number: int, finding: dict[str, Any]) -> dict[str, Any]:
    kind = finding["kind"]
    leak_excerpt = finding["leak_excerpt"]
    is_leak = kind == "leak"
    return {
        **finding,
        "number": number,
        "title": FINDING_TITLES[kind],
        "instances_text": ", ".join(finding["instances"]),
        "types_text": ", ".join(finding["types"]),
        "attacks_text": ", ".join(finding["attacks"]),
        "attack_count": len(finding["attacks"]),
        "is_leak": is_leak,
        "is_unrestored": kind in ("unrestored", "altered"),
        "is_inconsistent": kind == "inconsistent",
        "is_mangled": kind == "mangled",
        "leak_caret": (
            " " * len(leak_excerpt["before"]) + "^" * len(leak_excerpt["match"])
            if is_leak and leak_excerpt is not None
            else None
        ),
        "has_evidence": (
            leak_excerpt is not None
            or finding["diff_excerpt"] is not None
            or bool(finding["placeholders"])
        ),
    }


def _view_attacks(
    attacks: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    leaked_attacks: set[str],
) -> list[dict[str, Any]]:
    """Every attack with its generator, pass/fail verdict and failure text."""
    return [_view_attack(attack, findings, leaked_attacks) for attack in attacks]


def _view_attack(
    attack: dict[str, Any],
    findings: list[dict[str, Any]],
    leaked_attacks: set[str],
) -> dict[str, Any]:
    name = attack["name"]
    leaked = name in leaked_attacks
    is_failure = leaked or attack["status"] in FAILING_STATUSES
    matching = [finding for finding in findings if name in finding["attacks"]]
    failure = _failure_text(matching) if is_failure else None
    failure_detail = _failure_detail(matching) if is_failure else None
    return {
        **attack,
        "generator": name.split("/", 1)[0],
        "ok": attack["status"] in ACCEPTABLE_STATUSES and not leaked,
        "failure": failure,
        "failure_detail": failure_detail,
        "error": attack["reason"] if attack["status"] == "untrusted" and failure is None else None,
    }


def _failure_text(findings: list[dict[str, Any]]) -> str:
    """`"<title> at <location>"` for every finding, joined."""
    return "; ".join(f"{finding['title']} at {finding['location']}" for finding in findings)


def _failure_detail(findings: list[dict[str, Any]]) -> str:
    """Per listing finding, its title/location line followed by its evidence lines."""
    lines: list[str] = []
    for finding in findings:
        lines.append(f"{finding['title']} at {finding['location']}")
        lines.extend(_evidence_lines(finding))
    return "\n".join(lines)


def _evidence_lines(finding: dict[str, Any]) -> list[str]:
    """The evidence lines for one finding: an excerpt line, a diff or placeholder lines."""
    kind = finding["kind"]
    if kind == "leak" and finding["leak_excerpt"] is not None:
        excerpt = finding["leak_excerpt"]
        return [excerpt["before"] + excerpt["match"] + excerpt["after"]]
    if kind in ("unrestored", "altered", "mangled") and finding["diff_excerpt"] is not None:
        diff = finding["diff_excerpt"]
        return [f"expected: {diff['expected']}", f"actual:   {diff['actual']}"]
    if kind == "inconsistent":
        return [f"{p['placeholder']} at {p['path']}" for p in finding["placeholders"]]
    return []


def _run_failures(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One entry per finding attributed to an unexpected upstream request (no attacking attack)."""
    return [
        {
            "name": f"unexpected upstream request: {finding['location']}",
            "failure": _failure_text([finding]),
            "failure_detail": _failure_detail([finding]),
        }
        for finding in findings
        if "unexpected" in finding["attacks"]
    ]


def _view_problems(problems: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Every trust problem with its attacks joined into text."""
    return [{**problem, "attacks_text": ", ".join(problem["attacks"])} for problem in problems]


def _view_generators(attacks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One entry per generator, first-seen order, with totals and a status summary."""
    order: list[str] = []
    groups: dict[str, list[dict[str, Any]]] = {}
    for attack in attacks:
        name = attack["generator"]
        if name not in groups:
            groups[name] = []
            order.append(name)
        groups[name].append(attack)
    return [_generator_entry(name, groups[name]) for name in order]


def _generator_entry(name: str, attacks: list[dict[str, Any]]) -> dict[str, Any]:
    statuses = Counter(attack["status"] for attack in attacks)
    return {
        "name": name,
        "total": len(attacks),
        "failures": sum(1 for attack in attacks if attack["failure"] is not None),
        "errors": sum(1 for attack in attacks if attack["error"] is not None),
        "summary": ", ".join(f"{n} {status}" for status, n in sorted(statuses.items())),
        "attacks": attacks,
    }


def _view_faults(
    faults: list[dict[str, Any]], attacks: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Every fault with a one-line summary of its hooks and the attacks it faulted."""
    return [_view_fault(fault, attacks) for fault in faults]


def _view_fault(fault: dict[str, Any], attacks: list[dict[str, Any]]) -> dict[str, Any]:
    prefix = f"fault/{fault['name']}/"
    matching = [attack for attack in attacks if attack["name"].startswith(prefix)]
    hooks = f"{_hook_text('before', fault['before'])}, {_hook_text('after', fault['after'])}"
    suffix = (
        " — " + ", ".join(f"{attack['name']} {attack['status']}" for attack in matching)
        if matching
        else ""
    )
    return {**fault, "summary": hooks + suffix}


def _hook_text(name: str, hook: dict[str, Any] | None) -> str:
    """`"<name> not run"`, `"<name> timed out"` or `"<name> exit <code>"`."""
    if hook is None:
        return f"{name} not run"
    if hook["timed_out"]:
        return f"{name} timed out"
    return f"{name} exit {hook['exit']}"


def _view_run(run: dict[str, Any]) -> dict[str, Any]:
    """The run context with `config_text`, `routes_text` and `templates_text` added."""
    config = run["config"]
    config_text = "none" if config is None else f"{config['path']} ({config['sha256'][:12]})"
    routes_text = ", ".join(route["name"] for route in run["routes"])
    templates_text = ", ".join(dict.fromkeys(_enabled_templates(run["generators"])))
    return {
        **run,
        "config_text": config_text,
        "routes_text": routes_text,
        "templates_text": templates_text,
    }


def _enabled_templates(generators: dict[str, Any]) -> list[str]:
    """Templates of the enabled generators, in order baseline, fragmentation, fault."""
    templates: list[str] = []
    for name in GENERATOR_ORDER:
        settings = generators[name]
        if settings["enabled"]:
            templates.extend(settings["templates"])
    return templates


def _replay(seed: int, run: dict[str, Any]) -> str:
    """The CLI command that replays this run's seed (and config, if one was used)."""
    text = f"canarywire run --seed {seed}"
    config = run["config"]
    if config is not None:
        text += f" --config {config['path']}"
    return text
