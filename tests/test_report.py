import json
from pathlib import Path

import pytest

from canarywire.config import ReportSettings
from canarywire.report import EXIT_CODES, Report, decide
from canarywire.report.findings import diff_excerpt
from canarywire.report.mustache import Template
from canarywire.report.outputs import ResolvedOutput, load_outputs, resolve_outputs, write
from canarywire.runner.attacks import AttackResult, Mangled, Unrestored
from canarywire.runner.consistency import Inconsistent, Seen
from canarywire.runner.fault import FaultRecord
from canarywire.runner.hooks import HookResult
from canarywire.runner.scan import Hit


@pytest.mark.parametrize(
    ("leaks", "problems", "unrestored", "outcome"),
    [
        (True, ["x"], True, "fail"),
        (False, ["x"], True, "untrusted"),
        (False, [], True, "fail"),
        (False, [], False, "pass"),
    ],
)
def test_decide_order(leaks: bool, problems: list[str], unrestored: bool, outcome: str) -> None:
    assert decide(leaks=leaks, problems=problems, unrestored=unrestored) == outcome


def test_exit_codes() -> None:
    assert EXIT_CODES == {"pass": 0, "fail": 1, "untrusted": 2}


def test_inconsistent_fails_after_leaks_and_trust_problems() -> None:
    assert decide(leaks=False, problems=[], unrestored=False, inconsistent=True) == "fail"
    assert decide(leaks=False, problems=["x"], unrestored=False, inconsistent=True) == "untrusted"
    assert decide(leaks=True, problems=["x"], unrestored=False, inconsistent=True) == "fail"


def test_mangled_fails_after_leaks_and_trust_problems() -> None:
    assert decide(leaks=False, problems=[], unrestored=False, mangled=True) == "fail"
    assert decide(leaks=False, problems=["x"], unrestored=False, mangled=True) == "untrusted"
    assert decide(leaks=True, problems=["x"], unrestored=False, mangled=True) == "fail"


def mangled_report() -> tuple[Report, AttackResult]:
    report = Report(seed=1, target="t", capture_url="c", started_at="s")
    report.negative_control_caught = True
    attack = AttackResult("baseline/mt", status="mangled", client_status=200)
    attack.upstream_requests = 1
    attack.mangled = [Mangled("body.x", "Send {{email}} the invoice.", "Send <EMAIL_1>ice.", "mt")]
    report.attacks.append(attack)
    return report, attack


def test_mangled_alone_fails_the_run() -> None:
    report, _ = mangled_report()
    assert report.outcome() == "fail"


def test_report_lists_mangled_with_excerpt() -> None:
    report, item = mangled_report()
    data = report.to_dict()
    assert data["version"] == 4
    assert data["outcome"] == "fail"
    (entry,) = data["mangled"]
    assert entry["attack"] == "baseline/mt"
    assert entry["template"] == "mt"
    assert entry["expected"] == item.mangled[0].expected
    assert entry["actual"] == item.mangled[0].actual
    assert entry["excerpt"] == diff_excerpt(item.mangled[0].expected, item.mangled[0].actual)


def test_mangled_key_follows_inconsistent() -> None:
    report, _ = mangled_report()
    keys = list(report.to_dict())
    assert keys[keys.index("inconsistent") + 1] == "mangled"


def test_mangled_ranks_below_trust_problems_and_above_pass() -> None:
    report, attack = mangled_report()
    assert report.outcome() == "fail"

    report.trust_problems.append("some trust problem")
    assert report.outcome() == "untrusted"

    report.trust_problems = []
    attack.leaks.append(Hit("email", "a@example.org", "body.x"))
    assert report.outcome() == "fail"


def inconsistent_report() -> tuple[Report, AttackResult]:
    report = Report(seed=1, target="t", capture_url="c", started_at="s")
    report.negative_control_caught = True
    attack = AttackResult("baseline/mt", status="inconsistent", client_status=200)
    attack.upstream_requests = 1
    attack.inconsistent = [
        Inconsistent("mt", "email", "email", (Seen("body.a", "<E1>"), Seen("body.b", "<E2>")))
    ]
    attack.unrestored = [
        Unrestored("email", "ann@example.org", "body.x", "e", "a", "mt", "email", "a note")
    ]
    report.attacks.append(attack)
    return report, attack


def test_report_lists_inconsistent_and_notes() -> None:
    report, _ = inconsistent_report()
    data = report.to_dict()
    assert data["outcome"] == "fail"
    assert data["inconsistent"] == [
        {
            "attack": "baseline/mt",
            "template": "mt",
            "instance": "email",
            "type": "email",
            "occurrences": [
                {"path": "body.a", "placeholder": "<E1>"},
                {"path": "body.b", "placeholder": "<E2>"},
            ],
        }
    ]
    assert data["unrestored"][0]["note"] == "a note"
    json.dumps(data)  # serialisable


def test_inconsistent_alone_fails_the_run() -> None:
    report, attack = inconsistent_report()
    attack.unrestored = []
    assert report.outcome() == "fail"


def sample() -> Report:
    baseline = AttackResult(
        "baseline", status="unrestored", client_status=200, upstream_requests=2, restored=1
    )
    baseline.leaks.append(Hit("email", "a@example.org", "body.messages[0].content"))
    baseline.unrestored.append(
        Unrestored("email", "a@example.org", "body.x", "To a@example.org", "To <E>")
    )
    report = Report(
        seed=5, target="http://gw", capture_url="http://cap", started_at="2026-09-24T00:00:00+00:00"
    )
    report.negative_control_caught = True
    report.attacks.append(baseline)
    report.unexpected_upstream = 1
    report.unexpected_leaks.append(Hit("email", "a@example.org", "url"))
    return report


def test_to_dict() -> None:
    data = sample().to_dict()
    assert data["version"] == 4
    assert data["outcome"] == "fail"
    assert data["reason"] is None
    assert data["seed"] == 5
    assert data["capture"] == {"url": "http://cap", "requests": 2, "unexpected_upstream": 1}
    assert data["negative_control"] == {"caught": True, "templates": []}
    assert data["canaries"] == []
    assert data["verified"] == 1
    assert data["leaks"] == [
        {
            "attack": "baseline",
            "canary": "email",
            "value": "a@example.org",
            "location": "body.messages[0].content",
            "template": "",
            "type": "",
            "excerpt": None,
        },
        {
            "attack": "unexpected",
            "canary": "email",
            "value": "a@example.org",
            "location": "url",
            "template": "",
            "type": "",
            "excerpt": None,
        },
    ]
    assert data["unrestored"][0]["attack"] == "baseline"
    assert data["unrestored"][0]["excerpt"] == {
        "expected": "To a@example.org",
        "actual": "To <E>",
    }
    assert data["leaks"][0]["excerpt"] is None
    assert [(f["kind"], f["location"]) for f in data["findings"]] == [
        ("leak", "body.messages[0].content"),
        ("leak", "url"),
        ("unrestored", "body.x"),
    ]
    assert data["attacks"] == [
        {
            "name": "baseline",
            "status": "unrestored",
            "client_status": 200,
            "upstream_requests": 2,
            "reason": None,
            "upstream_aborted": None,
        }
    ]


def test_untrusted_attack_is_a_trust_problem() -> None:
    report = Report(seed=1, target="t", capture_url="c", started_at="s")
    attack = AttackResult("baseline")
    attack.untrusted("no upstream traffic")
    report.negative_control_caught = True
    report.attacks.append(attack)
    assert report.outcome() == "untrusted"
    assert report.to_dict()["reason"] == "baseline: no upstream traffic"
    (problem,) = report.to_dict()["problems"]
    assert problem["attacks"] == ["baseline"]
    assert report.problems() == ["baseline: no upstream traffic"]


def test_untrusted_attack_without_a_reason_is_named_not_blank() -> None:
    report = Report(seed=1, target="t", capture_url="c", started_at="s")
    report.negative_control_caught = True
    report.attacks.append(AttackResult("baseline"))  # never settled: untrusted, reason None
    (problem,) = report.to_dict()["problems"]
    assert problem["reason"] == "no reason recorded"
    assert report.problems() == ["baseline: no reason recorded"]


def test_empty_report_is_untrusted() -> None:
    report = Report(seed=1, target="t", capture_url="c", started_at="s")
    assert report.outcome() == "untrusted"
    assert "negative control did not run" in report.problems()
    assert "no attack ran" in report.problems()
    assert report.to_dict()["reason"] == report.problems()[0]
    data = report.to_dict()
    reasons = {(p["reason"], p["run_level"]) for p in data["problems"]}
    assert reasons == {("negative control did not run", True), ("no attack ran", True)}


def _default_loaded(out_dir: Path) -> list[tuple[ResolvedOutput, Template]]:
    return load_outputs(resolve_outputs(ReportSettings(), out_dir, None), None)


def test_write(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    path, errors = write(sample(), out_dir, _default_loaded(out_dir))
    assert errors == []
    assert json.loads(path.read_text())["outcome"] == "fail"
    markdown = (tmp_path / "out" / "report.md").read_text()
    assert markdown.startswith("# canarywire: FAIL")
    assert "body.messages[0].content" in markdown


def test_upstream_aborted_recorded_for_refused_attack() -> None:
    report = Report(seed=1, target="t", capture_url="c", started_at="s")
    report.negative_control_caught = True
    report.attacks += [
        AttackResult("baseline", status="restored", upstream_requests=1, restored=1),
        AttackResult("fragmentation/baseline", status="restored", upstream_requests=1, restored=1),
        AttackResult(
            "fragmentation/chunks:2@1",
            status="refused",
            upstream_requests=1,
            reason="refused with HTTP 502",
            upstream_aborted="2/5",
        ),
    ]
    attack = report.to_dict()["attacks"][2]
    assert attack["upstream_aborted"] == "2/5"
    assert report.outcome() == "pass"  # refused is acceptable


def fault_report() -> Report:
    report = Report(seed=1, target="t", capture_url="c", started_at="s")
    report.negative_control_caught = True
    report.attacks.append(
        AttackResult(
            "fault/down/default",
            status="refused",
            client_status=503,
            reason="refused with HTTP 503",
        )
    )
    report.faults = [
        FaultRecord(
            "down",
            ("refuse",),
            HookResult(0, False, 5, "faults/down.before.log"),
            HookResult(None, True, 60000, "faults/down.after.log"),
        ),
        FaultRecord("later", ("refuse", "restore")),
    ]
    return report


def test_faults_in_json() -> None:
    data = fault_report().to_dict()
    assert data["faults"] == [
        {
            "name": "down",
            "expect": ["refuse"],
            "before": {
                "exit": 0,
                "timed_out": False,
                "duration_ms": 5,
                "log": "faults/down.before.log",
            },
            "after": {
                "exit": None,
                "timed_out": True,
                "duration_ms": 60000,
                "log": "faults/down.after.log",
            },
        },
        {"name": "later", "expect": ["refuse", "restore"], "before": None, "after": None},
    ]
    keys = list(data)
    assert keys[keys.index("attacks") + 1] == "faults"
    json.dumps(data)


def test_refused_counts_as_passing() -> None:
    report = Report(seed=1, target="t", capture_url="c", started_at="s")
    report.negative_control_caught = True
    report.attacks.append(AttackResult("fault/d/default", status="refused", client_status=503))
    assert report.outcome() == "pass"


def test_no_faults_key_is_empty_list() -> None:
    assert sample().to_dict()["faults"] == []


# --- duty and version 2 -------------------------------------------------


def test_duty_follows_outcome_and_reason_and_verified_replaces_restored() -> None:
    data = sample().to_dict()
    keys = list(data)
    assert keys[:4] == ["version", "outcome", "reason", "duty"]
    assert data["duty"] == "restore"
    assert "restored" not in data
    assert data["verified"] == 1


def mask_only_report(*statuses: str) -> Report:
    report = Report(seed=1, target="t", capture_url="c", started_at="s", duty="mask-only")
    report.negative_control_caught = True
    report.attacks += [
        AttackResult(f"baseline/{i}", status=s, upstream_requests=1, restored=1)
        for i, s in enumerate(statuses)
    ]
    return report


def test_mask_only_duty_in_json() -> None:
    report = mask_only_report("delivered", "delivered")
    assert report.to_dict()["duty"] == "mask-only"
    assert report.to_dict()["verified"] == 2
    assert report.outcome() == "pass"


def test_altered_value_fails_under_mask_only_duty() -> None:
    report = mask_only_report("delivered", "altered")
    report.attacks[1].unrestored.append(
        Unrestored("email", "a@example.org", "body.x", "To <E1>", "To a@example.org")
    )
    assert report.outcome() == "fail"


def test_mask_only_duty_renders_altered_heading(tmp_path: Path) -> None:
    report = mask_only_report("delivered", "altered")
    report.attacks[1].unrestored.append(
        Unrestored("email", "a@example.org", "body.x", "To <E1>", "To a@example.org")
    )
    out_dir = tmp_path / "out"
    write(report, out_dir, _default_loaded(out_dir))
    markdown = (tmp_path / "out" / "report.md").read_text()
    assert "### 1. Altered:" in markdown
