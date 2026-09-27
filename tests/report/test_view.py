from canarywire.report import Report
from canarywire.report.samples import sample_reports
from canarywire.report.view import view
from canarywire.runner.attacks import AttackResult, Mangled, Unrestored
from canarywire.runner.scan import Hit


def test_outcome_flags_counts_and_titles() -> None:
    data = view(sample_reports()[0].to_dict())
    assert data["failed"]
    assert not data["passed"]
    assert not data["untrusted"]
    assert data["outcome_upper"] == "FAIL"
    assert data["counts"]["findings"] == len(data["findings"])
    assert [f["number"] for f in data["findings"]] == list(range(1, len(data["findings"]) + 1))
    assert data["findings"][0]["title"] == "Leak"
    assert data["has_findings"] is True


def test_leaked_restored_attack_is_a_failure_with_text() -> None:
    report = Report(seed=1, target="t", capture_url="c", started_at="s")
    report.negative_control_caught = True
    attack = AttackResult("baseline/t@r", status="restored", upstream_requests=1, restored=1)
    attack.leaks.append(Hit("card", "4000", "body.tools[0].function.description", "t", "card"))
    report.attacks.append(attack)
    data = view(report.to_dict())
    (viewed,) = data["attacks"]
    assert viewed["ok"] is False
    assert viewed["failure"] == "Leak at body.tools[0].function.description"
    assert viewed["error"] is None
    assert data["counts"]["failures"] == 1
    assert data["counts"]["errors"] == 0


def test_caret_and_leak_line() -> None:
    finding = next(f for f in view(sample_reports()[0].to_dict())["findings"] if f["is_leak"])
    excerpt = finding["leak_excerpt"]
    assert finding["leak_caret"] == " " * len(excerpt["before"]) + "^" * len(excerpt["match"])


def test_generators_summary_and_run_texts() -> None:
    data = view(sample_reports()[0].to_dict())
    names = [g["name"] for g in data["generators"]]
    assert names == list(dict.fromkeys(a["generator"] for a in data["attacks"]))
    assert data["replay"].startswith(f"canarywire run --seed {data['seed']}")
    assert data["run"]["config_text"].endswith(")")


def test_untrusted_sample_has_run_problems() -> None:
    data = view(sample_reports()[1].to_dict())
    assert data["untrusted"]
    assert data["has_run_problems"]
    assert data["run_problem_count"] == len(data["run_problems"])
    assert data["junit_errors"] == data["counts"]["errors"] + data["run_problem_count"]
    assert data["junit_tests"] == data["counts"]["attacks"] + data["run_problem_count"]


def test_unrestored_finding_with_no_expected_has_no_evidence() -> None:
    report = Report(seed=1, target="t", capture_url="c", started_at="s")
    report.negative_control_caught = True
    attack = AttackResult("baseline/t@r", status="unrestored", upstream_requests=1)
    attack.unrestored.append(
        Unrestored("email", "a@example.org", "body.x", None, None, "t", "email")
    )
    report.attacks.append(attack)
    (finding,) = view(report.to_dict())["findings"]
    assert finding["diff_excerpt"] is None
    assert finding["leak_excerpt"] is None
    assert finding["placeholders"] == []
    assert finding["has_evidence"] is False


def test_leak_finding_with_excerpt_has_evidence() -> None:
    finding = next(f for f in view(sample_reports()[0].to_dict())["findings"] if f["is_leak"])
    assert finding["has_evidence"] is True


def test_mangled_finding_and_attack_view() -> None:
    report = Report(seed=1, target="t", capture_url="c", started_at="s")
    report.negative_control_caught = True
    attack = AttackResult("baseline/t@r", status="mangled", upstream_requests=1)
    attack.mangled.append(
        Mangled("body.x", "Send {{email}} the invoice.", "Send <EMAIL_1>ice.", "t")
    )
    report.attacks.append(attack)
    data = view(report.to_dict())

    (finding,) = data["findings"]
    assert finding["title"] == "Mangled request"
    assert finding["is_mangled"] is True
    assert finding["instances_text"] == ""
    assert finding["has_evidence"] is True

    (viewed,) = data["attacks"]
    assert viewed["ok"] is False
    assert viewed["failure"].startswith("Mangled request at ")
    assert data["counts"]["failures"] == 1
    assert data["counts"]["mangled"] == 1


def test_unexpected_leak_is_a_run_failure_counted_by_junit() -> None:
    report = Report(seed=1, target="t", capture_url="c", started_at="s")
    report.negative_control_caught = True
    report.attacks.append(
        AttackResult("baseline/t@r", status="restored", upstream_requests=1, restored=1)
    )
    report.unexpected_leaks.append(Hit("email", "a@example.org", "url", "t", "email"))
    data = view(report.to_dict())

    assert data["has_run_suite"] is True
    (failure,) = data["run_failures"]
    assert failure["name"] == "unexpected upstream request: url"
    assert failure["failure"] == "Leak at url"
    assert failure["failure_detail"] == "Leak at url"
    assert data["junit_failures"] == data["counts"]["failures"] + 1
    assert data["junit_tests"] == data["counts"]["attacks"] + 1
    assert data["junit_errors"] == data["counts"]["errors"]


def test_view_does_not_mutate_input() -> None:
    data = sample_reports()[0].to_dict()
    before = repr(data)
    view(data)
    assert repr(data) == before
