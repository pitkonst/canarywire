from typing import Any

from canarywire.report.findings import (
    Excerpt,
    diff_excerpt,
    group_findings,
    group_problems,
    leak_excerpt,
    one_line,
    route_of,
)


def test_leak_excerpt_short_text_has_no_cut_marks() -> None:
    assert leak_excerpt("mail a@x.org now", "a@x.org") == Excerpt("mail ", "a@x.org", " now")


def test_leak_excerpt_cuts_to_40_each_side() -> None:
    text = "L" * 50 + "VALUE" + "R" * 50
    got = leak_excerpt(text, "VALUE")
    assert got == Excerpt("…" + "L" * 40, "VALUE", "R" * 40 + "…")


def test_leak_excerpt_uses_first_occurrence_and_one_line() -> None:
    got = leak_excerpt("a\tb\nVAL\x00VAL", "VAL")
    assert got == Excerpt("a⇥b⏎", "VAL", "�VAL")


def test_one_line() -> None:
    assert one_line("x\ny\tz\x07") == "x⏎y⇥z�"


def test_diff_excerpt_windows_around_first_difference() -> None:
    expected = "p" * 60 + "DE18782399793050373548 sent"
    actual = "p" * 60 + "<IBAN_CODE> sent"
    got = diff_excerpt(expected, actual)
    assert got == {
        "expected": "…" + "p" * 40 + "DE18782399793050373548 sent",
        "actual": "…" + "p" * 40 + "<IBAN_CODE> sent",
    }


def test_diff_excerpt_cuts_the_tail() -> None:
    got = diff_excerpt("A" + "x" * 60, "B" + "x" * 60)
    assert got == {"expected": "A" + "x" * 40 + "…", "actual": "B" + "x" * 40 + "…"}


def test_diff_excerpt_prefix_and_none() -> None:
    assert diff_excerpt("abc", "abcd") == {"expected": "abc", "actual": "abcd"}
    assert diff_excerpt(None, "x") is None
    assert diff_excerpt("x", None) is None


def test_route_of() -> None:
    assert route_of("baseline/default@openai-chat") == "openai-chat"
    assert route_of("fragmentation/default@openai-chat/chunks:2@1") == "openai-chat"
    assert route_of("fault/analyzer-down/default@claude") == "claude"
    assert route_of("unexpected") is None
    assert route_of("baseline") is None


def leak(attack: str, canary: str, location: str, template: str = "t") -> dict[str, Any]:
    return {
        "attack": attack,
        "canary": canary,
        "value": "v",
        "location": location,
        "template": template,
        "type": canary,
        "excerpt": {"before": "b", "match": "v", "after": "a"},
    }


def unrestored(attack: str, canary: str, location: str) -> dict[str, Any]:
    return {
        "attack": attack,
        "canary": canary,
        "value": "v",
        "location": location,
        "expected": "e",
        "actual": "a",
        "template": "t",
        "type": canary,
        "note": None,
        "excerpt": {"expected": "e", "actual": "a"},
    }


def mangled(attack: str, location: str, template: str = "t") -> dict[str, Any]:
    return {
        "attack": attack,
        "location": location,
        "expected": "e",
        "actual": "a",
        "template": template,
        "excerpt": {"expected": "e", "actual": "a"},
    }


def test_groups_by_kind_template_route_location_in_order() -> None:
    found = group_findings(
        [leak("baseline/t@r", "card", "body.x"), leak("baseline/t@r", "iban", "body.x")],
        [
            unrestored("fragmentation/t@r/c1", "email", "stream.s"),
            unrestored("fragmentation/t@r/c2", "email", "stream.s"),
            unrestored("baseline/t@r", "email", "body.y"),
        ],
        [],
        "restore",
        [],
    )
    assert [(f["kind"], f["location"], f["attacks"]) for f in found] == [
        ("leak", "body.x", ["baseline/t@r"]),
        ("unrestored", "stream.s", ["fragmentation/t@r/c1", "fragmentation/t@r/c2"]),
        ("unrestored", "body.y", ["baseline/t@r"]),
    ]
    first = found[0]
    assert first["instances"] == ["card", "iban"]
    assert first["occurrences"] == 2
    assert first["route"] == "r"
    assert first["leak_excerpt"] == {"before": "b", "match": "v", "after": "a"}
    assert first["diff_excerpt"] is None
    assert first["placeholders"] == []
    assert found[1]["diff_excerpt"] == {"expected": "e", "actual": "a"}
    assert found[1]["leak_excerpt"] is None


def test_altered_under_mask_only_and_inconsistent_placeholders() -> None:
    inconsistent = {
        "attack": "baseline/mt@r",
        "template": "mt",
        "instance": "email",
        "type": "email",
        "occurrences": [
            {"path": "body.a", "placeholder": "<E1>"},
            {"path": "body.b", "placeholder": "<E2>"},
        ],
    }
    found = group_findings(
        [], [unrestored("baseline/t@r", "email", "body.y")], [inconsistent], "mask-only", []
    )
    assert [f["kind"] for f in found] == ["altered", "inconsistent"]
    assert found[1]["location"] == "body.a"
    assert found[1]["instances"] == ["email"]
    assert found[1]["placeholders"] == [
        {"placeholder": "<E1>", "path": "body.a"},
        {"placeholder": "<E2>", "path": "body.b"},
    ]


def test_unexpected_leak_has_no_route() -> None:
    (finding,) = group_findings([leak("unexpected", "email", "url")], [], [], "restore", [])
    assert finding["route"] is None


def test_mangled_finding_has_no_instances_or_types() -> None:
    item = mangled("baseline/t@r", "body.x")
    (finding,) = group_findings([], [], [], "restore", [item])
    assert finding["kind"] == "mangled"
    assert finding["instances"] == []
    assert finding["types"] == []
    assert finding["diff_excerpt"] == item["excerpt"]
    assert finding["leak_excerpt"] is None
    assert finding["placeholders"] == []


def test_mangled_ranks_between_leak_and_unrestored() -> None:
    found = group_findings(
        [leak("baseline/t@r", "card", "body.x")],
        [unrestored("baseline/t@r", "email", "body.y")],
        [],
        "restore",
        [mangled("baseline/t@r", "body.z")],
    )
    assert [f["kind"] for f in found] == ["leak", "mangled", "unrestored"]


def test_group_problems_separates_run_level_from_attack_reasons() -> None:
    groups = group_problems(
        [
            ("timeout", True, None),
            ("timeout", False, "baseline/a@r"),
            ("timeout", False, "baseline/b@r"),
            ("timeout", True, None),
            ("negative control did not run", True, None),
        ]
    )
    assert groups == [
        {"reason": "timeout", "run_level": True, "attacks": [], "count": 2},
        {
            "reason": "timeout",
            "run_level": False,
            "attacks": ["baseline/a@r", "baseline/b@r"],
            "count": 2,
        },
        {"reason": "negative control did not run", "run_level": True, "attacks": [], "count": 1},
    ]
