from typing import Any

from canarywire.canaries import Canary
from canarywire.config import DEFAULT_ROUTES
from canarywire.runner.catalog import Occurrence, parse_template
from canarywire.runner.consistency import (
    Inconsistent,
    Seen,
    add_note,
    collision_notes,
    inconsistencies,
)
from canarywire.runner.prepare import BoundTemplate


def bound(consistency: str = "required") -> BoundTemplate:
    raw: dict[str, Any] = {
        "protocol": "openai-chat",
        "consistency": consistency,
        "canaries": {"email": "email", "colleague": "email"},
        "request": {"messages": [{"content": "{{ email.raw }} and {{ colleague.raw }}"}]},
        "response": {"choices": [{"message": {"content": "{{ email.masked }}"}}]},
    }
    template = parse_template("mt", raw)
    return BoundTemplate(
        template,
        (
            Canary("email", "ann@example.org", "email", "mt"),
            Canary("colleague", "bob@example.org", "email", "mt"),
        ),
        DEFAULT_ROUTES[0],
    )


A = "body.messages[0].content"
B = "body.messages[2].content"


def test_different_placeholders_are_inconsistent() -> None:
    occurrences = [
        Occurrence("email", A, "<EMAIL_1>"),
        Occurrence("colleague", A, "<EMAIL_2>"),
        Occurrence("email", B, "<EMAIL_3>"),
    ]
    assert inconsistencies(occurrences, bound()) == [
        Inconsistent("mt", "email", "email", (Seen(A, "<EMAIL_1>"), Seen(B, "<EMAIL_3>")))
    ]


def test_ignore_records_nothing() -> None:
    occurrences = [Occurrence("email", A, "<E1>"), Occurrence("email", B, "<E2>")]
    assert inconsistencies(occurrences, bound("ignore")) == []


def test_same_placeholder_everywhere_is_consistent() -> None:
    occurrences = [Occurrence("email", A, "<E1>"), Occurrence("email", B, "<E1>")]
    assert inconsistencies(occurrences, bound()) == []


def test_collision_notes() -> None:
    occurrences = [
        Occurrence("email", A, "<EMAIL_1>"),
        Occurrence("colleague", B, "<EMAIL_1>"),
        Occurrence("email", B, "<EMAIL_1>"),
    ]
    note = "instances colleague, email were masked to the same placeholder <EMAIL_1>"
    assert collision_notes(occurrences) == {"email": note, "colleague": note}


def test_no_collision_no_notes() -> None:
    occurrences = [Occurrence("email", A, "<E1>"), Occurrence("colleague", A, "<E2>")]
    assert collision_notes(occurrences) == {}


def test_add_note() -> None:
    assert add_note(None, None) is None
    assert add_note(None, "b") == "b"
    assert add_note("a", None) == "a"
    assert add_note("a", "b") == "a; b"
