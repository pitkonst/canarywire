import hashlib
import re
from dataclasses import replace
from pathlib import Path

import pytest

from canarywire.config import (
    BaselineSettings,
    ChunksSettings,
    Config,
    ConfigError,
    DelaySettings,
    FaultSettings,
    FaultSpec,
    FragmentationSettings,
    Generators,
    OutputSpec,
    RandomChunksSettings,
    RandomCutsSettings,
    ReportSettings,
    Route,
    Timeouts,
    fault_generator_runs,
    load,
    override,
    parse,
    parse_generator_names,
    parse_listen,
)


def test_no_file_means_defaults() -> None:
    assert load(None) == Config()


@pytest.mark.real_delays
def test_load_full_file(tmp_path: Path) -> None:
    path = tmp_path / "canarywire.yaml"
    path.write_text(
        "seed: 7\n"
        "capture:\n  url: http://capture:1\n"
        "target:\n  base_url: http://gateway:2\n"
        "timeouts:\n  client_request: 12\n  stop_grace: 0.5\n"
    )
    assert load(path) == Config(
        seed=7,
        capture_url="http://capture:1",
        target_url="http://gateway:2",
        timeouts=Timeouts(client_request=12.0, stop_grace=0.5),
        config_dir=tmp_path,
        config_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
    )


@pytest.mark.real_delays
def test_empty_file_means_defaults(tmp_path: Path) -> None:
    path = tmp_path / "canarywire.yaml"
    path.write_text("")
    assert load(path) == Config(config_dir=tmp_path, config_sha256=hashlib.sha256(b"").hexdigest())


def test_load_sets_config_dir_to_the_files_parent(tmp_path: Path) -> None:
    path = tmp_path / "canarywire.yaml"
    path.write_text("")
    assert load(path).config_dir == tmp_path
    assert load(None).config_dir is None


def test_load_hashes_the_bytes_it_parsed_and_override_keeps_it(tmp_path: Path) -> None:
    path = tmp_path / "canarywire.yaml"
    data = b"seed: 3\n# synthetic comment\n"
    path.write_bytes(data)
    config = load(path)
    assert config.config_sha256 == hashlib.sha256(data).hexdigest()
    assert override(config, seed=4, target_url="http://gw").config_sha256 == config.config_sha256
    assert replace(config, seed=5).config_sha256 == config.config_sha256
    assert load(None).config_sha256 is None


def test_cli_flags_override_file() -> None:
    base = Config(
        seed=1,
        capture_url="http://file",
        target_url="http://file-target",
        timeouts=Timeouts(client_request=3.0),
    )
    merged = override(
        base,
        seed=2,
        target_url="http://cli",
        timeouts={"client_request": None, "stop_grace": 4.0},
    )
    assert merged == Config(
        seed=2,
        capture_url="http://file",
        target_url="http://cli",
        timeouts=Timeouts(client_request=3.0, stop_grace=4.0),
    )


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ([], "<root>: expected a mapping"),
        ({"bogus": 1}, "bogus: unknown key"),
        ({"seed": "x"}, "seed: expected an integer"),
        ({"seed": True}, "seed: expected an integer"),
        ({"capture": {"port": 1}}, "capture.port: unknown key"),
        ({"capture": {"url": ""}}, "capture.url: expected a non-empty string"),
        ({"target": "http://x"}, "target: expected a mapping"),
        (
            {"timeouts": {"client_request": 0}},
            "timeouts.client_request: expected a positive number",
        ),
        (
            {"timeouts": {"client_request": "5"}},
            "timeouts.client_request: expected a positive number",
        ),
        ({"timeouts": {"nap": 5}}, "timeouts.nap: unknown key"),
    ],
)
def test_validation_errors_name_the_key(raw: object, message: str) -> None:
    with pytest.raises(ConfigError, match=f"^{re.escape(message)}$"):
        parse(raw)


def test_invalid_yaml(tmp_path: Path) -> None:
    path = tmp_path / "canarywire.yaml"
    path.write_text("a: [\n")
    with pytest.raises(ConfigError, match="invalid YAML"):
        load(path)


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="cannot read"):
        load(tmp_path / "missing.yaml")


def test_parse_listen() -> None:
    assert parse_listen("127.0.0.1:8765") == ("127.0.0.1", 8765)


@pytest.mark.parametrize("value", ["localhost", ":80", "h:0", "h:70000", "h:x"])
def test_parse_listen_rejects(value: str) -> None:
    with pytest.raises(ConfigError, match="expected HOST:PORT"):
        parse_listen(value)


@pytest.mark.real_delays
def test_generator_defaults() -> None:
    config = parse({})
    assert config.generators == Generators()
    assert config.generators.fragmentation.cases == (
        "baseline",
        "chunks",
        "random-chunks",
        "random-cuts",
    )
    assert config.timeouts.upstream_done == 2.0


def test_generators_from_file() -> None:
    config = parse(
        {
            "generators": {
                "baseline": {"enabled": False},
                "fragmentation": {
                    "cases": ["baseline", "chunks"],
                    "chunks": {"sizes": [3], "phases": "first"},
                    "random_chunks": {"samples": 2, "min": 2, "max": 3},
                    "random_cuts": {"samples": 1, "max_cuts": 2},
                    "delay_ms": {"min": 1, "max": 1},
                },
            },
            "timeouts": {"upstream_done": 0.5},
        }
    )
    assert config.generators == Generators(
        baseline=BaselineSettings(enabled=False),
        fragmentation=FragmentationSettings(
            cases=("baseline", "chunks"),
            chunks=ChunksSettings(sizes=(3,), phases="first"),
            random_chunks=RandomChunksSettings(samples=2, min_size=2, max_size=3),
            random_cuts=RandomCutsSettings(samples=1, max_cuts=2),
            delay=DelaySettings(min_ms=1, max_ms=1),
        ),
    )
    assert config.timeouts.upstream_done == 0.5


F = "generators.fragmentation"


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ({"generators": {"nope": {}}}, "generators.nope: unknown key"),
        (
            {"generators": {"baseline": {"enabled": "yes"}}},
            "generators.baseline.enabled: expected true or false",
        ),
        ({"generators": {"fragmentation": {"cases": []}}}, f"{F}.cases: expected a non-empty list"),
        (
            {"generators": {"fragmentation": {"cases": ["baseline", "zigzag"]}}},
            f"{F}.cases: unknown name 'zigzag'",
        ),
        (
            {"generators": {"fragmentation": {"cases": ["baseline", "baseline"]}}},
            f"{F}.cases: duplicate names",
        ),
        (
            {"generators": {"fragmentation": {"cases": ["chunks"]}}},
            f"{F}.cases: must include baseline when split cases are listed",
        ),
        (
            {"generators": {"fragmentation": {"chunks": {"sizes": [0]}}}},
            f"{F}.chunks.sizes: expected an integer >= 1",
        ),
        (
            {"generators": {"fragmentation": {"chunks": {"sizes": [2, 2]}}}},
            f"{F}.chunks.sizes: duplicate values",
        ),
        (
            {"generators": {"fragmentation": {"chunks": {"phases": "some"}}}},
            f"{F}.chunks.phases: expected one of all, first",
        ),
        (
            {"generators": {"fragmentation": {"random_chunks": {"samples": 0}}}},
            f"{F}.random_chunks.samples: expected an integer >= 1",
        ),
        (
            {"generators": {"fragmentation": {"random_chunks": {"min": 5, "max": 2}}}},
            f"{F}.random_chunks: min must not exceed max",
        ),
        (
            {"generators": {"fragmentation": {"random_cuts": {"max_cuts": 0}}}},
            f"{F}.random_cuts.max_cuts: expected an integer >= 1",
        ),
        (
            {"generators": {"fragmentation": {"delay_ms": {"min": -1}}}},
            f"{F}.delay_ms.min: expected an integer >= 0",
        ),
        (
            {"generators": {"fragmentation": {"delay_ms": {"min": 3, "max": 1}}}},
            f"{F}.delay_ms: min must not exceed max",
        ),
    ],
)
def test_generator_validation_errors(raw: object, message: str) -> None:
    with pytest.raises(ConfigError, match=f"^{re.escape(message)}$"):
        parse(raw)


def test_override_generators() -> None:
    merged = override(Config(), generators=("fragmentation",))
    assert merged.generators.baseline.enabled is False
    assert merged.generators.fragmentation.enabled is True


def test_parse_generator_names() -> None:
    assert parse_generator_names("baseline, fragmentation") == ("baseline", "fragmentation")


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("", "--generators: unknown name ''"),
        ("bogus", "--generators: unknown name 'bogus'"),
        ("baseline,baseline", "--generators: duplicate names"),
    ],
)
def test_parse_generator_names_rejects(text: str, message: str) -> None:
    with pytest.raises(ConfigError, match=f"^{re.escape(message)}$"):
        parse_generator_names(text)


def test_types_templates_and_generator_templates() -> None:
    config = parse(
        {
            "canary_types": {"customer_id": {"values": ["CUST-00412871"]}},
            "templates": {"invoice": {"protocol": "openai-chat"}},
            "generators": {
                "baseline": {"templates": ["default", "invoice"]},
                "fragmentation": {"templates": ["invoice"]},
            },
        }
    )
    assert config.canary_types["customer_id"].values == ("CUST-00412871",)
    assert config.templates == {"invoice": {"protocol": "openai-chat"}}
    assert config.generators.baseline == BaselineSettings(templates=("default", "invoice"))
    assert config.generators.fragmentation.templates == ("invoice",)


def test_unimportable_entry_points_still_parse() -> None:
    """Parsing (serve, stop) never imports user modules; `run` does, when it prepares."""
    config = parse(
        {
            "canary_types": {
                "loyalty": {"generator": "nomodule_xyz:make"},
                "ref": {"values": ["REF-AAAA01"], "checksum": "nomodule_xyz:check"},
            }
        }
    )
    assert config.canary_types["loyalty"].generator == "nomodule_xyz:make"
    assert config.canary_types["ref"].checksum == "nomodule_xyz:check"


def test_template_defaults() -> None:
    config = parse({})
    assert config.generators.baseline.templates == ("default", "tool-calls", "multi-turn")
    assert config.generators.fragmentation.templates == ("default", "multi-turn")
    assert config.canary_types == {}
    assert config.templates == {}


def test_override_keeps_templates() -> None:
    base = parse({"generators": {"baseline": {"templates": ["invoice"]}}})
    merged = override(base, generators=("fragmentation",))
    assert merged.generators.baseline == BaselineSettings(enabled=False, templates=("invoice",))


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        (
            {"canary_types": {"email": {"values": ["a"]}}},
            "canary_types.email: is a built-in type name",
        ),
        ({"templates": []}, "templates: expected a mapping"),
        ({"templates": {"bad name": {}}}, "templates.bad name: expected a name like invoice"),
        ({"templates": {"t": "x"}}, "templates.t: expected a mapping"),
        (
            {"generators": {"baseline": {"templates": []}}},
            "generators.baseline.templates: expected a non-empty list of names",
        ),
        (
            {"generators": {"fragmentation": {"templates": ["a", "a"]}}},
            "generators.fragmentation.templates: duplicate names",
        ),
    ],
)
def test_type_and_template_errors(raw: object, message: str) -> None:
    with pytest.raises(ConfigError, match=f"^{re.escape(message)}$"):
        parse(raw)


def fault_doc(**entry: object) -> dict[str, object]:
    base: dict[str, object] = {"name": "down", "before": "touch f", "after": "rm -f f"}
    base.update(entry)
    return {"faults": [base]}


def test_fault_defaults() -> None:
    config = parse(fault_doc())
    assert config.faults == (FaultSpec("down", "touch f", "rm -f f", ("refuse",), 0),)
    assert config.generators.fault == FaultSettings(True, ("default",))
    assert config.timeouts.fault_command == 60.0
    assert fault_generator_runs(config)
    assert not fault_generator_runs(parse({}))
    disabled = {**fault_doc(), "generators": {"fault": {"enabled": False}}}
    assert not fault_generator_runs(parse(disabled))


@pytest.mark.parametrize(
    ("expect", "normal"),
    [
        ("refuse", ("refuse",)),
        (["refuse"], ("refuse",)),
        (["refuse", "restore"], ("refuse", "restore")),
        (["restore", "refuse"], ("refuse", "restore")),
    ],
)
def test_fault_expect(expect: object, normal: tuple[str, ...]) -> None:
    assert parse(fault_doc(expect=expect)).faults[0].expect == normal


EXPECT_ERROR = "faults[0].expect: expected refuse or [refuse, restore] under duty restore"
TWO_A = {
    "faults": [
        {"name": "a", "before": "x", "after": "y"},
        {"name": "a", "before": "x", "after": "y"},
    ]
}


@pytest.mark.parametrize(
    ("doc", "message"),
    [
        (fault_doc(expect="restore"), EXPECT_ERROR),
        (fault_doc(expect=["refuse", "refuse"]), EXPECT_ERROR),
        (fault_doc(expect=7), EXPECT_ERROR),
        (fault_doc(name="bad name"), "faults[0].name: expected a name like analyzer-down"),
        (fault_doc(before=""), "faults[0].before: expected a non-empty command"),
        (fault_doc(after=3), "faults[0].after: expected a non-empty command"),
        (fault_doc(settle_ms=-1), "faults[0].settle_ms: expected an integer >= 0"),
        (fault_doc(extra=1), "faults[0].extra: unknown key"),
        ({"faults": {"a": 1}}, "faults: expected a list"),
        ({"faults": ["x"]}, "faults[0]: expected a mapping"),
        ({"faults": [{"before": "a", "after": "b"}]}, "faults[0].name: required"),
        (TWO_A, "faults[1].name: duplicate name 'a'"),
        (
            fault_doc(name="control"),
            "faults[0].name: 'control' is reserved for the control requests",
        ),
        ({"timeouts": {"fault_command": 0}}, "timeouts.fault_command: expected a positive number"),
        ({"generators": {"fault": {"extra": 1}}}, "generators.fault.extra: unknown key"),
    ],
)
def test_fault_errors(doc: object, message: str) -> None:
    with pytest.raises(ConfigError) as exc:
        parse(doc)
    assert str(exc.value) == message


def test_generators_flag_selects_fault() -> None:
    config = override(parse(fault_doc()), generators=("fault",))
    assert config.generators.fault.enabled
    assert not config.generators.baseline.enabled
    assert not config.generators.fragmentation.enabled
    assert parse_generator_names("fault") == ("fault",)
    assert not override(parse(fault_doc()), generators=("baseline",)).generators.fault.enabled


def test_default_routes_and_duty() -> None:
    config = parse({})
    assert config.routes == (Route("openai-chat", "openai-chat", "/v1/chat/completions"),)
    assert config.duty == "restore"


def test_routes() -> None:
    config = parse(
        {
            "target": {
                "duty": "mask-only",
                "routes": [
                    {"protocol": "openai-chat", "path": "/v1/chat/completions"},
                    {"protocol": "anthropic-messages", "path": "/v1/messages", "name": "claude"},
                ],
            }
        }
    )
    assert config.routes == (
        Route("openai-chat", "openai-chat", "/v1/chat/completions"),
        Route("claude", "anthropic-messages", "/v1/messages"),
    )
    assert config.duty == "mask-only"


ROUTE_A = {"protocol": "openai-chat", "path": "/a"}


@pytest.mark.parametrize(
    ("target", "message"),
    [
        ({"routes": []}, "target.routes: expected a non-empty list"),
        (
            {"routes": [{"protocol": "x", "path": "/a"}]},
            "target.routes[0].protocol: expected one of openai-chat, anthropic-messages",
        ),
        (
            {"routes": [{"protocol": "openai-chat", "path": "a"}]},
            "target.routes[0].path: expected a path starting with /",
        ),
        (
            {"routes": [{**ROUTE_A, "name": "bad name"}]},
            "target.routes[0].name: expected a name like claude",
        ),
        ({"routes": [{**ROUTE_A, "extra": 1}]}, "target.routes[0].extra: unknown key"),
        (
            {"routes": [ROUTE_A, {**ROUTE_A, "path": "/b"}]},
            "target.routes[1].name: duplicate name 'openai-chat' "
            "(a route's name defaults to its protocol; set name)",
        ),
        (
            {"routes": [ROUTE_A, {**ROUTE_A, "name": "other"}]},
            "target.routes[1]: duplicate route openai-chat /a",
        ),
        (
            {
                "routes": [
                    {**ROUTE_A, "name": "claude"},
                    {"protocol": "anthropic-messages", "path": "/b", "name": "claude"},
                ]
            },
            "target.routes[1].name: duplicate name 'claude'",
        ),
        ({"duty": "both"}, "target.duty: expected one of restore, mask-only"),
    ],
)
def test_route_errors(target: dict[str, object], message: str) -> None:
    with pytest.raises(ConfigError) as exc:
        parse({"target": target})
    assert str(exc.value) == message


@pytest.mark.parametrize(
    ("duty", "expect", "normal"),
    [
        ("mask-only", ["refuse", "deliver"], ("refuse", "deliver")),
        ("mask-only", ["deliver", "refuse"], ("refuse", "deliver")),
        ("mask-only", "refuse", ("refuse",)),
        ("restore", ["restore", "refuse"], ("refuse", "restore")),
    ],
)
def test_expect_per_duty(duty: str, expect: object, normal: tuple[str, ...]) -> None:
    doc = {"target": {"duty": duty}, **fault_doc(expect=expect)}
    assert parse(doc).faults[0].expect == normal


@pytest.mark.parametrize(
    ("duty", "expect", "message"),
    [
        (
            "mask-only",
            ["refuse", "restore"],
            "faults[0].expect: expected refuse or [refuse, deliver] under duty mask-only",
        ),
        (
            "restore",
            ["refuse", "deliver"],
            "faults[0].expect: expected refuse or [refuse, restore] under duty restore",
        ),
    ],
)
def test_expect_wrong_word_for_duty(duty: str, expect: object, message: str) -> None:
    with pytest.raises(ConfigError) as exc:
        parse({"target": {"duty": duty}, **fault_doc(expect=expect)})
    assert str(exc.value) == message


# --- report.outputs -------------------------------------------------------


def test_report_outputs_from_file() -> None:
    config = parse(
        {
            "report": {
                "dir": "reports",
                "outputs": [{"template": "builtin:junit", "path": "junit.xml"}],
            }
        }
    )
    assert config.report.dir == Path("reports")
    assert config.report.outputs == (OutputSpec("builtin:junit", "junit.xml", None),)


def test_no_report_key_means_default_outputs() -> None:
    assert parse({}).report.outputs == ReportSettings().outputs


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ({"report": {"bogus": 1}}, "report.bogus: unknown key"),
        (
            {"report": {"outputs": [{"template": "builtin:markdown", "path": "r.md", "bogus": 1}]}},
            "report.outputs[0].bogus: unknown key",
        ),
        (
            {"report": {"outputs": [{"template": "builtin:html", "path": "r.md"}]}},
            'report.outputs[0].template: unknown builtin "builtin:html"',
        ),
        (
            {"report": {"outputs": [{"template": "builtin:markdown", "path": "/abs.md"}]}},
            "report.outputs[0].path: must be relative",
        ),
        (
            {"report": {"outputs": [{"template": "builtin:markdown", "path": "../x.md"}]}},
            "report.outputs[0].path: must not contain ..",
        ),
        (
            {"report": {"outputs": [{"template": "builtin:markdown", "path": ""}]}},
            "report.outputs[0].path: must name a file",
        ),
        (
            {"report": {"outputs": [{"template": "builtin:markdown", "path": "."}]}},
            "report.outputs[0].path: must name a file",
        ),
        (
            {"report": {"outputs": [{"template": "builtin:markdown", "path": "./"}]}},
            "report.outputs[0].path: must name a file",
        ),
        (
            {"report": {"outputs": [{"template": "builtin:markdown", "path": "report.json"}]}},
            "report.outputs[0].path: report.json is reserved",
        ),
        (
            {
                "report": {
                    "outputs": [
                        {"template": "builtin:markdown", "path": "a.md"},
                        {"template": "builtin:markdown", "path": "a.md"},
                    ]
                }
            },
            "report.outputs[1].path: duplicate path a.md",
        ),
        (
            {
                "report": {
                    "outputs": [{"template": "builtin:markdown", "path": "r.md", "escape": "html"}]
                }
            },
            "report.outputs[0].escape: expected xml or none",
        ),
        ({"report": {"outputs": []}}, "report.outputs: expected a non-empty list"),
    ],
)
def test_report_output_errors(raw: object, message: str) -> None:
    with pytest.raises(ConfigError, match=f"^{re.escape(message)}$"):
        parse(raw)
