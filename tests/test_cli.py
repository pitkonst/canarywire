import hashlib
import json
import socket
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from canarywire import __version__
from canarywire import cli as cli_module
from canarywire.cli import main
from canarywire.config import Route
from canarywire.report import Report
from canarywire.report.samples import passing_report
from canarywire.runner.runner import RunSettings


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"canarywire {__version__}"


def test_no_args_prints_help(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 0
    assert "usage: canarywire" in capsys.readouterr().out


@pytest.mark.parametrize("command", ["serve", "stop"])
def test_config_error_exits_1_for_serve_and_stop(
    command: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "c.yaml"
    path.write_text("bogus: 1\n")
    assert main([command, "--config", str(path)]) == 1
    assert "bogus: unknown key" in capsys.readouterr().err


def test_serve_rejects_bad_listen(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["serve", "--listen", "nope"]) == 1
    assert "expected HOST:PORT" in capsys.readouterr().err


def test_stop_without_capture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    assert main(["stop"]) == 0


def test_timeout_flags_must_be_positive() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["stop", "--timeout-stop-grace", "0"])
    assert exc.value.code == 2


def _dead_url() -> str:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return f"http://127.0.0.1:{sock.getsockname()[1]}"


def test_run_without_target_exits_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["run", "--out", str(tmp_path / "out")]) == 2
    assert "no target" in capsys.readouterr().err


def test_run_config_error_exits_2_without_report(tmp_path: Path) -> None:
    path = tmp_path / "c.yaml"
    path.write_text("timeouts:\n  client_request: -1\n")
    assert main(["run", "--config", str(path), "--out", str(tmp_path / "out")]) == 2
    assert not (tmp_path / "out").exists()


def test_run_template_error_exits_2_without_report(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = tmp_path / "c.yaml"
    config.write_text(
        "templates:\n  t:\n    protocol: openai-chat\n    canaries: {a: email}\n"
        "    request: {x: '{{ a.masked }}'}\n    response: {}\n"
        "generators:\n  baseline: {templates: [t]}\n  fragmentation: {enabled: false}\n"
    )
    code = main(
        [
            "run",
            "--target",
            "http://127.0.0.1:9",
            "--config",
            str(config),
            "--out",
            str(tmp_path / "out"),
        ]
    )
    assert code == 2
    assert "templates.t.request.x: .masked is only allowed in the response" in (
        capsys.readouterr().err
    )
    assert not (tmp_path / "out").exists()


def test_run_crash_after_execute_exits_2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A crash writing/rendering the report must exit 2, not look like a fail or a pass."""

    def boom(report: Report, out_dir: Path) -> Path:
        raise TypeError("boom")

    monkeypatch.setattr(cli_module, "write", boom)
    code = main(
        [
            "run",
            "--target",
            _dead_url(),
            "--capture",
            _dead_url(),
            "--seed",
            "9",
            "--out",
            str(tmp_path / "out"),
            "--timeout-capture-connect",
            "1",
        ]
    )
    assert code == 2
    assert "cannot write report" in capsys.readouterr().err


def test_run_with_unreachable_capture_is_untrusted(tmp_path: Path) -> None:
    out = tmp_path / "out"
    code = main(
        [
            "run",
            "--target",
            _dead_url(),
            "--capture",
            _dead_url(),
            "--seed",
            "9",
            "--out",
            str(out),
            "--timeout-capture-connect",
            "1",
        ]
    )
    assert code == 2
    report = json.loads((out / "report.json").read_text())
    assert (report["outcome"], report["seed"]) == ("untrusted", 9)
    assert (out / "report.md").is_file()


def test_run_records_effective_config_in_report(tmp_path: Path) -> None:
    config = tmp_path / "c.yaml"
    config_bytes = b"seed: 9\n"
    config.write_bytes(config_bytes)
    out = tmp_path / "out"
    code = main(
        [
            "run",
            "--target",
            _dead_url(),
            "--capture",
            _dead_url(),
            "--config",
            str(config),
            "--out",
            str(out),
            "--timeout-capture-connect",
            "1",
            "--generators",
            "baseline",
        ]
    )
    assert code == 2
    report = json.loads((out / "report.json").read_text())
    run = report["run"]
    assert run["config"] == {
        "path": str(config),
        "sha256": hashlib.sha256(config_bytes).hexdigest(),
    }
    assert run["generators"]["fault"]["enabled"] is False
    assert run["generators"]["fragmentation"]["enabled"] is False
    assert run["generators"]["baseline"]["enabled"] is True


def test_run_rejects_unknown_generator(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["run", "--generators", "bogus", "--out", str(tmp_path / "out")]) == 2
    assert "--generators: unknown name 'bogus'" in capsys.readouterr().err


def test_run_accepts_new_flags(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = main(
        [
            "run",
            "--generators",
            "baseline",
            "--timeout-upstream-done",
            "1",
            "--out",
            str(tmp_path / "out"),
        ]
    )
    assert code == 2  # no target: the flags themselves parsed fine
    assert "no target" in capsys.readouterr().err


def test_run_interrupted_during_a_fault_exits_128_plus_signal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    async def interrupted(settings: object) -> Report:
        report = Report(seed=9, target="t", capture_url="c", started_at="s")
        report.interrupted = 15
        return report

    monkeypatch.setattr(cli_module, "execute", interrupted)
    out = tmp_path / "out"
    code = main(["run", "--target", _dead_url(), "--seed", "9", "--out", str(out)])
    assert code == 143
    assert not (out / "report.json").exists()
    err = capsys.readouterr().err
    assert "interrupted by signal 15; fault after-hook ran; no report written" in err


def test_run_interrupted_with_a_failed_after_hook_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    problem = "fault down: after-hook failed (exit 1); environment may still be faulted"

    async def interrupted(settings: object) -> Report:
        report = Report(seed=9, target="t", capture_url="c", started_at="s")
        report.trust_problems.append(problem)
        report.interrupted = 2
        return report

    monkeypatch.setattr(cli_module, "execute", interrupted)
    out = tmp_path / "out"
    code = main(["run", "--target", _dead_url(), "--seed", "9", "--out", str(out)])
    assert code == 130
    assert not (out / "report.json").exists()
    err = capsys.readouterr().err
    assert problem in err
    assert "interrupted by signal 2; fault after-hook failed" in err
    assert "may still be faulted; no report written" in err


def test_run_passes_faults_and_out_to_the_runner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[object] = []

    async def capture(settings: object) -> Report:
        seen.append(settings)
        return Report(seed=9, target="t", capture_url="c", started_at="s")

    config = tmp_path / "c.yaml"
    config.write_text("faults:\n  - {name: f, before: 'true', after: 'true'}\n")
    monkeypatch.setattr(cli_module, "execute", capture)
    out = tmp_path / "out"
    main(["run", "--target", _dead_url(), "--config", str(config), "--out", str(out)])
    settings = seen[0]
    assert [spec.name for spec in settings.faults] == ["f"]  # type: ignore[attr-defined]
    assert settings.out_dir == out  # type: ignore[attr-defined]


def test_run_passes_routes_and_duty_to_the_runner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[RunSettings] = []

    async def capture(settings: RunSettings) -> Report:
        seen.append(settings)
        return Report(seed=9, target="t", capture_url="c", started_at="s")

    config = tmp_path / "c.yaml"
    config.write_text(
        "target:\n"
        "  duty: mask-only\n"
        "  routes:\n"
        "    - {protocol: openai-chat, path: /v1/chat/completions}\n"
        "    - {name: claude, protocol: anthropic-messages, path: /v1/messages}\n"
    )
    monkeypatch.setattr(cli_module, "execute", capture)
    main(["run", "--target", _dead_url(), "--config", str(config), "--out", str(tmp_path / "o")])
    [settings] = seen
    assert settings.routes == (
        Route("openai-chat", "openai-chat", "/v1/chat/completions"),
        Route("claude", "anthropic-messages", "/v1/messages"),
    )
    assert settings.duty == "mask-only"
    assert settings.prepared is not None
    assert "default@claude" in settings.prepared.templates


# --- report.outputs / --junit / checks before traffic ---------------------


def test_bad_template_exits_2_before_any_traffic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    called: list[object] = []

    async def capture(settings: object) -> Report:
        called.append(settings)
        return Report(seed=9, target="t", capture_url="c", started_at="s")

    config = tmp_path / "c.yaml"
    config.write_text("report:\n  outputs:\n    - {template: missing.mustache, path: x.md}\n")
    monkeypatch.setattr(cli_module, "execute", capture)
    out = tmp_path / "out"
    code = main(["run", "--target", _dead_url(), "--config", str(config), "--out", str(out)])
    assert code == 2
    err = capsys.readouterr().err
    assert "canarywire: config error: report.outputs[0].template: cannot read" in err
    assert called == []


def test_template_failing_the_static_check_exits_2_before_any_traffic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    called: list[object] = []

    async def capture(settings: object) -> Report:
        called.append(settings)
        return Report(seed=9, target="t", capture_url="c", started_at="s")

    (tmp_path / "bad.mustache").write_text("{{^findings}}{{typo}}{{/findings}}\n")
    config = tmp_path / "c.yaml"
    config.write_text("report:\n  outputs:\n    - {template: bad.mustache, path: x.md}\n")
    monkeypatch.setattr(cli_module, "execute", capture)
    out = tmp_path / "out"
    code = main(["run", "--target", _dead_url(), "--config", str(config), "--out", str(out)])
    assert code == 2
    err = capsys.readouterr().err
    assert 'config error: report.outputs[0].template: bad.mustache:1: unknown name "typo"' in err
    assert called == []
    assert not out.exists()


def test_config_hash_is_of_the_bytes_read_before_traffic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "c.yaml"
    config_bytes = b"seed: 9\n"
    config.write_bytes(config_bytes)

    async def capture(settings: object) -> Report:
        config.write_bytes(b"seed: 10\n")  # edited while traffic runs: must not change the hash
        return passing_report()

    monkeypatch.setattr(cli_module, "execute", capture)
    out = tmp_path / "out"
    code = main(["run", "--target", _dead_url(), "--config", str(config), "--out", str(out)])
    assert code == 0
    run = json.loads((out / "report.json").read_text())["run"]
    assert run["config"] == {
        "path": str(config),
        "sha256": hashlib.sha256(config_bytes).hexdigest(),
    }


def test_junit_flag_writes_junit_xml_relative_to_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def capture(settings: object) -> Report:
        return passing_report()

    monkeypatch.setattr(cli_module, "execute", capture)
    monkeypatch.chdir(tmp_path)
    out = tmp_path / "out"
    code = main(
        ["run", "--target", _dead_url(), "--seed", "9", "--out", str(out), "--junit", "j.xml"]
    )
    assert code == 0
    junit_path = tmp_path / "j.xml"
    assert junit_path.exists()
    ET.fromstring(junit_path.read_text())  # noqa: S314 - our own rendered output


def test_report_dir_from_config_used_unless_out_flag_given(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def capture(settings: object) -> Report:
        return passing_report()

    monkeypatch.setattr(cli_module, "execute", capture)
    monkeypatch.chdir(tmp_path)
    config = tmp_path / "c.yaml"
    config.write_text("report:\n  dir: reports\n")
    code = main(["run", "--target", _dead_url(), "--seed", "9", "--config", str(config)])
    assert code == 0
    assert (tmp_path / "reports" / "report.json").exists()

    code = main(
        [
            "run",
            "--target",
            _dead_url(),
            "--seed",
            "9",
            "--config",
            str(config),
            "--out",
            "other",
        ]
    )
    assert code == 0
    assert (tmp_path / "other" / "report.json").exists()


def test_output_path_that_is_a_directory_still_writes_report_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    async def capture(settings: object) -> Report:
        return passing_report()

    monkeypatch.setattr(cli_module, "execute", capture)
    out = tmp_path / "out"
    out.mkdir()
    (out / "blocked").mkdir()
    config = tmp_path / "c.yaml"
    config.write_text(
        "report:\n"
        "  outputs:\n"
        "    - {template: builtin:markdown, path: report.md}\n"
        "    - {template: builtin:markdown, path: blocked}\n"
    )
    code = main(
        ["run", "--target", _dead_url(), "--seed", "9", "--config", str(config), "--out", str(out)]
    )
    assert code == 2
    assert (out / "report.json").exists()
    assert (out / "report.md").exists()
    captured = capsys.readouterr()
    assert "cannot write" in captured.err
    assert "; 1 output(s) not written" in captured.out
