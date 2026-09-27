"""Day-1 walking skeleton: the README's three steps, judged by exit code and report."""

import json
from typing import Any

import pytest
from harness import E2E, REPORT_DIR, Capture, free_port, refgw_spec

pytestmark = [pytest.mark.e2e, pytest.mark.anyio]


async def test_correct_gateway_holds(e2e: E2E, capture: Capture) -> None:
    gw = refgw_spec(upstream=capture.url, port=free_port())
    await e2e.start_gateway(gw)

    run = await e2e.canarywire(
        "run", "--target", gw.url, "--capture", capture.url, real_delays=True
    )

    assert run.returncode == 0, e2e.diagnostics()
    report = e2e.report()
    assert report["outcome"] == "pass"
    assert isinstance(report["seed"], int)
    assert report["capture"]["requests"] >= 1
    assert report["verified"] >= 1
    assert report["leaks"] == []
    assert report["unrestored"] == []
    assert (e2e.workdir / REPORT_DIR / "report.md").is_file()
    names = [attack["name"] for attack in report["attacks"]]
    assert "fragmentation/default@openai-chat/baseline" in names
    assert "fragmentation/multi-turn@openai-chat/baseline" in names
    assert {"baseline/tool-calls@openai-chat", "baseline/multi-turn@openai-chat"} <= set(names)
    assert len(names) == 35
    assert {attack["status"] for attack in report["attacks"]} == {"restored"}
    assert {c["type"] for c in report["canaries"]} == {
        "email",
        "phone",
        "iban",
        "card",
        "national_id",
    }


async def test_passthrough_leak_is_caught(e2e: E2E, capture: Capture) -> None:
    gw = refgw_spec(upstream=capture.url, port=free_port(), bug="passthrough")
    await e2e.start_gateway(gw)

    run = await e2e.canarywire("run", "--target", gw.url, "--capture", capture.url)

    assert run.returncode == 1, e2e.diagnostics()
    report = e2e.report()
    assert report["outcome"] == "fail"
    assert report["capture"]["requests"] >= 1
    assert any(
        leak["canary"] == "email" and leak["location"] == "body.messages[0].content"
        for leak in report["leaks"]
    ), report["leaks"]
    assert {leak["type"] for leak in report["leaks"]} >= {
        "email",
        "phone",
        "iban",
        "card",
        "national_id",
    }


async def test_unreachable_capture_is_untrusted(e2e: E2E) -> None:
    dead = f"http://127.0.0.1:{free_port()}"
    gw = refgw_spec(upstream=dead, port=free_port())
    await e2e.start_gateway(gw)

    run = await e2e.canarywire("run", "--target", gw.url, "--capture", dead)

    assert run.returncode == 2, e2e.diagnostics()
    assert e2e.report()["outcome"] == "untrusted"


async def test_blackhole_gateway_is_untrusted(e2e: E2E, capture: Capture) -> None:
    gw = refgw_spec(upstream=capture.url, port=free_port(), bug="blackhole")
    await e2e.start_gateway(gw)

    run = await e2e.canarywire("run", "--target", gw.url, "--capture", capture.url)

    assert run.returncode == 2, e2e.diagnostics()
    report = e2e.report()
    assert report["outcome"] == "untrusted"
    assert "no upstream traffic" in report["reason"]


async def test_second_serve_is_rejected(e2e: E2E, capture: Capture) -> None:
    second = await e2e.canarywire("serve", "--detach", "--listen", f"127.0.0.1:{free_port()}")

    assert second.returncode == 1, e2e.diagnostics()
    assert "already running" in second.stderr_path.read_text()


async def test_split_sse_bug_is_caught(e2e: E2E, capture: Capture) -> None:
    gw = refgw_spec(upstream=capture.url, port=free_port(), bug="split-sse")
    await e2e.start_gateway(gw)

    run = await e2e.canarywire(
        "run", "--target", gw.url, "--capture", capture.url, real_delays=True
    )

    assert run.returncode == 1, e2e.diagnostics()
    report = e2e.report()
    statuses = {attack["name"]: attack["status"] for attack in report["attacks"]}
    assert statuses["baseline/default@openai-chat"] == "restored"
    assert statuses["baseline/tool-calls@openai-chat"] == "restored"
    assert statuses["baseline/multi-turn@openai-chat"] == "restored"
    failing = [name for name, status in statuses.items() if status == "unrestored"]
    assert failing
    assert all(name.startswith("fragmentation/") for name in failing)


async def test_seed_replays_the_same_cases(e2e: E2E, capture: Capture) -> None:
    gw = refgw_spec(upstream=capture.url, port=free_port(), bug="split-sse")
    await e2e.start_gateway(gw)
    reports = []
    for out in ("out1", "out2"):
        await e2e.canarywire(
            "run", "--target", gw.url, "--capture", capture.url, "--seed", "42", "--out", out
        )
        reports.append(json.loads((e2e.workdir / out / "report.json").read_text()))

    def essence(report: dict[str, Any]) -> object:
        return (
            [(a["name"], a["status"]) for a in report["attacks"]],
            report["leaks"],
            report["unrestored"],
            report["canaries"],
        )

    assert essence(reports[0]) == essence(reports[1])


CUSTOM_CONFIG = """
canary_types:
  corporate_card:
    schema: { type: string, pattern: "^4[0-9]{15}$" }
    checksum: luhn
templates:
  cards:
    protocol: openai-chat
    canaries: { cc: corporate_card }
    request:
      model: canarywire-test
      messages:
        - role: user
          content: "Charge card {{ cc.raw }} please."
    response:
      choices:
        - index: 0
          finish_reason: stop
          message: { role: assistant, content: "Charged {{ cc.masked }}." }
generators:
  baseline: { templates: [default, cards] }
  fragmentation: { templates: [cards], cases: [baseline, chunks], chunks: { sizes: [2] } }
"""


@pytest.mark.parametrize(("bug", "code"), [(None, 0), ("passthrough", 1)])
async def test_custom_type_and_inline_template(
    e2e: E2E, capture: Capture, bug: str | None, code: int
) -> None:
    (e2e.workdir / "canarywire.yaml").write_text(CUSTOM_CONFIG)
    gw = refgw_spec(upstream=capture.url, port=free_port(), bug=bug)
    await e2e.start_gateway(gw)

    run = await e2e.canarywire(
        "run", "--target", gw.url, "--capture", capture.url, "--config", "canarywire.yaml"
    )

    assert run.returncode == code, e2e.diagnostics()
    report = e2e.report()
    names = [a["name"] for a in report["attacks"]]
    assert "baseline/cards@openai-chat" in names
    assert "fragmentation/cards@openai-chat/baseline" in names
    assert any(c["type"] == "corporate_card" for c in report["canaries"])
    if bug == "passthrough":
        assert any(leak["type"] == "corporate_card" for leak in report["leaks"])
