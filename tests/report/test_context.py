import hashlib
import json
from dataclasses import replace
from pathlib import Path

from canarywire import __version__
from canarywire.config import Config, FaultSpec, load
from canarywire.report.context import run_context


def test_defaults_without_config_file() -> None:
    run = run_context(Config(), None)
    assert run["canarywire_version"] == __version__
    assert run["config"] is None
    assert run["routes"] == [
        {"name": "openai-chat", "protocol": "openai-chat", "path": "/v1/chat/completions"}
    ]
    assert run["generators"]["baseline"] == {
        "enabled": True,
        "templates": ["default", "tool-calls", "multi-turn"],
    }
    assert run["faults"] == []
    assert run["timeouts"]["client_request"] == 30.0
    json.dumps(run)


def test_config_file_hash_and_faults_without_commands(tmp_path: Path) -> None:
    path = tmp_path / "c.yaml"
    path.write_bytes(b"seed: 1\n")
    faults = (FaultSpec("down", "echo SECRET-TOKEN", "echo x", ("refuse",), 5),)
    config = replace(load(path), faults=faults)
    path.write_bytes(b"seed: 2\n")  # the file is not read again: the hash is of what load parsed
    run = run_context(config, path)
    assert run["config"] == {"path": str(path), "sha256": hashlib.sha256(b"seed: 1\n").hexdigest()}
    assert run["faults"] == [{"name": "down", "expect": ["refuse"], "settle_ms": 5}]
    assert "SECRET-TOKEN" not in json.dumps(run)
