import json
from pathlib import Path

from canarywire.capture.recorder import Recorder


def test_appends_one_line_per_entry(tmp_path: Path) -> None:
    recorder = Recorder(tmp_path / "state" / "capture.jsonl")
    recorder.write({"id": "u1"})
    recorder.write({"id": "u2"})
    lines = recorder.path.read_text().splitlines()
    assert [json.loads(line)["id"] for line in lines] == ["u1", "u2"]
