import json

from smartrisk.unified.cli import main


def test_unified_cli_writes_final_json(tmp_path):
    output = tmp_path / "unified.json"
    assert main(["scan", "--run-id", "cli-test", "--output", str(output)]) == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["run_id"] == "cli-test"
    assert payload["risk"]["band"] == "unknown"
    assert len(payload["engines"]) == 3
