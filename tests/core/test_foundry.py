from pathlib import Path

from smartrisk.core.foundry import FoundryDeepRunner


def test_foundry_capabilities_are_safe_to_probe():
    caps = FoundryDeepRunner.capabilities()
    assert "forge" in caps and "halmos" in caps and "sandbox" in caps


def test_foundry_runner_reports_missing_tool_without_running_network(tmp_path: Path, monkeypatch):
    runner = FoundryDeepRunner()
    monkeypatch.setattr("smartrisk.core.foundry.shutil.which", lambda name: None)
    result = runner.run(tmp_path, mode="symbolic")
    assert result.status == "unavailable"
    assert result.tool == "halmos"
