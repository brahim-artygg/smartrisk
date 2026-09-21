from pathlib import Path

from smartrisk.static_engine.engine import StaticEngine
from smartrisk.static_engine.models import Evidence, Finding, SourceLocation


ROOT = Path(__file__).parent / "fixtures"


class MissingSlither:
    def run(self, project):
        raise RuntimeError("not used")

    def available(self):
        return False


def test_models_serialize_source_location():
    finding = Finding(
        finding_id="f-1",
        engine="static",
        rule_id="test.rule",
        title="Test",
        description="A test finding",
        severity="low",
        confidence=0.5,
        status="likely",
        source_location=SourceLocation("Minimal.sol", line=4),
        evidence_refs=["e-1"],
    )
    evidence = Evidence("e-1", "unit", "test")
    assert finding.source_location.file == "Minimal.sol"
    assert evidence.source == "test"


def test_missing_slither_is_unknown_not_safe(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "Minimal.sol").write_text("pragma solidity ^0.8.20; contract X {}", encoding="utf-8")

    class Adapter:
        def run(self, project):
            raise __import__("smartrisk.static_engine.slither_adapter", fromlist=["SlitherUnavailable"]).SlitherUnavailable("missing")

    result = StaticEngine(slither=Adapter()).analyze(project, run_id="test-run")
    assert result.status == "unknown"
    assert result.findings == []
    assert result.unknown_reasons


def test_nonexistent_project_is_failed():
    result = StaticEngine(slither=MissingSlither()).analyze("/does/not/exist", run_id="missing")
    assert result.status == "failed"
    assert result.unknown_reasons
