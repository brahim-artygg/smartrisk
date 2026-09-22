from smartrisk.static_engine.models import Finding, SourceLocation, StaticRun
from smartrisk.unified.engine import UnifiedRiskEngine


def test_critical_static_finding_becomes_hard_verdict():
    finding = Finding("f1", "static", "token.unprotected-mint-burn", "unprotected mint", "mint is reachable", "critical", 0.9, "likely")
    run = StaticRun("static", "complete", "static", "0.2", "hash", findings=[finding])
    verdicts = UnifiedRiskEngine._hard_verdicts([], run.to_dict()["findings"], [])
    assert verdicts[0]["verdict_id"] == "STATIC_CRITICAL_FINDING"
