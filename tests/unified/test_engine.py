from smartrisk.heuristics.models import ChainAnchor, Feature, HeuristicsRun, RiskScore, RuleDecision
from smartrisk.state_fork.models import BlockAnchor, ForkRun, SimulationResult
from smartrisk.static_engine.models import StaticRun
from smartrisk.unified.engine import UnifiedRiskEngine
from smartrisk.unified.models import UnifiedRequest


class FakeStatic:
    def analyze(self, project, run_id=None, compiler_version=None):
        return StaticRun(run_id, "complete", "static", "test", "hash", findings=[])


class FakeFork:
    def analyze(self, scenarios, run_id=None, block_tag="safe", block_number=None):
        anchor = BlockAnchor("0x1", 10, "0xblock", "0xparent", 1, "safe")
        return ForkRun(run_id, "complete", anchor, results=[SimulationResult("s1", "success", anchor)])


class FakeHeuristics:
    def analyze(self, chain_id, token_address, run_id=None, block_tag="safe", block_number=None, window_blocks=10000):
        anchor = ChainAnchor("0x1", 10, "0xblock", "safe")
        features = [Feature("chain.token_has_code", token_address, True, "boolean", "alchemy", 0.9, 1.0)]
        risk = RiskScore(12.0, "low", 0.9, 1.0, [RuleDecision("r1", "not_triggered", 0, "ok", [])], features=features)
        return HeuristicsRun(run_id, "complete", anchor, risk)


def test_unified_engine_aggregates_three_complete_engines():
    result = UnifiedRiskEngine(FakeStatic(), FakeFork(), FakeHeuristics()).analyze(
        UnifiedRequest(project="contract.sol", chain_id="ethereum", token_address="0xtoken", scenarios=["scenario"]),
        run_id="unified-test",
    )
    assert result.status == "complete"
    assert result.risk_score is not None
    assert result.risk_band == "low"
    assert result.verdict == "LOW_RISK"
    assert result.verdict_label == "LOW RISK"
    assert result.primary_detection["type"] == "risk_score"
    assert {engine.name for engine in result.engine_summaries} == {"static_ast", "state_fork", "heuristics"}
    assert result.versions["unified"] == "unified-v0.9.0"
    assert "contract_security" in result.risk_dimensions
    assert result.versions["release"] == "0.9.0"


def test_unified_engine_unknown_when_no_engine_has_input():
    result = UnifiedRiskEngine().analyze(UnifiedRequest(), run_id="empty")
    assert result.status == "unknown"
    assert result.risk_band == "unknown"
    assert result.risk_score is None
    assert result.unknowns


class FakeSource:
    def anchor(self, block_tag):
        return ChainAnchor("0x1", 77, "0xshared", "safe")

class FakeHeuristicsWithAnchor(FakeHeuristics):
    alchemy = FakeSource()

def test_unified_engine_reuses_shared_anchor_block_number_for_fork():
    class CapturingFork(FakeFork):
        seen = None
        def analyze(self, scenarios, run_id=None, block_tag="safe", block_number=None):
            self.seen = block_number
            return super().analyze(scenarios, run_id, block_tag, block_number)
    fork = CapturingFork()
    UnifiedRiskEngine(FakeStatic(), fork, FakeHeuristicsWithAnchor()).analyze(
        UnifiedRequest(project="contract.sol", chain_id="0x1", token_address="0xtoken", scenarios=["scenario"]),
        run_id="shared-anchor-test",
    )
    assert fork.seen == 77


from smartrisk.state_fork.models import HoneypotResult

class FakeHoneypotFork(FakeFork):
    def analyze_honeypot(self, sequence, run_id=None, block_tag="safe", block_number=None):
        anchor = BlockAnchor("0x1", 10, "0xblock", "0xparent", 1, "safe")
        return ForkRun(run_id, "complete", anchor, honeypot_results=[HoneypotResult(
            sequence_id="hp1", classification="sell_blocked", steps=[], anchor=anchor,
            evidence=["sell_tx"],
        )])

def test_unified_engine_emits_honeypot_verdict():
    class HpRequest(UnifiedRequest):
        pass
    result = UnifiedRiskEngine(FakeStatic(), FakeHoneypotFork(), FakeHeuristics()).analyze(
        UnifiedRequest(project="contract.sol", chain_id="0x1", token_address="0xtoken", honeypot=object()),
        run_id="hp-test",
    )
    assert result.verdict == "HONEYPOT_DETECTED"
    assert result.verdict_label == "HONEYPOT DETECTED"
    assert result.primary_detection["type"] == "honeypot"
    assert result.to_dict()["verdict"]["code"] == "HONEYPOT_DETECTED"

def test_unified_engine_emits_unverified_when_no_inputs():
    result = UnifiedRiskEngine().analyze(UnifiedRequest(), run_id="unverified")
    assert result.verdict == "UNVERIFIED"
    assert result.verdict_label == "UNVERIFIED"
