from smartrisk.heuristics.models import ChainAnchor, HeuristicsRun, RiskScore, Feature, RuleDecision
from smartrisk.static_engine.models import StaticRun, Finding
from smartrisk.state_fork.models import BlockAnchor, ForkRun, HoneypotResult, SimulationResult
from smartrisk.unified.engine import UnifiedRiskEngine
from smartrisk.unified.models import UnifiedRequest

class FakeStatic:
    def analyze(self, project, run_id=None, compiler_version=None):
        return StaticRun(run_id, "complete", "static", "test", "hash", findings=[
            Finding("static:mint", "static", "token.unrestricted_mint", "Unlimited mint", "Mint capability is unrestricted", "high", 0.9, "likely")
        ])

class FakeFork:
    def analyze(self, scenarios, run_id=None, block_tag="safe", block_number=None):
        anchor = BlockAnchor("0x1", 10, "0xblock", "0xparent", 1, "safe")
        hp = HoneypotResult("hp", "sell_blocked", [SimulationResult("sell", "reverted", anchor, tx_hash="0xsell")], anchor, ["0xsell"])
        return ForkRun(run_id, "complete", anchor, results=[], honeypot_results=[hp])

class FakeHeuristics:
    def analyze(self, chain_id, token_address, run_id=None, block_tag="safe", block_number=None, window_blocks=10000):
        anchor = ChainAnchor("0x1", 10, "0xblock", "safe")
        features = [
            Feature("market.pair_count", token_address, 1, "count", "dexscreener", 0.9, 1.0, evidence_refs=["dex:1"]),
            Feature("history.unique_buyers", token_address, 2, "count", "smartrisk-intelligence", 0.9, 1.0),
        ]
        intel = {
            "status": "complete", "coverage": 1.0, "confidence": 0.9,
            "payload": {"historical_behavior": {"unique_buyers": 2}},
            "findings": [{"finding_id":"intelligence:history.no_observed_sellers", "engine":"intelligence", "rule_id":"history.no_observed_sellers", "description":"No observed sellers", "severity":"medium", "confidence":0.9, "status":"confirmed", "evidence_refs":["intel:1"]}],
            "unknowns": [], "diagnostics": []
        }
        risk = RiskScore(20.0, "medium", 0.9, 1.0, [RuleDecision("market.sell_activity_absent", "triggered", 20.0, "buy/sell", ["x"], evidence_refs=["dex:1"])], features=features)
        return HeuristicsRun(run_id, "complete", anchor, risk, intelligence=intel)

def test_unified_correlates_fork_and_intelligence():
    result = UnifiedRiskEngine(FakeStatic(), FakeFork(), FakeHeuristics()).analyze(
        UnifiedRequest(project="contract.sol", chain_id="ethereum", token_address="0xtoken", scenarios=["scenario"]), run_id="corr")
    ids = {item["correlation_id"] for item in result.correlations}
    assert "corr.fork-market-honeypot" in ids
    assert result.hard_verdicts
    assert "holder_distribution" in result.risk_dimensions
