from pathlib import Path

from smartrisk.heuristics.models import Feature
from smartrisk.heuristics.policy import PolicyRegistry
from smartrisk.heuristics.rules import RuleEngine


def test_policy_registry_overrides_rule_weight():
    policy = PolicyRegistry.load(Path("policies/score-v0.2.json"))
    score = RuleEngine(policy).score([
        Feature("market.pair_count", "0xtoken", 1, "count", "test", 1, 1),
        Feature("market.best_liquidity_usd", "0xtoken", 1, "usd", "test", 1, 1),
    ])
    decision = next(item for item in score.decisions if item.rule_id == "market.low_liquidity")
    assert score.policy_version == "score-v0.2"
    assert decision.contribution == 25
