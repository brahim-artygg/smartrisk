from smartrisk.heuristics.models import Feature
from smartrisk.heuristics.rules import RuleEngine


def feature(name, value, unit="unit"):
    return Feature(name, "0xtoken", value, unit, "test", 0.9, 1.0, "now", [f"ev:{name}"])


def test_low_liquidity_and_no_sell_activity_contribute_score():
    score = RuleEngine().score([
        feature("market.pair_count", 1, "count"),
        feature("market.best_liquidity_usd", 1000, "usd"),
        feature("market.buys_h24", 25, "count"),
        feature("market.sells_h24", 0, "count"),
        feature("market.price_min_usd", 1, "usd"),
        feature("market.price_max_usd", 1.1, "usd"),
        feature("market.pair_age_hours", 12, "hours"),
        feature("chain.token_has_code", True, "boolean"),
    ])
    assert score.score < 15.0
    assert score.band == "low"
    assert {decision.rule_id for decision in score.decisions if decision.outcome == "triggered"} == {
        "market.low_liquidity", "market.sell_activity_absent"
    }


def test_missing_market_data_is_unknown_not_no_pair():
    missing = Feature(
        feature_id="market.pair_count",
        subject="0xtoken",
        value=None,
        unit="count",
        source="dexscreener",
        confidence=0.0,
        coverage=0.0,
        observed_at="now",
        evidence_refs=[],
        unknown_reasons=["provider timeout"],
    )
    score = RuleEngine().score([missing])
    no_pair = next(decision for decision in score.decisions if decision.rule_id == "market.no_pair")
    assert no_pair.outcome == "unknown"
    assert score.band == "unknown"


def test_holder_concentration_requires_a_minimum_observed_holder_sample():
    score = RuleEngine().score([
        feature("holders.holder_count", 2, "count"),
        feature("holders.top10_concentration", 0.99, "ratio"),
        feature("holders.top20_concentration", 0.99, "ratio"),
    ])
    assert all(decision.outcome == "not_triggered" for decision in score.decisions if decision.rule_id.startswith("holders."))
