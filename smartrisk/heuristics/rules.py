from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .models import Feature, RiskScore, RuleDecision
from .policy import PolicyRegistry


@dataclass(frozen=True)
class Rule:
    rule_id: str
    required: tuple[str, ...]
    weight: float
    evaluator: Callable[[dict[str, Feature]], tuple[str, str]]


class RuleEngine:
    VERSION = "score-v0.1"

    def __init__(self, policy: PolicyRegistry | None = None):
        self.policy = policy or PolicyRegistry.load()
        self.rules = [
            Rule("market.no_pair", ("market.pair_count",), 35.0, self._no_pair),
            Rule("market.low_liquidity", ("market.best_liquidity_usd",), 25.0, self._low_liquidity),
            Rule("market.sell_activity_absent", ("market.buys_h24", "market.sells_h24"), 25.0, self._sell_activity_absent),
            Rule("market.price_divergence", ("market.price_min_usd", "market.price_max_usd"), 15.0, self._price_divergence),
            Rule("market.stale_pair", ("market.pair_age_hours",), 8.0, self._stale_pair),
            Rule("chain.no_contract_code", ("chain.token_has_code",), 45.0, self._no_contract_code),
        ]

    def score(self, features: list[Feature]) -> RiskScore:
        index = {feature.feature_id: feature for feature in features}
        decisions: list[RuleDecision] = []
        unknowns: list[str] = []
        total = 0.0
        for rule in self.rules:
            missing = [name for name in rule.required if name not in index or index[name].value is None]
            if missing:
                reasons = []
                for name in missing:
                    reasons.extend(index[name].unknown_reasons if name in index else [f"missing feature: {name}"])
                decision = RuleDecision(rule.rule_id, "unknown", 0.0, "Required feature is unavailable", missing, unknown_reasons=reasons)
                unknowns.extend(reasons)
                decisions.append(decision)
                continue
            outcome, explanation = rule.evaluator(index)
            contribution = self.policy.weight(rule.rule_id, rule.weight) if outcome == "triggered" else 0.0
            total += contribution
            decisions.append(RuleDecision(rule.rule_id, outcome, contribution, explanation, list(rule.required), evidence_refs=self._refs(rule.required, index)))
        coverage = sum(feature.coverage for feature in features) / len(features) if features else 0.0
        confidence = sum(feature.confidence * feature.coverage for feature in features) / sum(feature.coverage for feature in features) if any(feature.coverage for feature in features) else 0.0
        score = min(100.0, round(total, 2))
        band = "unknown" if coverage < 0.75 else ("critical" if score >= 70 else "high" if score >= 45 else "medium" if score >= 20 else "low")
        return RiskScore(score, band, round(confidence, 3), round(coverage, 3), decisions, sorted(set(unknowns)), features, policy_version=self.policy.version)

    @staticmethod
    def _refs(required, index):
        refs = []
        for name in required:
            refs.extend(index[name].evidence_refs)
        return sorted(set(refs))

    @staticmethod
    def _no_pair(index):
        return ("triggered", "No DEX pair was returned for the token") if index["market.pair_count"].value == 0 else ("not_triggered", "At least one DEX pair was returned")

    @staticmethod
    def _low_liquidity(index):
        value = index["market.best_liquidity_usd"].value
        return ("triggered", f"Best observed liquidity is ${value:,.2f}") if value < 10_000 else ("not_triggered", f"Best observed liquidity is ${value:,.2f}")

    @staticmethod
    def _sell_activity_absent(index):
        buys, sells = index["market.buys_h24"].value, index["market.sells_h24"].value
        return ("triggered", "Buy activity exists but no sells were observed in the h24 window") if buys > 0 and sells == 0 else ("not_triggered", f"Observed h24 buys={buys}, sells={sells}")

    @staticmethod
    def _price_divergence(index):
        low, high = index["market.price_min_usd"].value, index["market.price_max_usd"].value
        divergence = (high - low) / low if low else 0
        return ("triggered", f"Price divergence across pairs is {divergence:.1%}") if divergence > 0.25 else ("not_triggered", f"Price divergence across pairs is {divergence:.1%}")

    @staticmethod
    def _stale_pair(index):
        age = index["market.pair_age_hours"].value
        return ("triggered", f"Pair age is {age:.1f} hours") if age > 24 * 365 else ("not_triggered", f"Pair age is {age:.1f} hours")

    @staticmethod
    def _no_contract_code(index):
        return ("triggered", "Alchemy returned empty runtime code") if index["chain.token_has_code"].value is False else ("not_triggered", "Alchemy confirmed runtime code")
