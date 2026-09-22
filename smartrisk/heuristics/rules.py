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
    optional: bool = False


class RuleEngine:
    VERSION = "score-v0.4"

    def __init__(self, policy: PolicyRegistry | None = None):
        self.policy = policy or PolicyRegistry.load()
        self.rules = [
            Rule("market.no_pair", ("market.pair_count",), 35.0, self._no_pair),
            Rule("market.low_liquidity", ("market.best_liquidity_usd",), 25.0, self._low_liquidity),
            Rule("market.sell_activity_absent", ("market.pair_count", "market.buys_h24", "market.sells_h24", "market.pair_age_hours"), 6.0, self._sell_activity_absent, optional=True),
            Rule("market.price_divergence", ("market.pair_count", "market.price_min_usd", "market.price_max_usd"), 4.0, self._price_divergence, optional=True),
            Rule("chain.no_contract_code", ("chain.token_has_code",), 45.0, self._no_contract_code),
            Rule("contract.selfdestruct_pattern", ("contract.selfdestruct_pattern",), 4.0, self._selfdestruct),
            Rule("contract.delegatecall_pattern", ("contract.delegatecall_present",), 6.0, self._delegatecall),
            Rule("contract.time_or_block_logic", ("contract.time_or_block_logic",), 3.0, self._time_logic),
            Rule("contract.proxy_detected", ("contract.proxy_detected",), 4.0, self._proxy_detected),
            Rule("holders.top20_concentration", ("holders.top20_concentration", "holders.holder_count"), 18.0, self._top20_concentration, optional=True),
            Rule("holders.top10_concentration", ("holders.top10_concentration", "holders.holder_count"), 12.0, self._top10_concentration, optional=True),
            Rule("liquidity.lp_top1_concentration", ("liquidity.max_lp_top1_share",), 15.0, self._lp_top1_concentration, optional=True),
            Rule("liquidity.lp_candidate_control", ("liquidity.max_lp_candidate_share",), 15.0, self._lp_candidate_control, optional=True),
            Rule("deployer.candidate_supply_concentration", ("deployer.candidate_supply_share",), 12.0, self._deployer_candidate_share, optional=True),
            Rule("clusters.large_supply_cluster", ("clusters.largest_supply_share",), 12.0, self._large_cluster, optional=True),
            Rule("clusters.coordinated_fanout", ("clusters.coordinated_fanout_bursts",), 8.0, self._fanout_bursts, optional=True),
            Rule("history.no_observed_sellers", ("history.unique_buyers", "history.unique_sellers", "history.transfer_count"), 12.0, self._no_observed_sellers, optional=True),
        ]

    def score(self, features: list[Feature]) -> RiskScore:
        index = {feature.feature_id: feature for feature in features}
        decisions: list[RuleDecision] = []
        unknowns: list[str] = []
        total = 0.0
        family_totals: dict[str, float] = {}
        hard_blocked = False
        for rule in self.rules:
            config = self.policy.rule(rule.rule_id)
            missing = [name for name in rule.required if name not in index or index[name].value is None]
            if self.policy.expired(rule.rule_id):
                decisions.append(RuleDecision(rule.rule_id, "unknown", 0.0, "Rule is expired in the active policy", list(rule.required), unknown_reasons=["policy expiry reached"], references=config.get("references", [])))
                unknowns.append(f"expired rule: {rule.rule_id}")
                continue
            if missing:
                reasons = []
                for name in missing:
                    reasons.extend(index[name].unknown_reasons if name in index else [f"missing feature: {name}"])
                if rule.optional:
                    decisions.append(RuleDecision(rule.rule_id, "not_triggered", 0.0, "Optional intelligence input is unavailable; rule was not scored", missing, unknown_reasons=reasons, references=config.get("references", [])))
                    continue
                decisions.append(RuleDecision(rule.rule_id, "unknown", 0.0, "Required feature is unavailable", missing, unknown_reasons=reasons, references=config.get("references", [])))
                unknowns.extend(reasons)
                continue
            outcome, explanation = rule.evaluator(index)
            family = config.get("family", rule.rule_id.split(".")[0])
            confidence_factor = float(config.get("confidence_factor", 1.0))
            feature_confidence = sum(index[name].confidence for name in rule.required) / len(rule.required)
            calibrated = "confidence_factor" in config
            raw = self.policy.weight(rule.rule_id, rule.weight) * confidence_factor * feature_confidence if outcome == "triggered" and calibrated else self.policy.weight(rule.rule_id, rule.weight) if outcome == "triggered" else 0.0
            cap = self.policy.family_cap(family)
            contribution = min(raw, max(0.0, cap - family_totals.get(family, 0.0)))
            family_totals[family] = family_totals.get(family, 0.0) + contribution
            is_hard_block = bool(config.get("hard_block", False) and outcome == "triggered")
            hard_blocked = hard_blocked or is_hard_block
            total = 100.0 if is_hard_block else total + contribution
            decisions.append(RuleDecision(rule.rule_id, outcome, contribution, explanation, list(rule.required), evidence_refs=self._refs(rule.required, index), references=config.get("references", []), hard_block=is_hard_block))
        covered = [feature for feature in features if feature.coverage > 0]
        coverage = sum(feature.coverage for feature in features) / len(features) if features else 0.0
        confidence = sum(feature.confidence * feature.coverage for feature in covered) / sum(feature.coverage for feature in covered) if covered else 0.0
        score = 100.0 if hard_blocked else min(100.0, round(total, 2))
        # Coverage affects confidence/status, not the primary risk band. A scan with
        # partial optional data can still have a decisive low/high result from the
        # controls that were actually evaluated. Only a scan with no usable score
        # should collapse to an unknown band upstream.
        band = "unknown" if coverage == 0 else ("critical" if hard_blocked else ("critical" if score >= 70 else "high" if score >= 45 else "medium" if score >= 20 else "low"))
        return RiskScore(score, band, round(confidence, 3), round(coverage, 3), decisions, sorted(set(unknowns)), features, policy_version=self.policy.version, hard_blocked=hard_blocked)

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
        age = index["market.pair_age_hours"].value
        pairs = index["market.pair_count"].value
        mature = isinstance(age, (int, float)) and age >= 6
        triggered = pairs > 0 and buys >= 10 and sells == 0 and mature
        if triggered:
            return ("triggered", f"Observed {buys} h24 buys and no sells after the pair had existed for {age:.1f} hours")
        return ("not_triggered", f"Observed h24 buys={buys}, sells={sells}; pair_age_hours={age:.1f}" if isinstance(age, (int, float)) else f"Observed h24 buys={buys}, sells={sells}; pair age unavailable")

    @staticmethod
    def _price_divergence(index):
        pair_count = index["market.pair_count"].value
        low, high = index["market.price_min_usd"].value, index["market.price_max_usd"].value
        if pair_count < 2 or low <= 0:
            return ("not_triggered", "Price divergence requires at least two valid pairs")
        divergence = (high - low) / low
        return ("triggered", f"Price divergence across pairs is {divergence:.1%}") if divergence > 0.25 else ("not_triggered", f"Price divergence across pairs is {divergence:.1%}")

    @staticmethod
    def _no_contract_code(index):
        return ("triggered", "Alchemy returned empty runtime code") if index["chain.token_has_code"].value is False else ("not_triggered", "Alchemy confirmed runtime code")

    @staticmethod
    def _selfdestruct(index):
        return ("triggered", "Runtime bytecode contains SELFDESTRUCT opcode") if index["contract.selfdestruct_pattern"].value else ("not_triggered", "No SELFDESTRUCT opcode observed")

    @staticmethod
    def _delegatecall(index):
        return ("triggered", "Runtime bytecode contains DELEGATECALL; authorization/proxy context must be checked") if index["contract.delegatecall_present"].value else ("not_triggered", "No DELEGATECALL opcode observed")

    @staticmethod
    def _time_logic(index):
        return ("triggered", "Runtime bytecode reads block timestamp/number; time-dependent behavior requires deeper control-flow analysis") if index["contract.time_or_block_logic"].value else ("not_triggered", "No timestamp/block-number opcode observed")

    @staticmethod
    def _top20_concentration(index):
        value = index["holders.top20_concentration"].value
        holder_count = index["holders.holder_count"].value
        if holder_count < 10:
            return ("not_triggered", f"Top 20 concentration is not scored until at least 10 observed holders exist (observed={holder_count})")
        return ("triggered", f"Top 20 observed holders control {value:.1%} of reconstructed positive supply") if value >= 0.80 else ("not_triggered", f"Top 20 observed holders control {value:.1%} of reconstructed positive supply")

    @staticmethod
    def _top10_concentration(index):
        value = index["holders.top10_concentration"].value
        holder_count = index["holders.holder_count"].value
        top20 = index.get("holders.top20_concentration")
        if holder_count < 5:
            return ("not_triggered", f"Top 10 concentration is not scored until at least 5 observed holders exist (observed={holder_count})")
        if top20 is not None and isinstance(top20.value, (int, float)) and top20.value >= 0.80:
            return ("not_triggered", f"Top 10 concentration is nested inside the stronger Top 20 concentration signal ({top20.value:.1%})")
        return ("triggered", f"Top 10 observed holders control {value:.1%} of reconstructed EOA supply") if value >= 0.60 else ("not_triggered", f"Top 10 observed holders control {value:.1%} of reconstructed EOA supply")

    @staticmethod
    def _lp_top1_concentration(index):
        value = index["liquidity.max_lp_top1_share"].value
        return ("triggered", f"A single observed LP holder controls {value:.1%} of reconstructed LP supply") if value >= 0.70 else ("not_triggered", f"Largest observed LP holder controls {value:.1%} of reconstructed LP supply")

    @staticmethod
    def _lp_candidate_control(index):
        value = index["liquidity.max_lp_candidate_share"].value
        return ("triggered", f"A deployer/candidate-linked address controls {value:.1%} of reconstructed LP supply") if value >= 0.25 else ("not_triggered", f"Deployer/candidate-linked LP control is {value:.1%}")

    @staticmethod
    def _deployer_candidate_share(index):
        value = index["deployer.candidate_supply_share"].value
        return ("triggered", f"A deployer/distribution candidate controls {value:.1%} of reconstructed positive token supply") if value >= 0.40 else ("not_triggered", f"Candidate supply control is {value:.1%}")

    @staticmethod
    def _large_cluster(index):
        value = index["clusters.largest_supply_share"].value
        return ("triggered", f"The largest reconstructed wallet cluster controls {value:.1%} of observed positive supply") if value >= 0.50 else ("not_triggered", f"Largest wallet cluster controls {value:.1%} of observed positive supply")

    @staticmethod
    def _fanout_bursts(index):
        value = index["clusters.coordinated_fanout_bursts"].value
        return ("triggered", f"Observed {value} narrow-window fan-out transfer burst(s)") if value >= 1 else ("not_triggered", "No narrow-window fan-out burst was observed")

    @staticmethod
    def _no_observed_sellers(index):
        buyers = index["history.unique_buyers"].value
        sellers = index["history.unique_sellers"].value
        transfers = index["history.transfer_count"].value
        triggered = buyers >= 10 and sellers == 0 and transfers >= 20
        return ("triggered", f"Observed {buyers} buy-like wallets and no sell-like wallet across {transfers} token transfers") if triggered else ("not_triggered", f"Observed buy-like wallets={buyers}, sell-like wallets={sellers}, transfers={transfers}")

    @staticmethod
    def _proxy_detected(index):
        return ("triggered", "Upgradeable/proxy-like behavior was detected from bytecode or EIP-1967 state") if index["contract.proxy_detected"].value else ("not_triggered", "No proxy signal observed")
