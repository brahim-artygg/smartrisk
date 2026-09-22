import time

from smartrisk.heuristics.engine import HeuristicsEngine
from smartrisk.heuristics.models import ChainAnchor, RawObservation


class FakeAlchemy:
    def capability_probe(self):
        return {"provider": "alchemy", "status": "ready"}

    def anchor(self, tag, block_number=None):
        return ChainAnchor("0x1", block_number or 100, "0xblock", tag)

    def get_code(self, address, anchor):
        return RawObservation("alchemy:code", "alchemy", "eth_getCode", address, "now", {"code": "0x6000"}, anchor)

    def get_logs(self, address, anchor, from_block, to_block):
        return RawObservation("alchemy:logs", "alchemy", "eth_getLogs", address, "now", {"logs": [{"logIndex": "0x0"}]}, anchor)


class FakeDex:
    def capability_probe(self):
        return {"provider": "dexscreener", "status": "ready"}

    def get_token_pairs(self, chain_id, token_address):
        return RawObservation("dex:pairs", "dexscreener", "token-pairs", token_address, "now", {"pairs": [{
            "liquidity": {"usd": 5000},
            "volume": {"h24": 10000},
            "txns": {"h24": {"buys": 10, "sells": 0}},
            "priceUsd": "1.0",
            "pairCreatedAt": int(time.time() * 1000),
        }]})


def test_engine_combines_chain_and_market_features():
    result = HeuristicsEngine(alchemy=FakeAlchemy(), dexscreener=FakeDex()).analyze("ethereum", "0xtoken", run_id="score-test")
    assert result.status == "complete"
    assert result.anchor.block_hash == "0xblock"
    assert result.risk.score < 10.0
    assert result.risk.band == "low"
    assert any(feature.feature_id == "chain.token_has_code" for feature in result.risk.features)
    assert any(decision.rule_id == "market.sell_activity_absent" and decision.outcome != "triggered" for decision in result.risk.decisions)


def test_dex_failure_is_partial_and_unknown():
    class FailingDex(FakeDex):
        def get_token_pairs(self, chain_id, token_address):
            return RawObservation("dex:failed", "dexscreener", "token-pairs", token_address, "now", {}, error="timeout", stale=True)

    result = HeuristicsEngine(alchemy=FakeAlchemy(), dexscreener=FailingDex()).analyze("ethereum", "0xtoken")
    assert result.status == "partial"
    assert result.risk.band == "unknown"
    assert any("timeout" in reason for reason in result.risk.unknowns)


class _ReadyAlchemy:
    def capability_probe(self): return {"status": "ready"}
    def anchor(self, tag="safe", block_number=None):
        from smartrisk.heuristics.models import ChainAnchor
        return ChainAnchor("1", 100, "0xblock", "safe")
    def get_code(self, address, anchor):
        from smartrisk.heuristics.models import RawObservation
        return RawObservation("code", "alchemy", "eth_getCode", address, "now", {"code": "0x6000"}, anchor)
    def get_logs(self, address, anchor, from_block, to_block):
        from smartrisk.heuristics.models import RawObservation
        return RawObservation("logs", "alchemy", "eth_getLogs", address, "now", {"logs": []}, anchor)
    def get_storage_at(self, address, slot, anchor):
        from smartrisk.heuristics.models import RawObservation
        return RawObservation("storage:" + slot, "alchemy", "eth_getStorageAt", address, "now", {"value": "0x0"}, anchor)
    def call_selector(self, address, selector, anchor):
        from smartrisk.heuristics.models import RawObservation
        return RawObservation("call:" + selector, "alchemy", "eth_call", address, "now", {"value": "0x"}, anchor)


class _Market:
    def capability_probe(self): return {"status": "ready"}
    def get_token_pairs(self, chain_id, token_address):
        from smartrisk.heuristics.models import RawObservation
        return RawObservation("market", "dexscreener", "token-pairs", token_address, "now", {"pairs": []})


def test_fingerprint_findings_are_attached_after_intelligence_result_exists():
    from smartrisk.heuristics.engine import HeuristicsEngine
    from smartrisk.heuristics.dexscreener import DexscreenerClient
    from smartrisk.heuristics.features import FeatureExtractor
    from smartrisk.heuristics.rules import RuleEngine
    from smartrisk.heuristics.policy import PolicyRegistry

    engine = HeuristicsEngine(alchemy=_ReadyAlchemy(), dexscreener=_Market())
    result = engine.analyze("1", "0x" + "11" * 20)
    assert result.status in {"complete", "partial"}
    assert isinstance(result.intelligence.get("findings", []), list)


def test_mature_pair_without_sells_is_flagged_but_market_context_stays_low_weight():
    class MatureDex(FakeDex):
        def get_token_pairs(self, chain_id, token_address):
            return RawObservation("dex:mature", "dexscreener", "token-pairs", token_address, "now", {"pairs": [{
                "liquidity": {"usd": 5000}, "volume": {"h24": 10000},
                "txns": {"h24": {"buys": 25, "sells": 0}},
                "priceUsd": "1.0",
                "pairCreatedAt": int((time.time() - 8 * 3600) * 1000),
            }]})
    result = HeuristicsEngine(alchemy=FakeAlchemy(), dexscreener=MatureDex()).analyze("ethereum", "0xtoken")
    decision = next(d for d in result.risk.decisions if d.rule_id == "market.sell_activity_absent")
    assert decision.outcome == "triggered"
    assert result.risk.score < 15.0
