import time

from smartrisk.heuristics.engine import HeuristicsEngine
from smartrisk.heuristics.models import ChainAnchor, RawObservation
from smartrisk.unified.engine import UnifiedRiskEngine
from smartrisk.unified.models import UnifiedRequest


class _ReadyAlchemy:
    def capability_probe(self): return {"status": "ready"}
    def anchor(self, tag="safe", block_number=None): return ChainAnchor("1", 100, "0xblock", "safe")
    def get_code(self, address, anchor): return RawObservation("code", "alchemy", "eth_getCode", address, "now", {"code": "0x6000"}, anchor)
    def get_logs(self, address, anchor, from_block, to_block, **kwargs): return RawObservation("logs", "alchemy", "eth_getLogs", address, "now", {"logs": []}, anchor)
    def get_storage_at(self, address, slot, anchor): return RawObservation("s", "alchemy", "eth_getStorageAt", address, "now", {"value": "0x0"}, anchor)
    def call_selector(self, address, selector, anchor): return RawObservation("c", "alchemy", "eth_call", address, "now", {"value": "0x"}, anchor)


class _Dex:
    def capability_probe(self):
        return {"status": "ready"}

    def get_token_pairs(self, chain_id, token_address):
        pair = {
            "chainId": "ethereum", "dexId": "uniswap", "pairAddress": "0x" + "a" * 40,
            "liquidity": {"usd": 250000}, "volume": {"h24": 90000},
            "txns": {"h24": {"buys": 120, "sells": 95}}, "priceUsd": "1.0",
            "pairCreatedAt": int((time.time() - 90 * 86400) * 1000),
            "baseToken": {"address": token_address}, "quoteToken": {"address": "0x" + "c" * 40},
        }
        return RawObservation("m", "dexscreener", "token-pairs", token_address, "now", {"pairs": [pair]})


def test_free_scan_is_not_forced_to_unverified_and_does_not_overclaim():
    engine = UnifiedRiskEngine(heuristics=HeuristicsEngine(alchemy=_ReadyAlchemy(), dexscreener=_Dex()))
    report = engine.analyze(UnifiedRequest(chain_id="1", token_address="0x" + "2" * 40, scan_profile="free"))
    assert report.coverage > 0.5                      # was ~0.29 -> always UNVERIFIED
    assert report.verdict == "NO_MAJOR_SIGNALS"       # not LOW_RISK: no sell simulation ran
    assert "not a guarantee" in report.primary_detection["explanation"]
