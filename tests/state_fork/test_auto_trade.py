from smartrisk.heuristics.models import RawObservation
from smartrisk.state_fork.auto_trade import AutoTradeAnalyzer
from smartrisk.state_fork.trade_builder import DexRouteConfig, DexRouteRegistry

TOKEN = "0x" + "11" * 20
WETH = "0x" + "22" * 20
ROUTER = "0x" + "33" * 20
TRADER = "0x" + "44" * 20
PAIR = "0x" + "55" * 20


class FakeRpc:
    rpc_url = "https://alchemy.test/v2/key"

    def capability_probe(self):
        return {"provider": "alchemy", "status": "ready"}

    def get_chain_id(self):
        return "0x1"

    def get_anchor(self, tag):
        return 100, {"hash": "0xblock", "parentHash": "0xparent", "timestamp": "0x64"}


class FakeDex:
    def capability_probe(self):
        return {"provider": "dexscreener", "status": "ready"}

    def get_token_pairs(self, chain_id, token_address):
        return RawObservation(
            "dex:test", "dexscreener", "token-pairs", token_address, "", {
                "pairs": [{
                    "chainId": "1", "dexId": "uniswap", "pairAddress": PAIR,
                    "baseToken": {"address": TOKEN, "symbol": "T"},
                    "quoteToken": {"address": WETH, "symbol": "WETH"},
                    "liquidity": {"usd": 100000}, "volume": {"h24": 200000},
                    "txns": {"h24": {"buys": 20, "sells": 12}},
                }]
            }
        )


def test_auto_trade_plan_only_discovers_pair_and_builds_route_without_anvil():
    routes = DexRouteRegistry([DexRouteConfig("1", "uniswap", ROUTER, WETH)])
    report = AutoTradeAnalyzer(FakeRpc(), FakeDex(), routes=routes).analyze(
        "1", TOKEN, TRADER, 10**15, run_id="auto-test", execute=False
    )
    assert report.status == "complete"
    assert report.pair_address == PAIR
    assert report.plan["discovery"]["selected_pair"]["pair_address"] == PAIR
    assert report.plan["execution_plan"]["executable"] is True
    assert len(report.plan["honeypot_matrix"]["attempts"]) == 6


def test_auto_trade_prefers_first_executable_route_over_top_liquidity(monkeypatch):
    from smartrisk.state_fork.auto_trade import AutoTradeAnalyzer
    from smartrisk.state_fork.dex_discovery import DexPair

    class ReadyRpc:
        chain = "eth-mainnet"
        provider_name = "test"
        rpc_url = "https://rpc.test"
        def capability_probe(self):
            return {"status": "ready"}
        def get_anchor(self, tag):
            return 1, {"hash": "0x1", "parentHash": "0x0", "timestamp": "0x1", "number": "0x1"}
        def get_chain_id(self):
            return "0x1"

    class Dex: 
        def capability_probe(self):
            return {"status": "ready"}
        def get_token_pairs(self, chain_id, token_address):
            return type("Obs", (), {"payload": {"pairs": [
                {"chainId": chain_id, "dexId": "unsupported", "pairAddress": "0x" + "11" * 20, "baseToken": {"address": token_address}, "quoteToken": {"address": "0x" + "22" * 20}, "liquidity": {"usd": 999999}, "volume": {"h24": 1}},
                {"chainId": chain_id, "dexId": "uniswap", "pairAddress": "0x" + "33" * 20, "baseToken": {"address": token_address}, "quoteToken": {"address": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"}, "liquidity": {"usd": 1}, "volume": {"h24": 1}},
            ]}, "error": None, "stale": False})()

    analyzer = AutoTradeAnalyzer(rpc=ReadyRpc(), dexscreener=Dex())
    # Make the route availability explicit without starting Anvil.
    result = analyzer.analyze("1", "0x" + "aa" * 20, "0x" + "bb" * 20, 10**15, execute=False)
    assert result.plan["discovery"]["selected_pair"]["dex_id"] == "uniswap"
    assert result.plan["execution_plan"]["executable"] is True
