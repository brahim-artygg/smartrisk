from smartrisk.heuristics.intelligence import IntelligenceAnalyzer
from smartrisk.heuristics.models import ChainAnchor, RawObservation

ZERO = "0x" + "0" * 40
PAIR = "0x00000000000000000000000000000000000000aa"
TOKEN = "0x00000000000000000000000000000000000000bb"
H1 = "0x0000000000000000000000000000000000000001"
H2 = "0x0000000000000000000000000000000000000002"
H3 = "0x0000000000000000000000000000000000000003"
W = "0x0000000000000000000000000000000000000004"

def word_addr(address: str) -> str:
    return address[2:].rjust(64, "0")

def word_uint(value: int) -> str:
    return f"{value:064x}"

class FakeAlchemy:
    def get_logs(self, address, anchor, from_block, to_block):
        if address.lower() == TOKEN.lower():
            logs = [
                {"address": TOKEN, "topics": ["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"], "data": "0x0", "blockNumber": "0x1", "blockHash": "0x1", "transactionHash": "0xt1", "logIndex": "0x0"},
                {"address": TOKEN, "topics": ["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", "0x" + "0"*64, "0x" + word_addr(H1)], "data": "0x" + word_uint(700), "blockNumber": "0x64", "blockHash": "0xb1", "transactionHash": "0xt2", "logIndex": "0x0"},
                {"address": TOKEN, "topics": ["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", "0x" + word_addr(H1), "0x" + word_addr(H2)], "data": "0x" + word_uint(100), "blockNumber": "0x65", "blockHash": "0xb2", "transactionHash": "0xt3", "logIndex": "0x0"},
                {"address": TOKEN, "topics": ["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", "0x" + word_addr(H1), "0x" + word_addr(H3)], "data": "0x" + word_uint(100), "blockNumber": "0x66", "blockHash": "0xb3", "transactionHash": "0xt4", "logIndex": "0x0"},
                {"address": TOKEN, "topics": ["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", "0x" + word_addr(PAIR), "0x" + word_addr(H1)], "data": "0x" + word_uint(50), "blockNumber": "0x67", "blockHash": "0xb4", "transactionHash": "0xt5", "logIndex": "0x0"},
                {"address": TOKEN, "topics": ["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", "0x" + word_addr(H1), "0x" + word_addr(PAIR)], "data": "0x" + word_uint(25), "blockNumber": "0x68", "blockHash": "0xb5", "transactionHash": "0xt6", "logIndex": "0x0"},
            ]
        else:
            logs = [
                {"address": PAIR, "topics": ["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", "0x" + "0"*64, "0x" + word_addr(H1)], "data": "0x" + word_uint(700), "blockNumber": "0x10", "blockHash": "0x10", "transactionHash": "0xl1", "logIndex": "0x0"},
                {"address": PAIR, "topics": ["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", "0x" + word_addr(H1), "0x" + word_addr(H2)], "data": "0x" + word_uint(100), "blockNumber": "0x11", "blockHash": "0x11", "transactionHash": "0xl2", "logIndex": "0x0"},
            ]
        return RawObservation(f"logs:{address}", "alchemy", "eth_getLogs", address, "now", {"logs": logs}, anchor)

    def call_data(self, address, data, anchor):
        selector = data[:10].lower()
        if selector == "0x0dfe1681":
            value = "0x" + word_addr(TOKEN)
        elif selector == "0xd21220a7":
            value = "0x" + word_addr("0x00000000000000000000000000000000000000cc")
        elif selector == "0x0902f1ac":
            value = "0x" + word_uint(1_000_000) + word_uint(2_000_000) + word_uint(123)
        elif selector == "0x18160ddd":
            value = "0x" + word_uint(800)
        else:
            raise AssertionError(f"unexpected selector {selector}")
        return RawObservation(f"call:{address}:{selector}", "alchemy", "eth_call", address, "now", {"data": data, "selector": selector, "value": value}, anchor)

    def get_code(self, address, anchor):
        # Treat H1 as contract-like to exercise holder classification.
        value = "0x60016000" if address.lower() == H1.lower() else "0x"
        return RawObservation(f"code:{address}", "alchemy", "eth_getCode", address, "now", {"code": value}, anchor)


def test_intelligence_builds_holders_lp_clusters_and_history():
    anchor = ChainAnchor("0x1", 200, "0xanchor", "final")
    token_logs = FakeAlchemy().get_logs(TOKEN, anchor, 0, 200)
    market = RawObservation("dex:pairs", "dexscreener", "token-pairs", TOKEN, "now", {"pairs": [{"pairAddress": PAIR, "liquidity": {"usd": 100000}}]})
    result = IntelligenceAnalyzer(FakeAlchemy()).analyze("0x1", TOKEN, anchor, token_logs, market, 1000)
    assert result.status in {"complete", "partial"}
    assert result.payload["holders"]["holder_count"] >= 3
    assert result.payload["holders"]["top_10_concentration"] > 0.7
    assert result.payload["liquidity"]["pairs"][0]["token0"] == TOKEN.lower()
    assert result.payload["liquidity"]["pairs"][0]["lp_total_supply"] == 800
    assert result.payload["historical_behavior"]["unique_buyers"] == 1
    assert result.payload["historical_behavior"]["unique_sellers"] == 1
    assert result.payload["clusters"]["cluster_count"] >= 1
    assert result.payload["holders"]["holder_types"]["contract_holder_count_observed"] >= 1
    assert any(item["rule_id"] in {"holders.top10_concentration", "holders.top20_concentration"} for item in result.findings)
