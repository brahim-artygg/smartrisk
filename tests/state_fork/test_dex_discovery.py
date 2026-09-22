from smartrisk.state_fork.dex_discovery import discover_pairs

TOKEN = "0x" + "11" * 20
WETH = "0x" + "22" * 20
PAIR1 = "0x" + "33" * 20
PAIR2 = "0x" + "44" * 20


def pair(address, liquidity, base=TOKEN, quote=WETH):
    return {
        "chainId": "1",
        "dexId": "uniswap",
        "pairAddress": address,
        "url": "https://dex.test/pair/" + address,
        "baseToken": {"address": base, "symbol": "T"},
        "quoteToken": {"address": quote, "symbol": "WETH"},
        "priceNative": "0.001",
        "priceUsd": "2.0",
        "txns": {"h24": {"buys": 12, "sells": 8}},
        "volume": {"h24": 1234.5},
        "liquidity": {"usd": liquidity, "base": 1000, "quote": 1},
        "pairCreatedAt": 1000,
    }


def test_discovery_normalizes_and_selects_by_liquidity_without_risk_judgment():
    report = discover_pairs({"pairs": [pair(PAIR1, 1000), pair(PAIR2, 5000)]}, "1", TOKEN)
    assert len(report.pairs) == 2
    assert report.selected_pair.pair_address == PAIR2
    assert report.selected_pair.quote_address == WETH
    assert report.selected_pair.trade_count_h24 == 20


def test_discovery_accepts_target_as_quote():
    report = discover_pairs({"pairs": [pair(PAIR1, 1000, base=WETH, quote=TOKEN)]}, "1", TOKEN)
    assert report.selected_pair.token_side(TOKEN) == "quote"
