from smartrisk.state_fork.dex_discovery import discover_pairs
from smartrisk.state_fork.trade_builder import (
    DexRouteConfig,
    DexRouteRegistry,
    UniswapV2ScenarioBuilder,
    encode_approve,
    encode_swap_exact_eth_for_tokens_native,
    encode_swap_exact_tokens_for_eth,
    scenario_from_sell_template,
)

TOKEN = "0x" + "11" * 20
WETH = "0x" + "22" * 20
ROUTER = "0x" + "33" * 20
TRADER = "0x" + "44" * 20
PAIR = "0x" + "55" * 20


def pair():
    payload = {"pairs": [{
        "chainId": "1", "dexId": "uniswap", "pairAddress": PAIR,
        "baseToken": {"address": TOKEN, "symbol": "T"},
        "quoteToken": {"address": WETH, "symbol": "WETH"},
        "liquidity": {"usd": 100000}, "volume": {"h24": 200000},
        "txns": {"h24": {"buys": 10, "sells": 10}},
    }]}
    return discover_pairs(payload, "1", TOKEN).selected_pair


def test_v2_native_builder_creates_buy_approve_and_dynamic_sells():
    registry = DexRouteRegistry([DexRouteConfig("1", "uniswap", ROUTER, WETH)])
    plan = UniswapV2ScenarioBuilder(registry).build_native_plan(pair(), TOKEN, TRADER, 10**15, 2000)
    assert plan.executable is True
    assert plan.buy.data.startswith("0xb6f9de95")
    assert plan.approve.data.startswith("0x095ea7b3")
    assert plan.sell_templates["partial_sell"]["fraction_bps"] == 5000
    sell = scenario_from_sell_template(plan.sell_templates["partial_sell"], 1000, ROUTER, PAIR, mode="partial_sell")
    assert sell.scenario_id == "trade:sell:partial_sell"
    assert "00000000000000000000000000000000000000000000000000000000000001f4" in sell.data.lower()


def test_builder_is_unknown_without_local_router_configuration():
    plan = UniswapV2ScenarioBuilder(DexRouteRegistry(include_defaults=False)).build_native_plan(pair(), TOKEN, TRADER, 10**15, 2000)
    assert plan.executable is False
    assert "no local router configuration" in plan.reason


def test_abi_encoding_has_dynamic_offsets():
    buy = encode_swap_exact_eth_for_tokens_native([WETH, TOKEN], TRADER, 2000)
    sell = encode_swap_exact_tokens_for_eth(123, [TOKEN, WETH], TRADER, 2000)
    assert buy.startswith("0xb6f9de95")
    assert sell.startswith("0x791ac947")
    assert buy[10:74] == "0" * 64
    assert buy[74:138].endswith("0080")
    assert encode_approve(ROUTER, 1).startswith("0x095ea7b3")


def test_v09_default_route_registry_covers_all_ten_networks():
    from smartrisk.core.networks import supported_networks
    from smartrisk.state_fork.trade_builder import DexRouteRegistry

    registry = DexRouteRegistry()
    for profile in supported_networks():
        dex_ids = {key[1] for key in registry._routes if key[0] == profile.chain_id}
        assert dex_ids, profile.name
        assert any(registry.resolve(profile.chain_id, dex_id) for dex_id in dex_ids)


def test_route_registry_resolves_dexscreener_chain_slug():
    registry = DexRouteRegistry()
    route = registry.resolve("bsc", "pancakeswap")
    assert route is not None
    assert route.chain_id == "56"
    assert route.router_address.lower() == "0x10ed43c718714eb63d5aa57b78b54704e256024e"


def test_celo_uses_erc20_native_asset_buy_and_token_to_token_sell():
    from smartrisk.core.networks import get_network
    celo = get_network("42220")
    payload = {"pairs": [{
        "chainId": "celo", "dexId": "sushiswap", "pairAddress": PAIR,
        "baseToken": {"address": TOKEN, "symbol": "T"},
        "quoteToken": {"address": celo.wrapped_native, "symbol": "CELO"},
        "liquidity": {"usd": 100000}, "volume": {"h24": 200000},
    }]}
    pair = discover_pairs(payload, celo.chain_id, TOKEN).selected_pair
    plan = UniswapV2ScenarioBuilder().build_native_plan(pair, TOKEN, TRADER, 10**18, 2000)
    assert plan.executable is True
    assert plan.route.style == "celo-sushiswap-v2"
    assert plan.pre_buy_approve is not None
    assert plan.pre_buy_approve.to_address.lower() == celo.wrapped_native.lower()
    assert plan.buy.data.startswith("0x5c11d795")
    assert plan.buy.value_wei == 0
    assert plan.sell_templates["baseline"]["method"] == "swapExactTokensForTokensSupportingFeeOnTransferTokens"
    sell = scenario_from_sell_template(plan.sell_templates["baseline"], 1_000_000, plan.route.router_address, PAIR, mode="baseline")
    assert sell.data.startswith("0x5c11d795")
