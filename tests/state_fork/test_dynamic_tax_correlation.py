from smartrisk.state_fork.models import BlockAnchor, SimulationResult
from smartrisk.state_fork.trade_analysis import correlate_trade_sequence
from smartrisk.state_fork.v2_math import amount_out_v2

ANCHOR = BlockAnchor("0x1", 100, "0xblock", "0xparent", 123, "safe")
TOKEN = "0x" + "11" * 20
WETH = "0x" + "22" * 20
PAIR = "0x" + "33" * 20
TRADER = "0x" + "44" * 20


def _state(reserve0=10**20, reserve1=2*10**20):
    return {"address": TRADER, "native_balance_wei": 10**21, "token_balances": {}, "allowances": {},
            "pair_reserves": {PAIR: {"reserve0": reserve0, "reserve1": reserve1}},
            "pair_tokens": {PAIR: {"token0": WETH, "token1": TOKEN}}, "errors": []}


def test_buy_and_sell_correlation_detects_input_tax():
    buy_amount = 10**17
    expected_buy = amount_out_v2(buy_amount, 10**20, 2*10**20, 30)
    bought = expected_buy * 9 // 10
    buy = SimulationResult("buy", "success", ANCHOR, tx_hash="0xbuy", receipt={"status": "0x1"}, state_diff={
        "before": _state(), "after": _state(), "delta": {"token_balance_delta": {TOKEN: bought}, "native_balance_delta_wei": -buy_amount},
        "event_analysis": {"erc20_transfers": [{"token": TOKEN, "from": PAIR, "to": TRADER, "amount": bought}]},
    })
    approve = SimulationResult("approve", "success", ANCHOR, tx_hash="0xapp", receipt={"status": "0x1"}, state_diff={"delta": {}})
    requested_sell = bought
    pair_received = requested_sell * 95 // 100
    expected_native = amount_out_v2(pair_received, 2*10**20, 10**20, 30)
    gas = 21_000
    sell = SimulationResult("sell", "success", ANCHOR, tx_hash="0xsell", receipt={"status": "0x1", "gasUsed": hex(gas), "effectiveGasPrice": "0x1"}, state_diff={
        "before": _state(reserve0=10**20 + buy_amount, reserve1=2*10**20 - bought), "after": _state(),
        "delta": {"token_balance_delta": {TOKEN: -requested_sell}, "native_balance_delta_wei": expected_native - gas},
        "event_analysis": {"erc20_transfers": [{"token": TOKEN, "from": TRADER, "to": PAIR, "amount": pair_received}]},
    })
    report = correlate_trade_sequence(buy, approve, sell, TOKEN, PAIR, WETH, requested_sell, buy_amount_wei=buy_amount)
    assert report["buy"]["effective_output_tax_bps"] >= 900
    assert 490 <= report["sell"]["input_tax_bps"] <= 510
    assert report["classification"] == "sell_succeeded"
