from smartrisk.state_fork.anvil import AnvilFork
from smartrisk.state_fork.dex_discovery import DexPair
from smartrisk.state_fork.models import BlockAnchor, SimulationResult
from smartrisk.state_fork.trade_builder import DexRouteConfig, DexRouteRegistry, UniswapV2ScenarioBuilder, encode_sell_from_template

TOKEN = "0x" + "11" * 20
WETH = "0x" + "22" * 20
ROUTER = "0x" + "33" * 20
TRADER = "0x" + "44" * 20
PAIR = "0x" + "55" * 20


class FakeFork(AnvilFork):
    def __init__(self):
        super().__init__()
        self.calls = []
        self._snap = 0

    def snapshot(self):
        self._snap += 1
        return str(self._snap)

    def revert(self, snapshot_id):
        return True

    def _execute_scenario(self, scenario, anchor):
        self.calls.append((scenario.scenario_id, scenario.value_wei, scenario.data))
        if scenario.scenario_id == "trade:buy:native-v2":
            diff = {"before": {"address": TRADER, "pair_reserves": {PAIR: {"reserve0": 10**20, "reserve1": 10**21}}, "pair_tokens": {PAIR: {"token0": WETH, "token1": TOKEN}},
                    }, "delta": {"token_balance_delta": {TOKEN: 1_000_000}}}
            return SimulationResult(scenario.scenario_id, "success", anchor, tx_hash="0xbuy", state_diff=diff)
        if scenario.scenario_id == "trade:approve:router":
            return SimulationResult(scenario.scenario_id, "success", anchor, tx_hash="0xapprove", state_diff={"before": {"address": TRADER}, "delta": {}})
        if scenario.scenario_id == "trade:transfer:only":
            return SimulationResult(scenario.scenario_id, "success", anchor, tx_hash="0xtransfer", receipt={"gasUsed": "0x5208", "effectiveGasPrice": "0x1"}, state_diff={
                "before": {"address": TRADER},
                "delta": {"token_balance_delta": {TOKEN: -1_000_000}},
                "event_analysis": {"erc20_transfers": [{"token": TOKEN, "from": TRADER, "to": PAIR, "amount": 1_000_000}]},
            })
        if scenario.scenario_id.startswith("trade:sell:"):
            frac = "partial_sell" if "partial_sell" in scenario.scenario_id else "baseline"
            amount = 500_000 if frac == "partial_sell" else 1_000_000
            return SimulationResult(scenario.scenario_id, "success", anchor, tx_hash="0xsell", receipt={"gasUsed": "0x5208", "effectiveGasPrice": "0x1"}, state_diff={
                "before": {"address": TRADER, "pair_reserves": {PAIR: {"reserve0": 10**20, "reserve1": 10**21}}, "pair_tokens": {PAIR: {"token0": WETH, "token1": TOKEN}}},
                "delta": {"token_balance_delta": {TOKEN: -amount}, "native_balance_delta_wei": 997_000_000_000_000},
                "event_analysis": {"erc20_transfers": [{"token": TOKEN, "from": TRADER, "to": PAIR, "amount": amount}]},
            })
        raise AssertionError(scenario.scenario_id)


def test_run_trade_matrix_uses_observed_buy_delta_and_independent_modes():
    pair = DexPair(
        chain_id="1", dex_id="uniswap", pair_address=PAIR, url=None,
        base_address=TOKEN, base_symbol="T", quote_address=WETH, quote_symbol="WETH",
        price_native=1.0, price_usd=1.0, liquidity_usd=100000.0,
        liquidity_base=None, liquidity_quote=None, volume_h24_usd=200000.0,
        buys_h24=20, sells_h24=12, pair_created_at_ms=None,
    )
    routes = DexRouteRegistry([DexRouteConfig("1", "uniswap", ROUTER, WETH)], include_defaults=False)
    plan = UniswapV2ScenarioBuilder(routes).build_native_plan(pair, TOKEN, TRADER, 10**15, 1000)
    anchor = BlockAnchor("1", 100, "0xblock", "0xparent", 100, "safe")
    fork = FakeFork()
    run = fork.run_trade_matrix(plan, anchor, "matrix-test", modes=("baseline", "partial_sell", "sell_all"))

    assert run.status == "complete"
    assert run.verdict == "LOW_RISK"
    sell_calls = [(sid, data) for sid, _, data in fork.calls if sid.startswith("trade:sell:")]
    assert len(sell_calls) == 3
    assert any(sid == "trade:sell:partial_sell" and data == encode_sell_from_template(plan.sell_templates["partial_sell"], 1_000_000) for sid, data in sell_calls)
    assert any(sid == "trade:sell:baseline" and data == encode_sell_from_template(plan.sell_templates["baseline"], 1_000_000) for sid, data in sell_calls)
    assert all(attempt.observed_buy_token_delta == 1_000_000 for attempt in run.attempts)


def test_run_trade_matrix_can_execute_transfer_only_without_approval():
    pair = DexPair(
        chain_id="1", dex_id="uniswap", pair_address=PAIR, url=None,
        base_address=TOKEN, base_symbol="T", quote_address=WETH, quote_symbol="WETH",
        price_native=1.0, price_usd=1.0, liquidity_usd=100000.0,
        liquidity_base=None, liquidity_quote=None, volume_h24_usd=200000.0,
        buys_h24=20, sells_h24=12, pair_created_at_ms=None,
    )
    routes = DexRouteRegistry([DexRouteConfig("1", "uniswap", ROUTER, WETH)], include_defaults=False)
    plan = UniswapV2ScenarioBuilder(routes).build_native_plan(pair, TOKEN, TRADER, 10**15, 1000)
    fork = FakeFork()
    run = fork.run_trade_matrix(plan, BlockAnchor("1", 100, "0xblock", "0xparent", 100, "safe"), "transfer-only", modes=("transfer_only",))
    assert run.status == "complete"
    assert run.attempts[0].mode == "transfer_only"
    assert run.attempts[0].classification == "transfer_succeeded"
    transfer_calls = [item for item in fork.calls if item[0] == "trade:transfer:only"]
    assert transfer_calls


def test_trade_matrix_marks_amount_threshold_when_small_sell_passes_and_large_sell_blocks():
    pair = DexPair(
        chain_id="1", dex_id="uniswap", pair_address=PAIR, url=None,
        base_address=TOKEN, base_symbol="T", quote_address=WETH, quote_symbol="WETH",
        price_native=1.0, price_usd=1.0, liquidity_usd=100000.0,
        liquidity_base=None, liquidity_quote=None, volume_h24_usd=200000.0,
        buys_h24=20, sells_h24=12, pair_created_at_ms=None,
    )
    routes = DexRouteRegistry([DexRouteConfig("1", "uniswap", ROUTER, WETH)], include_defaults=False)
    plan = UniswapV2ScenarioBuilder(routes).build_native_plan(pair, TOKEN, TRADER, 10**15, 1000)
    anchor = BlockAnchor("1", 100, "0xblock", "0xparent", 100, "safe")

    class ThresholdFork(FakeFork):
        def _execute_scenario(self, scenario, anchor):
            self.calls.append((scenario.scenario_id, scenario.value_wei, scenario.data))
            if scenario.scenario_id == "trade:buy:native-v2":
                return SimulationResult(scenario.scenario_id, "success", anchor, tx_hash="0xbuy", state_diff={"delta": {"token_balance_delta": {TOKEN: 1_000_000}}, "before": {"address": TRADER, "pair_reserves": {PAIR: {"reserve0": 10**20, "reserve1": 10**21}}, "pair_tokens": {PAIR: {"token0": WETH, "token1": TOKEN}}}})
            if scenario.scenario_id == "trade:approve:router":
                return SimulationResult(scenario.scenario_id, "success", anchor, tx_hash="0xapprove", state_diff={"delta": {}})
            if scenario.scenario_id.startswith("trade:sell:"):
                blocked = "sell_all" in scenario.scenario_id
                return SimulationResult(scenario.scenario_id, "reverted" if blocked else "success", anchor, tx_hash="0xsell" + scenario.scenario_id[-3:], error="transfer blocked" if blocked else None, state_diff={"before": {"address": TRADER, "pair_reserves": {PAIR: {"reserve0": 10**20, "reserve1": 10**21}}, "pair_tokens": {PAIR: {"token0": WETH, "token1": TOKEN}}}, "delta": {"token_balance_delta": {TOKEN: -500_000 if not blocked else 0}}, "event_analysis": {"erc20_transfers": [{"token": TOKEN, "from": TRADER, "to": PAIR, "amount": 500_000}] if not blocked else []}})
            raise AssertionError(scenario.scenario_id)

    run = ThresholdFork().run_trade_matrix(plan, anchor, "threshold", modes=("partial_sell", "sell_all"))
    assert any(signal["signal_id"] == "honeypot.amount_threshold.sell_restriction" for signal in run.hard_signals)
    assert run.verdict == "HONEYPOT_DETECTED"



def test_trade_matrix_adds_dynamic_tax_signal_when_sell_tax_changes_by_size():
    pair = DexPair(
        chain_id="1", dex_id="uniswap", pair_address=PAIR, url=None,
        base_address=TOKEN, base_symbol="T", quote_address=WETH, quote_symbol="WETH",
        price_native=1.0, price_usd=1.0, liquidity_usd=100000.0,
        liquidity_base=None, liquidity_quote=None, volume_h24_usd=200000.0,
        buys_h24=20, sells_h24=12, pair_created_at_ms=None,
    )
    routes = DexRouteRegistry([DexRouteConfig("1", "uniswap", ROUTER, WETH)], include_defaults=False)
    plan = UniswapV2ScenarioBuilder(routes).build_native_plan(pair, TOKEN, TRADER, 10**15, 1000)
    anchor = BlockAnchor("1", 100, "0xblock", "0xparent", 100, "safe")

    class TaxFork(FakeFork):
        def _execute_scenario(self, scenario, anchor):
            self.calls.append((scenario.scenario_id, scenario.value_wei, scenario.data))
            base_before = {"address": TRADER, "pair_reserves": {PAIR: {"reserve0": 10**20, "reserve1": 10**21}}, "pair_tokens": {PAIR: {"token0": WETH, "token1": TOKEN}}}
            if scenario.scenario_id == "trade:buy:native-v2":
                return SimulationResult(scenario.scenario_id, "success", anchor, tx_hash="0xbuy", state_diff={"before": base_before, "delta": {"token_balance_delta": {TOKEN: 1_000_000}}})
            if scenario.scenario_id == "trade:approve:router":
                return SimulationResult(scenario.scenario_id, "success", anchor, tx_hash="0xapprove", state_diff={"delta": {}})
            if scenario.scenario_id.startswith("trade:sell:"):
                is_partial = "partial_sell" in scenario.scenario_id
                requested = 500_000 if is_partial else 1_000_000
                received = 450_000 if is_partial else 700_000
                return SimulationResult(scenario.scenario_id, "success", anchor, tx_hash="0xsell", receipt={"gasUsed": "0x5208", "effectiveGasPrice": "0x1"}, state_diff={
                    "before": base_before, "delta": {"token_balance_delta": {TOKEN: -requested}},
                    "event_analysis": {"erc20_transfers": [{"token": TOKEN, "from": TRADER, "to": PAIR, "amount": received}]},
                })
            raise AssertionError(scenario.scenario_id)

    run = TaxFork().run_trade_matrix(plan, anchor, "dynamic-tax", modes=("partial_sell", "sell_all"))
    signal = next(item for item in run.hard_signals if item["signal_id"] == "tax.dynamic_sell_behavior")
    assert signal["severity"] == "high"
    assert len(signal["tax_samples_bps"]) == 2
