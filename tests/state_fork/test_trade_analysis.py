from types import SimpleNamespace

from smartrisk.state_fork.trade_analysis import effective_tax_bps, trade_observation


def test_effective_tax_bps():
    assert effective_tax_bps(1000, 900) == 1000
    assert effective_tax_bps(1000, 1000) == 0
    assert effective_tax_bps(0, 1) is None


def test_trade_observation_uses_runtime_state_diff():
    result = SimpleNamespace(
        scenario_id="sell",
        status="success",
        state_diff={"delta": {"token_balance_delta": {"0xtoken": 900}}, "event_analysis": {"erc20_transfers": []}},
    )
    observation = trade_observation(result, "0xtoken", expected_amount=1000)
    assert observation["effective_tax_bps"] == 1000
    assert observation["status"] == "success"


def test_fuzzer_argument_mutations_preserve_function_selector():
    from smartrisk.validation import DeterministicCalldataFuzzer
    fuzzer = DeterministicCalldataFuzzer(seed=7)
    base = "0xa9059cbb" + ("00" * 64)
    for mutation in ("zero", "ff", "bitflip", "byteflip", "truncate", "extend", "edge32"):
        mutated = fuzzer._mutate(base, mutation)
        assert mutated.startswith("0xa9059cbb")
