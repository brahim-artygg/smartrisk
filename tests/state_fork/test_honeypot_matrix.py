from smartrisk.state_fork.honeypot import HoneypotMatrix
from smartrisk.state_fork.models import SimulationResult


def test_honeypot_matrix_plans_independent_modes():
    report = HoneypotMatrix().plan("buy", "approve", {
        "baseline": "trade:sell:baseline",
        "partial_sell": "trade:sell:partial_sell",
        "sell_all": "trade:sell:sell_all",
    })
    assert [item.mode for item in report.attempts[:3]] == ["baseline", "partial_sell", "sell_all"]
    assert report.attempts[1].prerequisites == ("buy_success", "approve_success")


def test_honeypot_matrix_classifies_reverted_sell_as_blocked_signal():
    report = HoneypotMatrix().classify_results(
        [SimulationResult("trade:sell:partial_sell", "reverted", None, tx_hash="0x1", error="transfer blocked")],
        {"partial_sell": "trade:sell:partial_sell"},
    )
    assert report.classifications[0]["classification"] == "blocked"
    assert report.classifications[0]["failure_cause"] == "token_restriction"
    assert report.hard_signals[0]["severity"] == "critical"


def test_honeypot_matrix_does_not_promote_generic_router_revert_to_blocked():
    report = HoneypotMatrix().classify_results(
        [SimulationResult("trade:sell:partial_sell", "reverted", None, tx_hash="0x1", revert_reason="UniswapV2: K")],
        {"partial_sell": "trade:sell:partial_sell"},
    )
    assert report.classifications[0]["classification"] == "unknown"
    assert report.classifications[0]["failure_cause"] == "router_or_pair"
    assert not report.hard_signals
