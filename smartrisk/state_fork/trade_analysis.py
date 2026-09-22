from __future__ import annotations

from typing import Any

from .v2_math import amount_out_v2


def effective_tax_bps(expected_amount: int | None, actual_amount: int | None) -> int | None:
    if expected_amount is None or actual_amount is None or expected_amount <= 0 or actual_amount < 0 or actual_amount > expected_amount:
        return None
    return int(round(((expected_amount - actual_amount) * 10_000) / expected_amount))


def retained_bps(expected_amount: int | None, actual_amount: int | None) -> int | None:
    if expected_amount is None or actual_amount is None or expected_amount <= 0 or actual_amount < 0:
        return None
    return int(round((actual_amount * 10_000) / expected_amount))


def trade_observation(result: Any, token_address: str, expected_amount: int | None = None) -> dict[str, Any]:
    """Turn a SimulationResult into a neutral, auditable trade observation."""
    diff = (result.state_diff or {}).get("delta", {}) if getattr(result, "state_diff", None) else {}
    token_delta = diff.get("token_balance_delta", {}).get(token_address)
    native_delta = diff.get("native_balance_delta_wei")
    event_analysis = (result.state_diff or {}).get("event_analysis", {}) if getattr(result, "state_diff", None) else {}
    return {
        "scenario_id": getattr(result, "scenario_id", None),
        "status": getattr(result, "status", None),
        "token_address": token_address,
        "token_balance_delta": token_delta,
        "native_balance_delta_wei": native_delta,
        "expected_amount": expected_amount,
        "effective_tax_bps": effective_tax_bps(expected_amount, token_delta),
        "event_analysis": event_analysis,
        "trace_available": bool(getattr(result, "trace", None)) and not (isinstance(getattr(result, "trace", None), dict) and "unavailable" in getattr(result, "trace", {})),
    }


def correlate_trade_sequence(
    buy: Any,
    approve: Any,
    sell: Any,
    token_address: str,
    pair_address: str,
    wrapped_native: str,
    requested_sell_amount: int,
    buy_amount_wei: int | None = None,
    pair_fee_bps: int = 30,
    sell_output_is_erc20: bool = False,
) -> dict[str, Any]:
    """Correlate buy/sell receipts, ERC-20 events and V2 reserve state into one report.

    The important distinction is between:
      * token tax observed on buy output,
      * token input tax observed before the pair,
      * AMM output expected from the amount the pair actually received,
      * native output after gas.
    """
    buy_diff = (buy.state_diff or {}) if getattr(buy, "state_diff", None) else {}
    sell_diff = (sell.state_diff or {}) if getattr(sell, "state_diff", None) else {}
    bought = ((buy_diff.get("delta") or {}).get("token_balance_delta") or {}).get(token_address)
    sell_transfers = ((sell_diff.get("event_analysis") or {}).get("erc20_transfers") or [])
    buy_transfers = ((buy_diff.get("event_analysis") or {}).get("erc20_transfers") or [])
    pair = pair_address.lower()
    trader = str((buy_diff.get("before") or {}).get("address") or "").lower()

    sell_pair_state = (sell_diff.get("before") or {}).get("pair_reserves", {}).get(pair_address)
    if sell_pair_state is None:
        sell_pair_state = (sell_diff.get("before") or {}).get("pair_reserves", {}).get(pair)
    buy_pair_state = (buy_diff.get("before") or {}).get("pair_reserves", {}).get(pair_address)
    if buy_pair_state is None:
        buy_pair_state = (buy_diff.get("before") or {}).get("pair_reserves", {}).get(pair)
    pair_tokens = (sell_diff.get("before") or {}).get("pair_tokens", {}).get(pair_address)
    if pair_tokens is None:
        pair_tokens = (sell_diff.get("before") or {}).get("pair_tokens", {}).get(pair)

    analysis: dict[str, Any] = {
        "pair_address": pair_address,
        "token_address": token_address,
        "wrapped_native": wrapped_native,
        "requested_sell_amount": requested_sell_amount,
        "observed_buy_token_delta": bought,
        "buy": {
            "status": getattr(buy, "status", None),
            "token_received": _positive_user_delta(buy_transfers, token_address, trader, direction="in"),
            "pair_sent_token": _positive_user_delta(buy_transfers, token_address, pair, direction="out"),
        },
        "sell": {
            "status": getattr(sell, "status", None),
            "token_sent_to_pair": _positive_user_delta(sell_transfers, token_address, pair, direction="in_from_trader", trader=trader),
            "native_received_estimate_wei": _native_received_estimate(sell),
        },
        "pair_state": {
            "buy_before_reserves": buy_pair_state,
            "sell_before_reserves": sell_pair_state,
            "token0": pair_tokens.get("token0") if isinstance(pair_tokens, dict) else None,
            "token1": pair_tokens.get("token1") if isinstance(pair_tokens, dict) else None,
        },
        "unknowns": [],
    }

    sell_pair_input = analysis["sell"]["token_sent_to_pair"]
    if sell_pair_input is not None and requested_sell_amount > 0:
        analysis["sell"]["input_retained_bps"] = retained_bps(requested_sell_amount, sell_pair_input)
        analysis["sell"]["input_tax_bps"] = effective_tax_bps(requested_sell_amount, sell_pair_input)

    expected_buy = _expected_v2_output(
        buy_pair_state, pair_tokens, token_in=wrapped_native, token_out=token_address,
        amount_in=buy_amount_wei,
        fee_bps=pair_fee_bps,
    )
    if expected_buy is not None and bought is not None:
        analysis["buy"]["expected_pair_output"] = expected_buy
        analysis["buy"]["output_retained_bps"] = retained_bps(expected_buy, bought)
        analysis["buy"]["effective_output_tax_bps"] = effective_tax_bps(expected_buy, bought)
    else:
        analysis["unknowns"].append("could not compute expected V2 buy output from pair reserves/token orientation")

    if sell_pair_input is not None and sell_pair_input > 0:
        native_expected = _expected_v2_output(
            sell_pair_state, pair_tokens, token_in=token_address, token_out=wrapped_native,
            amount_in=sell_pair_input, fee_bps=pair_fee_bps,
        )
        if sell_output_is_erc20:
            actual_output = _positive_user_delta(sell_transfers, wrapped_native, trader, direction="in")
        else:
            actual_output = analysis["sell"]["native_received_estimate_wei"]
        if native_expected is not None:
            analysis["sell"]["expected_pair_output"] = native_expected
            analysis["sell"]["actual_native_output"] = None if sell_output_is_erc20 else actual_output
            analysis["sell"]["actual_output_amount"] = actual_output
            analysis["sell"]["output_asset"] = wrapped_native
            if actual_output is not None:
                analysis["sell"]["output_retained_bps"] = retained_bps(native_expected, actual_output)
                analysis["sell"]["output_tax_bps"] = effective_tax_bps(native_expected, actual_output)
        else:
            analysis["unknowns"].append("could not compute expected V2 sell output from pair reserves/token orientation")
    else:
        analysis["unknowns"].append("sell did not transfer a measurable token amount to the pair")

    analysis["classification"] = _trade_classification(sell, analysis)
    input_amount = analysis.get("sell", {}).get("token_sent_to_pair")
    input_tax = analysis.get("sell", {}).get("input_tax_bps")
    # A tax percentage is only evidence when the token movement to the pair was
    # actually observed. A successful tx with zero/missing transfer evidence is
    # an accounting unknown, not proof of a 100% tax.
    analysis["sell"]["effective_sell_tax_bps"] = (
        input_tax if isinstance(input_tax, int) and isinstance(input_amount, int) and input_amount > 0 else None
    )
    if analysis["sell"]["effective_sell_tax_bps"] is None and sell.status == "success":
        analysis["unknowns"].append("successful sell did not produce a positive measurable token transfer to the pair")
    return analysis


def _expected_v2_output(pair_state: dict[str, Any] | None, pair_tokens: dict[str, Any] | None, token_in: str, token_out: str, amount_in: int | None, fee_bps: int) -> int | None:
    if not isinstance(pair_state, dict) or not isinstance(pair_tokens, dict) or amount_in is None:
        return None
    token0 = str(pair_tokens.get("token0") or "").lower()
    token1 = str(pair_tokens.get("token1") or "").lower()
    reserve0 = _to_int(pair_state.get("reserve0"))
    reserve1 = _to_int(pair_state.get("reserve1"))
    if reserve0 is None or reserve1 is None:
        return None
    if token0 == token_in.lower() and token1 == token_out.lower():
        return amount_out_v2(amount_in, reserve0, reserve1, fee_bps)
    if token1 == token_in.lower() and token0 == token_out.lower():
        return amount_out_v2(amount_in, reserve1, reserve0, fee_bps)
    return None


def _positive_user_delta(transfers: list[dict[str, Any]], token_address: str, address: str, direction: str, trader: str | None = None) -> int | None:
    token = token_address.lower()
    addr = address.lower()
    total = 0
    matched = False
    for item in transfers:
        if str(item.get("token") or "").lower() != token:
            continue
        source = str(item.get("from") or "").lower()
        dest = str(item.get("to") or "").lower()
        amount = _to_int(item.get("amount")) or 0
        if direction == "in" and dest == addr:
            total += amount
            matched = True
        elif direction == "out" and source == addr:
            total += amount
            matched = True
        elif direction == "in_from_trader" and dest == addr and (trader is None or source == trader):
            total += amount
            matched = True
    return total if matched else None


def _native_received_estimate(result: Any) -> int | None:
    diff = (getattr(result, "state_diff", None) or {}).get("delta") or {}
    native_delta = _to_int(diff.get("native_balance_delta_wei"))
    receipt = getattr(result, "receipt", None) or {}
    gas_used = _hex_or_int(receipt.get("gasUsed"))
    gas_price = _hex_or_int(receipt.get("effectiveGasPrice"))
    if native_delta is None:
        return None
    if gas_used is None or gas_price is None:
        return native_delta
    return native_delta + gas_used * gas_price



def _trade_classification(sell: Any, analysis: dict[str, Any]) -> str:
    status = getattr(sell, "status", None)
    if status == "reverted":
        return "sell_blocked"
    if status == "unknown":
        return "unknown"
    input_tax = analysis.get("sell", {}).get("input_tax_bps")
    output_tax = analysis.get("sell", {}).get("output_tax_bps")
    if isinstance(input_tax, int) and input_tax >= 9500:
        return "sell_input_effectively_blocked"
    if isinstance(output_tax, int) and output_tax >= 9500:
        return "sell_output_effectively_blocked"
    return "sell_succeeded"


def _to_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _hex_or_int(value: Any) -> int | None:
    try:
        if isinstance(value, str):
            return int(value, 16) if value.startswith("0x") else int(value)
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None
