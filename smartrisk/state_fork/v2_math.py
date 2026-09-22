from __future__ import annotations

from typing import Any


def amount_out_v2(amount_in: int, reserve_in: int, reserve_out: int, fee_bps: int = 30) -> int | None:
    if amount_in <= 0 or reserve_in <= 0 or reserve_out <= 0 or not 0 <= fee_bps < 10_000:
        return None
    fee_denominator = 10_000
    amount_in_with_fee = amount_in * (fee_denominator - fee_bps)
    numerator = amount_in_with_fee * reserve_out
    denominator = reserve_in * fee_denominator + amount_in_with_fee
    if denominator <= 0:
        return None
    return numerator // denominator


def orientation(pair_state: dict[str, Any], token_in: str, token_out: str) -> tuple[int, int] | None:
    token0 = str(pair_state.get("token0") or "").lower()
    token1 = str(pair_state.get("token1") or "").lower()
    if token0 == token_in.lower() and token1 == token_out.lower():
        reserves = pair_state.get("reserves") or {}
        return int(reserves.get("reserve0", 0)), int(reserves.get("reserve1", 0))
    if token1 == token_in.lower() and token0 == token_out.lower():
        reserves = pair_state.get("reserves") or {}
        return int(reserves.get("reserve1", 0)), int(reserves.get("reserve0", 0))
    return None
