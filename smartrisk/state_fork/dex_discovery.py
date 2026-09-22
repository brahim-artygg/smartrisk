from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from ..core.networks import try_get_network


@dataclass(frozen=True)
class DexPair:
    chain_id: str
    dex_id: str
    pair_address: str
    url: str | None
    base_address: str
    base_symbol: str | None
    quote_address: str | None
    quote_symbol: str | None
    price_native: float | None
    price_usd: float | None
    liquidity_usd: float | None
    liquidity_base: float | None
    liquidity_quote: float | None
    volume_h24_usd: float | None
    buys_h24: int | None
    sells_h24: int | None
    pair_created_at_ms: int | None
    labels: tuple[str, ...] = ()
    fdv: float | None = None
    market_cap: float | None = None
    raw: dict[str, Any] = field(default_factory=dict, compare=False)

    def involves(self, token_address: str) -> bool:
        token = token_address.lower()
        return self.base_address.lower() == token or (self.quote_address or "").lower() == token

    def token_side(self, token_address: str) -> str | None:
        token = token_address.lower()
        if self.base_address.lower() == token:
            return "base"
        if (self.quote_address or "").lower() == token:
            return "quote"
        return None

    @property
    def volume_h24(self) -> float:
        return self.volume_h24_usd or 0.0

    @property
    def trade_count_h24(self) -> int:
        return (self.buys_h24 or 0) + (self.sells_h24 or 0)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DexDiscoveryReport:
    chain_id: str
    token_address: str
    pairs: list[DexPair] = field(default_factory=list)
    selected_pair: DexPair | None = None
    diagnostics: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "token_address": self.token_address,
            "pairs": [p.to_dict() for p in self.pairs],
            "selected_pair": self.selected_pair.to_dict() if self.selected_pair else None,
            "diagnostics": list(self.diagnostics),
        }


def discover_pairs(payload: dict[str, Any] | list[Any], chain_id: str, token_address: str) -> DexDiscoveryReport:
    raw_pairs = _extract_pairs(payload)
    normalized: list[DexPair] = []
    diagnostics: list[str] = []
    for raw in raw_pairs:
        if not isinstance(raw, dict):
            continue
        try:
            pair = _normalize_pair(raw, chain_id)
        except ValueError as exc:
            diagnostics.append(str(exc))
            continue
        if pair.chain_id.lower() != chain_id.lower() or not pair.involves(token_address):
            continue
        normalized.append(pair)
    normalized.sort(key=_pair_rank, reverse=True)
    if not normalized:
        diagnostics.append("no DexScreener pair involving the target token was discovered")
    return DexDiscoveryReport(chain_id, token_address, normalized, normalized[0] if normalized else None, diagnostics)


def _extract_pairs(payload: dict[str, Any] | list[Any]) -> list[Any]:
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        return []
    for key in ("pairs", "data", "pair"):
        value = payload.get(key)
        if isinstance(value, list):
            return value
        if isinstance(value, dict):
            return [value]
    return []


def _normalize_pair(raw: dict[str, Any], default_chain_id: str) -> DexPair:
    raw_chain = str(raw.get("chainId") or default_chain_id)
    profile = try_get_network(raw_chain)
    chain = profile.chain_id if profile else raw_chain
    dex = str(raw.get("dexId") or "unknown")
    pair_address = str(raw.get("pairAddress") or "")
    base = raw.get("baseToken") or {}
    quote = raw.get("quoteToken") or {}
    base_address = str(base.get("address") or "")
    if not pair_address or not base_address:
        raise ValueError("DexScreener returned a pair without pairAddress/baseToken.address")
    txns_h24 = raw.get("txns", {}).get("h24", {}) if isinstance(raw.get("txns"), dict) else {}
    volume_h24 = raw.get("volume", {}).get("h24") if isinstance(raw.get("volume"), dict) else None
    liquidity = raw.get("liquidity") if isinstance(raw.get("liquidity"), dict) else {}
    return DexPair(
        chain_id=chain,
        dex_id=dex,
        pair_address=pair_address,
        url=raw.get("url"),
        base_address=base_address,
        base_symbol=base.get("symbol"),
        quote_address=quote.get("address"),
        quote_symbol=quote.get("symbol"),
        price_native=_number(raw.get("priceNative")),
        price_usd=_number(raw.get("priceUsd")),
        liquidity_usd=_number(liquidity.get("usd")),
        liquidity_base=_number(liquidity.get("base")),
        liquidity_quote=_number(liquidity.get("quote")),
        volume_h24_usd=_number(volume_h24),
        buys_h24=_int(txns_h24.get("buys")),
        sells_h24=_int(txns_h24.get("sells")),
        pair_created_at_ms=_int(raw.get("pairCreatedAt")),
        labels=tuple(str(item) for item in (raw.get("labels") or []) if item is not None),
        fdv=_number(raw.get("fdv")),
        market_cap=_number(raw.get("marketCap")),
        raw=raw,
    )


def _pair_rank(pair: DexPair) -> tuple[float, float, int, int]:
    # Objective selection only: liquidity first, then trading activity.
    # Risk classification is deliberately not performed here.
    return (
        pair.liquidity_usd or 0.0,
        pair.volume_h24,
        pair.trade_count_h24,
        pair.pair_created_at_ms or 0,
    )


def _number(value: Any) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None
