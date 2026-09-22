from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .models import Feature, RawObservation


class FeatureExtractor:
    def extract_market_features(
        self,
        token_address: str,
        token_observation: RawObservation,
        code_observation: RawObservation | None = None,
        intelligence_observation: RawObservation | None = None,
    ) -> list[Feature]:
        payload = token_observation.payload
        pairs = payload.get("pairs") or []
        if not isinstance(pairs, list):
            pairs = []
        valid_pairs = [pair for pair in pairs if isinstance(pair, dict)]
        refs = [token_observation.observation_id]
        features: list[Feature] = []
        coverage = 0.0 if token_observation.error else (0.7 if token_observation.stale else 1.0)
        confidence = 0.7 if token_observation.stale else 0.88
        features.append(self._feature("market.pair_count", token_address, None if token_observation.error else len(valid_pairs), "count", token_observation, confidence, coverage, refs, token_observation.error))
        if valid_pairs:
            liquidities = [self._number(pair.get("liquidity", {}).get("usd")) for pair in valid_pairs]
            liquidities = [value for value in liquidities if value is not None and value >= 0]
            volumes = [self._number(pair.get("volume", {}).get("h24")) for pair in valid_pairs]
            volumes = [value for value in volumes if value is not None and value >= 0]
            buys = sum(self._number(pair.get("txns", {}).get("h24", {}).get("buys")) or 0 for pair in valid_pairs)
            sells = sum(self._number(pair.get("txns", {}).get("h24", {}).get("sells")) or 0 for pair in valid_pairs)
            prices = [self._number(pair.get("priceUsd")) for pair in valid_pairs]
            prices = [value for value in prices if value is not None and value > 0]
            created = [self._number(pair.get("pairCreatedAt")) for pair in valid_pairs]
            created = [value for value in created if value is not None and value > 0]
            pairs_with_sells = sum(1 for pair in valid_pairs if (self._number(pair.get("txns", {}).get("h24", {}).get("sells")) or 0) > 0)
            pairs_with_buys = sum(1 for pair in valid_pairs if (self._number(pair.get("txns", {}).get("h24", {}).get("buys")) or 0) > 0)
            features.extend([
                self._feature("market.best_liquidity_usd", token_address, max(liquidities) if liquidities else None, "usd", token_observation, confidence, coverage, refs, "liquidity missing" if not liquidities else None),
                self._feature("market.volume_h24_usd", token_address, sum(volumes) if volumes else None, "usd", token_observation, confidence, coverage, refs, "volume missing" if not volumes else None),
                self._feature("market.buys_h24", token_address, buys, "count", token_observation, confidence, coverage, refs),
                self._feature("market.sells_h24", token_address, sells, "count", token_observation, confidence, coverage, refs),
                self._feature("market.pairs_with_buys_h24", token_address, pairs_with_buys, "count", token_observation, confidence, coverage, refs),
                self._feature("market.pairs_with_sells_h24", token_address, pairs_with_sells, "count", token_observation, confidence, coverage, refs),
                self._feature("market.sell_buy_ratio_h24", token_address, (sells / buys) if buys else None, "ratio", token_observation, confidence, coverage, refs, "buy count is zero" if buys == 0 else None),
                self._feature("market.price_min_usd", token_address, min(prices) if prices else None, "usd", token_observation, confidence, coverage, refs, "price missing" if not prices else None),
                self._feature("market.price_max_usd", token_address, max(prices) if prices else None, "usd", token_observation, confidence, coverage, refs, "price missing" if not prices else None),
                self._feature("market.pair_age_hours", token_address, self._age_hours(min(created)) if created else None, "hours", token_observation, confidence, coverage, refs, "pair creation time missing" if not created else None),
            ])
        if code_observation:
            code = str(code_observation.payload.get("code", "0x"))
            code_conf = 0.99 if not code_observation.error else 0.0
            features.append(Feature(
                "chain.token_has_code", token_address, bool(code and code != "0x"), "boolean", getattr(code_observation, "provider", None) or "unknown", code_conf, 1.0 if not code_observation.error else 0.0,
                code_observation.observed_at, [code_observation.observation_id], [] if code and code != "0x" else ["Alchemy returned empty code"],
            ))
        if intelligence_observation:
            payload = intelligence_observation.payload
            for feature_id, value, unit, confidence in (
                ("contract.byte_length", payload.get("bytecode", {}).get("byte_length"), "bytes", 0.95),
                ("contract.delegatecall_present", payload.get("observable_capabilities", {}).get("can_execute_delegatecall"), "boolean", 0.95),
                ("contract.selfdestruct_pattern", payload.get("observable_capabilities", {}).get("can_selfdestruct_pattern"), "boolean", 0.90),
                ("contract.external_call_present", payload.get("observable_capabilities", {}).get("can_call_external"), "boolean", 0.90),
                ("contract.storage_write_present", payload.get("observable_capabilities", {}).get("can_write_storage"), "boolean", 0.95),
                ("contract.time_or_block_logic", payload.get("observable_capabilities", {}).get("uses_time_or_block_condition"), "boolean", 0.80),
            ):
                features.append(Feature(feature_id, token_address, value, unit, "smartrisk-bytecode", confidence, 1.0, intelligence_observation.observed_at, [intelligence_observation.observation_id]))
        return features

    @staticmethod
    def _feature(feature_id: str, subject: str, value: Any, unit: str, observation: RawObservation, confidence: float, coverage: float, refs: list[str], unknown: str | None = None) -> Feature:
        return Feature(feature_id, subject, value, unit, observation.provider, confidence, coverage, observation.observed_at, refs, [unknown] if unknown else [])

    @staticmethod
    def _number(value: Any) -> float | None:
        try:
            return float(value) if value is not None else None
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _age_hours(timestamp_ms: float) -> float:
        return max(0.0, (datetime.now(timezone.utc).timestamp() - timestamp_ms / 1000) / 3600)
