from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .models import ChainAnchor, Feature, RawObservation


class FeatureExtractor:
    def extract_market_features(
        self,
        token_address: str,
        token_observation: RawObservation,
        code_observation: RawObservation | None = None,
    ) -> list[Feature]:
        payload = token_observation.payload
        pairs = payload.get("pairs") or []
        if not isinstance(pairs, list):
            pairs = []
        valid_pairs = [pair for pair in pairs if isinstance(pair, dict)]
        refs = [token_observation.observation_id]
        features: list[Feature] = []
        coverage = 0.0 if token_observation.error else 1.0
        confidence = 0.7 if token_observation.stale else 0.85
        features.append(self._feature("market.pair_count", token_address, None if token_observation.error else len(valid_pairs), "count", token_observation, confidence, coverage, refs, token_observation.error))
        if not valid_pairs:
            return features
        liquidities = [self._number(pair.get("liquidity", {}).get("usd")) for pair in valid_pairs]
        liquidities = [value for value in liquidities if value is not None]
        volumes = [self._number(pair.get("volume", {}).get("h24")) for pair in valid_pairs]
        volumes = [value for value in volumes if value is not None]
        buys = sum(self._number(pair.get("txns", {}).get("h24", {}).get("buys")) or 0 for pair in valid_pairs)
        sells = sum(self._number(pair.get("txns", {}).get("h24", {}).get("sells")) or 0 for pair in valid_pairs)
        prices = [self._number(pair.get("priceUsd")) for pair in valid_pairs]
        prices = [value for value in prices if value is not None and value > 0]
        created = [self._number(pair.get("pairCreatedAt")) for pair in valid_pairs]
        created = [value for value in created if value is not None and value > 0]
        features.extend([
            self._feature("market.best_liquidity_usd", token_address, max(liquidities) if liquidities else None, "usd", token_observation, confidence, coverage, refs, "liquidity missing" if not liquidities else None),
            self._feature("market.volume_h24_usd", token_address, sum(volumes) if volumes else None, "usd", token_observation, confidence, coverage, refs, "volume missing" if not volumes else None),
            self._feature("market.buys_h24", token_address, buys, "count", token_observation, confidence, coverage, refs),
            self._feature("market.sells_h24", token_address, sells, "count", token_observation, confidence, coverage, refs),
            self._feature("market.price_min_usd", token_address, min(prices) if prices else None, "usd", token_observation, confidence, coverage, refs),
            self._feature("market.price_max_usd", token_address, max(prices) if prices else None, "usd", token_observation, confidence, coverage, refs),
            self._feature("market.pair_age_hours", token_address, self._age_hours(min(created)) if created else None, "hours", token_observation, confidence, coverage, refs),
        ])
        if code_observation:
            code = str(code_observation.payload.get("code", "0x"))
            features.append(Feature(
                "chain.token_has_code", token_address, bool(code and code != "0x"), "boolean", "alchemy", 0.98, 1.0,
                code_observation.observed_at, [code_observation.observation_id], [] if code and code != "0x" else ["Alchemy returned empty code"],
            ))
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
