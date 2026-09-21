from __future__ import annotations

import uuid
from typing import Any

from ..state_fork.alchemy_rpc import AlchemyRpcError
from .alchemy_source import AlchemySource
from .dexscreener import DexscreenerClient
from .features import FeatureExtractor
from .models import Feature, HeuristicsRun, RiskScore
from .rules import RuleEngine


class HeuristicsEngine:
    ENGINE_VERSION = "0.1.0"

    def __init__(
        self,
        alchemy: AlchemySource | None = None,
        dexscreener: DexscreenerClient | None = None,
        extractor: FeatureExtractor | None = None,
        rules: RuleEngine | None = None,
    ):
        self.alchemy = alchemy or AlchemySource()
        self.dexscreener = dexscreener or DexscreenerClient()
        self.extractor = extractor or FeatureExtractor()
        self.rules = rules or RuleEngine()

    def analyze(
        self,
        chain_id: str,
        token_address: str,
        run_id: str | None = None,
        block_tag: str = "safe",
        block_number: int | None = None,
        window_blocks: int = 10_000,
    ) -> HeuristicsRun:
        run_id = run_id or str(uuid.uuid4())
        capability = {"alchemy": self.alchemy.capability_probe(), "dexscreener": self.dexscreener.capability_probe()}
        if capability["alchemy"].get("status") != "ready":
            empty = RiskScore(0.0, "unknown", 0.0, 0.0, unknowns=["Alchemy RPC is unavailable"])
            return HeuristicsRun(run_id, "unknown", None, empty, capability=capability)
        try:
            anchor = self.alchemy.anchor(block_tag, block_number)
        except (AlchemyRpcError, KeyError, TypeError, ValueError) as exc:
            empty = RiskScore(0.0, "unknown", 0.0, 0.0, unknowns=[str(exc)])
            return HeuristicsRun(run_id, "unknown", None, empty, capability=capability)

        observations = []
        diagnostics: list[str] = []
        try:
            code = self.alchemy.get_code(token_address, anchor)
            observations.append(code)
        except Exception as exc:
            code = None
            diagnostics.append(f"Alchemy code lookup failed: {exc}")
        try:
            logs = self.alchemy.get_logs(token_address, anchor, max(0, anchor.block_number - window_blocks), anchor.block_number)
            observations.append(logs)
        except Exception as exc:
            logs = None
            diagnostics.append(f"Alchemy logs lookup failed: {exc}")
        try:
            market = self.dexscreener.get_token_pairs(chain_id, token_address)
            observations.append(market)
        except Exception as exc:
            market = None
            diagnostics.append(f"Dexscreener lookup failed: {exc}")

        if market is None:
            from .models import RawObservation
            market = RawObservation("dexscreener:missing", "dexscreener", "token-pairs", token_address, "", {}, error="Dexscreener observation unavailable", stale=True)
            observations.append(market)
        features = self.extractor.extract_market_features(token_address, market, code)
        if logs is not None:
            features.append(Feature(
                "chain.log_count_window", token_address, len(logs.payload.get("logs", [])), "count", "alchemy", 0.9, 1.0,
                logs.observed_at, [logs.observation_id],
            ))
        risk = self.rules.score(features)
        if diagnostics:
            risk.unknowns.extend(diagnostics)
        status = "complete" if risk.coverage >= 0.5 and not diagnostics and not risk.unknowns else "partial"
        if risk.coverage == 0:
            status = "unknown"
        return HeuristicsRun(run_id, status, anchor, risk, capability=capability, diagnostics=diagnostics)
