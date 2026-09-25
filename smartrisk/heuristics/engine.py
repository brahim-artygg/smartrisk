from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

from ..state_fork.alchemy_rpc import AlchemyRpcClient, AlchemyRpcError
from ..core.networks import get_network
from .alchemy_source import AlchemySource
from .contract_intelligence import EIP1967_ADMIN_SLOT, EIP1967_BEACON_SLOT, EIP1967_IMPLEMENTATION_SLOT, ContractIntelligence
from .dexscreener import DexscreenerClient
from .features import FeatureExtractor
from .intelligence import IntelligenceAnalyzer
from .models import Feature, HeuristicsRun, RawObservation, RiskScore
from .policy import PolicyRegistry
from .rules import RuleEngine


class HeuristicsEngine:
    ENGINE_VERSION = "0.4.0"

    def __init__(
        self,
        alchemy: AlchemySource | None = None,
        dexscreener: DexscreenerClient | None = None,
        extractor: FeatureExtractor | None = None,
        rules: RuleEngine | None = None,
        policy_path: str | Path | None = None,
        intelligence: ContractIntelligence | None = None,
        onchain_intelligence: IntelligenceAnalyzer | None = None,
    ):
        self.alchemy = alchemy or AlchemySource()
        self.dexscreener = dexscreener or DexscreenerClient()
        self.extractor = extractor or FeatureExtractor()
        self.rules = rules or RuleEngine(PolicyRegistry.load(policy_path))
        self.intelligence = intelligence or ContractIntelligence()
        self.onchain_intelligence = onchain_intelligence or IntelligenceAnalyzer(self.alchemy)

    def analyze(
        self,
        chain_id: str,
        token_address: str,
        run_id: str | None = None,
        block_tag: str = "safe",
        block_number: int | None = None,
        window_blocks: int = 10_000,
        deployer_address: str | None = None,
        max_pairs: int = 5,
        max_holder_contract_probes: int = 12,
        rpc_log_concurrency: int = 4,
        max_log_chunk_blocks: int = 1_500,
        probe_concurrency: int = 4,
        pair_concurrency: int = 2,
    ) -> HeuristicsRun:
        run_id = run_id or str(uuid.uuid4())
        network = get_network(chain_id)
        active_alchemy = self.alchemy
        alchemy_rpc = getattr(self.alchemy, "rpc", None)
        if alchemy_rpc is not None:
            active_rpc_chain = getattr(alchemy_rpc, "chain", None)
            if active_rpc_chain != network.rpc_chain:
                active_alchemy = AlchemySource(rpc=AlchemyRpcClient(chain=network.rpc_chain))
        active_intelligence = self.onchain_intelligence if active_alchemy is self.alchemy else IntelligenceAnalyzer(active_alchemy)
        capability = {"alchemy": active_alchemy.capability_probe(), "dexscreener": self.dexscreener.capability_probe()}
        if capability["alchemy"].get("status") != "ready":
            empty = RiskScore(0.0, "unknown", 0.0, 0.0, unknowns=["Alchemy RPC is unavailable"])
            return HeuristicsRun(run_id, "unknown", None, empty, capability=capability)
        try:
            anchor = active_alchemy.anchor(block_tag, block_number)
        except (AlchemyRpcError, KeyError, TypeError, ValueError) as exc:
            empty = RiskScore(0.0, "unknown", 0.0, 0.0, unknowns=[str(exc)])
            return HeuristicsRun(run_id, "unknown", None, empty, capability=capability)

        observations: list[RawObservation] = []
        diagnostics: list[str] = []
        code = None
        try:
            code = active_alchemy.get_code(token_address, anchor)
            observations.append(code)
        except Exception as exc:
            diagnostics.append(f"Alchemy code lookup failed: {exc}")

        logs = None
        try:
            try:
                    logs = active_alchemy.get_logs(
                        token_address, anchor, max(0, anchor.block_number - window_blocks), anchor.block_number,
                        max_chunk_blocks=max_log_chunk_blocks, concurrency=rpc_log_concurrency,
                        max_calls=max(1, int(max_log_chunk_blocks and (window_blocks // max_log_chunk_blocks + 1))),
                    )
            except TypeError:
                logs = active_alchemy.get_logs(token_address, anchor, max(0, anchor.block_number - window_blocks), anchor.block_number)
            observations.append(logs)
            payload = getattr(logs, "payload", None)
            if isinstance(payload, dict) and payload.get("truncated"):
                diagnostics.append("token transfer history was capped for this busy token; holder/history metrics reflect the most recent activity only")
        except Exception as exc:
            diagnostics.append(f"Alchemy logs lookup failed: {exc}")

        market = None
        try:
            market = self.dexscreener.get_token_pairs(network.dexscreener_id, token_address)
            observations.append(market)
        except Exception as exc:
            diagnostics.append(f"Dexscreener lookup failed: {exc}")

        if market is None:
            market = RawObservation("dexscreener:missing", "dexscreener", "token-pairs", token_address, "", {}, error="Dexscreener observation unavailable", stale=True)
            observations.append(market)

        intelligence = None
        intelligence_payload: dict[str, Any] = {}
        if code is not None and not code.error:
            storage: dict[str, str] = {}
            calls: dict[str, Any] = {}
            get_storage = getattr(active_alchemy, "get_storage_at", None)
            if callable(get_storage):
                for label, slot in (("implementation", EIP1967_IMPLEMENTATION_SLOT), ("admin", EIP1967_ADMIN_SLOT), ("beacon", EIP1967_BEACON_SLOT)):
                    try:
                        item = get_storage(token_address, slot, anchor)
                        observations.append(item)
                        storage[slot] = str(item.payload.get("value") or "0x")
                    except Exception:
                        # Optional proxy metadata must not turn an otherwise valid scan into failure.
                        storage[slot] = "0x"
            get_call = getattr(active_alchemy, "call_selector", None)
            if callable(get_call):
                try:
                    owner_call = get_call(token_address, "0x8da5cb5b", anchor)
                    observations.append(owner_call)
                    calls["owner"] = owner_call.payload.get("value")
                except Exception:
                    pass
            implementation_loader = None
            get_code = getattr(active_alchemy, "get_code", None)
            if callable(get_code):
                def _load_implementation(address: str) -> str:
                    item = get_code(address, anchor)
                    observations.append(item)
                    if item.error:
                        raise RuntimeError(item.error)
                    return str(item.payload.get("code", "0x"))
                implementation_loader = _load_implementation
            intelligence_payload = self.intelligence.build_recursive_profile(
                str(code.payload.get("code", "0x")),
                storage=storage,
                calls=calls,
                implementation_loader=implementation_loader,
                max_depth=2,
            )
            intelligence = RawObservation(
                observation_id=f"smartrisk:intelligence:{token_address}:{anchor.block_hash}",
                provider="smartrisk-bytecode",
                endpoint="local-contract-intelligence",
                subject=token_address,
                observed_at=code.observed_at,
                payload=intelligence_payload,
                anchor=anchor,
            )
            observations.append(intelligence)

        features = self.extractor.extract_market_features(token_address, market, code, intelligence)
        if logs is not None:
            features.append(Feature(
                "chain.log_count_window", token_address, len(logs.payload.get("logs", [])), "count", "alchemy", 0.9, 1.0,
                logs.observed_at, [logs.observation_id],
            ))
        if intelligence is not None:
            privileges = intelligence.payload.get("privileges", {})
            features.extend([
                Feature("contract.proxy_detected", token_address, bool(privileges.get("upgradeable")), "boolean", "smartrisk-bytecode", 0.95, 1.0, intelligence.observed_at, [intelligence.observation_id]),
                Feature("contract.owner_observed", token_address, bool(privileges.get("owner")), "boolean", "alchemy", 0.9, 1.0, intelligence.observed_at, [intelligence.observation_id]),
                Feature("contract.admin_observed", token_address, bool(privileges.get("admin")), "boolean", "alchemy", 0.9, 1.0, intelligence.observed_at, [intelligence.observation_id]),
            ])
            fingerprints = intelligence.payload.get("scam_fingerprints", {})
            fp_items = fingerprints.get("items", []) if isinstance(fingerprints, dict) else []
            features.extend([
                Feature("contract.fingerprint_count", token_address, len(fp_items), "count", "smartrisk-fingerprints", 0.82, 1.0, intelligence.observed_at, [intelligence.observation_id]),
                Feature("contract.deferred_behavior_signal", token_address, any(item.get("category") == "deferred_behavior" for item in fp_items if isinstance(item, dict)), "boolean", "smartrisk-fingerprints", 0.72, 1.0, intelligence.observed_at, [intelligence.observation_id]),
            ])

        intelligence_kwargs = {
            "chain_id": chain_id,
            "token_address": token_address,
            "anchor": anchor,
            "token_logs": logs,
            "market_observation": market,
            "window_blocks": window_blocks,
            "deployer_address": deployer_address,
            "max_pairs": max_pairs,
            "max_holder_contract_probes": max_holder_contract_probes,
            "probe_concurrency": probe_concurrency,
            "pair_concurrency": pair_concurrency,
            "log_concurrency": rpc_log_concurrency,
        }
        try:
            intelligence_result = active_intelligence.analyze(**intelligence_kwargs)
        except TypeError as exc:
            if "unexpected keyword argument" not in str(exc):
                raise
            for key in ("probe_concurrency", "pair_concurrency", "log_concurrency"):
                intelligence_kwargs.pop(key, None)
            intelligence_result = active_intelligence.analyze(**intelligence_kwargs)
        if intelligence is not None:
            fingerprints = intelligence.payload.get("scam_fingerprints", {})
            fp_items = fingerprints.get("items", []) if isinstance(fingerprints, dict) else []
            intelligence_payload.setdefault("findings", [])
            for item in fp_items:
                if not isinstance(item, dict):
                    continue
                finding_id = f"fingerprint:{item.get('fingerprint_id')}:{token_address.lower()}"
                fingerprint_finding = {
                    "finding_id": finding_id,
                    "engine": "intelligence",
                    "rule_id": f"fingerprint.{item.get('fingerprint_id')}",
                    "title": item.get("fingerprint_id", "Bytecode fingerprint"),
                    "description": item.get("explanation", "Deterministic bytecode fingerprint observed."),
                    "severity": "medium",
                    "confidence": float(item.get("confidence", 0.0) or 0.0),
                    "status": "likely",
                    "evidence_refs": [intelligence.observation_id],
                    "metadata": {"signals": item.get("signals", []), "category": item.get("category"), "fingerprint_version": fingerprints.get("version") if isinstance(fingerprints, dict) else None},
                }
                intelligence_payload["findings"].append(fingerprint_finding)
                intelligence_result.findings.append(fingerprint_finding)
        features.extend(intelligence_result.features)
        features.append(Feature(
            "intelligence.coverage", token_address, intelligence_result.coverage, "ratio",
            "smartrisk-intelligence", intelligence_result.confidence, intelligence_result.coverage,
            intelligence_result.observations[-1].observed_at if intelligence_result.observations else None,
            [intelligence_result.observations[-1].observation_id] if intelligence_result.observations else [],
        ))
        observations.extend(item for item in intelligence_result.observations if item.observation_id not in {obs.observation_id for obs in observations})
        risk = self.rules.score(features)
        risk.observations = observations
        if intelligence_result.unknowns:
            risk.unknowns.extend(f"intelligence: {reason}" for reason in intelligence_result.unknowns)
        if diagnostics:
            risk.unknowns.extend(diagnostics)
        if market is not None and market.error:
            # Market unavailability is a first-class uncertainty. It must not be
            # converted into a low-risk conclusion merely because chain facts exist.
            risk.band = "unknown"
        status = "complete" if risk.coverage >= 0.5 and not diagnostics and not risk.unknowns else "partial"
        if risk.coverage == 0:
            status = "unknown"
        return HeuristicsRun(run_id, status, anchor, risk, capability=capability, diagnostics=diagnostics, intelligence=intelligence_result.to_dict())
