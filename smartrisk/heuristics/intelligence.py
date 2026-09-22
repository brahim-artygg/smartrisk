from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .models import ChainAnchor, Feature, RawObservation
from ..indexer.ledger import TransferEvent, TransferLedger
from ..indexer.analytics import LedgerAnalytics

ZERO = "0x" + "0" * 40
BURN_ADDRESSES = {
    ZERO,
    "0x000000000000000000000000000000000000dead",
    "0x000000000000000000000000000000000000dEaD".lower(),
}
TRANSFER_SELECTOR = "0xddf252ad"
TOKEN0_SELECTOR = "0x0dfe1681"
TOKEN1_SELECTOR = "0xd21220a7"
GET_RESERVES_SELECTOR = "0x0902f1ac"
TOTAL_SUPPLY_SELECTOR = "0x18160ddd"
BALANCE_OF_SELECTOR = "0x70a08231"


@dataclass
class IntelligenceResult:
    status: str
    coverage: float
    confidence: float
    payload: dict[str, Any]
    features: list[Feature]
    observations: list[RawObservation]
    findings: list[dict[str, Any]]
    unknowns: list[str]
    diagnostics: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "coverage": self.coverage,
            "confidence": self.confidence,
            "payload": self.payload,
            "features": [feature.to_dict() for feature in self.features],
            "observations": [item.to_dict() for item in self.observations],
            "findings": self.findings,
            "unknowns": self.unknowns,
            "diagnostics": self.diagnostics,
        }


class IntelligenceAnalyzer:
    """Local on-chain intelligence: holders, LPs, deployer candidates, clusters and history.

    This layer deliberately uses only the supplied RPC/AlchemySource plus market observations
    already collected from DexScreener. It never asks a security provider for classifications.
    """

    ENGINE_VERSION = "0.5.0"

    def __init__(self, alchemy: Any):
        self.alchemy = alchemy

    def analyze(
        self,
        chain_id: str,
        token_address: str,
        anchor: ChainAnchor,
        token_logs: RawObservation | None,
        market_observation: RawObservation | None,
        window_blocks: int,
        deployer_address: str | None = None,
        max_pairs: int = 5,
        max_holder_contract_probes: int = 12,
    ) -> IntelligenceResult:
        observations: list[RawObservation] = []
        unknowns: list[str] = []
        diagnostics: list[str] = []
        features: list[Feature] = []
        findings: list[dict[str, Any]] = []

        token_ledger = TransferLedger()
        token_log_count = 0
        if token_logs is None or token_logs.error:
            unknowns.append("token transfer logs are unavailable")
        else:
            raw_logs = token_logs.payload.get("logs", []) if isinstance(token_logs.payload, dict) else []
            token_log_count = len(raw_logs) if isinstance(raw_logs, list) else 0
            token_ledger.ingest_logs(chain_id, raw_logs if isinstance(raw_logs, list) else [])
            observations.append(token_logs)

        analytics = LedgerAnalytics(token_ledger)
        holders = self._holder_intelligence(token_address, token_ledger, analytics, anchor, token_log_count, logs_available=bool(token_logs and not token_logs.error), excluded_addresses=self._pair_addresses(market_observation))
        holder_probe_observations, holder_type_summary = self._probe_holder_types(
            holders, token_address, anchor, max_holder_contract_probes
        )
        holders["holder_types"] = holder_type_summary
        observations.extend(holder_probe_observations)
        features.extend(self._features_from_mapping(token_address, holders, token_logs.observation_id if token_logs else None, confidence=0.93, coverage=holders.get("coverage", 0.0)))
        if holder_type_summary.get("probed_contract_holder_share") is not None:
            features.append(Feature(
                "holders.probed_contract_holder_share", token_address, holder_type_summary["probed_contract_holder_share"], "ratio",
                "smartrisk-intelligence", 0.88, holders.get("coverage", 0.0),
                datetime.now(timezone.utc).isoformat(), [token_logs.observation_id] if token_logs else []
            ))
        findings.extend(self._holder_findings(token_address, holders))

        pairs = self._market_pairs(market_observation.payload if market_observation and not market_observation.error else {})
        pair_addresses = [str(item.get("pairAddress")) for item in pairs if item.get("pairAddress")][:max_pairs]
        pair_reports: list[dict[str, Any]] = []
        lp_observation_ids: list[str] = []
        for pair in pairs[:max_pairs]:
            pair_address = str(pair.get("pairAddress") or "")
            if not pair_address:
                continue
            try:
                report, pair_obs, pair_unknowns = self._analyze_pair_lp(
                    chain_id, token_address, pair_address, anchor, window_blocks, holders.get("deployer_candidates", []), deployer_address
                )
                pair_reports.append(report)
                observations.extend(pair_obs)
                lp_observation_ids.extend(item.observation_id for item in pair_obs)
                unknowns.extend(pair_unknowns)
                findings.extend(self._lp_findings(pair_address, report))
            except Exception as exc:
                diagnostics.append(f"LP analysis failed for {pair_address}: {exc}")
                unknowns.append(f"LP analysis unavailable for {pair_address}")

        history = self._historical_behavior(token_address, token_ledger, pair_addresses, anchor, window_blocks, logs_available=bool(token_logs and not token_logs.error))
        clusters = self._wallet_clusters(token_address, token_ledger, pair_addresses, holders.get("balances", {}), logs_available=bool(token_logs and not token_logs.error))
        deployer = self._deployer_intelligence(token_address, token_ledger, holders, deployer_address, anchor, logs_available=bool(token_logs and not token_logs.error))

        features.extend(self._features_from_mapping(token_address, self._liquidity_summary(pair_reports), token_logs.observation_id if token_logs else None, confidence=0.84, coverage=self._liquidity_summary(pair_reports).get("coverage", 0.0)))
        features.extend(self._features_from_mapping(token_address, history, token_logs.observation_id if token_logs else None, confidence=0.88, coverage=history.get("coverage", 0.0)))
        features.extend(self._features_from_mapping(token_address, clusters, token_logs.observation_id if token_logs else None, confidence=0.82, coverage=clusters.get("coverage", 0.0)))
        features.extend(self._features_from_mapping(token_address, deployer, token_logs.observation_id if token_logs else None, confidence=0.86, coverage=deployer.get("coverage", 0.0)))

        findings.extend(self._history_findings(history))
        findings.extend(self._cluster_findings(clusters))
        findings.extend(self._deployer_findings(deployer))

        holder_payload = dict(holders)
        holder_payload.pop("balances", None)
        payload = {
            "engine_version": self.ENGINE_VERSION,
            "token": {
                "address": token_address,
                "chain_id": chain_id,
                "anchor_block": anchor.block_number,
                "log_count": token_log_count,
            },
            "holders": holder_payload,
            "liquidity": {
                "pairs": pair_reports,
                "selected_pair_count": len(pair_reports),
            },
            "deployer": deployer,
            "clusters": clusters,
            "historical_behavior": history,
            "evidence": {
                "token_log_observation": token_logs.observation_id if token_logs else None,
                "market_observation": market_observation.observation_id if market_observation else None,
                "lp_observations": lp_observation_ids,
            },
        }

        # Attach one deterministic synthetic observation so downstream correlation can
        # reference the whole intelligence bundle without losing the underlying raw refs.
        intel_observation = RawObservation(
            observation_id=f"smartrisk:intelligence:onchain:{token_address.lower()}:{anchor.block_number}",
            provider="smartrisk-intelligence",
            endpoint="local-onchain-intelligence",
            subject=token_address,
            observed_at=datetime.now(timezone.utc).isoformat(),
            payload=payload,
            anchor=anchor,
        )
        observations.append(intel_observation)
        intel_ref = intel_observation.observation_id
        for finding in findings:
            finding["evidence_refs"] = [intel_ref]
        for feature in features:
            if not feature.evidence_refs:
                feature.evidence_refs.append(intel_ref)
            elif intel_ref not in feature.evidence_refs:
                feature.evidence_refs.append(intel_ref)

        base_coverage = self._weighted_coverage(
            [holders.get("coverage", 0.0), history.get("coverage", 0.0), clusters.get("coverage", 0.0), deployer.get("coverage", 0.0),
             1.0 if pair_reports else (0.0 if market_observation and market_observation.error else 0.5)]
        )
        confidence = self._weighted_confidence([0.93, 0.88, 0.82, 0.86, 0.84])
        status = "complete" if base_coverage >= 0.75 and not unknowns and not diagnostics else "partial"
        if base_coverage == 0:
            status = "unknown"
        return IntelligenceResult(status, round(base_coverage, 3), round(confidence, 3), payload, features, observations, findings, sorted(set(unknowns)), diagnostics)

    @staticmethod
    def _market_pairs(payload: dict[str, Any]) -> list[dict[str, Any]]:
        pairs = payload.get("pairs") if isinstance(payload, dict) else []
        if not isinstance(pairs, list):
            return []
        valid = [item for item in pairs if isinstance(item, dict) and item.get("pairAddress")]
        def liquidity(item: dict[str, Any]) -> float:
            try:
                return float((item.get("liquidity") or {}).get("usd") or 0)
            except (TypeError, ValueError):
                return 0.0
        return sorted(valid, key=liquidity, reverse=True)

    @staticmethod
    def _pair_addresses(market_observation: RawObservation | None) -> set[str]:
        if not market_observation or market_observation.error or not isinstance(market_observation.payload, dict):
            return set()
        pairs = market_observation.payload.get("pairs") or []
        return {str(item.get("pairAddress")).lower() for item in pairs if isinstance(item, dict) and item.get("pairAddress")}

    def _holder_intelligence(self, token_address: str, ledger: TransferLedger, analytics: LedgerAnalytics, anchor: ChainAnchor, token_log_count: int, logs_available: bool, excluded_addresses: set[str] | None = None) -> dict[str, Any]:
        balances = ledger.holder_snapshot(token_address)
        excluded = {str(item).lower() for item in (excluded_addresses or set())}
        positive = {addr.lower(): amount for addr, amount in balances.items() if amount > 0}
        eoa_like = {addr: amount for addr, amount in positive.items() if addr not in BURN_ADDRESSES and addr not in excluded}
        ordered = sorted(eoa_like.items(), key=lambda item: item[1], reverse=True)
        total = sum(value for _, value in ordered)
        gross_total = sum(positive.values())
        top = lambda n: sum(value for _, value in ordered[:n]) / total if total else None
        mints = [event for event in ledger.events.values() if event.token_address.lower() == token_address.lower() and event.from_address == ZERO]
        mints.sort(key=lambda event: (event.block_number, event.log_index))
        candidate = mints[0].to_address.lower() if mints else None
        churn = analytics.holder_churn(token_address, max(0, anchor.block_number - max(1, token_log_count or 1) // 2)) if token_log_count else {"changed_holders": 0, "holder_count_before": 0, "holder_count_after": len(ordered)}
        candidate_supply_share = (sum(max(0, eoa_like.get(address, 0)) for address in ([candidate] if candidate and candidate not in excluded and candidate not in BURN_ADDRESSES else [])) / total) if candidate and total else None
        excluded_balance = sum(positive.get(address, 0) for address in excluded)
        burned_balance = sum(positive.get(address, 0) for address in BURN_ADDRESSES)
        return {
            "coverage": 1.0 if logs_available else 0.0,
            "deployer_candidate_share": candidate_supply_share,
            "holder_count": len(ordered),
            "positive_balance_total": gross_total,
            "adjusted_eoa_positive_balance_total": total,
            "excluded_pair_balance": excluded_balance,
            "burn_address_balance": burned_balance,
            "top_10_concentration": top(10),
            "top_20_concentration": top(20),
            "top_50_concentration": top(50),
            "top_100_concentration": top(100),
            "top_holders": [{"address": addr, "balance": value, "share": (value / total if total else None)} for addr, value in ordered[:100]],
            "deployer_candidates": [candidate] if candidate else [],
            "distribution_mint_count_observed": len(mints),
            "churn": churn,
            "balances": positive,
            "adjusted_balances": eoa_like,
            "excluded_addresses": sorted(excluded),
        }

    def _analyze_pair_lp(
        self,
        chain_id: str,
        token_address: str,
        pair_address: str,
        anchor: ChainAnchor,
        window_blocks: int,
        deployer_candidates: list[str],
        deployer_address: str | None,
    ) -> tuple[dict[str, Any], list[RawObservation], list[str]]:
        observations: list[RawObservation] = []
        unknowns: list[str] = []
        pair_lower = pair_address.lower()
        def call(data: str) -> str | None:
            getter = getattr(self.alchemy, "call_data", None)
            if not callable(getter):
                return None
            obs = getter(pair_address, data, anchor)
            observations.append(obs)
            return str(obs.payload.get("value") or "")

        token0 = self._decode_address(call(TOKEN0_SELECTOR))
        token1 = self._decode_address(call(TOKEN1_SELECTOR))
        reserves_raw = call(GET_RESERVES_SELECTOR)
        total_supply = self._decode_uint(call(TOTAL_SUPPLY_SELECTOR))
        if token0 is None or token1 is None:
            unknowns.append(f"pair token orientation unavailable for {pair_address}")
        reserves = self._decode_reserves(reserves_raw)
        if reserves is None:
            unknowns.append(f"pair reserves unavailable for {pair_address}")

        from_block = max(0, anchor.block_number - max(1, window_blocks))
        lp_logs = None
        try:
            getter = getattr(self.alchemy, "get_logs", None)
            if callable(getter):
                lp_logs = getter(pair_address, anchor, from_block, anchor.block_number)
                observations.append(lp_logs)
        except Exception as exc:
            unknowns.append(f"LP transfer history unavailable for {pair_address}: {exc}")

        lp_ledger = TransferLedger()
        lp_event_count = 0
        if lp_logs is not None and not lp_logs.error:
            raw = lp_logs.payload.get("logs", [])
            lp_event_count = len(raw) if isinstance(raw, list) else 0
            lp_ledger.ingest_logs(chain_id, raw if isinstance(raw, list) else [])
        elif lp_logs is not None and lp_logs.error:
            unknowns.append(f"LP logs error for {pair_address}: {lp_logs.error}")

        lp_balances = lp_ledger.holder_snapshot(pair_address)
        positive = {addr.lower(): value for addr, value in lp_balances.items() if value > 0}
        ordered = sorted(positive.items(), key=lambda item: item[1], reverse=True)
        lp_sum = sum(value for _, value in ordered)
        top1_share = ordered[0][1] / lp_sum if ordered and lp_sum else None
        top5_share = sum(value for _, value in ordered[:5]) / lp_sum if lp_sum else None
        burned = sum(value for addr, value in positive.items() if addr in BURN_ADDRESSES)
        candidate_addresses = {item.lower() for item in deployer_candidates if item}
        if deployer_address:
            candidate_addresses.add(deployer_address.lower())
        candidate_lp = sum(value for addr, value in positive.items() if addr in candidate_addresses)
        report = {
            "pair_address": pair_address,
            "token0": token0,
            "token1": token1,
            "reserves": reserves,
            "lp_total_supply": total_supply,
            "lp_holder_count_observed": len(positive),
            "lp_event_count_observed": lp_event_count,
            "lp_distribution_coverage": min(1.0, (lp_sum / total_supply)) if total_supply and lp_sum >= 0 else (1.0 if lp_event_count == 0 and total_supply == 0 else 0.5),
            "lp_top1_share": top1_share,
            "lp_top5_share": top5_share,
            "lp_burned_share": burned / total_supply if total_supply else None,
            "lp_deployer_or_candidate_share": candidate_lp / total_supply if total_supply else None,
            "top_lp_holders": [{"address": addr, "balance": value, "share": value / total_supply if total_supply else (value / lp_sum if lp_sum else None)} for addr, value in ordered[:25]],
        }
        report["coverage"] = report["lp_distribution_coverage"]
        return report, observations, unknowns

    @staticmethod
    def _liquidity_summary(pair_reports: list[dict[str, Any]]) -> dict[str, Any]:
        if not pair_reports:
            return {"coverage": 0.0, "pair_count": 0, "max_lp_top1_share": None, "max_lp_candidate_share": None, "max_lp_burned_share": None, "average_lp_distribution_coverage": None}
        top1 = [item.get("lp_top1_share") for item in pair_reports if isinstance(item.get("lp_top1_share"), (int, float))]
        candidate = [item.get("lp_deployer_or_candidate_share") for item in pair_reports if isinstance(item.get("lp_deployer_or_candidate_share"), (int, float))]
        burned = [item.get("lp_burned_share") for item in pair_reports if isinstance(item.get("lp_burned_share"), (int, float))]
        coverage = [float(item.get("lp_distribution_coverage")) for item in pair_reports if isinstance(item.get("lp_distribution_coverage"), (int, float))]
        return {
            "coverage": sum(coverage) / len(coverage) if coverage else 0.5,
            "pair_count": len(pair_reports),
            "max_lp_top1_share": max(top1) if top1 else None,
            "max_lp_candidate_share": max(candidate) if candidate else None,
            "max_lp_burned_share": max(burned) if burned else None,
            "average_lp_distribution_coverage": sum(coverage) / len(coverage) if coverage else None,
        }

    @staticmethod
    def _historical_behavior(token_address: str, ledger: TransferLedger, pair_addresses: list[str], anchor: ChainAnchor, window_blocks: int, logs_available: bool) -> dict[str, Any]:
        events = sorted((event for event in ledger.events.values() if event.token_address.lower() == token_address.lower()), key=lambda item: (item.block_number, item.log_index))
        if not events:
            return {"coverage": 1.0 if logs_available else 0.0, "transfer_count": 0, "active_wallets": 0, "unique_buyers": 0, "unique_sellers": 0, "round_trip_wallets": 0, "first_block": None, "last_block": None}
        pairs = {item.lower() for item in pair_addresses}
        buyers: set[str] = set()
        sellers: set[str] = set()
        for event in events:
            if event.from_address.lower() in pairs and event.to_address.lower() not in BURN_ADDRESSES:
                buyers.add(event.to_address.lower())
            if event.to_address.lower() in pairs and event.from_address.lower() not in BURN_ADDRESSES:
                sellers.add(event.from_address.lower())
        active = {addr for event in events for addr in (event.from_address.lower(), event.to_address.lower()) if addr not in BURN_ADDRESSES}
        round_trip = buyers & sellers
        split_index = max(1, len(events) // 2)
        early = events[:split_index]
        late = events[split_index:]
        early_wallets = {addr for event in early for addr in (event.from_address.lower(), event.to_address.lower()) if addr not in BURN_ADDRESSES}
        late_wallets = {addr for event in late for addr in (event.from_address.lower(), event.to_address.lower()) if addr not in BURN_ADDRESSES}
        return {
            "coverage": 1.0 if logs_available else 0.0,
            "transfer_count": len(events),
            "active_wallets": len(active),
            "unique_buyers": len(buyers),
            "unique_sellers": len(sellers),
            "round_trip_wallets": len(round_trip),
            "first_block": events[0].block_number,
            "last_block": events[-1].block_number,
            "window_blocks": window_blocks,
            "transferred_volume": sum(event.amount for event in events),
            "early_wallet_count": len(early_wallets),
            "late_wallet_count": len(late_wallets),
            "early_late_wallet_overlap": len(early_wallets & late_wallets),
        }

    @staticmethod
    def _wallet_clusters(token_address: str, ledger: TransferLedger, pair_addresses: list[str], balances: dict[str, int], logs_available: bool) -> dict[str, Any]:
        pairs = {item.lower() for item in pair_addresses}
        graph: dict[str, set[str]] = defaultdict(set)
        fanout_sources: dict[str, list[TransferEvent]] = defaultdict(list)
        for event in ledger.events.values():
            if event.token_address.lower() != token_address.lower():
                continue
            src, dst = event.from_address.lower(), event.to_address.lower()
            if src in BURN_ADDRESSES or dst in BURN_ADDRESSES or src in pairs or dst in pairs:
                fanout_sources[src].append(event)
                continue
            graph[src].add(dst)
            graph[dst].add(src)
            fanout_sources[src].append(event)

        seen: set[str] = set()
        components: list[set[str]] = []
        for node in graph:
            if node in seen:
                continue
            stack = [node]
            component: set[str] = set()
            while stack:
                cur = stack.pop()
                if cur in seen:
                    continue
                seen.add(cur)
                component.add(cur)
                stack.extend(graph.get(cur, ()))
            components.append(component)
        components.sort(key=lambda c: sum(max(0, balances.get(addr, 0)) for addr in c), reverse=True)
        total = sum(max(0, balances.get(addr, 0)) for addr in balances if addr not in BURN_ADDRESSES and addr not in pairs)
        largest_share = sum(max(0, balances.get(addr, 0)) for addr in components[0]) / total if components and total else None
        bursts = 0
        for source, events in fanout_sources.items():
            if source in BURN_ADDRESSES or len(events) < 3:
                continue
            recipients: dict[str, list[int]] = defaultdict(list)
            for event in events:
                recipients[event.to_address.lower()].append(event.block_number)
            distinct = [(addr, blocks) for addr, blocks in recipients.items() if addr not in BURN_ADDRESSES]
            if len(distinct) >= 3:
                flat = [block for _, blocks in distinct for block in blocks]
                if max(flat) - min(flat) <= 3:
                    bursts += 1
        return {
            "coverage": 1.0 if logs_available else 0.0,
            "cluster_count": len(components),
            "largest_cluster_wallet_count": len(components[0]) if components else 0,
            "largest_cluster_supply_share": largest_share,
            "coordinated_fanout_burst_count": bursts,
            "top_clusters": [
                {"wallet_count": len(component), "supply_share": (sum(max(0, balances.get(addr, 0)) for addr in component) / total if total else None), "addresses": sorted(component)[:50]}
                for component in components[:10]
            ],
        }

    @staticmethod
    def _deployer_intelligence(token_address: str, ledger: TransferLedger, holders: dict[str, Any], deployer_address: str | None, anchor: ChainAnchor, logs_available: bool) -> dict[str, Any]:
        candidates = {addr.lower() for addr in holders.get("deployer_candidates", []) if addr}
        provided = deployer_address.lower() if deployer_address else None
        if provided:
            candidates.add(provided)
        balances = holders.get("balances", {})
        total = sum(max(0, value) for value in balances.values())
        candidate_balances = {addr: max(0, balances.get(addr, 0)) for addr in candidates}
        candidate_share = (sum(candidate_balances.values()) / total) if total else None
        first_mint_block = None
        first_mint_amount = None
        for event in sorted(ledger.events.values(), key=lambda item: (item.block_number, item.log_index)):
            if event.token_address.lower() == token_address.lower() and event.from_address == ZERO:
                first_mint_block = event.block_number
                first_mint_amount = event.amount
                break
        return {
            "coverage": 1.0 if logs_available else 0.0,
            "address": provided,
            "candidate_addresses": sorted(candidates),
            "candidate_supply_share": candidate_share,
            "first_mint_block_observed": first_mint_block,
            "first_mint_amount_observed": first_mint_amount,
            "creator_verified": bool(provided),
            "creator_verification_method": "explicit_input" if provided else "not_verified_from_token_logs",
            "anchor_block": anchor.block_number,
        }

    @staticmethod
    def _features_from_mapping(token_address: str, payload: dict[str, Any], evidence_ref: str | None, confidence: float, coverage: float) -> list[Feature]:
        mapping = {
            "holders.holder_count": (payload.get("holder_count"), "count"),
            "holders.adjusted_eoa_positive_balance_total": (payload.get("adjusted_eoa_positive_balance_total"), "token_units"),
            "holders.excluded_pair_balance": (payload.get("excluded_pair_balance"), "token_units"),
            "holders.burn_address_balance": (payload.get("burn_address_balance"), "token_units"),
            "holders.top10_concentration": (payload.get("top_10_concentration"), "ratio"),
            "holders.top20_concentration": (payload.get("top_20_concentration"), "ratio"),
            "holders.top50_concentration": (payload.get("top_50_concentration"), "ratio"),
            "holders.top100_concentration": (payload.get("top_100_concentration"), "ratio"),
            "holders.deployer_candidate_share": (payload.get("deployer_candidate_share"), "ratio"),
            "holders.probed_contract_holder_share": (payload.get("contract_holder_share"), "ratio"),
            "history.transfer_count": (payload.get("transfer_count"), "count"),
            "history.unique_buyers": (payload.get("unique_buyers"), "count"),
            "history.unique_sellers": (payload.get("unique_sellers"), "count"),
            "history.round_trip_wallets": (payload.get("round_trip_wallets"), "count"),
            "clusters.cluster_count": (payload.get("cluster_count"), "count"),
            "clusters.largest_supply_share": (payload.get("largest_cluster_supply_share"), "ratio"),
            "clusters.coordinated_fanout_bursts": (payload.get("coordinated_fanout_burst_count"), "count"),
            "deployer.creator_verified": (payload.get("creator_verified"), "boolean"),
            "deployer.candidate_supply_share": (payload.get("candidate_supply_share"), "ratio"),
            "liquidity.pair_count_analyzed": (payload.get("pair_count"), "count"),
            "liquidity.max_lp_top1_share": (payload.get("max_lp_top1_share"), "ratio"),
            "liquidity.max_lp_candidate_share": (payload.get("max_lp_candidate_share"), "ratio"),
            "liquidity.max_lp_burned_share": (payload.get("max_lp_burned_share"), "ratio"),
            "liquidity.lp_distribution_coverage": (payload.get("average_lp_distribution_coverage"), "ratio"),
        }
        result: list[Feature] = []
        for feature_id, (value, unit) in mapping.items():
            if value is None:
                continue
            refs = [evidence_ref] if evidence_ref else []
            result.append(Feature(feature_id, token_address, value, unit, "smartrisk-intelligence", confidence, coverage, datetime.now(timezone.utc).isoformat(), refs))
        return result

    def _probe_holder_types(self, holders: dict[str, Any], token_address: str, anchor: ChainAnchor, max_probes: int) -> tuple[list[RawObservation], dict[str, Any]]:
        observations: list[RawObservation] = []
        top = holders.get("top_holders", []) if isinstance(holders, dict) else []
        addresses = [str(item.get("address")) for item in top[:max(0, max_probes)] if item.get("address")]
        address_types: dict[str, str] = {}
        for address in addresses:
            if address.lower() in BURN_ADDRESSES:
                address_types[address.lower()] = "burn"
                continue
            try:
                getter = getattr(self.alchemy, "get_code", None)
                if not callable(getter):
                    break
                obs = getter(address, anchor)
                observations.append(obs)
                code = str(obs.payload.get("code") or "0x")
                address_types[address.lower()] = "contract" if code not in {"", "0x", "0X"} else "eoa_or_unknown"
            except Exception:
                address_types[address.lower()] = "unknown"
        balances = holders.get("balances", {})
        total = sum(max(0, int(value)) for value in balances.values())
        contract_balance = sum(max(0, int(value)) for address, value in balances.items() if address.lower() in {item for item, kind in address_types.items() if kind == "contract"})
        return observations, {
            "probed_holder_count": len(address_types),
            "contract_holder_count_observed": sum(kind == "contract" for kind in address_types.values()),
            "probed_contract_holder_share": contract_balance / total if total and address_types else None,
            "types": address_types,
        }

    @staticmethod
    def _holder_findings(token_address: str, holders: dict[str, Any]) -> list[dict[str, Any]]:
        findings = []
        top10 = holders.get("top_10_concentration")
        top20 = holders.get("top_20_concentration")
        if isinstance(top20, float) and top20 >= 0.80:
            findings.append(IntelligenceAnalyzer._finding("holders.top20_concentration", "high", "Top 20 observed holders control at least 80% of reconstructed positive supply.", "holders", 0.92))
        elif isinstance(top10, float) and top10 >= 0.60:
            findings.append(IntelligenceAnalyzer._finding("holders.top10_concentration", "medium", "Top 10 observed holders control at least 60% of reconstructed positive supply.", "holders", 0.90))
        return findings

    @staticmethod
    def _lp_findings(pair_address: str, report: dict[str, Any]) -> list[dict[str, Any]]:
        findings = []
        top1 = report.get("lp_top1_share")
        if isinstance(top1, float) and top1 >= 0.70:
            findings.append(IntelligenceAnalyzer._finding("lp.top1_concentration", "high", f"A single observed LP holder controls {top1:.1%} of reconstructed LP supply for {pair_address}.", "liquidity", 0.90))
        candidate = report.get("lp_deployer_or_candidate_share")
        if isinstance(candidate, float) and candidate >= 0.25:
            findings.append(IntelligenceAnalyzer._finding("lp.candidate_control", "high", f"A deployer/candidate-linked address controls {candidate:.1%} of observed LP supply for {pair_address}.", "liquidity", 0.88))
        burned = report.get("lp_burned_share")
        if isinstance(burned, float) and burned >= 0.90:
            # Burned LP is informational context, not a risk penalty.
            findings.append(IntelligenceAnalyzer._finding("lp.burned_majority", "informational", f"At least {burned:.1%} of observed LP supply is held by a burn address for {pair_address}.", "liquidity", 0.96))
        return findings

    @staticmethod
    def _history_findings(history: dict[str, Any]) -> list[dict[str, Any]]:
        findings = []
        buyers, sellers = history.get("unique_buyers"), history.get("unique_sellers")
        transfers = history.get("transfer_count")
        # Meme launches can legitimately show buys before the first meaningful
        # sells. Require a mature-looking sample before treating no observed
        # sellers as a risk finding. The RuleEngine applies an additional policy
        # threshold, so the intelligence finding follows the same conservative gate.
        if isinstance(buyers, int) and buyers >= 10 and sellers == 0 and isinstance(transfers, int) and transfers >= 20:
            findings.append(IntelligenceAnalyzer._finding("history.no_observed_sellers", "medium", f"The observed on-chain window contains {buyers} buy-like wallets and no sell-like wallets across {transfers} token transfers.", "historical_behavior", 0.82))
        return findings

    @staticmethod
    def _cluster_findings(clusters: dict[str, Any]) -> list[dict[str, Any]]:
        findings = []
        share = clusters.get("largest_cluster_supply_share")
        bursts = clusters.get("coordinated_fanout_burst_count")
        if isinstance(share, float) and share >= 0.50:
            findings.append(IntelligenceAnalyzer._finding("clusters.large_supply_cluster", "medium", f"The largest reconstructed wallet cluster controls {share:.1%} of observed positive supply.", "clusters", 0.80))
        if isinstance(bursts, int) and bursts > 0:
            findings.append(IntelligenceAnalyzer._finding("clusters.coordinated_fanout", "low", f"Observed {bursts} fan-out transfer burst(s) to multiple wallets within a narrow block range.", "clusters", 0.74))
        return findings

    @staticmethod
    def _deployer_findings(deployer: dict[str, Any]) -> list[dict[str, Any]]:
        findings = []
        if deployer.get("creator_verified"):
            share = deployer.get("candidate_supply_share")
            if isinstance(share, float) and share >= 0.25:
                findings.append(IntelligenceAnalyzer._finding("deployer.high_supply_control", "high", f"The explicitly supplied creator/deployer address controls {share:.1%} of reconstructed positive token supply.", "deployer", 0.88))
        return findings

    @staticmethod
    def _finding(rule_id: str, severity: str, explanation: str, family: str, confidence: float) -> dict[str, Any]:
        return {
            "finding_id": f"intelligence:{rule_id}",
            "engine": "intelligence",
            "rule_id": rule_id,
            "title": explanation,
            "description": explanation,
            "severity": severity,
            "confidence": confidence,
            "status": "confirmed" if severity in {"high", "medium"} else "likely",
            "family": family,
            "evidence_refs": [],
        }

    @staticmethod
    def _decode_address(value: str | None) -> str | None:
        if not value:
            return None
        raw = value[2:] if value.startswith("0x") else value
        if len(raw) < 40:
            return None
        return "0x" + raw[-40:].lower()

    @staticmethod
    def _decode_uint(value: str | None) -> int | None:
        if not value:
            return None
        try:
            return int(value, 16)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _decode_reserves(value: str | None) -> dict[str, int] | None:
        if not value:
            return None
        raw = value[2:] if value.startswith("0x") else value
        if len(raw) < 128:
            return None
        try:
            return {"reserve0": int(raw[0:64], 16), "reserve1": int(raw[64:128], 16)}
        except ValueError:
            return None

    @staticmethod
    def _weighted_coverage(values: list[float]) -> float:
        if not values:
            return 0.0
        return sum(max(0.0, min(1.0, value)) for value in values) / len(values)

    @staticmethod
    def _weighted_confidence(values: list[float]) -> float:
        return round(sum(values) / len(values), 3) if values else 0.0
