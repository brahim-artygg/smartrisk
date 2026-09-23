from __future__ import annotations

import uuid
from typing import Any

from ..heuristics.engine import HeuristicsEngine
from ..core.models import AnalysisJob, SourceBundle, UnifiedAnchor
from ..core.scan_budget import ScanBudget, default_scan_timeout_seconds
from ..state_fork.engine import StateForkEngine
from ..state_fork.alchemy_rpc import AlchemyRpcClient
from ..core.networks import get_network
from ..heuristics.alchemy_source import AlchemySource
from ..static_engine.engine import StaticEngine
from .models import EngineSummary, UnifiedRequest, UnifiedRiskReport


class UnifiedRiskEngine:
    VERSION = "unified-v0.9.0"

    def __init__(
        self,
        static: StaticEngine | None = None,
        fork: StateForkEngine | None = None,
        heuristics: HeuristicsEngine | None = None,
    ):
        self.static = static or StaticEngine()
        self.fork = fork or StateForkEngine()
        self.heuristics = heuristics or HeuristicsEngine()

    def analyze(self, request: UnifiedRequest, run_id: str | None = None) -> UnifiedRiskReport:
        run_id = run_id or str(uuid.uuid4())
        budget = ScanBudget.from_seconds(request.timeout_seconds if request.timeout_seconds is not None else default_scan_timeout_seconds())
        summaries: list[EngineSummary] = []
        findings: list[dict[str, Any]] = []
        decisions: list[dict[str, Any]] = []
        evidence: list[dict[str, Any]] = []
        unknowns: list[str] = []
        static_dict: dict[str, Any] = {}
        fork_dict: dict[str, Any] = {}
        heuristic_dict: dict[str, Any] = {}
        effective_block_number = request.block_number
        shared_anchor = None
        active_heuristics = self.heuristics
        active_fork = self.fork
        network = get_network(request.chain_id) if request.chain_id else None
        if network is not None:
            heuristic_source = getattr(self.heuristics, "alchemy", None)
            heuristic_rpc = getattr(heuristic_source, "rpc", None)
            if heuristic_rpc is not None and getattr(heuristic_rpc, "chain", None) != network.rpc_chain:
                active_heuristics = HeuristicsEngine(
                    alchemy=AlchemySource(rpc=AlchemyRpcClient(chain=network.rpc_chain)),
                    dexscreener=self.heuristics.dexscreener,
                    extractor=self.heuristics.extractor,
                    rules=self.heuristics.rules,
                    intelligence=self.heuristics.intelligence,
                )
            fork_rpc = getattr(self.fork, "rpc", None)
            if fork_rpc is not None and getattr(fork_rpc, "chain", None) != network.rpc_chain:
                active_fork = StateForkEngine(rpc=AlchemyRpcClient(chain=network.rpc_chain), fork=self.fork)
        if effective_block_number is None and request.chain_id:
            source = getattr(active_heuristics, "alchemy", None)
            anchor_fn = getattr(source, "anchor", None)
            if callable(anchor_fn):
                try:
                    shared_anchor = anchor_fn(request.block_tag)
                    effective_block_number = shared_anchor.block_number
                except Exception as exc:
                    unknowns.append(f"anchor: shared anchor probe failed: {exc}")

        assumptions = [
            "Alchemy is the chain-facts source; Dexscreener is market-observation source only.",
            "State-Fork transactions execute locally and are never broadcast to the network.",
            "A missing engine result is unknown, not safe.",
            "A fingerprint is an evidence correlation signal, not a standalone maliciousness verdict.",
        ]

        if request.project:
            static_report = self.static.analyze(request.project, run_id=f"{run_id}:static", compiler_version=request.compiler_version)
            static_dict = static_report.to_dict()
            static_score = self._static_score(static_report)
            static_confidence = 0.85 if static_report.status == "complete" else 0.0
            static_coverage = 1.0 if static_report.status == "complete" else 0.0
            summaries.append(EngineSummary("static_ast", static_report.status, static_score, static_confidence, static_coverage, static_report.unknown_reasons, static_dict))
            findings.extend(static_dict.get("findings", []))
            evidence.extend(static_dict.get("evidence", []))
            unknowns.extend(f"static: {reason}" for reason in static_report.unknown_reasons)
        else:
            summaries.append(EngineSummary("static_ast", "unknown", None, 0.0, 0.0, ["project not provided"]))
            unknowns.append("static: project not provided")

        if request.honeypot:
            if budget.expired():
                budget.note_skipped("state_fork honeypot sequence", "scan time budget exhausted")
                summaries.append(EngineSummary("state_fork", "unknown", None, 0.0, 0.0, ["skipped: the scan time budget was exhausted before fork simulation"]))
                unknowns.append("fork: skipped because the scan time budget was exhausted")
            else:
                try:
                    fork_report = active_fork.analyze_honeypot(request.honeypot, run_id=f"{run_id}:fork", block_tag=request.block_tag, block_number=effective_block_number)
                except Exception as exc:
                    budget.note_skipped("state_fork honeypot sequence", str(exc))
                    fork_report = None
                if fork_report is not None:
                    fork_dict = fork_report.to_dict()
                    fork_score, fork_unknowns = self._fork_score(fork_report)
                    fork_confidence = 0.9 if fork_report.status == "complete" else 0.0
                    fork_coverage = 1.0 if fork_report.status == "complete" else 0.0
                    summaries.append(EngineSummary("state_fork", fork_report.status, fork_score, fork_confidence, fork_coverage, fork_report.unknown_reasons + fork_unknowns, fork_dict))
                    decisions.extend(self._fork_decisions(fork_report))
                    unknowns.extend(f"fork: {reason}" for reason in fork_report.unknown_reasons + fork_unknowns)
        elif request.scenarios:
            if budget.expired():
                budget.note_skipped("state_fork scenarios", "scan time budget exhausted")
                summaries.append(EngineSummary("state_fork", "unknown", None, 0.0, 0.0, ["skipped: the scan time budget was exhausted before fork simulation"]))
                unknowns.append("fork: skipped because the scan time budget was exhausted")
            else:
                try:
                    fork_report = active_fork.analyze(request.scenarios, run_id=f"{run_id}:fork", block_tag=request.block_tag, block_number=effective_block_number)
                except Exception as exc:
                    budget.note_skipped("state_fork scenarios", str(exc))
                    fork_report = None
                if fork_report is not None:
                    fork_dict = fork_report.to_dict()
                    fork_score, fork_unknowns = self._fork_score(fork_report)
                    fork_confidence = 0.9 if fork_report.status == "complete" else 0.0
                    fork_coverage = 1.0 if fork_report.status == "complete" else 0.0
                    summaries.append(EngineSummary("state_fork", fork_report.status, fork_score, fork_confidence, fork_coverage, fork_report.unknown_reasons + fork_unknowns, fork_dict))
                    decisions.extend(self._fork_decisions(fork_report))
                    unknowns.extend(f"fork: {reason}" for reason in fork_report.unknown_reasons + fork_unknowns)
        else:
            summaries.append(EngineSummary("state_fork", "unknown", None, 0.0, 0.0, ["scenarios not provided"]))
            unknowns.append("fork: scenarios not provided")

        if request.chain_id and request.token_address:
            heuristic_kwargs = {
                "run_id": f"{run_id}:heuristics",
                "block_tag": request.block_tag,
                "block_number": effective_block_number,
                "window_blocks": request.window_blocks,
            }
            if request.deployer_address is not None:
                heuristic_kwargs["deployer_address"] = request.deployer_address
            heuristic_report = active_heuristics.analyze(request.chain_id, request.token_address, **heuristic_kwargs)
            heuristic_dict = heuristic_report.to_dict()
            risk = heuristic_dict.get("risk", {})
            intelligence = heuristic_dict.get("intelligence", {}) or {}
            intelligence_findings = intelligence.get("findings", []) if isinstance(intelligence, dict) else []
            if isinstance(intelligence_findings, list):
                findings.extend(intelligence_findings)
            summaries.append(EngineSummary("heuristics", heuristic_report.status, risk.get("score"), risk.get("confidence", 0.0), risk.get("coverage", 0.0), risk.get("unknowns", []), heuristic_dict))
            decisions.extend(risk.get("decisions", []))
            evidence.extend(risk.get("observations", []))
            for decision in risk.get("decisions", []):
                if decision.get("outcome") == "triggered":
                    findings.append({
                        "finding_id": f"heuristics:{decision.get('rule_id')}",
                        "engine": "heuristics",
                        "rule_id": decision.get("rule_id"),
                        "title": decision.get("explanation", decision.get("rule_id")),
                        "description": decision.get("explanation", ""),
                        "severity": "high" if decision.get("hard_block") else "medium",
                        "confidence": risk.get("confidence", 0.0),
                        "status": "likely",
                        "evidence_refs": decision.get("evidence_refs", []),
                    })
            unknowns.extend(f"heuristics: {reason}" for reason in risk.get("unknowns", []))
        else:
            summaries.append(EngineSummary("heuristics", "unknown", None, 0.0, 0.0, ["chain_id and token_address not provided"]))
            unknowns.append("heuristics: chain_id and token_address not provided")

        correlations = self._correlate(static_dict, fork_dict, heuristic_dict, findings)
        for correlation in correlations:
            correlation_findings = correlation.get("finding_ids", [])
            for finding in findings:
                if finding.get("finding_id") in correlation_findings and correlation.get("strength") in {"high", "very_high"}:
                    finding["status"] = "confirmed"
                    finding["correlation_id"] = correlation.get("correlation_id")
        hard_verdicts = self._hard_verdicts(summaries, findings, decisions)
        score, band, confidence, coverage = self._combine(summaries)
        if hard_verdicts:
            score, band = 100.0, "critical"
            confidence = max(confidence, 0.95)
        risk_dimensions = self._risk_dimensions(summaries, decisions)
        status = "complete" if all(summary.status == "complete" for summary in summaries) else "partial" if any(summary.status in {"complete", "partial"} for summary in summaries) else "unknown"
        job_anchor = self._anchor_from_summaries(summaries)
        job = AnalysisJob.create(
            chain_id=request.chain_id,
            contract_address=request.token_address,
            anchor=job_anchor,
            source_bundle=SourceBundle(files=[request.project] if request.project else [], compiler_version=request.compiler_version),
            policy_version=self.VERSION,
        )
        job_payload = job.to_dict()
        job_payload["anchor_consistency"] = self._anchor_consistency(summaries)
        anchor_status = job_payload["anchor_consistency"]["status"]
        if anchor_status == "mismatch":
            unknowns.append("engine anchors are inconsistent; results were not proven to share one canonical block")
            status = "partial" if status != "unknown" else status
            coverage = round(coverage * 0.75, 3)
            confidence = round(confidence * 0.75, 3)
            for correlation in correlations:
                correlation["status"] = "anchor_mismatch"
                correlation["strength"] = "untrusted"
        evidence_graph = self._build_evidence_graph(summaries, findings, evidence, decisions, correlations)
        verdict, verdict_label, primary_detection = self._derive_verdict(
            hard_verdicts, findings, score, band, status, coverage
        )
        return UnifiedRiskReport(
            run_id=run_id,
            status=status,
            risk_score=score,
            risk_band=band,
            verdict=verdict,
            verdict_label=verdict_label,
            primary_detection=primary_detection,
            confidence=confidence,
            coverage=coverage,
            engine_summaries=summaries,
            findings=findings,
            decisions=decisions,
            hard_verdicts=hard_verdicts,
            risk_dimensions=risk_dimensions,
            evidence=evidence,
            correlations=correlations,
            evidence_graph=evidence_graph,
            unknowns=sorted(set(unknowns)),
            assumptions=assumptions,
            versions={"release": "0.9.0", "unified": self.VERSION, "static": "0.3.1", "fork": "0.9.0", "heuristics": "0.4.0", "intelligence": "0.5.0"},
            job=job_payload,
        )


    @staticmethod
    def _derive_verdict(hard_verdicts, findings, score, band, status, coverage):
        for verdict in hard_verdicts:
            if verdict.get("verdict_id") == "SELL_BLOCKED_IN_FORK":
                return (
                    "HONEYPOT_DETECTED",
                    "HONEYPOT DETECTED",
                    {
                        "type": "honeypot",
                        "title": "Sell blocked after a successful buy",
                        "verdict_id": verdict.get("verdict_id"),
                        "rule_id": verdict.get("rule_id"),
                        "evidence_refs": verdict.get("evidence_refs", []),
                        "explanation": verdict.get("explanation", "The token's sell path was blocked in the anchored fork scenario."),
                    },
                )
        for verdict in hard_verdicts:
            if verdict.get("verdict_id") == "STATIC_CRITICAL_FINDING":
                rule_id = verdict.get("rule_id")
                title = verdict.get("explanation", "Critical security finding")
                return (
                    "CRITICAL_RISK",
                    "CRITICAL RISK",
                    {
                        "type": "security",
                        "title": title,
                        "verdict_id": verdict.get("verdict_id"),
                        "rule_id": rule_id,
                        "finding_id": verdict.get("finding_id"),
                        "evidence_refs": verdict.get("evidence_refs", []),
                    },
                )
        if status == "unknown" or score is None or coverage < 0.50:
            return "UNVERIFIED", "UNVERIFIED", {"type": "insufficient_evidence", "title": "Required scan evidence is unavailable"}
        if band == "critical":
            return "CRITICAL_RISK", "CRITICAL RISK", {"type": "risk_score", "title": "Critical aggregate risk"}
        if band == "high":
            return "HIGH_RISK", "HIGH RISK", {"type": "risk_score", "title": "High aggregate risk"}
        if band == "medium":
            return "MEDIUM_RISK", "MEDIUM RISK", {"type": "risk_score", "title": "Medium aggregate risk"}
        return "LOW_RISK", "LOW RISK", {"type": "risk_score", "title": "No high-severity risk detected by the evaluated controls"}

    @staticmethod
    def _build_evidence_graph(summaries, findings, evidence, decisions, correlations):
        nodes = {}
        edges = []

        def add_node(node_id: str, node_type: str, **payload):
            if not node_id:
                return
            nodes.setdefault(node_id, {"id": node_id, "type": node_type, **payload})

        for summary in summaries:
            add_node(f"engine:{summary.name}", "engine", status=summary.status, score=summary.score, confidence=summary.confidence, coverage=summary.coverage)
        for finding in findings:
            fid = str(finding.get("finding_id") or "")
            add_node(fid, "finding", engine=finding.get("engine"), rule_id=finding.get("rule_id"), severity=finding.get("severity"), status=finding.get("status"))
            engine = str(finding.get("engine") or "")
            if engine:
                engine_node = {"static": "static_ast", "intelligence": "heuristics"}.get(engine, engine)
                if f"engine:{engine_node}" in nodes:
                    edges.append({"from": f"engine:{engine_node}", "to": fid, "type": "produces"})
            for ref in finding.get("evidence_refs", []) if isinstance(finding.get("evidence_refs"), list) else []:
                rid = str(ref)
                add_node(rid, "evidence")
                edges.append({"from": fid, "to": rid, "type": "supported_by"})
        for item in evidence:
            if isinstance(item, dict):
                eid = str(item.get("evidence_id") or item.get("observation_id") or "")
                if eid:
                    add_node(eid, "evidence", provider=item.get("provider"), endpoint=item.get("endpoint") or item.get("method"))
        for decision in decisions:
            rid = str(decision.get("rule_id") or "")
            did = f"decision:{rid}:{len(edges)}"
            add_node(did, "decision", rule_id=rid, outcome=decision.get("outcome"), contribution=decision.get("contribution"))
            for ref in decision.get("evidence_refs", []) if isinstance(decision.get("evidence_refs"), list) else []:
                edges.append({"from": did, "to": str(ref), "type": "uses_evidence"})
        for correlation in correlations:
            cid = str(correlation.get("correlation_id") or "")
            if not cid:
                continue
            add_node(f"correlation:{cid}", "correlation", strength=correlation.get("strength"), status=correlation.get("status", "trusted"))
            for fid in correlation.get("finding_ids", []) if isinstance(correlation.get("finding_ids"), list) else []:
                edges.append({"from": f"correlation:{cid}", "to": str(fid), "type": "corroborates"})
            for ref in correlation.get("evidence_refs", []) if isinstance(correlation.get("evidence_refs"), list) else []:
                edges.append({"from": f"correlation:{cid}", "to": str(ref), "type": "anchors_on"})
        dedup=[]
        seen=set()
        for edge in edges:
            key=(edge["from"],edge["to"],edge["type"])
            if key not in seen and edge["from"] in nodes and edge["to"] in nodes:
                seen.add(key); dedup.append(edge)
        return {"version": "evidence-graph-v0.1", "node_count": len(nodes), "edge_count": len(dedup), "nodes": list(nodes.values()), "edges": dedup}

    @staticmethod
    def _hard_verdicts(summaries, findings, decisions):
        verdicts = []
        for finding in findings:
            if finding.get("severity") == "critical" and finding.get("status") in {"likely", "confirmed"}:
                verdicts.append({
                    "verdict_id": "STATIC_CRITICAL_FINDING",
                    "status": "critical",
                    "rule_id": finding.get("rule_id"),
                    "finding_id": finding.get("finding_id"),
                    "evidence_refs": finding.get("evidence_refs", []),
                    "explanation": finding.get("description", finding.get("title", "Critical static finding")),
                })
        for decision in decisions:
            if decision.get("rule_id") == "fork.honeypot.sell_blocked" and decision.get("outcome") == "triggered":
                verdicts.append({
                    "verdict_id": "SELL_BLOCKED_IN_FORK",
                    "status": "critical",
                    "rule_id": decision.get("rule_id"),
                    "evidence_refs": decision.get("evidence_refs", []),
                    "explanation": "A completed buy/approve sequence was followed by a reverted sell in the same anchored fork state.",
                })
        dedup = {}
        for verdict in verdicts:
            dedup[(verdict.get("verdict_id"), verdict.get("rule_id"), verdict.get("finding_id"))] = verdict
        return list(dedup.values())

    @staticmethod
    def _risk_dimensions(summaries, decisions):
        dims = {
            "contract_security": {"score": 0.0, "signals": 0, "confidence": 0.0},
            "trading_security": {"score": 0.0, "signals": 0, "confidence": 0.0},
            "ownership_security": {"score": 0.0, "signals": 0, "confidence": 0.0},
            "liquidity_market": {"score": 0.0, "signals": 0, "confidence": 0.0},
            "holder_distribution": {"score": 0.0, "signals": 0, "confidence": 0.0},
            "deployer_risk": {"score": 0.0, "signals": 0, "confidence": 0.0},
            "cluster_behavior": {"score": 0.0, "signals": 0, "confidence": 0.0},
            "historical_behavior": {"score": 0.0, "signals": 0, "confidence": 0.0},
        }
        for decision in decisions:
            if decision.get("outcome") != "triggered":
                continue
            rid = str(decision.get("rule_id", ""))
            if rid.startswith("fork.") or any(x in rid for x in ("tax", "sell", "trading", "honeypot")):
                bucket = "trading_security"
            elif any(x in rid for x in ("owner", "role", "admin", "upgrade", "privilege")):
                bucket = "ownership_security"
            elif rid.startswith("market.") or rid.startswith("liquidity."):
                bucket = "liquidity_market"
            elif rid.startswith("holders."):
                bucket = "holder_distribution"
            elif rid.startswith("deployer."):
                bucket = "deployer_risk"
            elif rid.startswith("clusters."):
                bucket = "cluster_behavior"
            elif rid.startswith("history."):
                bucket = "historical_behavior"
            else:
                bucket = "contract_security"
            dims[bucket]["score"] += float(decision.get("contribution", 0.0) or 0.0)
            dims[bucket]["signals"] += 1
        for item in dims.values():
            item["score"] = round(min(100.0, item["score"]), 2)
            item["confidence"] = round(0.9 if item["signals"] else 0.0, 3)
        return dims

    @staticmethod
    def _correlate(static_dict: dict[str, Any], fork_dict: dict[str, Any], heuristic_dict: dict[str, Any], findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        correlations: list[dict[str, Any]] = []
        static_findings = static_dict.get("findings", []) if isinstance(static_dict, dict) else []
        intelligence = heuristic_dict.get("intelligence", {}) if isinstance(heuristic_dict, dict) else {}
        intelligence_findings = intelligence.get("findings", []) if isinstance(intelligence, dict) else []
        if not isinstance(static_findings, list):
            static_findings = []
        if not isinstance(intelligence_findings, list):
            intelligence_findings = []

        def add(cid: str, strength: str, finding_ids: list[str], evidence_refs: list[Any], explanation: str, engines: list[str]):
            correlations.append({
                "correlation_id": cid,
                "strength": strength,
                "finding_ids": sorted(set(x for x in finding_ids if x)),
                "evidence_refs": sorted(set(str(x) for x in evidence_refs if x)),
                "explanation": explanation,
                "engines": sorted(set(engines)),
            })

        static_text = " ".join(str(item.get("rule_id", "")) + " " + str(item.get("title", "")) + " " + str(item.get("description", "")) for item in static_findings).lower()
        intel_text = " ".join(str(item.get("rule_id", "")) + " " + str(item.get("description", "")) for item in intelligence_findings).lower()
        static_ids = [str(item.get("finding_id")) for item in static_findings]
        intel_ids = [str(item.get("finding_id")) for item in intelligence_findings]

        if "mint" in static_text and ("deployer.high_supply_control" in intel_text or "deployer" in intel_text and "supply" in intel_text):
            ev = [ref for item in intelligence_findings for ref in item.get("evidence_refs", [])]
            relevant_static = [str(item.get("finding_id")) for item in static_findings if "mint" in (str(item.get("rule_id", "")) + " " + str(item.get("description", ""))).lower()]
            relevant_intel = [str(item.get("finding_id")) for item in intelligence_findings if "deployer" in (str(item.get("rule_id", "")) + " " + str(item.get("description", ""))).lower()]
            add("corr.static-mint-deployer", "high", relevant_static + relevant_intel, ev, "Static analysis identifies supply-mutation capability while on-chain intelligence observes substantial creator/distribution-linked supply control.", ["static", "intelligence"])

        if ("blacklist" in static_text or "whitelist" in static_text or "transfer" in static_text) and "holders.top20_concentration" in intel_text:
            relevant_static = [str(item.get("finding_id")) for item in static_findings if any(term in (str(item.get("rule_id", "")) + " " + str(item.get("description", ""))).lower() for term in ("blacklist", "whitelist", "transfer"))]
            relevant_intel = [str(item.get("finding_id")) for item in intelligence_findings if "holders.top20_concentration" in str(item.get("rule_id", ""))]
            add("corr.static-transfer-holder", "medium", relevant_static + relevant_intel, [], "Static transfer-control signals are observed alongside concentrated holder distribution.", ["static", "intelligence"])

        honeypot_results = fork_dict.get("honeypot_results", []) if isinstance(fork_dict, dict) else []
        blocked = [item for item in honeypot_results if item.get("classification") == "sell_blocked"] if isinstance(honeypot_results, list) else []
        pair_count = None
        history_buyers = None
        if isinstance(heuristic_dict, dict):
            features = (heuristic_dict.get("risk") or {}).get("features", [])
            for feature in features if isinstance(features, list) else []:
                if feature.get("feature_id") == "market.pair_count":
                    pair_count = feature.get("value")
            history = intelligence.get("payload", {}).get("historical_behavior", {}) if isinstance(intelligence, dict) else {}
            history_buyers = history.get("unique_buyers") if isinstance(history, dict) else None
        if blocked and (pair_count or 0) > 0:
            ev = []
            for item in blocked:
                ev.extend(item.get("evidence", []))
            related = [str(item.get("finding_id")) for item in findings if item.get("rule_id") in {"history.no_observed_sellers", "market.sell_activity_absent"}]
            add("corr.fork-market-honeypot", "very_high", related, ev, "The State-Fork sell block is corroborated by observed market/on-chain trading context rather than being treated as an isolated revert.", ["state_fork", "intelligence", "market"])

        if blocked and history_buyers and history_buyers > 0:
            ev = []
            for item in blocked:
                ev.extend(item.get("evidence", []))
            add("corr.fork-history-honeypot", "high", [], ev, "The forked sell restriction is observed for a token with buy-like holder activity in the analyzed historical window.", ["state_fork", "intelligence"])

        # Correlate LP concentration with ownership/privilege signals when both are independently observed.
        if "lp.candidate_control" in intel_text and any(term in static_text for term in ("owner", "admin", "upgrade", "privilege")):
            relevant_static = [str(item.get("finding_id")) for item in static_findings if any(term in (str(item.get("rule_id", "")) + " " + str(item.get("description", ""))).lower() for term in ("owner", "admin", "upgrade", "privilege"))]
            relevant_intel = [str(item.get("finding_id")) for item in intelligence_findings if "lp.candidate_control" in str(item.get("rule_id", ""))]
            add("corr.lp-privilege", "high", relevant_static + relevant_intel, [], "Observed LP control by a creator/distribution candidate coincides with static privileged-control capabilities.", ["static", "intelligence"])

        return correlations

    @staticmethod
    def _anchor_consistency(summaries):
        anchors = []
        for summary in summaries:
            report = summary.report or {}
            anchor = report.get("anchor") if isinstance(report, dict) else None
            if not isinstance(anchor, dict):
                continue
            anchors.append({
                "engine": summary.name,
                "chain_id": str(anchor.get("chain_id", anchor.get("chainId", ""))),
                "block_number": anchor.get("block_number", anchor.get("blockNumber")),
                "block_hash": anchor.get("block_hash", anchor.get("blockHash")),
            })
        if not anchors:
            return {"status": "unknown", "anchors": []}
        canonical = (anchors[0]["chain_id"], anchors[0]["block_number"], anchors[0]["block_hash"])
        mismatch = [item for item in anchors if (item["chain_id"], item["block_number"], item["block_hash"]) != canonical]
        return {"status": "mismatch" if mismatch else "consistent", "anchors": anchors, "canonical": {"chain_id": canonical[0], "block_number": canonical[1], "block_hash": canonical[2]}}

    @staticmethod
    def _anchor_from_summaries(summaries):
        for summary in summaries:
            report = summary.report
            anchor = report.get("anchor") if isinstance(report, dict) else None
            if not anchor:
                continue
            return UnifiedAnchor(
                chain_id=str(anchor.get("chain_id", anchor.get("chainId", ""))),
                block_number=int(anchor.get("block_number", anchor.get("blockNumber", 0))),
                block_hash=anchor.get("block_hash", anchor.get("blockHash", "")),
                parent_hash=anchor.get("parent_hash", anchor.get("parentHash")),
                tag=anchor.get("finality", "safe"),
                finality="explicit" if anchor.get("finality") == "explicit" else anchor.get("finality", "safe"),
                timestamp=anchor.get("timestamp"),
            )
        return None

    @staticmethod
    def _static_score(report) -> float:
        weights = {"informational": 0, "low": 8, "medium": 18, "high": 32, "critical": 50}
        return min(100.0, float(sum(weights.get(f.severity, 0) for f in report.findings)))

    @staticmethod
    def _fork_score(report) -> tuple[float | None, list[str]]:
        if report.status == "unknown":
            return None, report.unknown_reasons
        score = 0.0
        unknowns = []
        for item in report.honeypot_results:
            if item.classification == "sell_blocked":
                score = max(score, 70.0)
            elif item.classification == "unknown":
                unknowns.append(f"honeypot sequence {item.sequence_id} is unknown")
        for result in report.results:
            if result.status == "reverted":
                score = max(score, 20.0)
            elif result.status == "unknown":
                unknowns.append(f"scenario {result.scenario_id} is unknown")
        return score, unknowns

    @staticmethod
    def _fork_decisions(report):
        decisions = []
        for item in report.honeypot_results:
            decisions.append({"rule_id": "fork.honeypot.sell_blocked", "outcome": "triggered" if item.classification == "sell_blocked" else "not_triggered", "contribution": 70.0 if item.classification == "sell_blocked" else 0.0, "explanation": item.classification, "evidence_refs": item.evidence})
        return decisions

    @staticmethod
    def _combine(summaries):
        available = [summary for summary in summaries if summary.score is not None]
        if not available:
            return None, "unknown", 0.0, 0.0
        weights = {"static_ast": 0.30, "state_fork": 0.40, "heuristics": 0.30}
        denominator = sum(weights.get(summary.name, 0.0) for summary in available)
        score = sum(summary.score * weights.get(summary.name, 0.0) for summary in available) / denominator
        coverage = sum(summary.coverage * weights.get(summary.name, 0.0) for summary in summaries) / sum(weights.values())
        confidence = sum(summary.confidence * weights.get(summary.name, 0.0) for summary in available) / denominator
        band = "critical" if score >= 70 else "high" if score >= 45 else "medium" if score >= 20 else "low"
        return round(score, 2), band, round(confidence, 3), round(coverage, 3)
