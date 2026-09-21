from __future__ import annotations

import uuid
from typing import Any

from ..heuristics.engine import HeuristicsEngine
from ..state_fork.engine import StateForkEngine
from ..static_engine.engine import StaticEngine
from .models import EngineSummary, UnifiedRequest, UnifiedRiskReport


class UnifiedRiskEngine:
    VERSION = "unified-v0.1"

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
        summaries: list[EngineSummary] = []
        findings: list[dict[str, Any]] = []
        decisions: list[dict[str, Any]] = []
        evidence: list[dict[str, Any]] = []
        unknowns: list[str] = []
        assumptions = [
            "Alchemy is the chain-facts source; Dexscreener is market-observation source only.",
            "State-Fork transactions execute locally and are never broadcast to the network.",
            "A missing engine result is unknown, not safe.",
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
            fork_report = self.fork.analyze_honeypot(request.honeypot, run_id=f"{run_id}:fork", block_tag=request.block_tag, block_number=request.block_number)
            fork_dict = fork_report.to_dict()
            fork_score, fork_unknowns = self._fork_score(fork_report)
            fork_confidence = 0.9 if fork_report.status == "complete" else 0.0
            fork_coverage = 1.0 if fork_report.status == "complete" else 0.0
            summaries.append(EngineSummary("state_fork", fork_report.status, fork_score, fork_confidence, fork_coverage, fork_report.unknown_reasons + fork_unknowns, fork_dict))
            decisions.extend(self._fork_decisions(fork_report))
            unknowns.extend(f"fork: {reason}" for reason in fork_report.unknown_reasons + fork_unknowns)
        elif request.scenarios:
            fork_report = self.fork.analyze(request.scenarios, run_id=f"{run_id}:fork", block_tag=request.block_tag, block_number=request.block_number)
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
            heuristic_report = self.heuristics.analyze(
                request.chain_id,
                request.token_address,
                run_id=f"{run_id}:heuristics",
                block_tag=request.block_tag,
                block_number=request.block_number,
                window_blocks=request.window_blocks,
            )
            heuristic_dict = heuristic_report.to_dict()
            risk = heuristic_dict.get("risk", {})
            summaries.append(EngineSummary("heuristics", heuristic_report.status, risk.get("score"), risk.get("confidence", 0.0), risk.get("coverage", 0.0), risk.get("unknowns", []), heuristic_dict))
            decisions.extend(risk.get("decisions", []))
            evidence.extend(risk.get("observations", []))
            unknowns.extend(f"heuristics: {reason}" for reason in risk.get("unknowns", []))
        else:
            summaries.append(EngineSummary("heuristics", "unknown", None, 0.0, 0.0, ["chain_id and token_address not provided"]))
            unknowns.append("heuristics: chain_id and token_address not provided")

        score, band, confidence, coverage = self._combine(summaries)
        status = "complete" if all(summary.status == "complete" for summary in summaries) else "partial" if any(summary.status in {"complete", "partial"} for summary in summaries) else "unknown"
        return UnifiedRiskReport(
            run_id=run_id,
            status=status,
            risk_score=score,
            risk_band=band,
            confidence=confidence,
            coverage=coverage,
            engine_summaries=summaries,
            findings=findings,
            decisions=decisions,
            evidence=evidence,
            unknowns=sorted(set(unknowns)),
            assumptions=assumptions,
            versions={"unified": self.VERSION, "static": "0.2.0", "fork": "0.2.0", "heuristics": "0.1.0"},
        )

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
        band = "unknown" if coverage < 0.75 else "critical" if score >= 70 else "high" if score >= 45 else "medium" if score >= 20 else "low"
        return round(score, 2), band, round(confidence, 3), round(coverage, 3)
