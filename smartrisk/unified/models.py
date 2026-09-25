from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class CheckResult:
    """User-facing state for one check; missing data is never treated as false."""

    check_id: str
    label: str
    state: str
    value: Any = None
    reason_code: str | None = None
    reason: str | None = None
    source: list[str] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    coverage: float = 0.0
    included_in_score: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class UnifiedRequest:
    project: str | None = None
    chain_id: str | None = None
    token_address: str | None = None
    scenarios: list[Any] = field(default_factory=list)
    honeypot: Any | None = None
    block_tag: str = "safe"
    block_number: int | None = None
    compiler_version: str | None = None
    window_blocks: int = 10_000
    deployer_address: str | None = None
    scan_profile: str = "paid"


@dataclass
class EngineSummary:
    name: str
    status: str
    score: float | None
    confidence: float
    coverage: float
    unknowns: list[str] = field(default_factory=list)
    report: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "score": self.score,
            "confidence": self.confidence,
            "coverage": self.coverage,
            "unknowns": self.unknowns,
            "report": self.report,
        }


@dataclass
class UnifiedRiskReport:
    run_id: str
    status: str
    risk_score: float | None
    risk_band: str
    confidence: float
    coverage: float
    verdict: str = "UNVERIFIED"
    verdict_label: str = "UNVERIFIED"
    primary_detection: dict[str, Any] = field(default_factory=dict)
    engine_summaries: list[EngineSummary] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    decisions: list[dict[str, Any]] = field(default_factory=list)
    hard_verdicts: list[dict[str, Any]] = field(default_factory=list)
    risk_dimensions: dict[str, dict[str, Any]] = field(default_factory=dict)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    correlations: list[dict[str, Any]] = field(default_factory=list)
    evidence_graph: dict[str, Any] = field(default_factory=dict)
    checks: list[dict[str, Any]] = field(default_factory=list)
    scan_budget: dict[str, Any] = field(default_factory=dict)
    ai_explanation: dict[str, Any] | None = None
    unknowns: list[str] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    versions: dict[str, str] = field(default_factory=dict)
    job: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "status": self.status,
            "verdict": {
                "code": self.verdict,
                "label": self.verdict_label,
                "primary_detection": self.primary_detection,
            },
            "risk": {
                "score": self.risk_score,
                "band": self.risk_band,
                "confidence": self.confidence,
                "coverage": self.coverage,
            },
            "engines": [engine.to_dict() for engine in self.engine_summaries],
            "findings": self.findings,
            "decisions": self.decisions,
            "hard_verdicts": self.hard_verdicts,
            "risk_dimensions": self.risk_dimensions,
            "evidence": self.evidence,
            "correlations": self.correlations,
            "evidence_graph": self.evidence_graph,
            "checks": self.checks,
            "scan_budget": self.scan_budget,
            "ai_explanation": self.ai_explanation,
            "unknowns": self.unknowns,
            "assumptions": self.assumptions,
            "versions": self.versions,
            "job": self.job,
        }

    def to_json(self) -> str:
        import json
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)
