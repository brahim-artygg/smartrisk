from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


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
    engine_summaries: list[EngineSummary] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    decisions: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    versions: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "status": self.status,
            "risk": {
                "score": self.risk_score,
                "band": self.risk_band,
                "confidence": self.confidence,
                "coverage": self.coverage,
            },
            "engines": [engine.to_dict() for engine in self.engine_summaries],
            "findings": self.findings,
            "decisions": self.decisions,
            "evidence": self.evidence,
            "unknowns": self.unknowns,
            "assumptions": self.assumptions,
            "versions": self.versions,
        }

    def to_json(self) -> str:
        import json
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)
