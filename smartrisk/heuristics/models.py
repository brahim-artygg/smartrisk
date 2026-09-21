from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal


@dataclass(frozen=True)
class ChainAnchor:
    chain_id: str
    block_number: int
    block_hash: str
    finality: str


@dataclass
class RawObservation:
    observation_id: str
    provider: str
    endpoint: str
    subject: str
    observed_at: str
    payload: dict[str, Any]
    anchor: ChainAnchor | None = None
    stale: bool = False
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Feature:
    feature_id: str
    subject: str
    value: Any
    unit: str
    source: str
    confidence: float
    coverage: float
    observed_at: str | None = None
    evidence_refs: list[str] = field(default_factory=list)
    unknown_reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RuleDecision:
    rule_id: str
    outcome: Literal["triggered", "not_triggered", "unknown"]
    contribution: float
    explanation: str
    required_features: list[str]
    evidence_refs: list[str] = field(default_factory=list)
    unknown_reasons: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    hard_block: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RiskScore:
    score: float
    band: Literal["low", "medium", "high", "critical", "unknown"]
    confidence: float
    coverage: float
    decisions: list[RuleDecision] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)
    features: list[Feature] = field(default_factory=list)
    observations: list[RawObservation] = field(default_factory=list)
    policy_version: str = "score-v0.1"
    hard_blocked: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class HeuristicsRun:
    run_id: str
    status: Literal["complete", "partial", "unknown", "failed"]
    anchor: ChainAnchor | None
    risk: RiskScore
    capability: dict[str, Any] = field(default_factory=dict)
    diagnostics: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        import json
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)
