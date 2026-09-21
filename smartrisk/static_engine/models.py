from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Severity = Literal["informational", "low", "medium", "high", "critical"]
Status = Literal["confirmed", "likely", "unknown"]


@dataclass(frozen=True)
class SourceLocation:
    file: str
    line: int | None = None
    column: int | None = None
    end_line: int | None = None
    end_column: int | None = None


@dataclass
class Evidence:
    evidence_id: str
    kind: str
    source: str
    locator: dict[str, Any] = field(default_factory=dict)
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    finding_id: str
    engine: str
    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: float
    status: Status
    source_location: SourceLocation | None = None
    evidence_refs: list[str] = field(default_factory=list)
    remediation: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class StaticRun:
    run_id: str
    status: Literal["complete", "partial", "unknown", "failed"]
    engine: str
    engine_version: str
    input_hash: str
    compiler: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    unknown_reasons: list[str] = field(default_factory=list)
    diagnostics: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        import json
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)
