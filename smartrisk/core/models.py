from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal


@dataclass(frozen=True)
class UnifiedAnchor:
    chain_id: str
    block_number: int
    block_hash: str
    parent_hash: str | None
    tag: str
    finality: Literal["final", "safe", "provisional", "explicit"]
    timestamp: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SourceBundle:
    files: list[str] = field(default_factory=list)
    compiler_version: str | None = None
    settings: dict[str, Any] = field(default_factory=dict)
    source_hash: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AnalysisJob:
    job_id: str
    chain_id: str | None
    contract_address: str | None
    anchor: UnifiedAnchor | None
    source_bundle: SourceBundle
    policy_version: str
    created_at: str
    mode: str = "deep"

    @classmethod
    def create(
        cls,
        chain_id: str | None = None,
        contract_address: str | None = None,
        anchor: UnifiedAnchor | None = None,
        source_bundle: SourceBundle | None = None,
        policy_version: str = "unified-v0.1",
        mode: str = "deep",
    ) -> "AnalysisJob":
        return cls(
            job_id=str(uuid.uuid4()),
            chain_id=chain_id,
            contract_address=contract_address,
            anchor=anchor,
            source_bundle=source_bundle or SourceBundle(),
            policy_version=policy_version,
            created_at=datetime.now(timezone.utc).isoformat(),
            mode=mode,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RawAlchemyEvidence:
    evidence_id: str
    provider: str
    method: str
    request_id: str
    params_hash: str
    params: list[Any]
    raw_response: Any
    fetched_at: str
    chain_id: str | None = None
    block_number: int | None = None
    block_hash: str | None = None
    page_key: str | None = None
    removed: bool = False
    error: str | None = None
    reason_code: str | None = None
    latency_ms: float | None = None

    @classmethod
    def create(cls, method: str, request_id: str, params: list[Any], raw_response: Any, **kwargs: Any) -> "RawAlchemyEvidence":
        provider = str(kwargs.pop("provider", "alchemy"))
        params_hash = hashlib.sha256(json.dumps(params, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
        evidence_id = f"raw:{provider}:{method}:{params_hash}:{request_id}"
        return cls(evidence_id, provider, method, request_id, params_hash, params, raw_response, datetime.now(timezone.utc).isoformat(), **kwargs)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
