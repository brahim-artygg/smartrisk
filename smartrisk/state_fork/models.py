from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal


@dataclass(frozen=True)
class BlockAnchor:
    chain_id: str
    block_number: int
    block_hash: str
    parent_hash: str | None
    timestamp: int | None
    finality: Literal["finalized", "safe", "latest", "explicit"]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SimulationScenario:
    scenario_id: str
    from_address: str
    to_address: str
    data: str = "0x"
    value_wei: int = 0
    gas_limit: int | None = None
    description: str = ""
    observed_tokens: tuple[str, ...] = ()
    observed_allowances: tuple[tuple[str, str], ...] = ()
    observed_pairs: tuple[str, ...] = ()
    category: str = "generic"
    risk_tags: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def rpc_transaction(self) -> dict[str, str]:
        tx: dict[str, str] = {
            "from": self.from_address,
            "to": self.to_address,
            "data": self.data,
            "value": hex(self.value_wei),
        }
        if self.gas_limit is not None:
            tx["gas"] = hex(self.gas_limit)
        return tx


@dataclass(frozen=True)
class HoneypotSequence:
    sequence_id: str
    buy: SimulationScenario
    sell: SimulationScenario
    approve: SimulationScenario | None = None
    token_address: str | None = None
    description: str = ""

    def steps(self) -> list[SimulationScenario]:
        values = [self.buy]
        if self.approve:
            values.append(self.approve)
        values.append(self.sell)
        return values


@dataclass
class SimulationResult:
    scenario_id: str
    status: Literal["success", "reverted", "unknown", "failed"]
    anchor: BlockAnchor | None
    tx_hash: str | None = None
    receipt: dict[str, Any] | None = None
    trace: dict[str, Any] | None = None
    return_data: str | None = None
    revert_data: str | None = None
    revert_reason: str | None = None
    revert_info: dict[str, Any] | None = None
    error: str | None = None
    logs: list[dict[str, Any]] = field(default_factory=list)
    state_diff: dict[str, Any] | None = None
    assumptions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class HoneypotResult:
    sequence_id: str
    classification: Literal["sell_succeeded", "sell_blocked", "buy_failed", "unknown"]
    steps: list[SimulationResult]
    anchor: BlockAnchor | None
    evidence: list[str] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TradeAttemptResult:
    mode: str
    classification: Literal["sell_succeeded", "sell_blocked", "transfer_succeeded", "transfer_blocked", "buy_failed", "approve_failed", "unknown"]
    buy: SimulationResult | None = None
    approve: SimulationResult | None = None
    pre_buy_approve: SimulationResult | None = None
    sell: SimulationResult | None = None
    observed_buy_token_delta: int | None = None
    analysis: dict[str, Any] = field(default_factory=dict)
    unknown_reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TradeMatrixRun:
    run_id: str
    status: Literal["complete", "partial", "unknown", "failed"]
    anchor: BlockAnchor | None
    token_address: str
    pair_address: str | None
    plan: dict[str, Any] = field(default_factory=dict)
    attempts: list[TradeAttemptResult] = field(default_factory=list)
    hard_signals: list[dict[str, Any]] = field(default_factory=list)
    unknown_reasons: list[str] = field(default_factory=list)
    verdict: str = "UNVERIFIED"
    verdict_label: str = "UNVERIFIED"
    primary_detection: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        import json
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)


@dataclass
class ForkRun:
    run_id: str
    status: Literal["complete", "partial", "unknown", "failed"]
    anchor: BlockAnchor | None
    results: list[SimulationResult] = field(default_factory=list)
    honeypot_results: list[HoneypotResult] = field(default_factory=list)
    capability: dict[str, Any] = field(default_factory=dict)
    unknown_reasons: list[str] = field(default_factory=list)
    diagnostics: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        import json
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)
