from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Iterable

from .models import SimulationResult


@dataclass(frozen=True)
class HoneypotAttempt:
    attempt_id: str
    mode: str
    prerequisites: tuple[str, ...]
    scenario_ids: tuple[str, ...]
    purpose: str


@dataclass
class HoneypotMatrixReport:
    attempts: list[HoneypotAttempt] = field(default_factory=list)
    classifications: list[dict[str, Any]] = field(default_factory=list)
    hard_signals: list[dict[str, Any]] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "attempts": [asdict(item) for item in self.attempts],
            "classifications": self.classifications,
            "hard_signals": self.hard_signals,
            "unknowns": self.unknowns,
        }


class HoneypotMatrix:
    """Planner + evidence classifier; it never turns missing data into a safe result."""

    DEFAULT_MODES = ("baseline", "micro_sell", "small_sell", "partial_sell", "sell_all", "transfer_only")

    def plan(self, buy_id: str, approve_id: str | None, sell_ids: dict[str, str]) -> HoneypotMatrixReport:
        attempts = []
        for mode in self.DEFAULT_MODES:
            if mode == "transfer_only":
                scenario_ids = (sell_ids.get("transfer", ""),)
                prerequisites = ()
                purpose = "Separate transfer restrictions from router-specific sell restrictions."
            else:
                sell_id = sell_ids.get(mode)
                if not sell_id:
                    continue
                scenario_ids = tuple(x for x in (buy_id, approve_id or "", sell_id) if x)
                prerequisites = ("buy_success",) + (("approve_success",) if approve_id else ())
                purpose = {
                    "baseline": "Normal buy then normal full-balance sell.",
                    "micro_sell": "Sell a very small fraction to detect size-dependent restrictions.",
                    "small_sell": "Sell a small fraction to detect thresholds and anti-bot rules.",
                    "partial_sell": "Sell half of the bought balance.",
                    "sell_all": "Sell the full observed bought balance.",
                }[mode]
            attempts.append(HoneypotAttempt(f"honeypot:{mode}", mode, prerequisites, scenario_ids, purpose))
        return HoneypotMatrixReport(attempts=attempts)

    def classify_results(self, results: Iterable[SimulationResult], sell_ids: dict[str, str]) -> HoneypotMatrixReport:
        by_id = {item.scenario_id: item for item in results}
        report = HoneypotMatrixReport()
        transfer_id = sell_ids.get("transfer")
        if transfer_id:
            transfer = by_id.get(transfer_id)
            if transfer is None:
                report.unknowns.append("transfer_only: transfer scenario result is missing")
            else:
                status = _classify_sell(transfer)
                report.classifications.append({"mode": "transfer_only", "scenario_id": transfer_id, "classification": status, "status": transfer.status, "failure_cause": _failure_cause(transfer)})
                if status == "blocked":
                    cause = _failure_cause(transfer)
                    report.hard_signals.append({"signal_id": "honeypot.transfer_only.transfer_blocked", "severity": "high", "evidence": [transfer.scenario_id, transfer.tx_hash, transfer.revert_data], "failure_cause": cause, "explanation": "A direct token transfer reverted after the buy prerequisite was completed."})
                elif status == "unknown":
                    report.unknowns.append("transfer_only: transfer result is unknown")
        for mode in ("baseline", "micro_sell", "small_sell", "partial_sell", "sell_all"):
            sell_id = sell_ids.get(mode)
            if not sell_id:
                continue
            sell = by_id.get(sell_id)
            if sell is None:
                report.unknowns.append(f"{mode}: sell scenario result is missing")
                continue
            status = _classify_sell(sell)
            item = {"mode": mode, "scenario_id": sell_id, "classification": status, "status": sell.status, "failure_cause": _failure_cause(sell)}
            report.classifications.append(item)
            if status == "blocked":
                cause = _failure_cause(sell)
                report.hard_signals.append({
                    "signal_id": f"honeypot.{mode}.sell_blocked",
                    "severity": "critical",
                    "evidence": [sell.scenario_id, sell.tx_hash, sell.revert_data],
                    "failure_cause": cause,
                    "explanation": f"{mode} sell reverted after its prerequisites were satisfied.",
                })
            elif status == "unknown":
                report.unknowns.append(f"{mode}: sell result is unknown")
        return report


def _classify_sell(result: SimulationResult) -> str:
    if result.status == "success":
        return "succeeded"
    if result.status == "reverted":
        cause = _failure_cause(result)
        return "blocked" if cause == "token_restriction" else "unknown"
    return "unknown"


_TOKEN_RESTRICTION_TERMS = (
    "blacklist", "whitelist", "denylist", "allowlist",
    "not allowed", "not authorised", "not authorized",
    "transfer restricted", "transfer prohibited", "transfer disabled", "transfer blocked",
    "trading disabled", "trading not open", "trading is not open",
    "cooldown", "max wallet", "max transaction", "max tx",
    "sell limit", "buy limit", "wallet limit", "sender is restricted",
    "recipient is restricted", "transfers are paused", "transfer paused",
    "blocked by token", "wallet blocked",
)
_ROUTER_FAILURE_TERMS = (
    "insufficient_output_amount", "insufficient_a_amount", "insufficient_b_amount",
    "insufficient liquidity", "expired", "pair: k", "uniswapv2: k", "router",
)
_BALANCE_ALLOWANCE_TERMS = (
    "insufficient balance", "transfer amount exceeds balance",
    "transfer amount exceeds allowance", "exceeds allowance",
)

def _failure_cause(result: SimulationResult) -> str:
    if result.status == "success":
        return "none"
    reason = str((result.revert_info or {}).get("reason") or result.revert_reason or result.error or "").lower()
    selector = str((result.revert_info or {}).get("selector") or "").lower()
    if reason and any(term in reason for term in _BALANCE_ALLOWANCE_TERMS):
        return "balance_or_allowance"
    if reason and any(term in reason for term in _ROUTER_FAILURE_TERMS):
        return "router_or_pair"
    if selector in {"0x4e487b71"}:
        return "contract_panic"
    if reason and any(term in reason for term in _TOKEN_RESTRICTION_TERMS):
        return "token_restriction"
    return "unknown_revert" if result.status == "reverted" else "unknown"
