from __future__ import annotations

import uuid
from typing import Iterable

from .alchemy_rpc import AlchemyRpcClient, AlchemyRpcError
from ..core.networks import get_network
from .anvil import AnvilFork, AnvilUnavailable
from .honeypot import _failure_cause
from .models import BlockAnchor, ForkRun, HoneypotResult, HoneypotSequence, SimulationScenario


class StateForkEngine:
    ENGINE_VERSION = "0.9.0"

    def __init__(self, rpc: AlchemyRpcClient | None = None, fork: AnvilFork | None = None):
        self.rpc = rpc or AlchemyRpcClient()
        self.fork = fork or AnvilFork()

    def analyze(
        self,
        scenarios: Iterable[SimulationScenario],
        run_id: str | None = None,
        block_tag: str = "safe",
        block_number: int | None = None,
    ) -> ForkRun:
        run_id = run_id or str(uuid.uuid4())
        capability = self.rpc.capability_probe()
        if capability.get("status") != "ready":
            return ForkRun(run_id, "unknown", None, capability=capability, unknown_reasons=["Alchemy RPC is unavailable"])
        anchor, error = self._resolve_anchor(block_tag, block_number)
        if error:
            return ForkRun(run_id, "unknown", None, capability=capability, unknown_reasons=[error])
        try:
            self._start_and_verify(anchor)
            results = [self.fork.run_scenario(scenario, anchor) for scenario in scenarios]
            status = "complete" if all(result.status in {"success", "reverted"} for result in results) else "partial"
            return ForkRun(run_id, status, anchor, results=results, capability=capability)
        except AnvilUnavailable as exc:
            return ForkRun(run_id, "unknown", anchor, capability=capability, unknown_reasons=[str(exc)])
        finally:
            self.fork.stop()

    def analyze_honeypot(
        self,
        sequence: HoneypotSequence,
        run_id: str | None = None,
        block_tag: str = "safe",
        block_number: int | None = None,
    ) -> ForkRun:
        """Run buy -> optional approve -> sell in one fork state.

        A failed buy is not a honeypot proof. A sell is classified as blocked
        only when the buy (and approve, when present) succeeded and the sell
        reverted in the same anchored fork.
        """
        run_id = run_id or str(uuid.uuid4())
        capability = self.rpc.capability_probe()
        if capability.get("status") != "ready":
            return ForkRun(run_id, "unknown", None, capability=capability, unknown_reasons=["Alchemy RPC is unavailable"])
        anchor, error = self._resolve_anchor(block_tag, block_number)
        if error:
            return ForkRun(run_id, "unknown", None, capability=capability, unknown_reasons=[error])
        try:
            self._start_and_verify(anchor)
            steps = self.fork.run_sequence(sequence, anchor)
            classification = self._classify_honeypot_steps(steps, sequence)
            sell_step = next((step for step in steps if step.scenario_id == sequence.sell.scenario_id), None)
            sell_cause = _failure_cause(sell_step) if sell_step is not None else "unknown"
            evidence = [
                "buy succeeded before sell classification" if steps and steps[0].status == "success" else "buy did not succeed",
                "sell transaction was blocked by token-level transfer/trading logic" if classification == "sell_blocked" else f"sell result recorded; failure_cause={sell_cause}",
            ]
            result = HoneypotResult(
                sequence_id=sequence.sequence_id,
                classification=classification,
                steps=steps,
                anchor=anchor,
                evidence=evidence,
                assumptions=[
                    "buy/approve/sell used the supplied calldata and addresses",
                    "execution occurred only on a local Anvil fork",
                    "liquidity and router selection were not inferred automatically",
                ],
            )
            status = "complete" if classification != "unknown" else "partial"
            return ForkRun(run_id, status, anchor, honeypot_results=[result], capability=capability)
        except AnvilUnavailable as exc:
            return ForkRun(run_id, "unknown", anchor, capability=capability, unknown_reasons=[str(exc)])
        finally:
            self.fork.stop()

    def analyze_fuzz(
        self,
        scenario: SimulationScenario,
        run_id: str | None = None,
        block_tag: str = "safe",
        block_number: int | None = None,
        iterations: int = 32,
        selectors: tuple[str, ...] = (),
        seed: int = 20260921,
    ):
        """Run deterministic mutation fuzzing against the local anchored fork."""
        from ..validation import DeterministicCalldataFuzzer, StateForkFuzzer
        run_id = run_id or str(uuid.uuid4())
        anchor, error = self._resolve_anchor(block_tag, block_number)
        if error or anchor is None:
            return {"run_id": run_id, "status": "unknown", "error": error or "anchor unavailable"}
        capability = self.rpc.capability_probe()
        if capability.get("status") != "ready":
            return {"run_id": run_id, "status": "unknown", "capability": capability, "error": "RPC unavailable"}
        try:
            self._start_and_verify(anchor)
            campaign = StateForkFuzzer(DeterministicCalldataFuzzer(seed=seed)).run(self.fork, scenario, anchor, iterations=iterations, selectors=selectors)
            return {"run_id": run_id, "status": "complete", "anchor": anchor.to_dict(), "campaign": campaign.to_dict(), "capability": capability}
        except AnvilUnavailable as exc:
            return {"run_id": run_id, "status": "unknown", "anchor": anchor.to_dict(), "error": str(exc), "capability": capability}
        finally:
            self.fork.stop()

    @staticmethod
    def analyze_symbolic(bytecode: str) -> dict:
        from ..validation import EvmBoundedSymbolicAnalyzer
        return EvmBoundedSymbolicAnalyzer().analyze(bytecode)

    def _rpc_for_chain(self, chain_id: str) -> AlchemyRpcClient:
        profile = get_network(chain_id)
        current_chain = getattr(self.rpc, "chain", None)
        if current_chain == profile.rpc_chain:
            return self.rpc
        return AlchemyRpcClient(chain=profile.rpc_chain)

    def analyze_auto_trade(
        self,
        chain_id: str,
        token_address: str,
        trader: str,
        buy_amount_wei: int,
        run_id: str | None = None,
        block_tag: str = "safe",
        block_number: int | None = None,
        execute: bool = True,
    ):
        """Run automatic DexScreener discovery + local native V2 trade matrix."""
        from .auto_trade import AutoTradeAnalyzer
        analyzer = AutoTradeAnalyzer(rpc=self._rpc_for_chain(chain_id), fork=self.fork)
        return analyzer.analyze(
            chain_id=chain_id, token_address=token_address, trader=trader,
            buy_amount_wei=buy_amount_wei, run_id=run_id, block_tag=block_tag,
            block_number=block_number, execute=execute,
        )

    def _resolve_anchor(self, block_tag: str, block_number: int | None) -> tuple[BlockAnchor | None, str | None]:
        try:
            chain_id = self.rpc.get_chain_id()
            tag = hex(block_number) if block_number is not None else block_tag
            number, block = self.rpc.get_anchor(tag)
            anchor = BlockAnchor(
                chain_id=chain_id,
                block_number=number,
                block_hash=block["hash"],
                parent_hash=block.get("parentHash"),
                timestamp=int(block["timestamp"], 16) if block.get("timestamp") else None,
                finality="explicit" if block_number is not None else block_tag,  # type: ignore[arg-type]
            )
            return anchor, None
        except (AlchemyRpcError, KeyError, TypeError, ValueError) as exc:
            return None, str(exc)

    def _start_and_verify(self, anchor: BlockAnchor) -> None:
        upstream = self.rpc.rpc_url
        if not upstream:
            raise AnvilUnavailable("Alchemy RPC URL is not configured")
        self.fork.start(upstream, anchor)
        fork_block = self.fork.rpc_request("eth_getBlockByNumber", [hex(anchor.block_number), False])
        if not fork_block or fork_block.get("hash") != anchor.block_hash:
            raise AnvilUnavailable("fork anchor mismatch: local Anvil block hash differs from Alchemy")

    @staticmethod
    def _classify_honeypot_steps(steps, sequence: HoneypotSequence) -> str:
        if not steps or steps[0].scenario_id != sequence.buy.scenario_id:
            return "unknown"
        if steps[0].status != "success":
            return "buy_failed"
        expected_sell_id = sequence.sell.scenario_id
        sell = next((step for step in steps if step.scenario_id == expected_sell_id), None)
        if sell is None or sell.status == "unknown":
            return "unknown"
        if sell.status == "success":
            return "sell_succeeded"
        if sell.status == "reverted":
            return "sell_blocked" if _failure_cause(sell) == "token_restriction" else "unknown"
        return "unknown"
