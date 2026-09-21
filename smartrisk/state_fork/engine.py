from __future__ import annotations

import uuid
from typing import Iterable

from .alchemy_rpc import AlchemyRpcClient, AlchemyRpcError
from .anvil import AnvilFork, AnvilUnavailable
from .models import BlockAnchor, ForkRun, HoneypotResult, HoneypotSequence, SimulationScenario


class StateForkEngine:
    ENGINE_VERSION = "0.2.0"

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
            evidence = [
                "buy succeeded before sell classification" if steps and steps[0].status == "success" else "buy did not succeed",
                "sell transaction reverted in the same fork state" if classification == "sell_blocked" else "sell result recorded",
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
        return "sell_blocked"
