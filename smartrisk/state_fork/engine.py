from __future__ import annotations

import uuid
from typing import Any, Iterable

from .alchemy_rpc import AlchemyRpcClient, AlchemyRpcError
from .anvil import AnvilFork, AnvilUnavailable
from .models import BlockAnchor, ForkRun, SimulationScenario


class StateForkEngine:
    ENGINE_VERSION = "0.1.0"

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
        scenarios = list(scenarios)
        capability = self.rpc.capability_probe()
        if capability.get("status") != "ready":
            return ForkRun(run_id, "unknown", None, capability=capability, unknown_reasons=["Alchemy RPC is unavailable"])
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
        except AlchemyRpcError as exc:
            return ForkRun(run_id, "unknown", None, capability=capability, unknown_reasons=[str(exc)])
        try:
            upstream = self.rpc.rpc_url
            if not upstream:
                raise AnvilUnavailable("Alchemy RPC URL is not configured")
            self.fork.start(upstream, anchor)
            fork_block = self.fork.rpc_request(
                "eth_getBlockByNumber", [hex(anchor.block_number), False]
            )
            if not fork_block or fork_block.get("hash") != anchor.block_hash:
                raise AnvilUnavailable(
                    "fork anchor mismatch: local Anvil block hash differs from Alchemy"
                )
            results = [self.fork.run_scenario(scenario, anchor) for scenario in scenarios]
            status = "complete" if all(result.status in {"success", "reverted"} for result in results) else "partial"
            return ForkRun(run_id, status, anchor, results=results, capability=capability)
        except AnvilUnavailable as exc:
            return ForkRun(run_id, "unknown", anchor, capability=capability, unknown_reasons=[str(exc)])
        finally:
            self.fork.stop()
