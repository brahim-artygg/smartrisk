from __future__ import annotations

import time
import uuid
from typing import Any

from .anvil import AnvilFork, AnvilUnavailable
from .dex_discovery import DexDiscoveryReport, discover_pairs
from .models import BlockAnchor, TradeMatrixRun
from .honeypot import HoneypotMatrix
from .trade_builder import DexRouteRegistry, UniswapV2ScenarioBuilder
from ..heuristics.dexscreener import DexscreenerClient
from ..core.networks import get_network
from .alchemy_rpc import AlchemyRpcClient, AlchemyRpcError


class AutoTradeAnalyzer:
    """Discover a market pair, build a local route plan, and optionally execute it on Anvil."""

    ENGINE_VERSION = "0.9.0"

    def __init__(
        self,
        rpc: AlchemyRpcClient | None = None,
        dexscreener: DexscreenerClient | None = None,
        fork: AnvilFork | None = None,
        routes: DexRouteRegistry | None = None,
    ):
        self.rpc = rpc or AlchemyRpcClient()
        self.dexscreener = dexscreener or DexscreenerClient()
        self.fork = fork or AnvilFork()
        self.builder = UniswapV2ScenarioBuilder(routes)

    def discover(
        self,
        chain_id: str,
        token_address: str,
    ) -> tuple[BlockAnchor | None, DexDiscoveryReport, dict[str, Any]]:
        capability = {"alchemy": self.rpc.capability_probe(), "dexscreener": self.dexscreener.capability_probe()}
        if capability["alchemy"].get("status") != "ready":
            report = DexDiscoveryReport(chain_id, token_address, diagnostics=["Alchemy RPC is unavailable"])
            return None, report, capability
        try:
            anchor = self._anchor("safe", None)
        except (AlchemyRpcError, KeyError, TypeError, ValueError) as exc:
            report = DexDiscoveryReport(chain_id, token_address, diagnostics=[f"anchor resolution failed: {exc}"])
            return None, report, capability
        network = get_network(chain_id)
        observation = self.dexscreener.get_token_pairs(network.dexscreener_id, token_address)
        report = discover_pairs(observation.payload, network.chain_id, token_address)
        report.selected_pair = next((pair for pair in report.pairs if self.builder.registry.resolve(pair.chain_id, pair.dex_id)), report.selected_pair)
        if observation.error:
            report.diagnostics.append(f"DexScreener observation error: {observation.error}")
        if observation.stale:
            report.diagnostics.append("DexScreener observation is stale")
        return anchor, report, capability

    def analyze(
        self,
        chain_id: str,
        token_address: str,
        trader: str,
        buy_amount_wei: int,
        run_id: str | None = None,
        block_tag: str = "safe",
        block_number: int | None = None,
        execute: bool = True,
    ) -> TradeMatrixRun:
        run_id = run_id or str(uuid.uuid4())
        capability = {"alchemy": self.rpc.capability_probe(), "dexscreener": self.dexscreener.capability_probe()}
        if capability["alchemy"].get("status") != "ready":
            return TradeMatrixRun(run_id, "unknown", None, token_address, None, plan={"capability": capability}, unknown_reasons=["Alchemy RPC is unavailable"])
        try:
            anchor = self._anchor(block_tag, block_number)
        except (AlchemyRpcError, KeyError, TypeError, ValueError) as exc:
            return TradeMatrixRun(run_id, "unknown", None, token_address, None, plan={"capability": capability}, unknown_reasons=[str(exc)])

        network = get_network(chain_id)
        discovery_chain = network.dexscreener_id
        observation = self.dexscreener.get_token_pairs(discovery_chain, token_address)
        discovery = discover_pairs(observation.payload, network.chain_id, token_address)
        if observation.error:
            discovery.diagnostics.append(f"DexScreener observation error: {observation.error}")
        if discovery.selected_pair is None:
            return TradeMatrixRun(run_id, "unknown", anchor, token_address, None, plan={"discovery": discovery.to_dict()}, unknown_reasons=discovery.diagnostics)

        deadline = (anchor.timestamp or int(time.time())) + 900
        selected_plan = None
        selected_pair = None
        rejected_routes: list[str] = []
        for pair in discovery.pairs:
            candidate = self.builder.build_native_plan(pair, token_address, trader, buy_amount_wei, deadline)
            if candidate.executable:
                selected_plan = candidate
                selected_pair = pair
                break
            rejected_routes.append(f"{pair.dex_id}:{candidate.reason or 'not executable'}")
        if selected_plan is None:
            selected_pair = discovery.selected_pair
            selected_plan = self.builder.build_native_plan(selected_pair, token_address, trader, buy_amount_wei, deadline)
        discovery.selected_pair = selected_pair
        plan = selected_plan
        if rejected_routes:
            discovery.diagnostics.extend(f"route skipped: {item}" for item in rejected_routes)
        matrix_plan = HoneypotMatrix().plan(
            plan.buy.scenario_id if plan.buy else "",
            plan.approve.scenario_id if plan.approve else None,
            {
                "baseline": "trade:sell:baseline",
                "micro_sell": "trade:sell:micro_sell",
                "small_sell": "trade:sell:small_sell",
                "partial_sell": "trade:sell:partial_sell",
                "sell_all": "trade:sell:sell_all",
                "transfer": "trade:transfer:only",
            },
        )
        plan_payload = {"discovery": discovery.to_dict(), "execution_plan": plan.to_dict(), "honeypot_matrix": matrix_plan.to_dict(), "capability": capability}
        if not execute:
            return TradeMatrixRun(run_id, "complete" if plan.executable else "partial", anchor, token_address, discovery.selected_pair.pair_address, plan=plan_payload, unknown_reasons=[] if plan.executable else [plan.reason or "plan is not executable"])
        if not plan.executable:
            return TradeMatrixRun(run_id, "unknown", anchor, token_address, discovery.selected_pair.pair_address, plan=plan_payload, unknown_reasons=[plan.reason or "trade plan is not executable"])
        try:
            self._start_and_verify(anchor)
            result = self.fork.run_trade_matrix(plan, anchor, run_id)
            result.plan = plan_payload
            return result
        except AnvilUnavailable as exc:
            return TradeMatrixRun(run_id, "unknown", anchor, token_address, discovery.selected_pair.pair_address, plan=plan_payload, unknown_reasons=[str(exc)])
        finally:
            self.fork.stop()

    def _anchor(self, block_tag: str, block_number: int | None) -> BlockAnchor:
        tag = hex(block_number) if block_number is not None else block_tag
        number, block = self.rpc.get_anchor(tag)
        return BlockAnchor(
            chain_id=self.rpc.get_chain_id(),
            block_number=number,
            block_hash=block["hash"],
            parent_hash=block.get("parentHash"),
            timestamp=int(block["timestamp"], 16) if block.get("timestamp") else None,
            finality="explicit" if block_number is not None else block_tag,  # type: ignore[arg-type]
        )

    def _start_and_verify(self, anchor: BlockAnchor) -> None:
        if not self.rpc.rpc_url:
            raise AnvilUnavailable("Alchemy RPC URL is not configured")
        self.fork.start(self.rpc.rpc_url, anchor)
        fork_block = self.fork.rpc_request("eth_getBlockByNumber", [hex(anchor.block_number), False])
        if not fork_block or fork_block.get("hash") != anchor.block_hash:
            raise AnvilUnavailable("fork anchor mismatch: local Anvil block hash differs from Alchemy")
