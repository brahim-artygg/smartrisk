from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..core.alchemy_gateway import AlchemyGateway
from .canonical import CanonicalBlock, CanonicalChain


@dataclass(frozen=True)
class SyncResult:
    status: str
    from_block: int | None
    to_block: int | None
    processed_blocks: int
    reorgs: int
    log_count: int
    diagnostics: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "from_block": self.from_block,
            "to_block": self.to_block,
            "processed_blocks": self.processed_blocks,
            "reorgs": self.reorgs,
            "log_count": self.log_count,
            "diagnostics": list(self.diagnostics),
        }


class PollingChainIndexer:
    """Small reorg-aware polling/backfill coordinator for a single token.

    It intentionally uses normal JSON-RPC only. WebSocket transport can be added
    later without changing the canonical ledger contract.
    """

    def __init__(
        self,
        gateway: AlchemyGateway | None = None,
        chain: CanonicalChain | None = None,
        token_address: str | None = None,
        reorg_window: int = 12,
        max_blocks_per_poll: int = 64,
    ):
        self.gateway = gateway or AlchemyGateway()
        self.chain = chain or CanonicalChain("unknown")
        self.token_address = token_address
        self.reorg_window = max(1, reorg_window)
        self.max_blocks_per_poll = max(1, max_blocks_per_poll)

    def sync_once(self, from_block: int | None = None, to_block: int | None = None) -> SyncResult:
        latest_raw, _ = self.gateway.get_block_by_number("latest", False, fresh=True)
        if not isinstance(latest_raw, dict) or not latest_raw.get("number") or not latest_raw.get("hash"):
            return SyncResult("unknown", None, None, 0, 0, 0, ("latest block response is unavailable",))
        latest = self._hex_int(latest_raw["number"])
        current = self.chain.blocks.get(self.chain.head) if self.chain.head else None
        if from_block is None:
            if current is None:
                from_block = latest
            else:
                from_block = max(0, current.number - self.reorg_window + 1)
        to_block = latest if to_block is None else min(latest, to_block)
        if to_block < from_block:
            return SyncResult("complete", from_block, to_block, 0, 0, 0)

        if current and from_block > current.number + 1:
            from_block = current.number + 1

        diagnostics: list[str] = []
        processed = reorgs = log_count = 0
        for number in range(from_block, to_block + 1):
            try:
                block_raw, _ = self.gateway.get_block_by_number(number, False, fresh=True)
                if not isinstance(block_raw, dict) or not block_raw.get("hash"):
                    diagnostics.append(f"block {number} unavailable")
                    continue
                logs: list[dict[str, Any]] = []
                if self.token_address:
                    params = {"address": self.token_address, "fromBlock": hex(number), "toBlock": hex(number)}
                    logs_raw, _ = self.gateway.get_logs(params, fresh=True)
                    if isinstance(logs_raw, list):
                        logs = [item for item in logs_raw if isinstance(item, dict)]
                        log_count += len(logs)
                block = CanonicalBlock(
                    number=number,
                    block_hash=str(block_raw["hash"]),
                    parent_hash=str(block_raw.get("parentHash")) if block_raw.get("parentHash") else None,
                    logs=logs,
                )
                outcome = self.chain.ingest_block(block)
                if outcome.get("reorg"):
                    reorgs += 1
                processed += 1
            except Exception as exc:
                diagnostics.append(f"block {number} sync failed: {exc}")

        status = "complete" if processed == (to_block - from_block + 1) and not diagnostics else "partial" if processed else "unknown"
        return SyncResult(status, from_block, to_block, processed, reorgs, log_count, tuple(diagnostics))

    @staticmethod
    def _hex_int(value: Any) -> int:
        return int(value, 16) if isinstance(value, str) else int(value)
