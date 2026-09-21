from __future__ import annotations

from typing import Any

from ..core.alchemy_gateway import AlchemyGateway
from ..core.models import UnifiedAnchor
from .ledger import TransferLedger


class AlchemyEventIndexer:
    def __init__(self, gateway: AlchemyGateway | None = None, ledger: TransferLedger | None = None, chunk_size: int = 2_000):
        self.gateway = gateway or AlchemyGateway()
        self.ledger = ledger or TransferLedger()
        self.chunk_size = chunk_size

    def backfill_token(self, chain_id: str, token_address: str, from_block: int, to_block: int, anchor: UnifiedAnchor | None = None) -> dict[str, Any]:
        if to_block < from_block:
            raise ValueError("to_block must be >= from_block")
        totals = {"accepted": 0, "duplicate": 0, "removed": 0, "malformed": 0, "chunks": 0}
        start = from_block
        while start <= to_block:
            end = min(start + self.chunk_size - 1, to_block)
            result, _evidence = self.gateway.call("eth_getLogs", [{"address": token_address, "fromBlock": hex(start), "toBlock": hex(end), "topics": []}], anchor=anchor)
            stats = self.ledger.ingest_logs(chain_id, result or [])
            for key, value in stats.items():
                totals[key] += value
            totals["chunks"] += 1
            start = end + 1
        totals["holders"] = len(self.ledger.holder_snapshot(token_address))
        return totals
