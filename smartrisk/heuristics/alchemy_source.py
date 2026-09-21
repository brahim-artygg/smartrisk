from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ..state_fork.alchemy_rpc import AlchemyRpcClient, AlchemyRpcError
from .models import ChainAnchor, RawObservation


class AlchemySource:
    def __init__(self, rpc: AlchemyRpcClient | None = None):
        self.rpc = rpc or AlchemyRpcClient()

    def capability_probe(self) -> dict[str, Any]:
        return self.rpc.capability_probe()

    def anchor(self, tag: str = "safe", block_number: int | None = None) -> ChainAnchor:
        tag_value = hex(block_number) if block_number is not None else tag
        number, block = self.rpc.get_anchor(tag_value)
        return ChainAnchor(
            chain_id=self.rpc.get_chain_id(),
            block_number=number,
            block_hash=block["hash"],
            finality="explicit" if block_number is not None else tag,
        )

    def get_code(self, address: str, anchor: ChainAnchor) -> RawObservation:
        return self._observation("eth_getCode", address, {"code": self.rpc.get_code(address, hex(anchor.block_number))}, anchor)

    def get_balance(self, address: str, anchor: ChainAnchor) -> RawObservation:
        return self._observation("eth_getBalance", address, {"balance": self.rpc.get_balance(address, hex(anchor.block_number))}, anchor)

    def get_logs(self, address: str, anchor: ChainAnchor, from_block: int, to_block: int) -> RawObservation:
        payload = self.rpc.request("eth_getLogs", [{"address": address, "fromBlock": hex(from_block), "toBlock": hex(to_block)}])
        return self._observation("eth_getLogs", address, {"logs": payload or [], "fromBlock": from_block, "toBlock": to_block}, anchor)

    def _observation(self, endpoint: str, subject: str, payload: dict[str, Any], anchor: ChainAnchor) -> RawObservation:
        return RawObservation(
            observation_id=f"alchemy:{endpoint}:{anchor.block_hash}:{subject}",
            provider="alchemy",
            endpoint=endpoint,
            subject=subject,
            observed_at=datetime.now(timezone.utc).isoformat(),
            payload=payload,
            anchor=anchor,
        )
