from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ..core.alchemy_gateway import AlchemyGateway
from ..state_fork.alchemy_rpc import AlchemyRpcClient, AlchemyRpcError
from .models import ChainAnchor, RawObservation


class AlchemySource:
    """Chain-facts adapter backed by the shared Alchemy gateway."""

    def __init__(self, rpc: AlchemyRpcClient | None = None, gateway: AlchemyGateway | None = None):
        self.gateway = gateway or AlchemyGateway(rpc or AlchemyRpcClient())
        self.rpc = self.gateway.rpc

    def capability_probe(self) -> dict[str, Any]:
        return self.rpc.capability_probe()

    def anchor(self, tag: str = "safe", block_number: int | None = None) -> ChainAnchor:
        tag_value = hex(block_number) if block_number is not None else tag
        value, _evidence = self.gateway.get_block_by_number(tag_value, False, fresh=True)
        if not isinstance(value, dict) or not value.get("number") or not value.get("hash"):
            raise AlchemyRpcError(f"Alchemy returned an invalid {tag_value} block")
        chain_id, _chain_ev = self.gateway.call("eth_chainId", [], anchor=None, use_cache=True)
        return ChainAnchor(
            chain_id=str(chain_id),
            block_number=self._hex_int(value["number"]),
            block_hash=str(value["hash"]),
            finality="explicit" if block_number is not None else tag,
        )

    def get_code(self, address: str, anchor: ChainAnchor) -> RawObservation:
        value, _evidence = self.gateway.call("eth_getCode", [address, hex(anchor.block_number)], anchor=anchor)
        return self._observation("eth_getCode", address, {"code": value}, anchor)

    def get_balance(self, address: str, anchor: ChainAnchor) -> RawObservation:
        value, _evidence = self.gateway.call("eth_getBalance", [address, hex(anchor.block_number)], anchor=anchor)
        return self._observation("eth_getBalance", address, {"balance": value}, anchor)

    def get_logs(self, address: str, anchor: ChainAnchor, from_block: int, to_block: int, max_chunk_blocks: int = 512) -> RawObservation:
        """Read logs with adaptive chunking so free/low-limit RPC plans do not fail a scan."""
        if from_block > to_block:
            return self._observation("eth_getLogs", address, {"logs": [], "fromBlock": from_block, "toBlock": to_block, "chunks": 0}, anchor)
        chunks: list[dict[str, Any]] = []
        start = from_block
        chunk_count = 0
        while start <= to_block:
            end = min(to_block, start + max(1, max_chunk_blocks) - 1)
            logs = self._get_logs_chunk(address, start, end, min_chunk=1, anchor=anchor)
            chunks.extend(logs)
            chunk_count += 1
            start = end + 1
        return self._observation("eth_getLogs", address, {"logs": chunks, "fromBlock": from_block, "toBlock": to_block, "chunks": chunk_count}, anchor)

    def _get_logs_chunk(self, address: str, from_block: int, to_block: int, min_chunk: int = 1, anchor: ChainAnchor | None = None) -> list[dict[str, Any]]:
        try:
            result, _evidence = self.gateway.get_logs(
                {"address": address, "fromBlock": hex(from_block), "toBlock": hex(to_block)},
                anchor=anchor,
                fresh=True,
            )
            return [item for item in (result or []) if isinstance(item, dict)]
        except Exception:
            if from_block >= to_block or (to_block - from_block + 1) <= min_chunk:
                raise
            midpoint = (from_block + to_block) // 2
            return self._get_logs_chunk(address, from_block, midpoint, min_chunk, anchor) + self._get_logs_chunk(address, midpoint + 1, to_block, min_chunk, anchor)

    def get_storage_at(self, address: str, slot: str, anchor: ChainAnchor) -> RawObservation:
        value, _evidence = self.gateway.get_storage_at(address, slot, hex(anchor.block_number), anchor=anchor)
        return self._observation("eth_getStorageAt", address, {"slot": slot, "value": value}, anchor)

    def call_selector(self, address: str, selector: str, anchor: ChainAnchor) -> RawObservation:
        return self.call_data(address, selector, anchor)

    def call_data(self, address: str, data: str, anchor: ChainAnchor) -> RawObservation:
        value, _evidence = self.gateway.eth_call({"to": address, "data": data}, hex(anchor.block_number), anchor=anchor)
        return self._observation("eth_call", address, {"data": data, "selector": data[:10], "value": value}, anchor)

    @staticmethod
    def _hex_int(value: Any) -> int:
        return int(value, 16) if isinstance(value, str) else int(value)

    def _observation(self, endpoint: str, subject: str, payload: dict[str, Any], anchor: ChainAnchor) -> RawObservation:
        return RawObservation(
            observation_id=f"alchemy:{endpoint}:{anchor.block_hash}:{subject}",
            provider=str(self.gateway.provider_health().get("selected_provider") or getattr(self.gateway.rpc, "provider_name", "alchemy")),
            endpoint=endpoint,
            subject=subject,
            observed_at=datetime.now(timezone.utc).isoformat(),
            payload=payload,
            anchor=anchor,
        )
