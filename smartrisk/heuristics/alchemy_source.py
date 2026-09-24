from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
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
        try:
            value, _evidence = self.gateway.get_block_by_number(tag_value, False, fresh=True)
        except Exception:
            # Some RPC plans do not expose safe/finalized, and a transient 429
            # on that optional tag must not discard an otherwise valid scan.
            if block_number is not None or tag_value == "latest":
                raise
            value, _evidence = self.gateway.get_block_by_number("latest", False, fresh=True)
            tag = "latest"
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

    def get_logs(
        self,
        address: str,
        anchor: ChainAnchor,
        from_block: int,
        to_block: int,
        max_chunk_blocks: int = 1_500,
        concurrency: int = 4,
        topic0: str | None = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
    ) -> RawObservation:
        """Read filtered logs with bounded parallelism and adaptive fallback.

        SmartRisk primarily consumes ERC-20/ERC-721 Transfer events for holder/history
        analysis, so filtering by topic0 materially reduces provider payload size.
        """
        if from_block > to_block:
            return self._observation("eth_getLogs", address, {"logs": [], "fromBlock": from_block, "toBlock": to_block, "chunks": 0}, anchor)

        size = max(1, int(max_chunk_blocks))
        ranges = []
        start = from_block
        while start <= to_block:
            end = min(to_block, start + size - 1)
            ranges.append((start, end))
            start = end + 1

        results: dict[int, list[dict[str, Any]]] = {}
        max_workers = max(1, min(int(concurrency), len(ranges)))
        if max_workers == 1:
            for idx, (start, end) in enumerate(ranges):
                results[idx] = self._get_logs_chunk(address, start, end, min_chunk=1, anchor=anchor, topic0=topic0)
        else:
            with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="smartrisk-rpc-logs") as executor:
                futures = {
                    executor.submit(self._get_logs_chunk, address, start, end, 1, anchor, topic0): idx
                    for idx, (start, end) in enumerate(ranges)
                }
                for future in as_completed(futures):
                    results[futures[future]] = future.result()

        chunks: list[dict[str, Any]] = []
        for idx in range(len(ranges)):
            chunks.extend(results.get(idx, []))
        return self._observation(
            "eth_getLogs", address,
            {
                "logs": chunks,
                "fromBlock": from_block,
                "toBlock": to_block,
                "chunks": len(ranges),
                "topic0": topic0,
            },
            anchor,
        )

    def _get_logs_chunk(
        self,
        address: str,
        from_block: int,
        to_block: int,
        min_chunk: int = 1,
        anchor: ChainAnchor | None = None,
        topic0: str | None = None,
    ) -> list[dict[str, Any]]:
        params = {"address": address, "fromBlock": hex(from_block), "toBlock": hex(to_block)}
        if topic0:
            params["topics"] = [topic0]
        try:
            result, _evidence = self.gateway.get_logs(params, anchor=anchor, fresh=False)
            return [item for item in (result or []) if isinstance(item, dict)]
        except Exception as exc:
            if from_block >= to_block or (to_block - from_block + 1) <= min_chunk:
                raise
            # A rate-limit or transport failure is not a provider range-limit
            # error. Splitting it recursively multiplies requests and makes a
            # 429 storm worse; let the paced provider retry the same request.
            # Only split errors that look like an oversized getLogs query.
            # The generic provider error text is retained in the raised error.
            if "429" in str(exc) or "rate limit" in str(exc).lower():
                raise
            midpoint = (from_block + to_block) // 2
            left = self._get_logs_chunk(address, from_block, midpoint, min_chunk, anchor, topic0)
            right = self._get_logs_chunk(address, midpoint + 1, to_block, min_chunk, anchor, topic0)
            return left + right

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
