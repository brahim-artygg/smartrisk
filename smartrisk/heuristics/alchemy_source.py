from __future__ import annotations

import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any

from ..core.alchemy_gateway import AlchemyGateway
from ..state_fork.alchemy_rpc import AlchemyRpcClient, AlchemyRpcError
from .models import ChainAnchor, RawObservation


class _LogBudget:
    """Shared, thread-safe limits for one log read (busy tokens must not exhaust memory or CU)."""

    def __init__(self, max_logs: int, max_calls: int):
        self.max_logs, self.max_calls = max_logs, max_calls
        self.total = 0
        self.calls = 0
        self.truncated = False
        self.reason: str | None = None
        self._lock = threading.Lock()

    def exhausted(self) -> bool:
        with self._lock:
            if self.total >= self.max_logs:
                self.truncated, self.reason = True, self.reason or "max_logs"
            elif self.calls >= self.max_calls:
                self.truncated, self.reason = True, self.reason or "max_calls"
            return self.truncated

    def count_call(self) -> None:
        with self._lock:
            self.calls += 1

    def add_logs(self, n: int) -> None:
        with self._lock:
            self.total += n


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
        # Newest -> oldest, so a truncated read keeps the most recent activity.
        ranges = []
        end = to_block
        while end >= from_block:
            start = max(from_block, end - size + 1)
            ranges.append((start, end))
            end = start - 1

        budget = _LogBudget(
            max_logs=self._env_int("SMARTRISK_LOG_MAX_LOGS", 30_000),
            max_calls=self._env_int("SMARTRISK_LOG_MAX_CALLS", 150),
        )
        workers = max(1, min(int(concurrency), len(ranges)))
        chunks: list[dict[str, Any]] = []
        done = 0
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="smartrisk-rpc-logs") as executor:
            for i in range(0, len(ranges), workers):
                if budget.exhausted():
                    break
                batch = ranges[i:i + workers]
                if workers == 1:
                    parts = [self._get_logs_chunk(address, a, b, 1, anchor, topic0, budget) for a, b in batch]
                else:
                    parts = list(executor.map(lambda r: self._get_logs_chunk(address, r[0], r[1], 1, anchor, topic0, budget), batch))
                for part in parts:
                    chunks.extend(part)
                done += len(batch)
        if len(chunks) > budget.max_logs:
            chunks = chunks[: budget.max_logs]
        truncated = budget.truncated or done < len(ranges)
        return self._observation(
            "eth_getLogs", address,
            {
                "logs": chunks,
                "fromBlock": from_block,
                "toBlock": to_block,
                "chunks": done,
                "topic0": topic0,
                "rpc_calls": budget.calls,
                "truncated": truncated,
                "truncation_reason": budget.reason or ("max_logs/max_calls" if truncated else None),
            },
            anchor,
        )

    @staticmethod
    def _env_int(name: str, default: int) -> int:
        try:
            return max(1, int(os.getenv(name, default)))
        except (TypeError, ValueError):
            return default

    _BLOCK_LIMIT_RE = re.compile(r"up to an? (\d+)\s*block range", re.IGNORECASE)

    def _get_logs_chunk(
        self,
        address: str,
        from_block: int,
        to_block: int,
        min_chunk: int = 1,
        anchor: ChainAnchor | None = None,
        topic0: str | None = None,
        budget: "_LogBudget | None" = None,
    ) -> list[dict[str, Any]]:
        if budget is not None and budget.exhausted():
            return []
        params = {"address": address, "fromBlock": hex(from_block), "toBlock": hex(to_block)}
        if topic0:
            params["topics"] = [topic0]
        try:
            if budget is not None:
                budget.count_call()
            result, _evidence = self.gateway.get_logs(params, anchor=anchor, fresh=False)
            items = [item for item in (result or []) if isinstance(item, dict)]
            if budget is not None:
                budget.add_logs(len(items))
            return items
        except Exception as exc:
            if from_block >= to_block or (to_block - from_block + 1) <= min_chunk:
                raise
            # A rate-limit or transport failure is not a provider range-limit
            # error. Splitting it recursively multiplies requests and makes a
            # 429 storm worse; let the paced provider retry the same request.
            if "429" in str(exc) or "rate limit" in str(exc).lower():
                raise
            # Providers state their hard range limit (Alchemy free tier: 10 blocks). Use it
            # directly instead of bisecting through ~2,500 doomed requests.
            match = self._BLOCK_LIMIT_RE.search(str(exc))
            if match:
                limit = max(1, int(match.group(1)))
                if (to_block - from_block + 1) > limit:
                    out: list[dict[str, Any]] = []
                    end = to_block  # newest first
                    while end >= from_block and not (budget is not None and budget.exhausted()):
                        start = max(from_block, end - limit + 1)
                        out.extend(self._get_logs_chunk(address, start, end, limit, anchor, topic0, budget))
                        end = start - 1
                    return out
            midpoint = (from_block + to_block) // 2
            right = self._get_logs_chunk(address, midpoint + 1, to_block, min_chunk, anchor, topic0, budget)
            left = self._get_logs_chunk(address, from_block, midpoint, min_chunk, anchor, topic0, budget)
            return right + left

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
